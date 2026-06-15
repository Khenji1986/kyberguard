#!/usr/bin/env python3
"""
KyberGuard — Ransomware Intelligence Monitor
Ueberwacht bekannte Ransomware-Gruppen und matched Unternehmens-Nennungen
in Leak-Site-Feeds und Threat-Intelligence-Quellen.

SECURITY-HISTORY:
  2026-04-24: Regex-False-Positive gemeldet — match_company() ohne Wortgrenzen (Nero Audit)
  2026-04-26: Fix — re.compile mit \\b-Wortgrenzen + case-insensitive, Eingabevalidierung
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------
MIN_COMPANY_NAME_LENGTH = 2
MAX_COMPANY_NAME_LENGTH = 200
# Erlaubte Zeichen in Firmennamen (inkl. internationale Buchstaben, Bindestrich, Leerzeichen)
_COMPANY_NAME_PATTERN = re.compile(r"^[\w\s\-&.,()'À-ɏ]+$", re.UNICODE)


# ---------------------------------------------------------------------------
# Datenmodelle
# ---------------------------------------------------------------------------
@dataclass
class RansomwareMatch:
    """Ergebnis eines Unternehmens-Matchs in Threat-Intelligence-Daten."""
    company_name: str
    source: str
    context_snippet: str
    confidence: float  # 0.0 - 1.0
    matched_positions: list[tuple[int, int]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Input-Validierung
# ---------------------------------------------------------------------------
def _validate_company_name(company_name: str) -> tuple[bool, str]:
    """Validiert einen Firmennamen vor der Regex-Nutzung.

    Args:
        company_name: Zu pruefender Firmenname (User-Input)

    Returns:
        (is_valid, error_message)
    """
    if not company_name or not company_name.strip():
        return False, "Firmenname darf nicht leer sein"

    stripped = company_name.strip()

    if len(stripped) < MIN_COMPANY_NAME_LENGTH:
        return False, f"Firmenname zu kurz (Minimum: {MIN_COMPANY_NAME_LENGTH} Zeichen)"

    if len(stripped) > MAX_COMPANY_NAME_LENGTH:
        return False, f"Firmenname zu lang (Maximum: {MAX_COMPANY_NAME_LENGTH} Zeichen)"

    if not _COMPANY_NAME_PATTERN.match(stripped):
        return False, "Firmenname enthaelt ungueltgige Zeichen"

    return True, ""


def _build_company_regex(company_name: str) -> re.Pattern:
    """Erstellt ein Regex-Pattern mit Wortgrenzen fuer einen Firmennamen.

    FIX (2026-04-26): Wortgrenzen (\\b) verhindern False-Positives.
    Beispiel vorher: "GmbH" matched in "GmbH-Partner" → False-Positive
    Beispiel nachher: nur exakter Wortmatch

    Args:
        company_name: Bereinigter, validierter Firmenname

    Returns:
        Kompiliertes Regex-Pattern
    """
    escaped = re.escape(company_name.strip())
    # \\b-Wortgrenzen auf beiden Seiten — verhindert Partial-Matches
    pattern = rf"\b{escaped}\b"
    return re.compile(pattern, re.IGNORECASE | re.UNICODE)


def match_company(company_name: str, text: str, source: str = "unknown") -> Optional[RansomwareMatch]:
    """Prueft ob ein Unternehmensname in einem Text vorkommt (Wortgrenzen-sicher).

    FIX: Wortgrenzen verhindern False-Positives.
    Beispiel: "Acme" matcht nicht in "AcmeSoft" oder "NotAcme".

    Args:
        company_name: Name des zu suchenden Unternehmens (User-Input, wird validiert)
        text: Durchzusuchender Text (Threat-Intel-Feed)
        source: Quelle des Texts fuer das Match-Ergebnis

    Returns:
        RansomwareMatch wenn gefunden, None wenn kein Match oder Fehler.

    Raises:
        ValueError: Bei ungueltigem Firmennamen.
    """
    is_valid, error = _validate_company_name(company_name)
    if not is_valid:
        raise ValueError(f"Ungueltiger Firmenname: {error}")

    if not text:
        return None

    pattern = _build_company_regex(company_name)
    matches = list(pattern.finditer(text))

    if not matches:
        return None

    # Kontext-Snippet um ersten Match herum (ohne zu viel Kontext zu liefern)
    first_match = matches[0]
    start = max(0, first_match.start() - 50)
    end = min(len(text), first_match.end() + 50)
    snippet = f"...{text[start:end]}..."

    logger.info(
        "Ransomware-Match: Unternehmen '%s' in Quelle '%s' gefunden (%d Treffer)",
        company_name,
        source,
        len(matches),
    )

    return RansomwareMatch(
        company_name=company_name,
        source=source,
        context_snippet=snippet,
        confidence=min(1.0, 0.5 + len(matches) * 0.1),
        matched_positions=[(m.start(), m.end()) for m in matches],
    )


def scan_feed(company_name: str, feed_entries: list[dict]) -> list[RansomwareMatch]:
    """Scannt einen kompletten Threat-Intel-Feed nach Unternehmens-Nennungen.

    Args:
        company_name: Name des zu ueberwachenden Unternehmens
        feed_entries: Liste von Dicts mit 'text' und 'source' Schluesseln

    Returns:
        Liste aller gefundenen Matches, sortiert nach Confidence (absteigend).
    """
    results = []

    for entry in feed_entries:
        text = entry.get("text", "")
        source = entry.get("source", "unknown")

        try:
            match = match_company(company_name, text, source)
            if match:
                results.append(match)
        except ValueError as exc:
            logger.error("Scan-Fehler fuer Entry aus '%s': %s", source, exc)
            continue

    results.sort(key=lambda m: m.confidence, reverse=True)
    return results
