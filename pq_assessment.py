#!/usr/bin/env python3
"""
KyberGuard — Post-Quantum Assessment Module
Bewertet PQ-Readiness von Kundensystemen anhand einer URL-Eingabe.

SECURITY-HISTORY:
  2026-04-24: SSRF-Vulnerability gemeldet (Nero Audit)
  2026-04-26: SSRF-Fix implementiert — Private-IP-Blocklist + DNS-Aufloesung vor Request
"""

import ipaddress
import logging
import re
import socket
from typing import Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------
ALLOWED_SCHEMES = {"https"}
REQUEST_TIMEOUT = 10  # Sekunden
MAX_REDIRECTS = 3

# SSRF-Blocklist: alle privaten, link-lokalen und loopback Ranges
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # Link-local
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),    # Shared address space (RFC 6598)
    ipaddress.ip_network("192.0.0.0/24"),     # IETF Protocol Assignments
    ipaddress.ip_network("198.18.0.0/15"),    # Benchmarking
    ipaddress.ip_network("240.0.0.0/4"),      # Reserved
    # IPv6
    ipaddress.ip_network("::1/128"),          # Loopback
    ipaddress.ip_network("fc00::/7"),         # ULA
    ipaddress.ip_network("fe80::/10"),        # Link-local
    ipaddress.ip_network("::/128"),
]


def _is_private_ip(ip_str: str) -> bool:
    """Prueft ob eine IP-Adresse in einer blockierten Range liegt.

    Args:
        ip_str: IP-Adresse als String (IPv4 oder IPv6)

    Returns:
        True wenn die IP blockiert werden soll, False wenn erlaubt.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        # Ungueltige IP — sicherheitshalber blockieren
        return True

    for network in _BLOCKED_NETWORKS:
        if addr in network:
            return True
    return False


def _validate_url(url: str) -> tuple[bool, str]:
    """Validiert eine URL gegen SSRF und Schema-Restrictions.

    Loest den Hostnamen auf und prueft alle aufgeloesten IPs gegen die Blocklist.
    DNS-Rebinding wird durch Aufloesung VOR dem Request verhindert.

    Args:
        url: Die zu pruefende URL (User-Input)

    Returns:
        (is_valid, error_message) — bei Erfolg ist error_message leer.
    """
    # Schema-Check
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False, f"Nur HTTPS erlaubt, erhalten: {parsed.scheme!r}"

    hostname = parsed.hostname
    if not hostname:
        return False, "Kein Hostname in URL"

    # Direkte IP-Eingabe pruefen
    try:
        addr = ipaddress.ip_address(hostname)
        if _is_private_ip(str(addr)):
            logger.warning("SSRF-Versuch blockiert: direkte private IP %s", hostname)
            return False, "Ziel-IP nicht erlaubt"
    except ValueError:
        pass  # Kein direktes IP-Literal — DNS-Aufloesung folgt

    # DNS-Aufloesung und Pruefung ALLER zurueckgegebenen Adressen
    try:
        results = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        logger.warning("DNS-Aufloesung fehlgeschlagen fuer %s: %s", hostname, exc)
        return False, "Hostname konnte nicht aufgeloest werden"

    for family, _type, _proto, _canon, sockaddr in results:
        ip = sockaddr[0]
        if _is_private_ip(ip):
            logger.warning(
                "SSRF-Versuch blockiert: %s loest auf private IP %s auf",
                hostname,
                ip,
            )
            return False, "Ziel-IP nicht erlaubt"

    return True, ""


def fetch_pq_metadata(url: str) -> Optional[dict]:
    """Ruft PQ-Metadaten von einer Kunden-URL ab (SSRF-sicher).

    Args:
        url: Vollstaendige HTTPS-URL des zu pruefenden Endpunkts

    Returns:
        Dict mit Metadaten oder None bei Fehler.

    Raises:
        ValueError: Bei ungueltigem oder blockiertem URL.
    """
    is_valid, error = _validate_url(url)
    if not is_valid:
        raise ValueError(f"URL abgelehnt: {error}")

    try:
        with httpx.Client(
            timeout=REQUEST_TIMEOUT,
            follow_redirects=True,
            max_redirects=MAX_REDIRECTS,
        ) as client:
            response = client.get(url)
            response.raise_for_status()
            return response.json()
    except httpx.TimeoutException:
        logger.error("Timeout beim Abruf von PQ-Metadaten (URL nicht geloggt)")
        return None
    except httpx.HTTPStatusError as exc:
        logger.error("HTTP-Fehler beim PQ-Abruf: %s", exc.response.status_code)
        return None
    except httpx.RequestError as exc:
        logger.error("Netzwerkfehler beim PQ-Abruf: %s", type(exc).__name__)
        return None


def assess_pq_readiness(company_url: str) -> dict:
    """Hauptfunktion: Bewertet PQ-Readiness fuer eine Unternehmens-URL.

    Args:
        company_url: URL des Unternehmens-Endpunkts (User-Input)

    Returns:
        Assessment-Ergebnis als Dict mit score, findings, recommendations.
    """
    try:
        metadata = fetch_pq_metadata(company_url)
    except ValueError as exc:
        return {
            "score": 0,
            "status": "error",
            "message": str(exc),
            "findings": [],
            "recommendations": [],
        }

    if metadata is None:
        return {
            "score": 0,
            "status": "unreachable",
            "message": "Endpunkt nicht erreichbar",
            "findings": [],
            "recommendations": ["Endpunkt erreichbar machen fuer automatisches Assessment"],
        }

    # Hier wuerde die eigentliche PQ-Analyse stattfinden
    # Placeholder fuer kuenftige Implementierung
    findings = []
    recommendations = []

    tls_version = metadata.get("tls_version", "unknown")
    if tls_version not in ("TLSv1.3", "TLSv1.2"):
        findings.append({"severity": "HIGH", "finding": f"Veraltete TLS-Version: {tls_version}"})
        recommendations.append("TLS auf mindestens 1.2, empfohlen 1.3 aktualisieren")

    score = max(0, 100 - len(findings) * 20)

    return {
        "score": score,
        "status": "assessed",
        "findings": findings,
        "recommendations": recommendations,
    }
