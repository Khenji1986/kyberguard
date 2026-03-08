#!/usr/bin/env python3
"""
VIPER - Vishing Intelligence & Protection Engine
Teil von SecureBot AI | Reich Frieguen

Analysiert Telefonnummern auf Vishing/Scam-Verdacht.
Free:    Spam-Score + Meldungsanzahl
Pro/Biz: Vollanalyse + Carrier + Kampagnen-Kontext
"""

import os
import re
import sqlite3
import logging
import httpx
from datetime import date

logger = logging.getLogger(__name__)

# Veriphone.io  — explizit DE/EU-Support, Carrier + Line-Type + Region
# Kostenloser Tier: veriphone.io
VERIPHONE_KEY = os.getenv("VERIPHONE_API_KEY", "")

# AbstractAPI Phone Validation — 190+ Laender, 250 Requests/Monat gratis
# Kostenloser Tier: abstractapi.com/api/phone-validation-api
ABSTRACT_KEY = os.getenv("ABSTRACTAPI_PHONE_KEY", "")

DB_PATH = "/app/data/securebot.db"

PHONE_RE = re.compile(r"^\+[1-9]\d{6,14}$")


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------

def normalize_number(raw: str) -> str:
    """Bereinigt und normalisiert auf E.164 Format (+49151...)."""
    cleaned = re.sub(r"[\s\-\(\)\/\.]", "", raw.strip())
    if cleaned.startswith("0049"):
        cleaned = "+49" + cleaned[4:]
    elif cleaned.startswith("00"):
        cleaned = "+" + cleaned[2:]
    elif cleaned.startswith("0") and not cleaned.startswith("+"):
        cleaned = "+49" + cleaned[1:]
    elif not cleaned.startswith("+"):
        cleaned = "+" + cleaned
    return cleaned


def is_valid_number(number: str) -> bool:
    return bool(PHONE_RE.match(number))


# ---------------------------------------------------------------------------
# Datenbank
# ---------------------------------------------------------------------------

def init_viper_tables(conn: sqlite3.Connection):
    """VIPER-Tabellen in bestehender SecureBot-DB erstellen."""
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS viper_numbers (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            number     TEXT NOT NULL UNIQUE,
            carrier    TEXT,
            line_type  TEXT,
            country    TEXT,
            region     TEXT,
            spam_score INTEGER DEFAULT 0,
            report_cnt INTEGER DEFAULT 0,
            first_seen DATE DEFAULT CURRENT_DATE,
            last_seen  DATE DEFAULT CURRENT_DATE
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS viper_campaigns (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            description TEXT,
            target_org  TEXT,
            scam_type   TEXT,
            active      INTEGER DEFAULT 1,
            started_at  DATE DEFAULT CURRENT_DATE,
            ended_at    DATE
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS viper_number_campaigns (
            number_id   INTEGER REFERENCES viper_numbers(id),
            campaign_id INTEGER REFERENCES viper_campaigns(id),
            confidence  INTEGER DEFAULT 80,
            PRIMARY KEY (number_id, campaign_id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS viper_reports (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            number      TEXT NOT NULL,
            scam_type   TEXT,
            description TEXT,
            reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()


def _db_check(number: str, conn: sqlite3.Connection) -> dict:
    """Prüft ob Nummer in VIPER-DB bekannt ist und liefert Kampagnen."""
    c = conn.cursor()
    c.execute(
        "SELECT id, spam_score, report_cnt, carrier, line_type, country, region "
        "FROM viper_numbers WHERE number = ?",
        (number,),
    )
    row = c.fetchone()
    if not row:
        return {}

    num_id, spam_score, report_cnt, carrier, line_type, country, region = row

    c.execute(
        """
        SELECT vc.name, vc.description, vc.target_org, vc.scam_type, vnc.confidence
        FROM viper_campaigns vc
        JOIN viper_number_campaigns vnc ON vc.id = vnc.campaign_id
        WHERE vnc.number_id = ? AND vc.active = 1
        """,
        (num_id,),
    )
    campaigns = [
        {"name": r[0], "description": r[1], "target_org": r[2], "scam_type": r[3], "confidence": r[4]}
        for r in c.fetchall()
    ]

    return {
        "known": True,
        "spam_score": spam_score,
        "report_cnt": report_cnt,
        "carrier": carrier,
        "line_type": line_type,
        "country": country,
        "region": region,
        "campaigns": campaigns,
    }


def _db_upsert(number: str, info: dict, conn: sqlite3.Connection):
    """Speichert oder aktualisiert Nummereintrag."""
    c = conn.cursor()
    c.execute(
        """
        INSERT INTO viper_numbers (number, carrier, line_type, country, region, spam_score, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, CURRENT_DATE)
        ON CONFLICT(number) DO UPDATE SET
            carrier    = COALESCE(excluded.carrier,    carrier),
            line_type  = COALESCE(excluded.line_type,  line_type),
            country    = COALESCE(excluded.country,    country),
            region     = COALESCE(excluded.region,     region),
            spam_score = MAX(spam_score, excluded.spam_score),
            last_seen  = CURRENT_DATE
        """,
        (
            number,
            info.get("carrier") or None,
            info.get("line_type") or None,
            info.get("country") or None,
            info.get("region") or None,
            info.get("spam_score", 0),
        ),
    )
    conn.commit()


def db_add_report(number: str, scam_type: str, description: str, conn: sqlite3.Connection):
    """Fuegt anonymen Community-Report hinzu und erhoeht Spam-Score."""
    c = conn.cursor()
    c.execute(
        "INSERT INTO viper_reports (number, scam_type, description) VALUES (?, ?, ?)",
        (number, scam_type, description),
    )
    c.execute(
        """
        INSERT INTO viper_numbers (number, report_cnt, spam_score, last_seen)
        VALUES (?, 1, 40, CURRENT_DATE)
        ON CONFLICT(number) DO UPDATE SET
            report_cnt = report_cnt + 1,
            spam_score = MIN(100, spam_score + 10),
            last_seen  = CURRENT_DATE
        """,
        (number,),
    )
    conn.commit()


def db_get_stats(conn: sqlite3.Connection) -> dict:
    """Liefert VIPER-Statistiken fuer Admin."""
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM viper_numbers")
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM viper_numbers WHERE spam_score >= 75")
    high_risk = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM viper_reports")
    reports = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM viper_campaigns WHERE active = 1")
    campaigns = c.fetchone()[0]
    return {"total": total, "high_risk": high_risk, "reports": reports, "campaigns": campaigns}


# ---------------------------------------------------------------------------
# API-Lookups
# ---------------------------------------------------------------------------

async def _lookup_tellows(number: str) -> dict:
    """
    Tellows.de — groesste deutsche Spam-Datenbank.
    Oeffentliche XML-Schnittstelle, kein Account noetig.
    Liefert: score (1=gut, 9=sehr schlimm), calls, comments
    """
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            r = await client.get(
                f"https://www.tellows.de/basic/num/{number}",
                params={"xml": "1", "partner": "test", "apikey": "test"},
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if r.status_code != 200:
                return {}
            text = r.text
            # Score aus XML parsen (1=vertrauenswuerdig, 9=sehr gefaehrlich)
            import re as _re
            score_match   = _re.search(r"<score>(\d+)</score>", text)
            calls_match   = _re.search(r"<calls>(\d+)</calls>", text)
            comments_match = _re.search(r"<comments>(\d+)</comments>", text)
            if score_match:
                tellows_score = int(score_match.group(1))  # 1-9
                calls    = int(calls_match.group(1))    if calls_match    else 0
                comments = int(comments_match.group(1)) if comments_match else 0
                # Tellows 1-9 → VIPER 0-100 umrechnen
                # 1-3 = sicher (0-20), 4-5 = neutral (20-40), 6-7 = verdaechtig (50-75), 8-9 = gefaehrlich (80-100)
                viper_score = max(0, (tellows_score - 1) * 12)
                return {
                    "tellows_score": tellows_score,
                    "spam_score":    viper_score,
                    "calls":         calls,
                    "comments":      comments,
                }
    except Exception as e:
        logger.warning(f"VIPER Tellows Fehler: {e}")
    return {}


async def _lookup_veriphone(number: str) -> dict:
    """
    Veriphone.io — Carrier, Line-Type, Region.
    Explizit DE/EU-Support. Kostenloser Tier: veriphone.io
    Response-Felder: phone_valid, phone_type, carrier, country_code, country_name, region_name
    """
    if not VERIPHONE_KEY:
        return {}
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            r = await client.get(
                "https://api.veriphone.io/v2/verify",
                params={"phone": number, "key": VERIPHONE_KEY},
            )
            data = r.json()
            if data.get("phone_valid"):
                return {
                    "carrier":   data.get("carrier", ""),
                    "line_type": data.get("phone_type", ""),
                    "country":   data.get("country", ""),
                    "region":    data.get("city", "") or data.get("region_name", ""),
                    "voip":      data.get("phone_type", "").lower() in ("voip", "fixed_voip", "non_fixed_voip"),
                }
    except Exception as e:
        logger.warning(f"VIPER Veriphone Fehler: {e}")
    return {}


async def _lookup_abstract(number: str) -> dict:
    """
    AbstractAPI Phone Validation — 190+ Laender, 250 Requests/Monat gratis.
    abstractapi.com/api/phone-validation-api
    Response-Felder: valid, country.name, carrier, line_type, is_valid_for_region
    """
    if not ABSTRACT_KEY:
        return {}
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            r = await client.get(
                "https://phonevalidation.abstractapi.com/v1/",
                params={"api_key": ABSTRACT_KEY, "phone": number},
            )
            data = r.json()
            if data.get("valid"):
                country_info = data.get("country", {})
                type_info    = data.get("type", "")
                return {
                    "carrier":   data.get("carrier", ""),
                    "line_type": type_info,
                    "country":   country_info.get("name", ""),
                    "voip":      type_info.lower() in ("voip", "fixed_voip", "non_fixed_voip"),
                }
    except Exception as e:
        logger.warning(f"VIPER AbstractAPI Fehler: {e}")
    return {}


# ---------------------------------------------------------------------------
# Score-Berechnung
# ---------------------------------------------------------------------------

def _build_score(db_info: dict, api_info: dict, tellows: dict) -> int:
    """Berechnet finalen Spam-Score 0-100."""
    score = 0

    # Tellows (primaere Quelle — groesste DE-Datenbank)
    if tellows:
        score = max(score, tellows.get("spam_score", 0))

    # Eigene Community-Reports (stark gewichtet)
    report_cnt = db_info.get("report_cnt", 0)
    score += min(40, report_cnt * 8)

    # VoIP ohne bekannten Carrier leicht verdaechtig
    if api_info.get("voip"):
        score = max(score, 30)

    # Bereits in DB bekannt (eigene Kampagnen)
    if db_info.get("known"):
        score = max(score, db_info.get("spam_score", 0))
        if db_info.get("campaigns"):
            score = max(score, 80)

    return min(100, score)


def _score_label(score: int) -> tuple:
    if score >= 75:
        return "🔴", "HOHES RISIKO"
    elif score >= 45:
        return "🟡", "VERDAECHTIG"
    elif score >= 20:
        return "🟠", "LEICHT VERDAECHTIG"
    else:
        return "🟢", "UNAUFFAELLIG"


# ---------------------------------------------------------------------------
# Hauptfunktion
# ---------------------------------------------------------------------------

async def analyze(number: str, is_pro: bool, conn: sqlite3.Connection) -> str:
    """
    Analysiert eine Telefonnummer.
    is_pro=False -> kompakte Free-Antwort
    is_pro=True  -> vollstaendige Pro-Antwort
    """
    norm = normalize_number(number)

    if not is_valid_number(norm):
        return (
            "Ungueltige Telefonnummer.\n"
            "Bitte im Format: `+49151...` oder `0151...`"
        )

    # Daten sammeln (parallel via asyncio wäre ideal, sequenziell reicht hier)
    db_info  = _db_check(norm, conn)
    tellows  = await _lookup_tellows(norm)
    veriph   = await _lookup_veriphone(norm)
    abstract = await _lookup_abstract(norm) if not veriph else {}

    # Beste verfuegbare Info zusammenfuehren (DB > Veriphone > Abstract)
    api       = veriph or abstract
    carrier   = db_info.get("carrier")   or api.get("carrier")   or "Unbekannt"
    line_type = db_info.get("line_type") or api.get("line_type") or "Unbekannt"
    country   = db_info.get("country")   or api.get("country")   or "Unbekannt"
    region    = db_info.get("region")    or api.get("region")    or ""
    report_cnt = db_info.get("report_cnt", 0)

    score = _build_score(db_info, api, tellows)
    icon, label = _score_label(score)

    # In DB speichern/aktualisieren
    _db_upsert(norm, {
        "carrier": carrier, "line_type": line_type,
        "country": country, "region": region, "spam_score": score,
    }, conn)

    # --- FREE-Antwort ---
    if not is_pro:
        lines = [
            f"*VIPER Check* - `{norm}`",
            "-----------------------------",
            f"Spam-Score: *{score}/100*  {icon} {label}",
            f"Community-Meldungen: {report_cnt}x",
        ]
        if tellows:
            lines.append(f"Tellows: {tellows.get('tellows_score')}/9 ({tellows.get('calls', 0)} gemeldete Anrufe)")
        if score >= 45:
            lines.append("\nEmpfehlung: Nicht zurueckrufen!")
        lines.append(
            f"\nVollanalyse (Carrier, Kampagnen, Trend) nur mit SecureBot Pro - /upgrade"
        )
        lines.append(f"Nummer melden: `/vreport {norm}`")
        return "\n".join(lines)

    # --- PRO-Antwort ---
    lines = [
        "*VIPER Intelligence Report*",
        "-----------------------------",
        f"Nummer:  `{norm}`",
        f"Carrier: {carrier}",
        f"Typ:     {line_type}",
        f"Land:    {country}",
    ]
    if region:
        lines.append(f"Region:  {region}")

    lines += [
        "",
        f"Spam-Score: *{score}/100*  {icon} {label}",
        f"Community-Meldungen: {report_cnt}x",
    ]

    if api:
        lines.append(f"VoIP-Nummer: {'Ja' if api.get('voip') else 'Nein'}")
    if tellows:
        lines.append(f"Tellows-Score: {tellows.get('tellows_score')}/9  ({tellows.get('calls', 0)} Anrufe, {tellows.get('comments', 0)} Kommentare)")

    campaigns = db_info.get("campaigns", [])
    if campaigns:
        lines.append("")
        lines.append("*AKTIVE KAMPAGNE ERKANNT:*")
        for camp in campaigns[:2]:
            lines.append(f"  {camp['name']}")
            if camp.get("target_org"):
                lines.append(f"  Ziel: {camp['target_org']}")
            if camp.get("scam_type"):
                lines.append(f"  Typ:  {camp['scam_type']}")
            lines.append(f"  Konfidenz: {camp['confidence']}%")

    lines.append("")
    if score >= 75:
        lines.append("EMPFEHLUNG: SOFORT BLOCKIEREN")
        lines.append("Nicht zurueckrufen - Kosten- oder Datenfalle")
    elif score >= 45:
        lines.append("EMPFEHLUNG: Vorsicht - nicht zurueckrufen ohne Verifizierung")
    else:
        lines.append("EMPFEHLUNG: Wahrscheinlich sicher - dennoch aufmerksam bleiben")

    lines.append(f"\nNummer melden: `/vreport {norm}`")
    return "\n".join(lines)
