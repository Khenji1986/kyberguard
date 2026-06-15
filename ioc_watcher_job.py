#!/usr/bin/env python3
"""
KyberGuard IOC-Watcher — Systemd-Timer-Job (täglich 02:30 UTC)
GUARDIAN-Fähigkeit #1: Kundenregistrierte Assets gegen Threat-Intelligence-Feeds prüfen.

Feeds:
  - URLhaus (abuse.ch)  — bösartige URLs und Domains
  - ThreatFox (abuse.ch) — IPs und Domains von Malware-C2s
  - CISA KEV             — bekannte ausgenutzte Schwachstellen (Domains/IPs)

Ablauf:
  1. Feeds laden (gecacht in /var/cache/kyberguard-ioc/, TTL 12h)
  2. Alle registrierten Kunden-Assets aus DB lesen
  3. Jedes Asset gegen Feed-Sets prüfen
  4. Neue Treffer als ioc_alerts in DB speichern
  5. E-Mail-Alerts für Business+ Kunden senden (wenn neue Treffer)
"""

import csv
import gzip
import io
import zipfile
import json
import logging
import os
import smtplib
import sys
from datetime import datetime, timezone, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import httpx
import psycopg2
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    format="%(asctime)s [IOC-Watcher] %(levelname)s %(message)s",
    level=logging.INFO,
    stream=sys.stdout,
)
logger = logging.getLogger("ioc_watcher")

# ---------------------------------------------------------------------------
# Konfiguration
# ---------------------------------------------------------------------------
DATABASE_URL = os.environ["DATABASE_URL"]
SMTP_HOST    = os.environ.get("SMTP_HOST", "")
SMTP_PORT    = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER    = os.environ.get("SMTP_USER", "")
SMTP_PASS    = os.environ.get("SMTP_PASS", "")
MAIL_FROM    = os.environ.get("MAIL_FROM", "alerts@kyberguard.de")

CACHE_DIR    = Path(os.environ.get("IOC_CACHE_DIR", "/var/cache/kyberguard-ioc"))
CACHE_TTL_H  = 12  # Stunden

PLANS_EMAIL_ALERT = {"business", "enterprise"}

# ---------------------------------------------------------------------------
# Feed-URLs  (online-only CSV = aktive Einträge, kein gzip)
# ---------------------------------------------------------------------------
URLHAUS_CSV   = "https://urlhaus.abuse.ch/downloads/csv_online/"
THREATFOX_CSV = "https://threatfox.abuse.ch/export/csv/full/"

# ---------------------------------------------------------------------------
# Cache-Hilfsfunktionen
# ---------------------------------------------------------------------------
def _cache_path(name: str) -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / f"{name}.json"


def _load_cache(name: str) -> list[str] | None:
    p = _cache_path(name)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text())
        cached_at = datetime.fromisoformat(data["cached_at"])
        if datetime.now(timezone.utc) - cached_at > timedelta(hours=CACHE_TTL_H):
            return None
        return data["items"]
    except Exception:
        return None


def _save_cache(name: str, items: list[str]) -> None:
    _cache_path(name).write_text(json.dumps({
        "cached_at": datetime.now(timezone.utc).isoformat(),
        "items": items,
    }))


# ---------------------------------------------------------------------------
# Feed-Loader
# ---------------------------------------------------------------------------
def _load_urlhaus() -> set[str]:
    cached = _load_cache("urlhaus")
    if cached is not None:
        logger.info("URLhaus: %d Einträge aus Cache", len(cached))
        return set(cached)

    logger.info("URLhaus: Feed laden...")
    try:
        with httpx.Client(timeout=30, follow_redirects=True) as client:
            r = client.get(URLHAUS_CSV)
            r.raise_for_status()
        # NUL-Bytes entfernen (abuse.ch liefert manchmal komprimierte Daten)
        raw = r.content
        if raw[:2] == b'\x1f\x8b':
            raw = gzip.decompress(raw)
        text = raw.replace(b'\x00', b'').decode('utf-8', errors='replace')
        domains: set[str] = set()
        # URLhaus CSV: # id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
        # URL steht in Spalte 2 (0-basiert)
        reader = csv.reader(io.StringIO(text))
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            if len(row) < 3:
                continue
            url = row[2].strip().lower()
            try:
                if "://" in url:
                    host = url.split("://", 1)[1].split("/")[0].split(":")[0]
                    if host and "." in host and not host.replace(".","").isdigit():
                        domains.add(host)
            except Exception:
                pass
        items = list(domains)
        _save_cache("urlhaus", items)
        logger.info("URLhaus: %d Domains geladen", len(items))
        return set(items)
    except Exception as e:
        logger.error("URLhaus-Fehler: %s", e)
        return set()


def _load_threatfox() -> tuple[set[str], set[str]]:
    """Gibt (ip_set, domain_set) zurück."""
    cached = _load_cache("threatfox")
    if cached is not None:
        ips = set(x for x in cached if ":" not in x and x.replace(".", "").isdigit() or _is_ip(x))
        domains = set(x for x in cached if not _is_ip(x))
        logger.info("ThreatFox: %d Einträge aus Cache", len(cached))
        return ips, domains

    logger.info("ThreatFox: Feed laden...")
    try:
        with httpx.Client(timeout=60, follow_redirects=True) as client:
            r = client.get(THREATFOX_CSV)
            r.raise_for_status()
        raw = r.content
        # ThreatFox liefert ZIP-Archiv (PK-Magic)
        if raw[:2] == b'PK':
            z = zipfile.ZipFile(io.BytesIO(raw))
            csv_name = next((n for n in z.namelist() if n.endswith('.csv')), z.namelist()[0])
            raw = z.read(csv_name)
        elif raw[:2] == b'\x1f\x8b':
            raw = gzip.decompress(raw)
        text = raw.replace(b'\x00', b'').decode('utf-8', errors='replace')
        ips: set[str] = set()
        domains: set[str] = set()
        # ThreatFox CSV-Format: datum, id, ioc, ioc_type, threat_type, ...
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('"#'):
                continue
            parts = line.split(',', 5)
            if len(parts) < 4:
                continue
            ioc      = parts[2].strip().strip('"').lower()
            ioc_type = parts[3].strip().strip('"').lower()
            if ioc_type in ("ip:port", "ip") and ioc:
                ip = ioc.split(":")[0]
                if _is_ip(ip):
                    ips.add(ip)
            elif ioc_type in ("domain", "url", "domain|ip") and ioc:
                host = ioc.split("/")[0].split(":")[0]
                if host and "." in host:
                    domains.add(host)

        all_items = list(ips | domains)
        _save_cache("threatfox", all_items)
        logger.info("ThreatFox: %d IPs + %d Domains geladen", len(ips), len(domains))
        return ips, domains
    except Exception as e:
        logger.error("ThreatFox-Fehler: %s", e)
        return set(), set()


def _is_ip(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Haupt-Check-Logik
# ---------------------------------------------------------------------------
def _ensure_tables() -> None:
    """DB-Tabellen anlegen falls noch nicht vorhanden (idempotent)."""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS monitored_assets (
                    id          SERIAL PRIMARY KEY,
                    user_id     INTEGER NOT NULL,
                    asset_type  VARCHAR(10) NOT NULL,
                    asset_value VARCHAR(253) NOT NULL,
                    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    UNIQUE(user_id, asset_value)
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS ioc_alerts (
                    id           SERIAL PRIMARY KEY,
                    user_id      INTEGER NOT NULL,
                    asset_value  VARCHAR(253) NOT NULL,
                    ioc_source   VARCHAR(50) NOT NULL,
                    severity     VARCHAR(10) NOT NULL DEFAULT 'medium',
                    detail       TEXT,
                    first_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    alerted_at   TIMESTAMPTZ,
                    dismissed_at TIMESTAMPTZ,
                    UNIQUE(user_id, asset_value, ioc_source)
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS vuln_scans (
                    id           SERIAL PRIMARY KEY,
                    user_id      INTEGER NOT NULL,
                    domain       VARCHAR(253) NOT NULL,
                    started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    finished_at  TIMESTAMPTZ,
                    status       VARCHAR(20) NOT NULL DEFAULT 'queued',
                    findings     JSONB NOT NULL DEFAULT '[]'::jsonb
                )
            """)
        conn.commit()
        conn.close()
        logger.info("DB-Tabellen sichergestellt")
    except Exception as e:
        logger.error("DB-Tabellen-Fehler: %s", e)


def run_ioc_check() -> None:
    logger.info("=== IOC-Watcher gestartet ===")
    _ensure_tables()

    # Feeds laden
    urlhaus_domains = _load_urlhaus()
    tf_ips, tf_domains = _load_threatfox()
    all_malicious_domains = urlhaus_domains | tf_domains
    all_malicious_ips = tf_ips

    logger.info(
        "Feeds geladen: %d bösartige Domains, %d bösartige IPs",
        len(all_malicious_domains), len(all_malicious_ips),
    )

    # Kunden-Assets aus DB lesen
    try:
        conn = psycopg2.connect(DATABASE_URL)
        with conn.cursor() as cur:
            cur.execute("""
                SELECT ma.user_id, ma.asset_type, ma.asset_value,
                       u.email, u.plan
                FROM monitored_assets ma
                JOIN users u ON u.id = ma.user_id
                WHERE u.active = TRUE
            """)
            assets = cur.fetchall()
        conn.close()
    except Exception as e:
        logger.error("DB-Fehler beim Laden der Assets: %s", e)
        return

    logger.info("%d Assets von %d Kunden werden geprüft", len(assets),
                len(set(a[0] for a in assets)))

    new_alerts: list[dict] = []

    for user_id, asset_type, asset_value, email, plan in assets:
        matched_source = None
        severity = "medium"

        if asset_type == "ip" and asset_value in all_malicious_ips:
            matched_source = "ThreatFox"
            severity = "high"
        elif asset_type == "domain":
            # Exakter Treffer
            if asset_value in all_malicious_domains:
                matched_source = "URLhaus/ThreatFox"
                severity = "high"
            # Subdomain-Check: prüfe ob registrierte Domain Suffix eines bösartigen Eintrags ist
            elif any(bad.endswith(f".{asset_value}") for bad in all_malicious_domains):
                matched_source = "URLhaus/ThreatFox (Subdomain)"
                severity = "medium"

        if matched_source:
            new_alerts.append({
                "user_id": user_id,
                "asset_value": asset_value,
                "ioc_source": matched_source,
                "severity": severity,
                "email": email,
                "plan": plan,
            })

    logger.info("%d potenzielle IOC-Treffer gefunden", len(new_alerts))

    if not new_alerts:
        logger.info("Keine Treffer. Alle Assets sind sauber.")
        return

    # Neue Alerts in DB speichern (ON CONFLICT — nicht doppelt eintragen)
    newly_inserted: list[dict] = []
    try:
        conn = psycopg2.connect(DATABASE_URL)
        with conn.cursor() as cur:
            for alert in new_alerts:
                cur.execute("""
                    INSERT INTO ioc_alerts
                        (user_id, asset_value, ioc_source, severity, detail)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (user_id, asset_value, ioc_source) DO NOTHING
                    RETURNING id
                """, (
                    alert["user_id"],
                    alert["asset_value"],
                    alert["ioc_source"],
                    alert["severity"],
                    f"Asset in {alert['ioc_source']}-Feed gefunden",
                ))
                row = cur.fetchone()
                if row:  # Nur wirklich neue Alerts
                    newly_inserted.append(alert)
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error("DB-Fehler beim Speichern der Alerts: %s", e)
        return

    logger.info("%d neue IOC-Alerts in DB gespeichert", len(newly_inserted))

    # E-Mail-Alerts für Business+ Kunden
    if not SMTP_HOST:
        logger.info("SMTP nicht konfiguriert — keine E-Mail-Alerts")
        return

    alerts_by_user: dict[int, list] = {}
    for alert in newly_inserted:
        if alert["plan"] in PLANS_EMAIL_ALERT:
            alerts_by_user.setdefault(alert["user_id"], []).append(alert)

    for user_id, user_alerts in alerts_by_user.items():
        email = user_alerts[0]["email"]
        _send_alert_mail(email, user_alerts)


def _send_alert_mail(to_email: str, alerts: list[dict]) -> None:
    count = len(alerts)
    subject = f"[KyberGuard] Bedrohungsalert — {count} Asset(s) in Threat-Intelligence-Feeds gefunden"

    lines = []
    for a in alerts:
        lines.append(f"  - {a['asset_value']} ({a['asset_type'] if 'asset_type' in a else 'asset'}) — Quelle: {a['ioc_source']} — Schweregrad: {a['severity']}")

    body = f"""Sehr geehrte Damen und Herren,

KyberGuard hat bei der täglichen Prüfung Ihrer registrierten Assets einen Treffer in unseren Threat-Intelligence-Feeds festgestellt.

Betroffene Assets:
{chr(10).join(lines)}

Empfehlung:
Bitte überprüfen Sie diese Assets umgehend. Loggen Sie sich in Ihr KyberGuard-Dashboard ein für weitere Details und Handlungsempfehlungen.

Dashboard: https://kyberguard.de/dashboard

Mit freundlichen Grüßen
Ihr KyberGuard Security Team
"""

    msg = MIMEMultipart()
    msg["From"]    = MAIL_FROM
    msg["To"]      = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain", "utf-8"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(MAIL_FROM, [to_email], msg.as_string())
        logger.info("Alert-Mail gesendet an %s (%d Treffer)", to_email[:4] + "***", count)
    except Exception as e:
        logger.error("Mail-Fehler an %s: %s", to_email[:4] + "***", e)


if __name__ == "__main__":
    run_ioc_check()
    logger.info("=== IOC-Watcher beendet ===")
