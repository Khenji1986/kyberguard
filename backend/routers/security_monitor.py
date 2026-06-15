#!/usr/bin/env python3
"""
KyberGuard Security Monitor — GUARDIAN-Fähigkeiten als Dashboard-Feature
Nero-Standard: Zero-Trust-Validierung, Plan-Gates, DSGVO-konformes Logging

Endpunkte:
  GET    /api/dashboard/monitor/assets           — Registrierte Assets abrufen
  POST   /api/dashboard/monitor/assets           — Asset registrieren (IP oder Domain)
  DELETE /api/dashboard/monitor/assets/{id}      — Asset entfernen
  GET    /api/dashboard/monitor/alerts           — IOC-Alerts abrufen
  DELETE /api/dashboard/monitor/alerts/{id}      — Alert als gelesen markieren
  POST   /api/dashboard/monitor/vuln-scan        — NUCLEI-Schwachstellen-Scan (Business+)
  GET    /api/dashboard/monitor/vuln-scan/{id}   — Scan-Ergebnis abrufen

Plan-Gates:
  free/demo : 1 Asset (nur Domain), kein NUCLEI, kein E-Mail-Alert
  pro       : 3 Assets (1 Domain + 2 IPs), E-Mail-Alert, kein NUCLEI
  business  : 10 Assets, E-Mail-Alert, NUCLEI 1x/Woche
  enterprise: 50 Assets, E-Mail-Alert sofort, NUCLEI 1x/Tag
"""

import asyncio
import ipaddress
import json
import logging
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone, timedelta
from typing import Annotated

import psycopg2
import tldextract
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
from slowapi import Limiter
from slowapi.util import get_remote_address

from routers.dashboard import get_current_user

logger = logging.getLogger(__name__)
limiter = Limiter(key_func=get_remote_address)
router = APIRouter(tags=["monitor"])

# ---------------------------------------------------------------------------
# Plan-Grenzen
# ---------------------------------------------------------------------------
_ASSET_LIMITS: dict[str | None, int] = {
    None: 1, "demo": 1, "free": 1,
    "personal": 1, "family": 1,
    "pro": 3,
    "business": 10,
    "enterprise": 50,
}
_NUCLEI_ALLOWED = {"business", "enterprise"}

# NUCLEI-Cooldown in Tagen
_NUCLEI_COOLDOWN: dict[str | None, int] = {
    "business": 7,
    "enterprise": 1,
}

# ---------------------------------------------------------------------------
# Validierung
# ---------------------------------------------------------------------------
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("10.8.0.0/24"),
    ipaddress.ip_network("172.18.0.0/16"),
]


def _validate_asset(value: str) -> tuple[bool, str, str]:
    """Prüft ob der Wert eine gültige öffentliche IP oder Domain ist.
    Returns (ok, normalized_value, error_msg)
    """
    value = value.strip().lower()
    if not value or len(value) > 253:
        return False, "", "Ungültige Eingabe"

    # IP-Adresse prüfen
    try:
        addr = ipaddress.ip_address(value)
        for net in _PRIVATE_NETWORKS:
            if addr in net:
                return False, "", "Private/interne IP-Adressen sind nicht erlaubt"
        return True, str(addr), "ip"
    except ValueError:
        pass

    # Domain prüfen
    extracted = tldextract.extract(value)
    if not extracted.domain or not extracted.suffix:
        return False, "", "Keine gültige Domain"
    clean = f"{extracted.domain}.{extracted.suffix}"
    if extracted.subdomain:
        clean = f"{extracted.subdomain}.{clean}"
    return True, clean, "domain"


# ---------------------------------------------------------------------------
# DB-Hilfsfunktionen
# ---------------------------------------------------------------------------
def _db() -> psycopg2.extensions.connection:
    return psycopg2.connect(os.environ["DATABASE_URL"])


def _ensure_tables(conn) -> None:
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS monitored_assets (
                id          SERIAL PRIMARY KEY,
                user_id     INTEGER NOT NULL,
                asset_type  VARCHAR(10) NOT NULL CHECK (asset_type IN ('domain','ip')),
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
        cur.execute("CREATE INDEX IF NOT EXISTS idx_mon_assets_uid ON monitored_assets(user_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_ioc_alerts_uid ON ioc_alerts(user_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_vuln_scans_uid ON vuln_scans(user_id)")
    conn.commit()


# ---------------------------------------------------------------------------
# Pydantic-Modelle
# ---------------------------------------------------------------------------
class AssetIn(BaseModel):
    value: str

    @field_validator("value")
    @classmethod
    def clean(cls, v: str) -> str:
        v = v.strip()
        if len(v) > 253:
            raise ValueError("Wert zu lang")
        return v


# ---------------------------------------------------------------------------
# GET /assets
# ---------------------------------------------------------------------------
@router.get("/monitor/assets")
@limiter.limit("30/minute")
async def list_assets(
    request: Request,
    auth: Annotated[tuple[int, str | None], Depends(get_current_user)],
) -> JSONResponse:
    user_id, plan = auth
    try:
        conn = _db()
        _ensure_tables(conn)
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, asset_type, asset_value, created_at FROM monitored_assets "
                "WHERE user_id = %s ORDER BY created_at DESC",
                (user_id,),
            )
            rows = cur.fetchall()
        conn.close()
    except Exception as e:
        logger.error("monitor list_assets DB-Fehler uid=%d: %s", user_id, e)
        raise HTTPException(status_code=500, detail="Datenbankfehler")

    limit = _ASSET_LIMITS.get(plan, 1)
    assets = [
        {"id": r[0], "type": r[1], "value": r[2], "created_at": r[3].isoformat()}
        for r in rows
    ]
    return JSONResponse({"assets": assets, "limit": limit, "count": len(assets)})


# ---------------------------------------------------------------------------
# POST /assets
# ---------------------------------------------------------------------------
@router.post("/monitor/assets")
@limiter.limit("10/minute")
async def add_asset(
    request: Request,
    body: AssetIn,
    auth: Annotated[tuple[int, str | None], Depends(get_current_user)],
) -> JSONResponse:
    user_id, plan = auth

    ok, normalized, asset_type_or_err = _validate_asset(body.value)
    if not ok:
        raise HTTPException(status_code=400, detail=asset_type_or_err)

    asset_type = asset_type_or_err  # "ip" oder "domain"

    # Plan-Gate
    limit = _ASSET_LIMITS.get(plan, 1)
    try:
        conn = _db()
        _ensure_tables(conn)
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM monitored_assets WHERE user_id = %s",
                (user_id,),
            )
            current_count = cur.fetchone()[0]

            if current_count >= limit:
                conn.close()
                return JSONResponse(
                    status_code=403,
                    content={"error": f"Ihr Plan erlaubt maximal {limit} Assets. Bitte upgraden."},
                )

            cur.execute(
                "INSERT INTO monitored_assets (user_id, asset_type, asset_value) "
                "VALUES (%s, %s, %s) RETURNING id, created_at",
                (user_id, asset_type, normalized),
            )
            row = cur.fetchone()
        conn.commit()
        conn.close()
    except psycopg2.errors.UniqueViolation:
        return JSONResponse(status_code=409, content={"error": "Asset bereits registriert"})
    except Exception as e:
        logger.error("monitor add_asset DB-Fehler uid=%d: %s", user_id, e)
        raise HTTPException(status_code=500, detail="Datenbankfehler")

    logger.info("monitor add_asset uid=%d type=%s value=%s", user_id, asset_type, normalized[:20])
    return JSONResponse(
        status_code=201,
        content={"id": row[0], "type": asset_type, "value": normalized, "created_at": row[1].isoformat()},
    )


# ---------------------------------------------------------------------------
# DELETE /assets/{asset_id}
# ---------------------------------------------------------------------------
@router.delete("/monitor/assets/{asset_id}")
@limiter.limit("20/minute")
async def remove_asset(
    request: Request,
    asset_id: int,
    auth: Annotated[tuple[int, str | None], Depends(get_current_user)],
) -> JSONResponse:
    user_id, _plan = auth
    try:
        conn = _db()
        _ensure_tables(conn)
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM monitored_assets WHERE id = %s AND user_id = %s RETURNING id",
                (asset_id, user_id),
            )
            deleted = cur.fetchone()
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error("monitor remove_asset DB-Fehler uid=%d: %s", user_id, e)
        raise HTTPException(status_code=500, detail="Datenbankfehler")

    if not deleted:
        raise HTTPException(status_code=404, detail="Asset nicht gefunden")
    return JSONResponse({"ok": True})


# ---------------------------------------------------------------------------
# GET /alerts
# ---------------------------------------------------------------------------
@router.get("/monitor/alerts")
@limiter.limit("30/minute")
async def list_alerts(
    request: Request,
    auth: Annotated[tuple[int, str | None], Depends(get_current_user)],
) -> JSONResponse:
    user_id, _plan = auth
    try:
        conn = _db()
        _ensure_tables(conn)
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, asset_value, ioc_source, severity, detail, first_seen
                FROM ioc_alerts
                WHERE user_id = %s AND dismissed_at IS NULL
                ORDER BY first_seen DESC
                LIMIT 50
                """,
                (user_id,),
            )
            rows = cur.fetchall()
        conn.close()
    except Exception as e:
        logger.error("monitor list_alerts DB-Fehler uid=%d: %s", user_id, e)
        raise HTTPException(status_code=500, detail="Datenbankfehler")

    alerts = [
        {
            "id": r[0], "asset": r[1], "source": r[2],
            "severity": r[3], "detail": r[4],
            "first_seen": r[5].isoformat(),
        }
        for r in rows
    ]
    return JSONResponse({"alerts": alerts})


# ---------------------------------------------------------------------------
# DELETE /alerts/{alert_id}  — als gelesen/dismissed markieren
# ---------------------------------------------------------------------------
@router.delete("/monitor/alerts/{alert_id}")
@limiter.limit("20/minute")
async def dismiss_alert(
    request: Request,
    alert_id: int,
    auth: Annotated[tuple[int, str | None], Depends(get_current_user)],
) -> JSONResponse:
    user_id, _plan = auth
    try:
        conn = _db()
        _ensure_tables(conn)
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE ioc_alerts SET dismissed_at = NOW() WHERE id = %s AND user_id = %s RETURNING id",
                (alert_id, user_id),
            )
            updated = cur.fetchone()
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error("monitor dismiss_alert DB-Fehler uid=%d: %s", user_id, e)
        raise HTTPException(status_code=500, detail="Datenbankfehler")

    if not updated:
        raise HTTPException(status_code=404, detail="Alert nicht gefunden")
    return JSONResponse({"ok": True})


# ---------------------------------------------------------------------------
# POST /vuln-scan  — NUCLEI-Scan (Business+)
# ---------------------------------------------------------------------------
class VulnScanIn(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def clean(cls, v: str) -> str:
        return v.strip().lower()


@router.post("/monitor/vuln-scan")
@limiter.limit("3/hour")
async def start_vuln_scan(
    request: Request,
    body: VulnScanIn,
    auth: Annotated[tuple[int, str | None], Depends(get_current_user)],
) -> JSONResponse:
    user_id, plan = auth

    if plan not in _NUCLEI_ALLOWED:
        return JSONResponse(
            status_code=403,
            content={"error": "NUCLEI-Scans sind ab Business-Plan verfügbar."},
        )

    ok, domain, asset_type = _validate_asset(body.domain)
    if not ok or asset_type != "domain":
        raise HTTPException(status_code=400, detail="Ungültige Domain")

    # Cooldown prüfen
    cooldown_days = _NUCLEI_COOLDOWN.get(plan, 7)
    try:
        conn = _db()
        _ensure_tables(conn)
        with conn.cursor() as cur:
            # Domain muss als registriertes Asset vorhanden sein
            cur.execute(
                "SELECT id FROM monitored_assets WHERE user_id = %s AND asset_value = %s",
                (user_id, domain),
            )
            if not cur.fetchone():
                conn.close()
                return JSONResponse(
                    status_code=400,
                    content={"error": "Domain muss zuerst als Asset registriert werden."},
                )
            # Letzten Scan prüfen
            cur.execute(
                """
                SELECT started_at FROM vuln_scans
                WHERE user_id = %s AND domain = %s AND status != 'failed'
                ORDER BY started_at DESC LIMIT 1
                """,
                (user_id, domain),
            )
            last = cur.fetchone()
            if last:
                since = datetime.now(timezone.utc) - last[0]
                if since < timedelta(days=cooldown_days):
                    remaining = cooldown_days - since.days
                    conn.close()
                    return JSONResponse(
                        status_code=429,
                        content={"error": f"Scan-Cooldown aktiv. Nächster Scan in {remaining} Tag(en) möglich."},
                    )
            # Scan-Eintrag anlegen
            cur.execute(
                "INSERT INTO vuln_scans (user_id, domain, status) VALUES (%s, %s, 'queued') RETURNING id",
                (user_id, domain),
            )
            scan_id = cur.fetchone()[0]
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error("monitor vuln-scan DB-Fehler uid=%d: %s", user_id, e)
        raise HTTPException(status_code=500, detail="Datenbankfehler")

    # Scan asynchron starten
    asyncio.create_task(_run_nuclei_scan(scan_id, domain))
    logger.info("monitor vuln-scan gestartet uid=%d domain=%s scan_id=%d", user_id, domain, scan_id)
    return JSONResponse(status_code=202, content={"scan_id": scan_id, "status": "queued"})


# ---------------------------------------------------------------------------
# GET /vuln-scan/{scan_id}
# ---------------------------------------------------------------------------
@router.get("/monitor/vuln-scan/{scan_id}")
@limiter.limit("30/minute")
async def get_vuln_scan(
    request: Request,
    scan_id: int,
    auth: Annotated[tuple[int, str | None], Depends(get_current_user)],
) -> JSONResponse:
    user_id, _plan = auth
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT domain, started_at, finished_at, status, findings "
                "FROM vuln_scans WHERE id = %s AND user_id = %s",
                (scan_id, user_id),
            )
            row = cur.fetchone()
        conn.close()
    except Exception as e:
        logger.error("monitor get_vuln_scan DB-Fehler uid=%d: %s", user_id, e)
        raise HTTPException(status_code=500, detail="Datenbankfehler")

    if not row:
        raise HTTPException(status_code=404, detail="Scan nicht gefunden")

    return JSONResponse({
        "scan_id": scan_id,
        "domain": row[0],
        "started_at": row[1].isoformat(),
        "finished_at": row[2].isoformat() if row[2] else None,
        "status": row[3],
        "findings": row[4] if row[4] else [],
    })


# ---------------------------------------------------------------------------
# NUCLEI-Scan Hintergrundtask
# ---------------------------------------------------------------------------
async def _run_nuclei_scan(scan_id: int, domain: str) -> None:
    nuclei_bin = os.environ.get("NUCLEI_BIN", "nuclei")
    db_url = os.environ.get("DATABASE_URL", "")

    try:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_path = tf.name

        proc = await asyncio.create_subprocess_exec(
            nuclei_bin,
            "-u", f"https://{domain}",
            "-t", "http/misconfiguration/",
            "-t", "http/exposures/",
            "-t", "ssl/",
            "-t", "dns/",
            "-severity", "medium,high,critical",
            "-json-export", out_path,
            "-no-color",
            "-silent",
            "-timeout", "10",
            "-rate-limit", "20",
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            await asyncio.wait_for(proc.communicate(), timeout=180)
        except asyncio.TimeoutError:
            proc.kill()
            logger.warning("nuclei scan timeout domain=%s scan_id=%d", domain, scan_id)

        findings: list[dict] = []
        try:
            with open(out_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        findings.append({
                            "template": obj.get("template-id", ""),
                            "name": obj.get("info", {}).get("name", ""),
                            "severity": obj.get("info", {}).get("severity", "info"),
                            "matched": obj.get("matched-at", ""),
                        })
                    except json.JSONDecodeError:
                        pass
        except FileNotFoundError:
            pass

        import os as _os
        try:
            _os.unlink(out_path)
        except OSError:
            pass

        conn = psycopg2.connect(db_url)
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE vuln_scans SET status='done', finished_at=NOW(), findings=%s WHERE id=%s",
                (json.dumps(findings), scan_id),
            )
        conn.commit()
        conn.close()
        logger.info("nuclei scan done domain=%s findings=%d scan_id=%d", domain, len(findings), scan_id)

    except FileNotFoundError:
        logger.warning("nuclei binary nicht gefunden — scan_id=%d", scan_id)
        conn = psycopg2.connect(db_url)
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE vuln_scans SET status='failed', finished_at=NOW() WHERE id=%s",
                (scan_id,),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error("nuclei scan fehlgeschlagen scan_id=%d: %s", scan_id, e)
        try:
            conn = psycopg2.connect(db_url)
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE vuln_scans SET status='failed', finished_at=NOW() WHERE id=%s",
                    (scan_id,),
                )
            conn.commit()
            conn.close()
        except Exception:
            pass
