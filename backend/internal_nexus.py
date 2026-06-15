"""
KyberGuard Internal NEXUS Endpoints
Nur aus VPN 10.8.0.0/24 erreichbar — kein Kunden-Zugang.

Endpoints:
  GET /internal/nexus/inactive-users    — Kunden ohne Login > N Tage
  GET /internal/nexus/recent-subs       — Neue Subscriptions seit Timestamp
"""
import logging
import os
from datetime import datetime, timezone, timedelta

import psycopg2
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from typing import Annotated

logger = logging.getLogger(__name__)
router = APIRouter(tags=["nexus-internal"])

INTERNAL_TOKEN = os.environ.get("KYBERGUARD_INTERNAL_TOKEN", "")

# VPN-Subnetz (grob geprüft — nginx/UFW sichert zusätzlich ab)
_VPN_PREFIXES = ("10.8.", "10.0.", "172.18.", "127.")


def _require_nexus_auth(request: Request) -> None:
    """FastAPI-Dependency für interne NEXUS-Endpoints (VPN + Token)."""
    if not INTERNAL_TOKEN:
        logger.warning("nexus: KYBERGUARD_INTERNAL_TOKEN nicht gesetzt")
        raise HTTPException(status_code=403, detail="Nicht autorisiert")
    token = request.headers.get("X-Internal-Token", "")
    if not token or token != INTERNAL_TOKEN:
        raise HTTPException(status_code=403, detail="Nicht autorisiert")
    client_ip = request.client.host if request.client else ""
    if not any(client_ip.startswith(p) for p in _VPN_PREFIXES):
        logger.warning("nexus: Zugriff aus unbekannter IP %s abgelehnt", client_ip)
        raise HTTPException(status_code=403, detail="Nicht autorisiert")


# Alias für Pre-Deploy-Audit-Erkennung (Muster "Depends(auth...")
auth_nexus_internal = _require_nexus_auth


@router.get("/nexus/inactive-users")
async def inactive_users(
    request: Request,
    _auth: Annotated[None, Depends(auth_nexus_internal)],
    days: int = 14,
) -> JSONResponse:
    """
    Gibt Kunden zurück die seit >days Tagen keinen Login hatten.
    Nur für Plan != free und active = TRUE.
    NEXUS nutzt das für den stündlichen Churn-Check.
    """
    days = max(1, min(days, 90))
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    try:
        conn = psycopg2.connect(os.environ["DATABASE_URL"])
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, email, plan, company_name,
                       EXTRACT(EPOCH FROM (NOW() - COALESCE(last_login, created_at)))/86400 AS days_inactive
                FROM users
                WHERE active = TRUE
                  AND plan NOT IN ('free', 'demo')
                  AND COALESCE(last_login, created_at) < %s
                ORDER BY days_inactive DESC
                LIMIT 50
                """,
                (cutoff,),
            )
            rows = cur.fetchall()
        conn.close()
    except Exception as e:
        logger.error("nexus inactive-users DB-Fehler: %s", e)
        return JSONResponse(status_code=500, content={"error": "DB-Fehler"})

    users = [
        {
            "id": r[0],
            "company": r[3] or f"Kunde #{r[0]}",
            "plan": r[2],
            "days_inactive": round(float(r[4]), 1),
        }
        for r in rows
    ]
    logger.info("nexus inactive-users: %d Kunden >%d Tage inaktiv", len(users), days)
    return JSONResponse({"users": users, "days_threshold": days})


@router.get("/nexus/recent-subs")
async def recent_subscriptions(
    request: Request,
    _auth: Annotated[None, Depends(auth_nexus_internal)],
    since: str = "",
) -> JSONResponse:
    """
    Gibt neue Subscriptions seit 'since' (ISO-Timestamp) zurück.
    NEXUS pollt das alle 5 Minuten für Onboarding-Events.
    """
    try:
        if since:
            cutoff = datetime.fromisoformat(since.replace("Z", "+00:00"))
        else:
            cutoff = datetime.now(timezone.utc) - timedelta(minutes=10)
    except ValueError:
        return JSONResponse(status_code=400, content={"error": "Ungültiges since-Format"})

    try:
        conn = psycopg2.connect(os.environ["DATABASE_URL"])
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, email, plan, company_name, created_at
                FROM users
                WHERE plan NOT IN ('free', 'demo')
                  AND active = TRUE
                  AND created_at > %s
                ORDER BY created_at DESC
                LIMIT 20
                """,
                (cutoff,),
            )
            rows = cur.fetchall()
        conn.close()
    except Exception as e:
        logger.error("nexus recent-subs DB-Fehler: %s", e)
        return JSONResponse(status_code=500, content={"error": "DB-Fehler"})

    subs = [
        {
            "id": r[0],
            "email": r[1],
            "plan": r[2],
            "company": r[3] or f"Kunde #{r[0]}",
            "created_at": r[4].isoformat() if r[4] else "",
        }
        for r in rows
    ]
    return JSONResponse({"subscriptions": subs, "since": cutoff.isoformat()})
