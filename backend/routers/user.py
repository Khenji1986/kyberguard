"""KyberGuard — User-Router: /api/user/*, /api/compliance/*"""

import hashlib
import logging
import os
import secrets
import string

import psycopg2
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from supertokens_python.recipe.session.framework.fastapi import verify_session

logger = logging.getLogger(__name__)
limiter = Limiter(key_func=get_remote_address)
router = APIRouter()

DATABASE_URL = os.environ.get("DATABASE_URL", "")


def _db() -> psycopg2.extensions.connection:
    return psycopg2.connect(DATABASE_URL)


def _get_user_id(supertokens_id: str) -> int | None:
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE supertokens_id = %s", (supertokens_id,))
            row = cur.fetchone()
        conn.close()
        return row[0] if row else None
    except Exception as e:
        logger.error("_get_user_id Fehler: %s", e)
        return None


# ---------------------------------------------------------------------------
# GET /api/user/scans  — Scan-Verlauf des eingeloggten Nutzers
# ---------------------------------------------------------------------------
@router.get("/user/scans")
@limiter.limit("30/minute")
async def get_user_scans(request: Request, session_container=Depends(verify_session())):
    user_id = _get_user_id(session_container.get_user_id())
    if not user_id:
        return JSONResponse({"scans": [], "summary": {
            "total_activities": 0, "phishing_scans": 0,
            "domain_scans": 0, "nis2_checks": 0
        }})
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                """SELECT id, input_text, score, risk_level, findings, created_at
                   FROM scans WHERE user_id = %s
                   ORDER BY created_at DESC LIMIT 50""",
                (user_id,)
            )
            rows = cur.fetchall()
            cur.execute(
                """SELECT COUNT(*) FROM scans WHERE user_id = %s""", (user_id,)
            )
            total = cur.fetchone()[0]
            cur.execute(
                """SELECT COUNT(*) FROM scans WHERE user_id = %s AND risk_level = 'high'""",
                (user_id,)
            )
            phishing_count = cur.fetchone()[0]
            cur.execute(
                """SELECT COUNT(*) FROM asm_scans WHERE user_id = %s""", (user_id,)
            )
            domain_count = cur.fetchone()[0]
            cur.execute(
                """SELECT COUNT(*) FROM nis2_results WHERE user_id = %s""", (user_id,)
            )
            nis2_count = cur.fetchone()[0]
        conn.close()
        scans = [
            {
                "id": r[0],
                "input_preview": (r[1] or "")[:60],
                "score": min(r[2] or 0, 10),
                "risk_level": r[3] or "low",
                "findings": r[4] if isinstance(r[4], list) else [],
                "findings_count": len(r[4]) if isinstance(r[4], list) else 0,
                "created_at": r[5].isoformat() if r[5] else None,
            }
            for r in rows
        ]
        return JSONResponse({
            "scans": scans,
            "summary": {
                "total_activities": total,
                "phishing_scans": phishing_count,
                "domain_scans": domain_count,
                "nis2_checks": nis2_count,
            }
        })
    except Exception as e:
        logger.error("get_user_scans Fehler: %s", e)
        return JSONResponse({"scans": [], "summary": {
            "total_activities": 0, "phishing_scans": 0,
            "domain_scans": 0, "nis2_checks": 0
        }})


# ---------------------------------------------------------------------------
# GET /api/compliance/score  — NIS2-Compliance-Score des Nutzers
# ---------------------------------------------------------------------------
@router.get("/compliance/score")
@limiter.limit("30/minute")
async def get_compliance_score(request: Request, session_container=Depends(verify_session())):
    user_id = _get_user_id(session_container.get_user_id())
    if not user_id:
        return JSONResponse({"has_result": False, "score": None, "level": None,
                             "critical_count": 0, "updated_at": None})
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                """SELECT score, level, critical_count, high_count, medium_count, updated_at
                   FROM nis2_results WHERE user_id = %s""",
                (user_id,)
            )
            row = cur.fetchone()
        conn.close()
        if not row:
            return JSONResponse({"has_result": False, "score": None, "level": None,
                                 "critical_count": 0, "updated_at": None})
        return JSONResponse({
            "has_result": True,
            "score": row[0],
            "level": row[1],
            "critical_count": row[2] or 0,
            "high_count": row[3] or 0,
            "medium_count": row[4] or 0,
            "updated_at": row[5].isoformat() if row[5] else None,
        })
    except Exception as e:
        logger.error("get_compliance_score Fehler: %s", e)
        return JSONResponse({"has_result": False, "score": None, "level": None,
                             "critical_count": 0, "updated_at": None})


# ---------------------------------------------------------------------------
# GET /api/user/account  — Account-Daten des Nutzers
# ---------------------------------------------------------------------------
@router.get("/user/account")
@limiter.limit("20/minute")
async def get_account(request: Request, session_container=Depends(verify_session())):
    user_id = _get_user_id(session_container.get_user_id())
    if not user_id:
        return JSONResponse(status_code=404, content={"error": "Nutzer nicht gefunden"})
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                """SELECT email, plan, plan_until, created_at, company_name,
                          mfa_enabled, ransomware_alert, email_marketing_opt_in
                   FROM users WHERE id = %s""",
                (user_id,)
            )
            row = cur.fetchone()
        conn.close()
        if not row:
            return JSONResponse(status_code=404, content={"error": "Nutzer nicht gefunden"})
        return JSONResponse({
            "email": row[0],
            "plan": row[1],
            "plan_until": row[2].isoformat() if row[2] else None,
            "created_at": row[3].isoformat() if row[3] else None,
            "company_name": row[4] or "",
            "mfa_enabled": bool(row[5]),
            "ransomware_alert": bool(row[6]),
            "email_marketing_opt_in": bool(row[7]),
        })
    except Exception as e:
        logger.error("get_account Fehler: %s", e)
        return JSONResponse(status_code=500, content={"error": "Datenbankfehler"})


# ---------------------------------------------------------------------------
# GET /api/user/alert-settings  — Alert-Einstellungen
# ---------------------------------------------------------------------------
@router.get("/user/alert-settings")
@limiter.limit("20/minute")
async def get_alert_settings(request: Request, session_container=Depends(verify_session())):
    user_id = _get_user_id(session_container.get_user_id())
    if not user_id:
        return JSONResponse({"ransomware_alert": False, "email_digest": False})
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT ransomware_alert, email_marketing_opt_in FROM users WHERE id = %s",
                (user_id,)
            )
            row = cur.fetchone()
        conn.close()
        if not row:
            return JSONResponse({"ransomware_alert": False, "email_digest": False})
        return JSONResponse({
            "ransomware_alert": bool(row[0]),
            "email_digest": bool(row[1]),
        })
    except Exception as e:
        logger.error("get_alert_settings Fehler: %s", e)
        return JSONResponse({"ransomware_alert": False, "email_digest": False})


# ---------------------------------------------------------------------------
# POST /api/user/alert-settings  — Alert-Einstellungen speichern
# ---------------------------------------------------------------------------
@router.post("/user/alert-settings")
@limiter.limit("10/minute")
async def update_alert_settings(request: Request, session_container=Depends(verify_session())):
    user_id = _get_user_id(session_container.get_user_id())
    if not user_id:
        return JSONResponse(status_code=404, content={"error": "Nutzer nicht gefunden"})
    try:
        body = await request.json()
        ransomware_alert = bool(body.get("ransomware_alert", False))
        email_digest = bool(body.get("email_digest", False))
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE users SET ransomware_alert = %s, email_marketing_opt_in = %s
                   WHERE id = %s""",
                (ransomware_alert, email_digest, user_id)
            )
        conn.commit()
        conn.close()
        return JSONResponse({"ok": True})
    except Exception as e:
        logger.error("update_alert_settings Fehler: %s", e)
        return JSONResponse(status_code=500, content={"error": "Speichern fehlgeschlagen"})


# ---------------------------------------------------------------------------
# POST /api/user/change-password  — Passwort ändern
# ---------------------------------------------------------------------------
@router.post("/user/change-password")
@limiter.limit("5/minute")
async def change_password(request: Request, session_container=Depends(verify_session())):
    supertokens_id = session_container.get_user_id()
    try:
        body = await request.json()
        new_password = body.get("new_password", "")
        if len(new_password) < 8:
            return JSONResponse(status_code=400,
                                content={"error": "Passwort muss mindestens 8 Zeichen haben"})
        from supertokens_python.recipe.emailpassword.asyncio import update_email_or_password
        result = await update_email_or_password(user_id=supertokens_id, password=new_password)
        if result.is_ok:
            return JSONResponse({"ok": True})
        return JSONResponse(status_code=400, content={"error": "Passwort konnte nicht geändert werden"})
    except Exception as e:
        logger.error("change_password Fehler: %s", e)
        return JSONResponse(status_code=500, content={"error": "Interner Fehler"})


# ---------------------------------------------------------------------------
# GET /api/keys  — API-Schlüssel des Nutzers
# ---------------------------------------------------------------------------
@router.get("/keys")
@limiter.limit("20/minute")
async def get_keys(request: Request, session_container=Depends(verify_session())):
    user_id = _get_user_id(session_container.get_user_id())
    if not user_id:
        return JSONResponse([])
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                """SELECT key_prefix, name, created_at, last_used, active
                   FROM api_keys WHERE user_id = %s AND active = true
                   ORDER BY created_at DESC""",
                (user_id,)
            )
            rows = cur.fetchall()
        conn.close()
        return JSONResponse([
            {
                "prefix": r[0],
                "name": r[1],
                "created_at": r[2].isoformat() if r[2] else None,
                "last_used": r[3].isoformat() if r[3] else None,
            }
            for r in rows
        ])
    except Exception as e:
        logger.error("get_keys Fehler: %s", e)
        return JSONResponse([])


# ---------------------------------------------------------------------------
# DELETE /api/keys/{prefix}  — API-Key deaktivieren
# ---------------------------------------------------------------------------
@router.delete("/keys/{prefix}")
@limiter.limit("10/minute")
async def delete_key(prefix: str, request: Request, session_container=Depends(verify_session())):
    user_id = _get_user_id(session_container.get_user_id())
    if not user_id:
        return JSONResponse(status_code=404, content={"error": "Nicht gefunden"})
    if len(prefix) > 20 or not prefix.isalnum():
        return JSONResponse(status_code=400, content={"error": "Ungültiger Key-Prefix"})
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE api_keys SET active = false WHERE user_id = %s AND key_prefix = %s",
                (user_id, prefix)
            )
        conn.commit()
        conn.close()
        return JSONResponse({"ok": True})
    except Exception as e:
        logger.error("delete_key Fehler: %s", e)
        return JSONResponse(status_code=500, content={"error": "Fehler beim Löschen"})
