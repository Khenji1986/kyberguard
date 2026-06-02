#!/usr/bin/env python3
"""
KyberGuard Dashboard API — Auth-geschuetzte Endpunkte
Nero-Standard: SuperTokens-Session required, DSGVO-konformes Logging

Endpunkte:
  POST /api/dashboard/kyberassist  — KI-Assistent mit Plan-basiertem Limit
"""

import logging
import os
from typing import Annotated

import httpx
import psycopg2
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
from slowapi import Limiter
from slowapi.util import get_remote_address

logger = logging.getLogger(__name__)
limiter = Limiter(key_func=get_remote_address)
router = APIRouter(tags=["dashboard"])

# ---------------------------------------------------------------------------
# Plan-basierte KyberAssist-Limits
# ---------------------------------------------------------------------------
PLAN_LIMITS: dict[str | None, int | None] = {
    None: 10,           # Demo (kein Abo) — 10 Anfragen gesamt
    "demo": 10,
    "free": 10,
    "personal": 10,     # B2C Personal — kein KyberAssist-Vollzugang
    "family": 10,       # B2C Family — kein KyberAssist-Vollzugang
    "pro": 10,          # Pro: kein KyberAssist (konsistent mit Landing-Page)
    "business": None,   # Business: unbegrenzt
    "enterprise": None, # Enterprise: unbegrenzt
}

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://10.8.0.20:11434")
KYBERASSIST_MODEL = os.environ.get("KYBERASSIST_MODEL", "qwen2.5:32b")

SYSTEM_PROMPT = (
    "Du bist KyberAssist, der KI-Assistent von KyberGuard. "
    "Du hilfst KMU-Kunden bei Fragen zu NIS2-Compliance, IT-Sicherheit, "
    "Cyberbedrohungen und der Nutzung von KyberGuard. "
    "Antworte praezise, professionell und auf Deutsch (oder in der Sprache der Frage). "
    "Gib keine Rechts- oder Steuerberatung. "
    "Verweise bei komplexen Rechtsfragen an einen zugelassenen Anwalt."
)


class AssistRequest(BaseModel):
    message: str

    @field_validator("message")
    @classmethod
    def validate_message(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Nachricht darf nicht leer sein")
        if len(v) > 2000:
            raise ValueError("Nachricht zu lang (max. 2000 Zeichen)")
        # Null-Bytes und Steuerzeichen entfernen
        v = "".join(ch for ch in v if ch >= " " or ch in "\n\r\t")
        return v


async def get_current_user(request: Request) -> tuple[int, str | None]:
    """
    FastAPI Dependency: prueft SuperTokens-Session und gibt (user_id, plan) zurueck.
    Wirft HTTPException 401/403 wenn nicht authentifiziert oder Konto fehlt.
    """
    try:
        from supertokens_python.recipe.session.asyncio import get_session
        sess = await get_session(request, session_required=True)
    except Exception:
        raise HTTPException(status_code=401, detail="Nicht authentifiziert. Bitte einloggen.")

    if not sess:
        raise HTTPException(status_code=401, detail="Nicht authentifiziert. Bitte einloggen.")

    user_id, plan = _get_user(sess.get_user_id())
    if user_id is None:
        logger.warning("dashboard auth: SuperTokens-User nicht in DB sid=%s", sess.get_user_id()[:8])
        raise HTTPException(status_code=403, detail="Konto nicht gefunden.")

    return user_id, plan


def _get_user(supertokens_id: str) -> tuple[int | None, str | None]:
    """Gibt (user_id, plan) aus der DB zurueck. Niemals Exception nach aussen."""
    try:
        conn = psycopg2.connect(os.environ["DATABASE_URL"])
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, plan FROM users WHERE supertokens_id = %s",
                (supertokens_id,),
            )
            row = cur.fetchone()
        conn.close()
        if row:
            return row[0], row[1]
    except Exception as e:
        logger.error("_get_user DB-Fehler: %s", type(e).__name__)
    return None, None


def _get_and_increment_usage(user_id: int, limit: int | None) -> tuple[bool, int]:
    """
    Prueft Demo-Limit und erhoehe den Zaehler atomisch.
    Gibt (allowed, current_count) zurueck.
    Erstellt 'assist_usage' Tabelle per Lifespan — sicher idempotent.
    """
    try:
        conn = psycopg2.connect(os.environ["DATABASE_URL"])
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS assist_usage (
                    user_id   INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                    count     INTEGER NOT NULL DEFAULT 0,
                    updated   TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            cur.execute(
                """
                INSERT INTO assist_usage (user_id, count)
                VALUES (%s, 1)
                ON CONFLICT (user_id) DO UPDATE
                  SET count   = assist_usage.count + 1,
                      updated = NOW()
                RETURNING count
                """,
                (user_id,),
            )
            new_count = cur.fetchone()[0]

            # Rollback wenn Limit ueberschritten
            if limit is not None and new_count > limit:
                conn.rollback()
                conn.close()
                return False, new_count - 1

        conn.commit()
        conn.close()
        return True, new_count
    except Exception as e:
        logger.error("_get_and_increment_usage DB-Fehler: %s", type(e).__name__)
        # Im Fehlerfall: erlaube den Request (fail-open fuer UX)
        return True, 0


async def _call_ollama(message: str) -> str | None:
    """Ruft Ollama API auf. Gibt Antworttext oder None bei Fehler."""
    payload = {
        "model": KYBERASSIST_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": message},
        ],
        "stream": False,
        "options": {"temperature": 0.3, "num_predict": 1024},
    }
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=90.0, write=10.0, pool=5.0)
        ) as client:
            resp = await client.post(f"{OLLAMA_URL}/api/chat", json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data.get("message", {}).get("content", "").strip() or None
    except httpx.TimeoutException:
        logger.warning("KyberAssist Ollama Timeout")
    except httpx.HTTPStatusError as e:
        logger.error("KyberAssist Ollama HTTP %s", e.response.status_code)
    except Exception as e:
        logger.error("KyberAssist Ollama Fehler: %s", type(e).__name__)
    return None


# ---------------------------------------------------------------------------
# ENDPOINT: POST /api/dashboard/kyberassist
# ---------------------------------------------------------------------------

@router.post("/kyberassist")
@limiter.limit("20/minute")
async def kyberassist(
    request: Request,
    auth: Annotated[tuple[int, str | None], Depends(get_current_user)],
) -> JSONResponse:
    """
    KI-Assistent. Erfordert aktive SuperTokens-Session (via get_current_user).
    Demo-Nutzer: max. 10 Anfragen. Pro/Business/Enterprise: unbegrenzt.

    DSGVO: Kein Nachrichteninhalt wird geloggt.
    """
    user_id, plan = auth

    # --- Request-Body validieren ---
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Ungueltige JSON-Anfrage"})

    try:
        req = AssistRequest(**body)
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

    # --- 4. Demo-Limit pruefen und inkrementieren ---
    limit = PLAN_LIMITS.get(plan, 10)
    if limit is not None:
        allowed, current = _get_and_increment_usage(user_id, limit)
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "error": f"Demo-Limit erreicht ({limit} Anfragen). "
                             "Upgrade auf Pro fuer uneingeschraenkten Zugang.",
                    "limit": limit,
                    "used": current,
                },
            )
    else:
        _get_and_increment_usage(user_id, None)

    # --- 5. Ollama aufrufen ---
    answer = await _call_ollama(req.message)

    if answer is None:
        return JSONResponse(
            status_code=503,
            content={
                "error": "KyberAssist ist momentan nicht verfuegbar. "
                         "Bitte in wenigen Minuten erneut versuchen."
            },
        )

    # DSGVO: Nur Metadaten, kein Inhalt
    logger.info(
        "kyberassist ok user_id=%s plan=%s msg_len=%d ans_len=%d",
        user_id, plan, len(req.message), len(answer),
    )

    return JSONResponse({"answer": answer, "plan": plan})
