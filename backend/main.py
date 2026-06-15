#!/usr/bin/env python3
"""
KyberGuard Public API — FastAPI Backend
Nero-Standard: Security-First, kein Over-Engineering

Architektur:
  nginx (TLS1.3+PQ) -> WAF -> FastAPI (uvicorn, port 8000)
  Nur /api/public/* ist ohne Auth erreichbar.
  Alle anderen Routen sind NICHT implementiert (404 by default).
"""

import logging
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe.session.framework.fastapi import verify_session

from auth import init_supertokens
from routers.dashboard import router as dashboard_router, _ensure_assist_tables
from routers.features import router as features_router
from routers.public import router as public_router
from routers.public_feeds import router as public_feeds_router
from routers.security_monitor import router as monitor_router
from routers.user import router as user_router

load_dotenv()
init_supertokens()

# ---------------------------------------------------------------------------
# Logging — kein Stack-Trace nach aussen
# ---------------------------------------------------------------------------
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# httpx darf keine vollen URLs loggen (koennten Tokens enthalten)
logging.getLogger("httpx").setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# Rate-Limiter (global, IP-basiert via slowapi)
# ---------------------------------------------------------------------------
limiter = Limiter(key_func=get_remote_address)


# ---------------------------------------------------------------------------
# Lifespan: Startup-Check
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("KyberGuard Public API startet...")
    crowdsec_url = os.environ.get("CROWDSEC_LAPI_URL", "")
    if not crowdsec_url:
        logger.warning(
            "CROWDSEC_LAPI_URL nicht gesetzt — /map-data liefert Placeholder-Daten"
        )
    _ensure_assist_tables()
    yield
    logger.info("KyberGuard Public API beendet.")


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="KyberGuard Public API",
    version="1.0.0",
    # OpenAPI-Docs nur intern erreichbar machen (nginx blockiert /docs extern)
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)

# Rate-Limiter an App haengen
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# SuperTokens-Middleware — muss VOR CORSMiddleware registriert werden
app.add_middleware(get_middleware())

# ---------------------------------------------------------------------------
# CORS — nur die eigene Landing Page darf zugreifen
# ---------------------------------------------------------------------------
ALLOWED_ORIGINS = os.environ.get(
    "ALLOWED_ORIGINS",
    "https://kyberguard.de,https://www.kyberguard.de",
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in ALLOWED_ORIGINS],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "rid", "fdi-version", "anti-csrf", "st-auth-mode"],
    expose_headers=["front-token", "anti-csrf", "st-access-token", "st-refresh-token"],
    max_age=600,
)


# ---------------------------------------------------------------------------
# Security-Response-Headers (Middleware)
# ---------------------------------------------------------------------------
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "0"  # Modern: CSP statt XSS-Filter
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    # HSTS: 1 Jahr, includeSubDomains — erzwingt HTTPS auf allen Subdomains
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Permissions-Policy: alle sensitiven Browser-APIs deaktivieren
    response.headers["Permissions-Policy"] = (
        "geolocation=(), camera=(), microphone=(), payment=(), "
        "usb=(), magnetometer=(), gyroscope=(), accelerometer=()"
    )
    # Server-Header verstecken
    response.headers["Server"] = "KyberGuard"
    return response


# ---------------------------------------------------------------------------
# Globaler Fehler-Handler — niemals interne Details preisgeben
# ---------------------------------------------------------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unbehandelter Fehler bei {request.url.path}: {type(exc).__name__}")
    return JSONResponse(
        status_code=500,
        content={"error": "Interner Fehler. Bitte spaeter erneut versuchen."},
    )


# ---------------------------------------------------------------------------
# Router einbinden
# ---------------------------------------------------------------------------
app.include_router(public_router, prefix="/api/public")
app.include_router(dashboard_router, prefix="/api/dashboard")
app.include_router(monitor_router, prefix="/api/dashboard")
app.include_router(user_router, prefix="/api")
app.include_router(features_router, prefix="/api")
app.include_router(public_feeds_router, prefix="/api")


# ---------------------------------------------------------------------------
# Health-Check (intern, kein Rate-Limit)
# ---------------------------------------------------------------------------
@app.get("/health", include_in_schema=False)
async def health():
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Session-Check — Frontend prüft ob User eingeloggt ist
# ---------------------------------------------------------------------------
@app.get("/api/user/me", include_in_schema=False)
@limiter.limit("30/minute")
async def get_me(request: Request, session_container=Depends(verify_session())):
    import psycopg2
    supertokens_id = session_container.get_user_id()
    email = ""
    try:
        from supertokens_python.recipe.emailpassword.asyncio import get_user_by_id
        st_user = await get_user_by_id(supertokens_id)
        if st_user:
            email = st_user.email
    except Exception:
        pass
    plan = "free"
    try:
        conn = psycopg2.connect(os.environ["DATABASE_URL"])
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT plan FROM users WHERE supertokens_id = %s",
                    (supertokens_id,),
                )
                row = cur.fetchone()
                if row:
                    plan = row[0]
        finally:
            conn.close()
    except Exception as e:
        logger.error("get_me DB-Fehler: %s", e)
    return JSONResponse({"email": email, "plan": plan, "user_id": supertokens_id})


# ---------------------------------------------------------------------------
# MFA-Check — nach Login prüfen ob Gerät bekannt ist
# ---------------------------------------------------------------------------
@app.post("/api/auth/mfa/check", include_in_schema=False)
@limiter.limit("10/minute")
async def mfa_check(request: Request, session_container=Depends(verify_session())):
    # MFA ist derzeit deaktiviert — direkt weiterleiten
    return JSONResponse({"mfa_required": False})
