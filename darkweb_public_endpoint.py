"""
Dark Web Check — Öffentlicher Endpoint-Code (Append zu public.py)
Atlas/Nero-Standard: k-Anonymity, DSGVO-konform, Rate-Limit 5/min, Kein Email-Logging

Dieser Code wird am Ende von /home/ceuleeneo/kyberguard-web/backend/public.py eingefügt.

Endpunkt: POST /api/public/dark-web-check
"""

# ============================================================
# DARK WEB FREE CHECK — Öffentlich, kein Login
# Nero-Standard:
#   - Rate-Limit: 5/Minute pro IP
#   - E-Mail-Validierung: RFC 5321 (max 254 Zeichen, Regex)
#   - HIBP: nur truncated response (nur Namen, kein PII-Dump)
#   - Logging: NUR E-Mail-Hash (SHA256[:16]), nie Klartext
#   - DSGVO Opt-In: parametrisiert in DB, kein SQL-Injection
#   - marketing_leads Tabelle: CREATE IF NOT EXISTS
# ============================================================

import hashlib as _dwc_hashlib
import re as _dwc_re
import os as _dwc_os
import logging as _dwc_logging
from urllib.parse import quote as _dwc_quote
from datetime import datetime, timezone

import httpx as _dwc_httpx
import psycopg2 as _dwc_pg

_dwc_logger = _dwc_logging.getLogger(__name__)

# E-Mail-Regex (RFC 5321 vereinfacht, sicher für Validierung)
_EMAIL_PATTERN = _dwc_re.compile(
    r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
)
_EMAIL_MAX_LEN = 254  # RFC 5321

# HIBP API — truncated=true: gibt nur Namen zurück, kein PII-Dump
_HIBP_BREACH_URL = 'https://haveibeenpwned.com/api/v3/breachedaccount/{}?truncateResponse=true'
_HIBP_TIMEOUT = _dwc_httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0)


def _ensure_marketing_leads_table() -> None:
    """Erstellt marketing_leads Tabelle falls nicht vorhanden. Idempotent."""
    try:
        conn = _dwc_pg.connect(_dwc_os.environ['DATABASE_URL'])
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS marketing_leads (
                    id            SERIAL PRIMARY KEY,
                    email_hash    VARCHAR(64) NOT NULL,
                    email         VARCHAR(254) NOT NULL,
                    opt_in        BOOLEAN NOT NULL DEFAULT FALSE,
                    source        VARCHAR(64) NOT NULL DEFAULT 'dark_web_check',
                    breach_count  INTEGER,
                    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    UNIQUE(email)
                )
            """)
            # Index für schnelle Lookups via email
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_marketing_leads_email
                ON marketing_leads (email)
            """)
        conn.commit()
        conn.close()
    except Exception as e:
        _dwc_logger.error('marketing_leads table init: %s', type(e).__name__)


def _hash_email(email: str) -> str:
    """SHA256-Hash der E-Mail für Privacy-konformes Logging."""
    return _dwc_hashlib.sha256(email.lower().encode()).hexdigest()[:16]


async def _hibp_check_public(email: str) -> dict:
    """
    HIBP Breach-Check mit truncated response.
    Gibt nur: found (bool), count (int), breach_names (list[str]).
    KEINE vollständigen Breach-Daten (kein PII-Risiko für User).

    Fallback wenn kein HIBP-Key: simulated response (degraded mode).
    """
    hibp_key = _dwc_os.environ.get('HIBP_API_KEY', '')

    if not hibp_key:
        _dwc_logger.warning('HIBP_API_KEY fehlt — Dark Web Check degraded mode')
        return {'found': False, 'count': 0, 'breach_names': [], 'degraded': True}

    url = _HIBP_BREACH_URL.format(_dwc_quote(email, safe=''))
    headers = {
        'hibp-api-key': hibp_key,
        'user-agent': 'KyberGuard-Web/2.0-FreeCheck',
    }

    try:
        async with _dwc_httpx.AsyncClient(
            timeout=_HIBP_TIMEOUT,
            verify=True,
            follow_redirects=False,
        ) as client:
            resp = await client.get(url, headers=headers)

            if resp.status_code == 200:
                breaches = resp.json()
                # truncateResponse=true: nur Name-Felder vorhanden
                names = [b.get('Name', '') for b in breaches if b.get('Name')]
                return {
                    'found': True,
                    'count': len(names),
                    'breach_names': names[:10],  # max 10 Namen ausgeben
                    'degraded': False,
                }
            elif resp.status_code == 404:
                return {'found': False, 'count': 0, 'breach_names': [], 'degraded': False}
            elif resp.status_code == 429:
                _dwc_logger.warning('HIBP Rate-Limit erreicht')
                return {'found': None, 'count': 0, 'breach_names': [], 'degraded': True, 'rate_limited': True}
            else:
                _dwc_logger.error('HIBP HTTP %s', resp.status_code)
                return {'found': None, 'count': 0, 'breach_names': [], 'degraded': True}
    except _dwc_httpx.TimeoutException:
        _dwc_logger.warning('HIBP Timeout')
        return {'found': None, 'count': 0, 'breach_names': [], 'degraded': True}
    except Exception as e:
        _dwc_logger.error('HIBP Fehler: %s', type(e).__name__)
        return {'found': None, 'count': 0, 'breach_names': [], 'degraded': True}


def _save_marketing_lead(email: str, opt_in: bool, breach_count: int) -> None:
    """
    Speichert Marketing Lead bei Opt-In. DSGVO-konform.
    Upsert: bei existierender E-Mail opt_in aktualisieren.
    Parametrisierte Query — kein SQL-Injection-Risiko.
    """
    email_hash = _hash_email(email)
    try:
        conn = _dwc_pg.connect(_dwc_os.environ['DATABASE_URL'])
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO marketing_leads (email_hash, email, opt_in, source, breach_count)
                VALUES (%s, %s, %s, 'dark_web_check', %s)
                ON CONFLICT (email) DO UPDATE
                SET opt_in = EXCLUDED.opt_in,
                    breach_count = EXCLUDED.breach_count,
                    created_at = NOW()
            """, (email_hash, email, opt_in, breach_count))
        conn.commit()
        conn.close()
        _dwc_logger.info(
            'marketing_lead_saved hash=%s opt_in=%s',
            email_hash, opt_in
        )
    except Exception as e:
        _dwc_logger.error('marketing_lead save: %s', type(e).__name__)


# ============================================================
# ENDPOINT DEFINITION — wird in router eingehängt
# ============================================================

@router.post('/dark-web-check')
@limiter.limit('5/minute')
async def dark_web_check_public(request: Request) -> JSONResponse:
    """
    Kostenloser Dark Web E-Mail-Check für die Landing Page.
    Kein Login erforderlich.

    Rate-Limit: 5 Requests/IP/Minute.
    Input: { "email": "...", "opt_in": bool (optional) }
    Output: { "found": bool, "count": int, "breach_names": [...], "opted_in": bool }

    Sicherheit:
    - E-Mail-Validierung (Regex + Länge)
    - Kein Klartext-Logging der E-Mail (nur Hash)
    - HIBP truncated response (keine vollständigen Breach-Daten)
    - Parametrisierte DB-Queries
    - Rate-Limit 5/Minute per IP
    """
    # Tabelle beim ersten Request sicherstellen (idempotent)
    _ensure_marketing_leads_table()

    ip_hash = _dwc_hashlib.sha256(
        (request.client.host if request.client else 'unknown').encode()
    ).hexdigest()[:16]

    # --- Input lesen ---
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={'error': 'Ungültige Anfrage'})

    email = str(body.get('email', '')).strip().lower()
    opt_in = bool(body.get('opt_in', False))

    # --- E-Mail validieren ---
    if not email:
        return JSONResponse(status_code=422, content={'error': 'E-Mail-Adresse fehlt'})

    if len(email) > _EMAIL_MAX_LEN:
        return JSONResponse(status_code=422, content={'error': 'E-Mail-Adresse zu lang'})

    # Null-Bytes und Kontrollzeichen
    if '\x00' in email or any(ord(c) < 0x20 for c in email):
        return JSONResponse(status_code=422, content={'error': 'Ungültige Zeichen in E-Mail'})

    if not _EMAIL_PATTERN.match(email):
        return JSONResponse(status_code=422, content={'error': 'Ungültige E-Mail-Adresse'})

    email_hash = _hash_email(email)
    _dwc_logger.info('dark_web_check_public ip_hash=%s email_hash=%s', ip_hash, email_hash)

    # --- HIBP Check ---
    result = await _hibp_check_public(email)

    # --- Opt-In speichern (nur wenn Nutzer zustimmt) ---
    opted_in = False
    if opt_in and result.get('found') is not None:
        _save_marketing_lead(email, True, result.get('count', 0))
        opted_in = True
    elif not opt_in and result.get('found') is not None:
        # Kein Opt-In: trotzdem E-Mail-Hash loggen für Frequenz-Analyse (kein PII)
        _dwc_logger.info(
            'dark_web_check_no_optin hash=%s found=%s count=%s',
            email_hash, result.get('found'), result.get('count', 0)
        )

    # --- Response ---
    if result.get('degraded') and not result.get('rate_limited'):
        # Service degraded — keine falschen Ergebnisse ausgeben
        return JSONResponse(
            status_code=503,
            content={'error': 'Dienst vorübergehend nicht verfügbar. Bitte erneut versuchen.'}
        )

    if result.get('rate_limited'):
        return JSONResponse(
            status_code=429,
            content={'error': 'Zu viele Anfragen. Bitte kurz warten.'}
        )

    return JSONResponse(content={
        'found': result.get('found', False),
        'count': result.get('count', 0),
        'breach_names': result.get('breach_names', []),
        'opted_in': opted_in,
        'checked_at': datetime.now(timezone.utc).isoformat(),
    })
