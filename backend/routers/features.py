"""KyberGuard — Feature-Router: CVE-Radar, Ransomware, Phishing, Domain, NIS2, etc."""

import asyncio
import hashlib
import json
import logging
import os
import re
import secrets
import string
from datetime import datetime, timezone, timedelta
from typing import Any

import httpx
import psycopg2
from cachetools import TTLCache
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from slowapi import Limiter
from slowapi.util import get_remote_address
from supertokens_python.recipe.session.framework.fastapi import verify_session

logger = logging.getLogger(__name__)
limiter = Limiter(key_func=get_remote_address)
router = APIRouter()

DATABASE_URL = os.environ.get("DATABASE_URL", "")


def _load_anthropic_key() -> str:
    cred_path = "/run/credentials/kyberguard-api.service/anthropic_api_key"
    if os.path.exists(cred_path):
        try:
            with open(cred_path) as f:
                return f.read().strip()
        except Exception:
            pass
    return os.environ.get("ANTHROPIC_API_KEY", "")

_cve_cache: TTLCache = TTLCache(maxsize=4, ttl=900)   # 15 Minuten
_ransom_cache: TTLCache = TTLCache(maxsize=4, ttl=1800)  # 30 Minuten


def _db() -> psycopg2.extensions.connection:
    return psycopg2.connect(DATABASE_URL)


def _get_user_id(supertokens_id: str) -> int | None:
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute("SELECT id, plan FROM users WHERE supertokens_id = %s", (supertokens_id,))
            row = cur.fetchone()
        conn.close()
        return row[0] if row else None
    except Exception as e:
        logger.error("_get_user_id Fehler: %s", e)
        return None


def _get_user(supertokens_id: str) -> tuple[int | None, str | None]:
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute("SELECT id, plan FROM users WHERE supertokens_id = %s", (supertokens_id,))
            row = cur.fetchone()
        conn.close()
        return (row[0], row[1]) if row else (None, None)
    except Exception as e:
        logger.error("_get_user Fehler: %s", e)
        return (None, None)


# CVE-Radar und Ransomware-Monitor sind in routers/public_feeds.py (public, kein Auth)


# ---------------------------------------------------------------------------
# POST /api/check  — Phishing/Betrugsprüfung im Dashboard
# ---------------------------------------------------------------------------
_PHISHING_INDICATORS = [
    (r"(?i)(verify|bestätigen|account|konto|suspended|gesperrt)", 2, "Konto-Bedrohung erwähnt"),
    (r"(?i)(click here|hier klicken|sofort|immediately|urgent|dringend)", 1, "Dringende Handlung gefordert"),
    (r"(?i)(password|passwort|login|anmelden|credential)", 2, "Zugangsdaten erwähnt"),
    (r"(?i)(prize|gewinn|winner|gewonnen|lottery|lotterie)", 3, "Gewinn-Versprechen"),
    (r"(?i)(bank|paypal|amazon|apple|microsoft|netflix|sparkasse|ing|commerzbank)", 2, "Bekannte Marke imitiert"),
    (r"https?://\S+", 0, "URL enthalten"),
    (r"(?i)(wire transfer|überweisung|bitcoin|crypto|kryptowäh)", 3, "Zahlungsaufforderung"),
    (r"(?i)(irs|finanzamt|police|polizei|interpol|gericht)", 3, "Behörde imitiert"),
]

_SPAM_INDICATORS = [
    # Marketing-Spam
    (r"(?i)(unsubscribe|abbestellen|opt.?out|abmelden|newsletter|mailing list)", 1, "Newsletter/Massen-E-Mail"),
    (r"(?i)(sonderangebot|angebot|rabatt|discount|sale|clearance|promotion|limited time|zeitlich begrenzt)", 2, "Werbe-Inhalt"),
    (r"(?i)(congratulations|herzlichen glückwunsch|you.ve been selected|auserwählt|gewinner benachrichtigung)", 2, "Falsche Gewinnbenachrichtigung"),
    (r"(?i)(make money|geld verdienen|passive income|passives einkommen|work from home|heimarbeit|reich werden)", 2, "Zweifelhafte Einkommens-Versprechen"),
    (r"(?i)(free trial|kostenlose probe|risk.?free|ohne risiko|no obligation|unverbindlich|gratis testen)", 1, "Marketing-Hooks"),
    (r"(?i)(dear (valued )?(customer|member|friend)|liebe?r (kunde|mitglied|freund|benutzer))", 1, "Unpersönliche Massen-Anrede"),
    (r"(?i)(act now|jetzt handeln|don.t miss|verpassen sie nicht|last chance|letzte chance|expires soon)", 2, "Künstliche Dringlichkeit"),
    (r"(?i)(click (below|here) to (buy|order|shop|purchase)|jetzt kaufen|hier bestellen)", 2, "Direkte Kauf-Aufforderung"),
    # Romance-Scam / Dating-Spam
    (r"(?i)(saw your (photos?|profile|pictures?|pic)|deine (fotos?|bilder|profil) gesehen)", 3, "Romance-Scam: Foto-Kontakt"),
    (r"(?i)(you look (interesting|beautiful|attractive|hot|cute|stunning|amazing)|du siehst (interessant|wunderschön|attraktiv|gut aus))", 3, "Romance-Scam: Äußerlichkeiten-Köder"),
    (r"(?i)(add me on (whatsapp|telegram|snapchat|instagram|kik|viber)|schreib mir auf (whatsapp|telegram))", 3, "Romance-Scam: Plattformwechsel"),
    (r"(?i)(i('m| am) (single|lonely|looking for|searching for)|ich bin (single|einsam|auf der Suche nach))", 2, "Dating-Spam: Status-Köder"),
    (r"(?i)(let('s| us) (meet|chat|talk|get to know)|lass uns (treffen|schreiben|kennenlernen))", 2, "Dating-Spam: Kontaktaufnahme"),
    (r"(?i)(military|soldier|doctor|engineer|widow|widower|oil (rig|platform)|(us|un) (army|navy|force))", 2, "Romance-Scam: Klassische Persona"),
    (r"(?i)(send me (your|a) (photo|picture|pic|nude|selfie)|schick mir (dein|ein) (foto|bild))", 4, "Sexueller Spam / Sextortion-Risiko"),
    # Unaufgeforderter Fremden-Kontakt
    (r"(?i)(i (found|got|saw) your (email|contact|number|profile) (from|on|via|through)|ich habe deine .* (gefunden|erhalten|gesehen))", 2, "Unaufgeforderter Fremden-Kontakt"),
    (r"(?i)(mutual (friend|contact|connection)|gemeinsame.? (freunde?|kontakte?|bekannte?))", 1, "Vorgetäuschte Gemeinsamkeit"),
    (r"(?i)(don't (delete|ignore) this|bitte nicht (löschen|ignorieren)|this is not spam|das ist kein spam)", 2, "Spam-Leugnung"),
    # Pharma / Produkt-Spam
    (r"(?i)(cialis|viagra|levitra|sildenafil|tadalafil|erectile|potenz|potenzmittel)", 3, "Pharma-Spam"),
    (r"(?i)(weight loss|abnehmen|lose \d+ (kg|pounds?)|schlank|diet pills?|fatburner)", 2, "Diät/Gewichtsverlust-Spam"),
    # Krypto-/Investment-Spam
    (r"(?i)(bitcoin|crypto|ethereum|nft|blockchain).{0,30}(invest|profit|earn|verdien|gewinn|return)", 3, "Krypto-Investment-Spam"),
    (r"(?i)(guaranteed (return|profit|income)|garantierte.? (rendite|gewinn|einnahmen))", 3, "Garantierte-Rendite-Betrug"),
]


@router.post("/check")
@limiter.limit("20/minute")
async def phishing_check(request: Request, session_container=Depends(verify_session())):
    supertokens_id = session_container.get_user_id()
    user_id = _get_user_id(supertokens_id)

    try:
        body = await request.json()
        text = str(body.get("text", "")).strip()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Ungültige Anfrage"})

    if not text:
        return JSONResponse(status_code=400, content={"error": "Kein Text angegeben"})
    if len(text) > 5000:
        return JSONResponse(status_code=413, content={"error": "Text zu lang (max 5000 Zeichen)"})

    phishing_score = 0
    spam_score = 0
    findings: list[str] = []

    for pattern, weight, label in _PHISHING_INDICATORS:
        if re.search(pattern, text):
            phishing_score += weight
            if label not in findings:
                findings.append(label)

    for pattern, weight, label in _SPAM_INDICATORS:
        if re.search(pattern, text):
            spam_score += weight
            if label not in findings:
                findings.append(label)

    phishing_score = min(phishing_score, 10)
    spam_score = min(spam_score, 10)
    score = max(phishing_score, spam_score)

    # Phishing hat Priorität über Spam
    if phishing_score >= 7:
        risk_level = "high"
        risk_label = "Hohes Phishing-Risiko"
        recommendation = "Dieser Text weist starke Phishing-Merkmale auf. Nicht auf Links klicken, keine Daten eingeben."
    elif phishing_score >= 4:
        risk_level = "medium"
        risk_label = "Mittleres Phishing-Risiko"
        recommendation = "Vorsicht geboten. Absender unabhängig verifizieren, bevor Sie handeln."
    elif phishing_score >= 1:
        risk_level = "low"
        risk_label = "Geringes Phishing-Risiko"
        recommendation = "Wenige Phishing-Indikatoren gefunden. Übliche Vorsicht walten lassen."
    elif spam_score >= 4:
        risk_level = "spam"
        risk_label = "Spam"
        recommendation = "Diese Nachricht enthält starke Spam-Merkmale. Kein direktes Phishing-Risiko, aber ignorieren empfohlen."
    elif spam_score >= 1:
        risk_level = "low"
        risk_label = "Möglicher Spam"
        recommendation = "Einige Spam-Merkmale erkannt. Wahrscheinlich unerwünschte Werbung, kein direktes Phishing-Risiko."
    else:
        risk_level = "safe"
        risk_label = "Unbedenklich"
        recommendation = "Keine Phishing- oder Spam-Merkmale gefunden."

    # Scan in DB speichern
    if user_id:
        try:
            raw_ip = get_remote_address(request) or ""
            ip_hash = hashlib.sha256(raw_ip.encode()).hexdigest()[:16]
            conn = _db()
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO scans (user_id, ip_hash, input_text, score, risk_level, findings)
                       VALUES (%s, %s, %s, %s, %s, %s)""",
                    (user_id, ip_hash, text[:500], score, risk_level, json.dumps(findings))
                )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error("check: DB-Speichern fehlgeschlagen: %s", e)

    return JSONResponse({
        "score": score,
        "risk_level": risk_level,
        "risk_label": risk_label,
        "recommendation": recommendation,
        "findings": findings,
    })


# ---------------------------------------------------------------------------
# GET /api/darkweb/emails  — Überwachte E-Mails des Nutzers
# POST /api/darkweb/check  — Neuen Breach-Check für E-Mail
# ---------------------------------------------------------------------------
@router.get("/darkweb/emails")
@limiter.limit("20/minute")
async def get_darkweb_emails(request: Request, session_container=Depends(verify_session())):
    user_id = _get_user_id(session_container.get_user_id())
    if not user_id:
        return JSONResponse({"emails": []})
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                """SELECT email, breach_count, breaches, added_at, last_checked
                   FROM monitored_emails WHERE user_id = %s ORDER BY added_at DESC""",
                (user_id,)
            )
            rows = cur.fetchall()
        conn.close()
        return JSONResponse({"emails": [
            {
                "email": r[0],
                "breach_count": r[1] or 0,
                "breaches": r[2] if isinstance(r[2], list) else [],
                "added_at": r[3].isoformat() if r[3] else None,
                "last_checked": r[4].isoformat() if r[4] else None,
            }
            for r in rows
        ]})
    except Exception as e:
        logger.error("get_darkweb_emails Fehler: %s", e)
        return JSONResponse({"emails": []})


@router.post("/darkweb/check")
@limiter.limit("10/minute")
async def darkweb_check(request: Request, session_container=Depends(verify_session())):
    user_id = _get_user_id(session_container.get_user_id())
    if not user_id:
        return JSONResponse(status_code=401, content={"error": "Nicht eingeloggt"})
    try:
        body = await request.json()
        email = str(body.get("email", "")).strip().lower()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Ungültige Anfrage"})

    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return JSONResponse(status_code=400, content={"error": "Ungültige E-Mail-Adresse"})

    hibp_key = os.environ.get("HIBP_API_KEY", "")
    breaches: list[dict] = []
    breach_count = 0

    if hibp_key:
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
                resp = await client.get(
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                    headers={"hibp-api-key": hibp_key, "User-Agent": "KyberGuard"},
                    params={"truncateResponse": "false"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    breach_count = len(data)
                    breaches = [
                        {"name": b.get("Name"), "date": b.get("BreachDate"),
                         "count": b.get("PwnCount", 0)}
                        for b in data[:10]
                    ]
        except Exception as e:
            logger.error("HIBP-Check Fehler: %s", e)

    # In DB speichern/aktualisieren
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO monitored_emails (user_id, email, breach_count, breaches, last_checked)
                   VALUES (%s, %s, %s, %s, NOW())
                   ON CONFLICT (user_id, email) DO UPDATE
                   SET breach_count = %s, breaches = %s, last_checked = NOW()""",
                (user_id, email, breach_count, json.dumps(breaches),
                 breach_count, json.dumps(breaches))
            )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error("darkweb_check DB Fehler: %s", e)

    return JSONResponse({
        "email": email,
        "breach_count": breach_count,
        "breaches": breaches,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    })


# ---------------------------------------------------------------------------
# GET /api/asm/status  — ASM-Status des Nutzers
# ---------------------------------------------------------------------------
@router.get("/asm/status")
@limiter.limit("20/minute")
async def get_asm_status(request: Request, session_container=Depends(verify_session())):
    user_id = _get_user_id(session_container.get_user_id())
    if not user_id:
        return JSONResponse({"scans": [], "last_scan": None})
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                """SELECT domain, scan_type, changes, change_summary, scanned_at
                   FROM asm_scans WHERE user_id = %s
                   ORDER BY scanned_at DESC LIMIT 10""",
                (user_id,)
            )
            rows = cur.fetchall()
        conn.close()
        scans = [
            {
                "domain": r[0],
                "scan_type": r[1],
                "changes": bool(r[2]),
                "change_summary": r[3] or "",
                "scanned_at": r[4].isoformat() if r[4] else None,
            }
            for r in rows
        ]
        return JSONResponse({
            "scans": scans,
            "last_scan": scans[0]["scanned_at"] if scans else None,
        })
    except Exception as e:
        logger.error("get_asm_status Fehler: %s", e)
        return JSONResponse({"scans": [], "last_scan": None})


# ---------------------------------------------------------------------------
# GET /api/domain/verified  — Verifizierte Domains
# POST /api/domain/scan  — Domain-Scan starten
# POST /api/domain/osint  — Domain-OSINT
# GET /api/domain/scan-pdf  — PDF-Report
# ---------------------------------------------------------------------------
@router.get("/domain/verified")
@limiter.limit("20/minute")
async def get_verified_domains(request: Request, session_container=Depends(verify_session())):
    user_id = _get_user_id(session_container.get_user_id())
    if not user_id:
        return JSONResponse({"domains": []})
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                """SELECT domain, verified, verified_at, token FROM verified_domains
                   WHERE user_id = %s ORDER BY created_at DESC""",
                (user_id,)
            )
            rows = cur.fetchall()
        conn.close()
        return JSONResponse({"domains": [
            {"domain": r[0], "verified": bool(r[1]),
             "verified_at": r[2].isoformat() if r[2] else None, "token": r[3]}
            for r in rows
        ]})
    except Exception as e:
        logger.error("get_verified_domains Fehler: %s", e)
        return JSONResponse({"domains": []})


@router.post("/domain/scan")
@limiter.limit("5/hour")
async def domain_scan(request: Request, session_container=Depends(verify_session())):
    _, plan = _get_user(session_container.get_user_id())
    try:
        body = await request.json()
        domain = str(body.get("domain", "")).strip().lower()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Ungültige Anfrage"})

    if not re.match(r"^[a-z0-9][a-z0-9\-\.]{1,250}$", domain):
        return JSONResponse(status_code=400, content={"error": "Ungültige Domain"})

    try:
        from routers.public import _run_domain_scan
        result = await _run_domain_scan(domain)
        return JSONResponse(result)
    except Exception as e:
        logger.error("domain_scan Fehler: %s", e)
        return JSONResponse({
            "domain": domain,
            "security_score": 0,
            "security_grade": "N/A",
            "error": "Scan vorübergehend nicht verfügbar",
        })


@router.post("/domain/osint")
@limiter.limit("5/hour")
async def domain_osint(request: Request, session_container=Depends(verify_session())):
    try:
        body = await request.json()
        domain = str(body.get("domain", "")).strip().lower()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Ungültige Anfrage"})

    if not re.match(r"^[a-z0-9][a-z0-9\-\.]{1,250}$", domain):
        return JSONResponse(status_code=400, content={"error": "Ungültige Domain"})

    results: dict[str, Any] = {
        "domain": domain,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "subdomains": [],
        "cert_count": 0,
        "recent_certs": [],
        "exposure_score": 0,
        "security_headers": {},
        "missing_headers": [],
        "spf": False,
        "dmarc": False,
        "dmarc_policy": None,
        "dkim": False,
        "open_ports": [],
    }

    _SECURITY_HEADERS = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]

    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0), follow_redirects=True) as client:
        # DNS Records: SPF, DMARC, DKIM
        try:
            from routers.public import _check_dns_records
            dns = await _check_dns_records(domain)
            results["spf"] = dns.get("spf", {}).get("exists", False)
            results["dmarc"] = dns.get("dmarc", {}).get("exists", False)
            results["dmarc_policy"] = dns.get("dmarc", {}).get("policy")
            results["dkim"] = dns.get("dkim", {}).get("exists", False)
        except Exception as e:
            logger.warning("domain_osint DNS Fehler: %s", e)

        # Security-Headers via HEAD-Request
        try:
            resp = await client.head(f"https://{domain}", follow_redirects=True,
                                     timeout=httpx.Timeout(8.0))
            headers_ci = {k.lower(): v for k, v in resp.headers.items()}
            present: dict[str, bool] = {}
            missing: list[str] = []
            for h in _SECURITY_HEADERS:
                exists = h.lower() in headers_ci
                present[h] = exists
                if not exists:
                    missing.append(h)
            results["security_headers"] = present
            results["missing_headers"] = missing
        except Exception as e:
            logger.warning("domain_osint Headers Fehler: %s", e)
            results["security_headers"] = {h: False for h in _SECURITY_HEADERS}
            results["missing_headers"] = list(_SECURITY_HEADERS)

        # Subdomains + Certs via crt.sh
        try:
            resp = await client.get(f"https://crt.sh/?q={domain}&output=json",
                                    timeout=httpx.Timeout(10.0))
            if resp.status_code == 200:
                certs = resp.json()
                results["cert_count"] = len(certs)
                results["recent_certs"] = [
                    {"name": c.get("name_value", ""), "date": c.get("not_before", "")}
                    for c in certs[:5]
                ]
                subdomains_set: set[str] = set()
                for c in certs:
                    for name in (c.get("name_value", "") or "").split("\n"):
                        n = name.strip().lstrip("*.")
                        if n and n != domain and n.endswith(f".{domain}") and len(n) <= 253:
                            subdomains_set.add(n)
                results["subdomains"] = sorted(subdomains_set)[:20]
        except Exception as e:
            logger.warning("domain_osint crt.sh Fehler: %s", e)

    # Exposure-Score berechnen (höher = riskanter)
    exposure = 0
    if not results["spf"]:   exposure += 25
    if not results["dmarc"]: exposure += 25
    if not results["dkim"]:  exposure += 10
    exposure += min(len(results["missing_headers"]) * 5, 30)
    exposure += min(len(results["subdomains"]) * 2, 10)
    results["exposure_score"] = min(exposure, 100)

    return JSONResponse(results)


@router.get("/domain/scan-pdf")
@limiter.limit("3/hour")
async def domain_scan_pdf(request: Request, session_container=Depends(verify_session())):
    domain = request.query_params.get("domain", "")
    if not domain:
        return JSONResponse(status_code=400, content={"error": "Domain fehlt"})
    return JSONResponse({"message": "PDF-Export in Kürze verfügbar",
                         "domain": domain})


# ---------------------------------------------------------------------------
# POST /api/ir-playbook  — IR-Playbook generieren (Ollama)
# ---------------------------------------------------------------------------
@router.post("/ir-playbook")
@limiter.limit("5/hour")
async def ir_playbook(request: Request, session_container=Depends(verify_session())):
    _, plan = _get_user(session_container.get_user_id())
    if plan not in ("pro", "business", "enterprise"):
        return JSONResponse(status_code=403, content={"error": "Pro oder Business Plan erforderlich"})

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Ungültige Anfrage"})

    incident_type = str(body.get("incident_type", "ransomware"))[:50]
    branche = str(body.get("branche", "Allgemein"))[:50]
    groesse = str(body.get("unternehmensgroesse", "KMU"))[:30]
    system = str(body.get("betroffenes_system", ""))[:100]

    prompt = (
        f"Erstelle ein professionelles Incident-Response-Playbook auf Deutsch für:\n"
        f"Incident-Typ: {incident_type}\n"
        f"Branche: {branche}\n"
        f"Unternehmensgröße: {groesse}\n"
        f"Betroffenes System: {system}\n\n"
        "Das Playbook soll folgende Abschnitte enthalten:\n"
        "1. Sofortmaßnahmen (0-1 Stunde)\n"
        "2. Eindämmung (1-24 Stunden)\n"
        "3. Wiederherstellung (24-72 Stunden)\n"
        "4. Nachbereitung und Lehren\n"
        "5. Kommunikation und Meldepflichten (NIS2)\n\n"
        "Schreibe konkret, umsetzbar und für IT-Sicherheitsverantwortliche verständlich."
    )

    playbook_text = ""

    # Layer 1: Anthropic Claude Haiku 4.5
    api_key = _load_anthropic_key()
    if api_key:
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(90.0)) as client:
                resp = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": "claude-haiku-4-5-20251001",
                        "max_tokens": 2048,
                        "messages": [{"role": "user", "content": prompt}],
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()
                    playbook_text = data["content"][0]["text"]
        except Exception as e:
            logger.warning("ir-playbook Anthropic Fehler: %s", e)

    # Layer 2: Ollama Mistral Fallback
    if not playbook_text:
        ollama_url = os.environ.get("OLLAMA_API_URL", "http://localhost:11434")
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(120.0)) as client:
                resp = await client.post(
                    f"{ollama_url}/api/generate",
                    json={"model": os.environ.get("OLLAMA_MODEL", "mistral"),
                          "prompt": prompt, "stream": False},
                )
                if resp.status_code == 200:
                    playbook_text = resp.json().get("response", "")
        except Exception as e:
            logger.error("ir-playbook Ollama Fehler: %s", e)

    if not playbook_text:
        # Fallback: statisches Template
        playbook_text = (
            f"=== INCIDENT RESPONSE PLAYBOOK ===\n"
            f"Typ: {incident_type} | Branche: {branche} | Größe: {groesse}\n\n"
            "SOFORTMASSNAHMEN (0-1h):\n"
            "- Betroffene Systeme isolieren\n"
            "- CSIRT/SOC informieren\n"
            "- Forensische Sicherung beginnen\n\n"
            "EINDÄMMUNG (1-24h):\n"
            "- Netzwerksegmentierung prüfen\n"
            "- Zugangsdaten zurücksetzen\n"
            "- Backup-Integrität verifizieren\n\n"
            "WIEDERHERSTELLUNG (24-72h):\n"
            "- Saubere Systeme aus Backup wiederherstellen\n"
            "- Monitoring intensivieren\n"
            "- Patch-Level aktualisieren\n\n"
            "MELDEPFLICHTEN (NIS2 Art. 23):\n"
            "- Frühwarnung: innerhalb 24h an BSI\n"
            "- Meldung: innerhalb 72h\n"
            "- Abschlussbericht: innerhalb 1 Monat\n"
        )

    return JSONResponse({
        "incident_type": incident_type,
        "branche": branche,
        "unternehmensgroesse": groesse,
        "betroffenes_system": system,
        "playbook_text": playbook_text,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    })


# ---------------------------------------------------------------------------
# NIS2 — Fragen, Check, PDF
# ---------------------------------------------------------------------------
_NIS2_QUESTIONS = [
    {"id": "backup", "category": "Datensicherung", "text": "Führen Sie regelmäßige Datensicherungen durch?", "weight": 3},
    {"id": "backup_test", "category": "Datensicherung", "text": "Testen Sie Ihre Backups regelmäßig auf Wiederherstellbarkeit?", "weight": 2},
    {"id": "mfa", "category": "Zugangsschutz", "text": "Ist Multi-Faktor-Authentifizierung für kritische Systeme aktiviert?", "weight": 3},
    {"id": "patch", "category": "Patch-Management", "text": "Werden Sicherheitsupdates innerhalb von 30 Tagen eingespielt?", "weight": 2},
    {"id": "incident_plan", "category": "Incident Response", "text": "Haben Sie einen dokumentierten Incident-Response-Plan?", "weight": 3},
    {"id": "training", "category": "Awareness", "text": "Führen Sie regelmäßige Security-Awareness-Schulungen durch?", "weight": 2},
    {"id": "supplier", "category": "Lieferkette", "text": "Prüfen Sie die Sicherheitsmaßnahmen Ihrer IT-Dienstleister?", "weight": 2},
    {"id": "encryption", "category": "Datenschutz", "text": "Werden sensible Daten im Ruhezustand verschlüsselt?", "weight": 2},
    {"id": "access_control", "category": "Zugangsschutz", "text": "Wenden Sie das Prinzip der minimalen Rechte an?", "weight": 2},
    {"id": "logging", "category": "Monitoring", "text": "Haben Sie ein zentrales Logging und Security-Monitoring?", "weight": 3},
    {"id": "vuln_scan", "category": "Schwachstellen", "text": "Führen Sie regelmäßige Schwachstellenscans durch?", "weight": 2},
    {"id": "network_seg", "category": "Netzwerk", "text": "Ist Ihr Netzwerk in sichere Zonen segmentiert?", "weight": 2},
    {"id": "dsgvo", "category": "Compliance", "text": "Sind Ihre Datenschutz-Prozesse DSGVO-konform dokumentiert?", "weight": 2},
    {"id": "nis2_aware", "category": "Compliance", "text": "Kennen Sie Ihre spezifischen NIS2-Meldepflichten?", "weight": 3},
    {"id": "continuity", "category": "Business Continuity", "text": "Haben Sie einen Business-Continuity-Plan?", "weight": 2},
    {"id": "risk_assessment", "category": "Risikomanagement", "text": "Führen Sie regelmäßige Risikoanalysen und -bewertungen durch?", "weight": 3},
    {"id": "third_party_audit", "category": "Lieferkette", "text": "Werden externe Dienstleister und Cloud-Anbieter regelmäßig auditiert?", "weight": 2},
    {"id": "vuln_mgmt_process", "category": "Schwachstellen", "text": "Haben Sie einen formellen Prozess für Schwachstellenmanagement und -behebung?", "weight": 2},
    {"id": "physical_security", "category": "Physische Sicherheit", "text": "Sind physische Zugangssicherungen für Serverräume und IT-Systeme implementiert?", "weight": 2},
    {"id": "crisis_communication", "category": "Krisenmanagement", "text": "Haben Sie einen Krisenkommunikationsplan für den Ernstfall eines Cyberangriffs?", "weight": 2},
]


@router.get("/nis2/questions")
@limiter.limit("30/minute")
async def nis2_questions(request: Request, session_container=Depends(verify_session())):
    return JSONResponse({"questions": _NIS2_QUESTIONS})


@router.post("/nis2/check")
@limiter.limit("10/minute")
async def nis2_check(request: Request, session_container=Depends(verify_session())):
    user_id = _get_user_id(session_container.get_user_id())
    try:
        body = await request.json()
        answers: dict = body.get("answers", {})
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Ungültige Anfrage"})

    max_score = sum(q["weight"] for q in _NIS2_QUESTIONS)
    achieved = sum(
        q["weight"] for q in _NIS2_QUESTIONS if answers.get(q["id"]) is True
    )
    percent = int(achieved / max_score * 100) if max_score else 0

    gaps = [q for q in _NIS2_QUESTIONS if answers.get(q["id"]) is not True]
    critical = [q for q in gaps if q["weight"] >= 3]
    high = [q for q in gaps if q["weight"] == 2]

    if percent >= 80:
        level = "Gut geschützt"
    elif percent >= 60:
        level = "Verbesserungsbedarf"
    elif percent >= 40:
        level = "Erhebliche Lücken"
    else:
        level = "Kritisch"

    if user_id:
        try:
            conn = _db()
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO nis2_results
                         (user_id, score, level, critical_count, high_count, medium_count, updated_at)
                       VALUES (%s, %s, %s, %s, %s, %s, NOW())
                       ON CONFLICT (user_id) DO UPDATE
                       SET score=%s, level=%s, critical_count=%s, high_count=%s,
                           medium_count=%s, updated_at=NOW()""",
                    (user_id, percent, level, len(critical), len(high), 0,
                     percent, level, len(critical), len(high), 0)
                )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error("nis2_check DB Fehler: %s", e)

    return JSONResponse({
        "percent": percent,
        "level": level,
        "critical_count": len(critical),
        "high_count": len(high),
        "medium_count": 0,
        "gaps": [{"id": g["id"], "text": g["text"], "category": g["category"],
                  "priority": "kritisch" if g["weight"] >= 3 else "hoch"} for g in gaps[:12]],
    })


@router.post("/nis2/pdf")
@limiter.limit("3/hour")
async def nis2_pdf(request: Request, session_container=Depends(verify_session())):
    return JSONResponse({"message": "PDF-Export wird vorbereitet. Bitte in Kürze erneut versuchen."})


# ---------------------------------------------------------------------------
# Partner-Keys
# ---------------------------------------------------------------------------
@router.get("/partner/usage")
@limiter.limit("20/minute")
async def get_partner_usage(request: Request, session_container=Depends(verify_session())):
    user_id = _get_user_id(session_container.get_user_id())
    if not user_id:
        return JSONResponse({"has_key": False, "requests_today": 0, "total_requests": 0})
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                """SELECT created_at, last_used, request_count, requests_today
                   FROM partner_api_keys WHERE user_id = %s ORDER BY created_at DESC LIMIT 1""",
                (user_id,)
            )
            row = cur.fetchone()
        conn.close()
        if not row:
            return JSONResponse({"has_key": False, "requests_today": 0, "total_requests": 0})
        return JSONResponse({
            "has_key": True,
            "created_at": row[0].isoformat() if row[0] else None,
            "last_used": row[1].isoformat() if row[1] else None,
            "total_requests": row[2] or 0,
            "requests_today": row[3] or 0,
        })
    except Exception as e:
        logger.error("get_partner_usage Fehler: %s", e)
        return JSONResponse({"has_key": False, "requests_today": 0, "total_requests": 0})


@router.post("/partner/generate-key")
@limiter.limit("3/hour")
async def generate_partner_key(request: Request, session_container=Depends(verify_session())):
    user_id, plan = _get_user(session_container.get_user_id())
    if not user_id:
        return JSONResponse(status_code=401, content={"error": "Nicht eingeloggt"})
    if plan not in ("pro", "business", "enterprise"):
        return JSONResponse(status_code=403, content={"error": "Pro oder Business Plan erforderlich"})

    try:
        body = await request.json()
        key_name = str(body.get("name", "API-Schlüssel"))[:100]
    except Exception:
        key_name = "API-Schlüssel"

    raw_key = "kyb_" + secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key_prefix = secrets.token_hex(8)

    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO partner_api_keys (user_id, api_key_hash, created_at, request_count, requests_today)
                   VALUES (%s, %s, NOW(), 0, 0)""",
                (user_id, key_hash)
            )
            cur.execute(
                """INSERT INTO api_keys (user_id, key_prefix, name, created_at, active)
                   VALUES (%s, %s, %s, NOW(), true)""",
                (user_id, key_prefix, key_name)
            )
        conn.commit()
        conn.close()
        return JSONResponse({"api_key": raw_key,
                             "note": "Diesen Schlüssel sicher aufbewahren — er wird nur einmal angezeigt."})
    except Exception as e:
        logger.error("generate_partner_key Fehler: %s", e)
        return JSONResponse(status_code=500, content={"error": "Key-Generierung fehlgeschlagen"})


# ---------------------------------------------------------------------------
# Pentest-Engagements
# ---------------------------------------------------------------------------
@router.get("/pentest/engagements")
@limiter.limit("20/minute")
async def get_pentest_engagements(request: Request, session_container=Depends(verify_session())):
    user_id = _get_user_id(session_container.get_user_id())
    if not user_id:
        return JSONResponse([])
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                """SELECT id, name, status, created_at, updated_at
                   FROM pentest_engagements WHERE user_id = %s ORDER BY created_at DESC""",
                (user_id,)
            )
            rows = cur.fetchall()
        conn.close()
        return JSONResponse([
            {"id": r[0], "name": r[1], "status": r[2],
             "created_at": r[3].isoformat() if r[3] else None,
             "updated_at": r[4].isoformat() if r[4] else None}
            for r in rows
        ])
    except Exception as e:
        logger.error("get_pentest_engagements Fehler: %s", e)
        return JSONResponse([])


@router.post("/pentest/engagement")
@limiter.limit("5/hour")
async def create_pentest_engagement(request: Request, session_container=Depends(verify_session())):
    user_id, plan = _get_user(session_container.get_user_id())
    if not user_id:
        return JSONResponse(status_code=401, content={"error": "Nicht eingeloggt"})
    if plan not in ("pro", "business", "enterprise"):
        return JSONResponse(status_code=403, content={"error": "Pro oder Business Plan erforderlich"})
    try:
        body = await request.json()
        name = str(body.get("name", ""))[:200]
        if not name:
            return JSONResponse(status_code=400, content={"error": "Name erforderlich"})
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO pentest_engagements (user_id, name, status, created_at, updated_at)
                   VALUES (%s, %s, 'planned', NOW(), NOW()) RETURNING id""",
                (user_id, name)
            )
            new_id = cur.fetchone()[0]
        conn.commit()
        conn.close()
        return JSONResponse({"id": new_id, "name": name, "status": "planned"})
    except Exception as e:
        logger.error("create_pentest_engagement Fehler: %s", e)
        return JSONResponse(status_code=500, content={"error": "Engagement konnte nicht erstellt werden"})


@router.get("/pentest/engagements/{eid}")
@limiter.limit("20/minute")
async def get_pentest_engagement(eid: int, request: Request, session_container=Depends(verify_session())):
    user_id = _get_user_id(session_container.get_user_id())
    if not user_id:
        return JSONResponse(status_code=404, content={"error": "Nicht gefunden"})
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, name, status, scope_json, created_at FROM pentest_engagements WHERE id = %s AND user_id = %s",
                (eid, user_id)
            )
            row = cur.fetchone()
        conn.close()
        if not row:
            return JSONResponse(status_code=404, content={"error": "Engagement nicht gefunden"})
        return JSONResponse({
            "id": row[0], "name": row[1], "status": row[2],
            "scope": json.loads(row[3]) if row[3] else {},
            "created_at": row[4].isoformat() if row[4] else None,
        })
    except Exception as e:
        logger.error("get_pentest_engagement Fehler: %s", e)
        return JSONResponse(status_code=500, content={"error": "Fehler beim Laden"})


@router.get("/pentest/hardening-checklist")
@limiter.limit("30/minute")
async def pentest_hardening_checklist(request: Request, session_container=Depends(verify_session())):
    return JSONResponse({"items": [
        {"id": "fw", "text": "Firewall-Regeln auf Minimalanforderungen prüfen", "category": "Netzwerk"},
        {"id": "ssh", "text": "SSH: nur Key-Auth, kein Root-Login, Port ändern", "category": "Zugangssicherung"},
        {"id": "updates", "text": "Automatische Sicherheitsupdates aktivieren", "category": "Patch-Management"},
        {"id": "mfa", "text": "MFA für alle Admin-Zugänge", "category": "Authentifizierung"},
        {"id": "backup", "text": "Offline-Backups testen und verschlüsseln", "category": "Datensicherung"},
    ]})


@router.get("/pentest/nis2-mapping")
@limiter.limit("30/minute")
async def pentest_nis2_mapping(request: Request, session_container=Depends(verify_session())):
    return JSONResponse({"mapping": []})


@router.get("/pentest/partners")
@limiter.limit("20/minute")
async def pentest_partners(request: Request, session_container=Depends(verify_session())):
    return JSONResponse({"partners": []})


# ---------------------------------------------------------------------------
# Phone-Check im Dashboard
# ---------------------------------------------------------------------------
@router.post("/phone/check")
@limiter.limit("10/hour")
async def phone_check_dashboard(request: Request, session_container=Depends(verify_session())):
    try:
        body = await request.json()
        number = str(body.get("number", "")).strip()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Ungültige Anfrage"})
    # Intern Quick-Check via public-Router
    async with httpx.AsyncClient(timeout=httpx.Timeout(20.0)) as client:
        try:
            resp = await client.post(
                "http://172.18.0.1:8000/api/public/phone-check",
                json={"number": number},
            )
            if resp.status_code == 200:
                return JSONResponse(resp.json())
        except Exception as e:
            logger.error("phone_check_dashboard Fehler: %s", e)
    return JSONResponse({"number": number, "risk": "unknown", "findings": []})


# ---------------------------------------------------------------------------
# PQ-Assessment (Post-Quantum)
# ---------------------------------------------------------------------------
_PQ_QUESTIONS = [
    {"id": "tls13", "text": "Nutzen Sie TLS 1.3 für alle externen Verbindungen?", "weight": 3},
    {"id": "cert_rotation", "text": "Rotieren Sie Zertifikate regelmäßig (< 1 Jahr)?", "weight": 2},
    {"id": "vpn_pq", "text": "Unterstützt Ihr VPN Post-Quantum-Algorithmen?", "weight": 3},
    {"id": "long_data", "text": "Schützen Sie Langzeitdaten vor zukünftiger Entschlüsselung?", "weight": 3},
    {"id": "algo_inventory", "text": "Haben Sie ein Inventar aller kryptographischen Algorithmen?", "weight": 2},
]

_PQ_FINDINGS = {
    "tls13": "TLS 1.3 nicht aktiv — ältere Protokolle (TLS 1.2) sind durch NIST PQC-Angriffe gefährdet. Sofort-Migration auf TLS 1.3 einleiten.",
    "cert_rotation": "Zertifikate werden nicht regelmäßig rotiert — Risiko kompromittierter Schlüssel ohne Erkennung. Automatische Rotation via Let's Encrypt oder ACME empfohlen.",
    "vpn_pq": "VPN unterstützt keine Post-Quantum-Algorithmen — gefährdet durch 'Harvest Now, Decrypt Later'-Angriffe. ML-KEM (CRYSTALS-Kyber) fähige VPN-Lösung prüfen.",
    "long_data": "Langzeitdaten unverschlüsselt oder klassisch verschlüsselt — besonders kritisch für Daten mit Schutzfristen > 10 Jahre. AES-256 mit hybridem PQ-KEM kombinieren.",
    "algo_inventory": "Kein kryptographisches Algorithmen-Inventar — NIST-Migration zu ML-KEM/ML-DSA/SLH-DSA ohne Überblick nicht planbar. Crypto-Agility-Audit durchführen.",
}


@router.post("/pq-assessment")
@limiter.limit("10/hour")
async def pq_assessment(request: Request, session_container=Depends(verify_session())):
    try:
        body = await request.json()
        answers: dict = body.get("answers", {})
        domain = str(body.get("domain", "")).strip().lower()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Ungültige Anfrage"})

    max_score = sum(q["weight"] for q in _PQ_QUESTIONS)
    achieved = sum(q["weight"] for q in _PQ_QUESTIONS if answers.get(q["id"]) is True)
    score = int(achieved / max_score * 100) if max_score else 0

    findings: list[str] = []
    for q in _PQ_QUESTIONS:
        if not answers.get(q["id"]):
            findings.append(_PQ_FINDINGS.get(q["id"], f"Lücke erkannt: {q['text']}"))

    if score <= 30:
        risk = "KRITISCH"
    elif score <= 60:
        risk = "GEFÄHRDET"
    elif score <= 80:
        risk = "GUT"
    else:
        risk = "SEHR GUT"

    if not findings:
        findings.append("Alle Post-Quantum-Basismaßnahmen implementiert — weiterhin NIST-Updates verfolgen.")

    # TLS-Details für Domain (SSL-Socket-Level)
    import ssl as _ssl
    import socket as _socket
    tls_version: str | None = None
    cert_algorithm: str | None = None
    hsts = False
    cipher_suite: str | None = None

    if domain and re.match(r"^[a-z0-9][a-z0-9\-\.]{1,250}$", domain):
        try:
            ctx = _ssl.create_default_context()
            loop = asyncio.get_running_loop()

            def _ssl_check() -> dict:
                try:
                    sock = _socket.create_connection((domain, 443), timeout=8)
                    conn = ctx.wrap_socket(sock, server_hostname=domain)
                    proto = conn.version() or ""
                    cipher = conn.cipher()
                    conn.close()
                    tls_map = {
                        "TLSv1.3": "TLSv1.3",
                        "TLSv1.2": "TLSv1.2",
                        "TLSv1.1": "TLSv1.1",
                        "TLSv1":   "TLSv1.0",
                    }
                    return {
                        "tls_version": tls_map.get(proto, proto or "Unbekannt"),
                        "cipher_suite": cipher[0][:60] if cipher and cipher[0] else None,
                        "cert_algorithm": "ECDSA" if cipher and "ECDSA" in (cipher[0] or "") else "RSA",
                    }
                except Exception:
                    return {"tls_version": None, "cipher_suite": None, "cert_algorithm": None}

            ssl_info = await loop.run_in_executor(None, _ssl_check)
            tls_version = ssl_info.get("tls_version")
            cipher_suite = ssl_info.get("cipher_suite")
            cert_algorithm = ssl_info.get("cert_algorithm")
        except Exception:
            pass

        # HSTS via HEAD-Request
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
                resp = await client.head(f"https://{domain}", follow_redirects=True)
                hsts = "strict-transport-security" in {k.lower() for k in resp.headers}
        except Exception:
            pass

    # HNDL-Risiko bestimmen
    if tls_version in ("TLSv1.0", "TLSv1.1"):
        hndl_risk = "HIGH"
    elif tls_version == "TLSv1.2" or cert_algorithm == "RSA":
        hndl_risk = "MEDIUM"
    elif tls_version == "TLSv1.3":
        hndl_risk = "LOW"
    else:
        hndl_risk = "UNKNOWN"

    migration_effort = "Niedrig" if score >= 60 else ("Mittel" if score >= 30 else "Hoch")

    # Findings als strukturierte Objekte
    structured_findings: list[dict] = []
    for finding_text in findings:
        text_lower = finding_text.lower()
        if any(kw in text_lower for kw in ["tls 1.0", "tls 1.1", "harvest", "kyber", "langzeit"]):
            sev = "HIGH"
        elif any(kw in text_lower for kw in ["vpn", "zertifikat", "inventar", "rotation"]):
            sev = "MEDIUM"
        else:
            sev = "LOW"
        parts = finding_text.split(" — ", 1)
        structured_findings.append({
            "severity": sev,
            "issue": parts[0][:120],
            "recommendation": parts[1][:250] if len(parts) > 1 else None,
        })

    return JSONResponse({
        "score": score,
        "risk": risk,
        "findings": structured_findings,
        "domain": domain or "",
        "tls_version": tls_version,
        "cert_algorithm": cert_algorithm,
        "hsts": hsts,
        "cipher_suite": cipher_suite,
        "hndl_risk": hndl_risk,
        "migration_effort": migration_effort,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    })


# ---------------------------------------------------------------------------
# Sentinel (Domain-Überwachung)
# ---------------------------------------------------------------------------
@router.get("/sentinel/status")
@limiter.limit("20/minute")
async def get_sentinel_status(request: Request, session_container=Depends(verify_session())):
    user_id = _get_user_id(session_container.get_user_id())
    if not user_id:
        return JSONResponse({"alerts": [], "total": 0, "company_name": None, "monitoring_active": False})
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                """SELECT alert_type, detail, found_at, notified
                   FROM sentinel_alerts WHERE user_id = %s
                   ORDER BY found_at DESC LIMIT 20""",
                (user_id,)
            )
            rows = cur.fetchall()
            cur.execute("SELECT company_name FROM users WHERE id = %s", (user_id,))
            user_row = cur.fetchone()
        conn.close()
        company_name = user_row[0] if user_row and user_row[0] else None
        return JSONResponse({
            "alerts": [
                {"alert_type": r[0], "detail": r[1],
                 "found_at": r[2].isoformat() if r[2] else None,
                 "notified": bool(r[3])}
                for r in rows
            ],
            "total": len(rows),
            "company_name": company_name,
            "monitoring_active": bool(company_name),
        })
    except Exception as e:
        logger.error("get_sentinel_status Fehler: %s", e)
        return JSONResponse({"alerts": [], "total": 0, "company_name": None, "monitoring_active": False})


@router.post("/sentinel/check")
@limiter.limit("5/hour")
async def sentinel_check(request: Request, session_container=Depends(verify_session())):
    user_id, plan = _get_user(session_container.get_user_id())
    if not user_id:
        return JSONResponse(status_code=401, content={"error": "Nicht eingeloggt"})

    domain = ""
    company_name = ""
    try:
        body = await request.json()
        domain = str(body.get("domain", "")).strip().lower()
    except Exception:
        pass

    # Ohne Domain: erste verifizierte Domain des Nutzers aus DB laden
    if not domain or not re.match(r"^[a-z0-9][a-z0-9\-\.]{1,250}$", domain):
        try:
            conn = _db()
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT domain FROM verified_domains WHERE user_id = %s AND verified = true ORDER BY verified_at DESC LIMIT 1",
                    (user_id,)
                )
                row = cur.fetchone()
                cur.execute("SELECT company_name FROM users WHERE id = %s", (user_id,))
                urow = cur.fetchone()
            conn.close()
            domain = row[0] if row else ""
            company_name = urow[0] if urow and urow[0] else ""
        except Exception as e:
            logger.warning("sentinel_check DB-Lookup Fehler: %s", e)

    if not domain:
        return JSONResponse(status_code=400, content={"error": "Keine verifizierte Domain gefunden — bitte zuerst eine Domain verifizieren."})
    if not re.match(r"^[a-z0-9][a-z0-9\-\.]{1,250}$", domain):
        return JSONResponse(status_code=400, content={"error": "Ungültige Domain"})

    found = False
    detail = ""

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
            resp = await client.get(
                f"https://crt.sh/?q={domain}&output=json",
                follow_redirects=True,
            )
            if resp.status_code == 200:
                certs = resp.json()
                suspicious = [
                    c for c in certs
                    if c.get("not_before", "") >= (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")
                    and c.get("name_value", "") != domain
                ]
                if suspicious:
                    found = True
                    detail = f"{len(suspicious)} verdächtige Lookalike-Zertifikate in den letzten 30 Tagen"
    except Exception as e:
        logger.warning("sentinel_check Fehler: %s", e)

    if found and user_id:
        try:
            conn = _db()
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO sentinel_alerts (user_id, alert_type, detail, found_at, notified)
                       VALUES (%s, 'lookalike_cert', %s, NOW(), false)""",
                    (user_id, detail)
                )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error("sentinel_check DB Fehler: %s", e)

    return JSONResponse({
        "domain": domain,
        "found": found,
        "detail": detail,
        "company_checked": company_name or domain,
        "domain_checked": domain,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    })


# ---------------------------------------------------------------------------
# Supplier-Risk (Lieferanten-Risiko)
# ---------------------------------------------------------------------------
@router.post("/supplier-risk")
@limiter.limit("5/hour")
async def supplier_risk(request: Request, session_container=Depends(verify_session())):
    _, plan = _get_user(session_container.get_user_id())
    try:
        body = await request.json()
        packages: list = body.get("packages", [])
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Ungültige Anfrage"})

    if not packages or len(packages) > 20:
        return JSONResponse(status_code=400, content={"error": "1-20 Pakete angeben"})
    if not isinstance(packages, list):
        return JSONResponse(status_code=400, content={"error": "packages muss eine Liste sein"})

    # Strings wie "log4j:2.14.1" oder "django" in Objekte umwandeln
    normalized: list[dict] = []
    for p in packages[:20]:
        if isinstance(p, str):
            parts = p.split(":", 1)
            normalized.append({"name": parts[0].strip(), "version": parts[1].strip() if len(parts) > 1 else "latest"})
        elif isinstance(p, dict):
            normalized.append(p)
    packages = normalized

    from urllib.parse import quote as _url_quote

    results: list[dict] = []
    total_score = 0

    for pkg in packages:
        try:
            name = str(pkg.get("name", ""))[:100].strip()
            version = str(pkg.get("version", "latest"))[:30]
        except (AttributeError, TypeError):
            continue
        if not name:
            continue
        cve_count = 0
        risk_level = "niedrig"

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(8.0)) as client:
                resp = await client.get(
                    f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={_url_quote(name)}&resultsPerPage=5"
                )
                if resp.status_code == 200:
                    data = resp.json()
                    cve_count = data.get("totalResults", 0)
                    if cve_count >= 10:
                        risk_level = "hoch"
                    elif cve_count >= 3:
                        risk_level = "mittel"
        except Exception:
            pass

        pkg_score = min(100, cve_count * 5)
        total_score += pkg_score
        results.append({
            "name": name, "version": version,
            "cve_count": cve_count, "risk_level": risk_level, "score": pkg_score,
        })

    overall = int(total_score / len(results)) if results else 0
    if overall >= 60:
        overall_level = "Hohes Risiko"
    elif overall >= 30:
        overall_level = "Mittleres Risiko"
    else:
        overall_level = "Geringes Risiko"

    return JSONResponse({
        "packages": results,
        "overall_score": overall,
        "overall_level": overall_level,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    })


# ---------------------------------------------------------------------------
# WiFi-Spy
# ---------------------------------------------------------------------------
_WIFI_QUESTIONS = [
    {"id": "wpa3", "category": "Verschlüsselung", "text": "Nutzen Sie WPA3 oder WPA2-Enterprise?"},
    {"id": "guest", "category": "Netzwerktrennung", "text": "Haben Sie ein separates Gäste-WLAN?"},
    {"id": "hidden", "category": "SSID", "text": "Verstecken Sie Ihre SSID?"},
    {"id": "radius", "category": "Authentifizierung", "text": "Nutzen Sie RADIUS-Authentifizierung?"},
    {"id": "ids", "category": "Monitoring", "text": "Haben Sie ein WLAN-Intrusion-Detection-System?"},
    {"id": "rogue", "category": "Rogue-AP", "text": "Scannen Sie regelmäßig nach nicht autorisierten Access Points?"},
    {"id": "update", "category": "Firmware", "text": "Halten Sie Access-Point-Firmware aktuell?"},
]


@router.get("/wifispy/questions")
@limiter.limit("30/minute")
async def wifispy_questions(request: Request, session_container=Depends(verify_session())):
    return JSONResponse(_WIFI_QUESTIONS)


@router.post("/wifispy/check")
@limiter.limit("10/hour")
async def wifispy_check(request: Request, session_container=Depends(verify_session())):
    try:
        body = await request.json()
        answers: dict = body.get("answers", {})
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Ungültige Anfrage"})

    yes_count = sum(1 for v in answers.values() if v is True)
    total = len(_WIFI_QUESTIONS)
    score = int((1 - yes_count / total) * 100) if total else 0

    findings: list[str] = []
    recs: list[str] = []

    if not answers.get("wpa3"):
        findings.append("Veraltete WLAN-Verschlüsselung")
        recs.append("Auf WPA3 oder WPA2-Enterprise umsteigen")
    if not answers.get("guest"):
        findings.append("Kein separates Gäste-WLAN")
        recs.append("Gäste-WLAN einrichten um Firmennetz zu trennen")
    if not answers.get("rogue"):
        findings.append("Keine Kontrolle auf nicht autorisierte Access Points")
        recs.append("Regelmäßige WLAN-Scans einrichten")

    return JSONResponse({
        "score": score,
        "findings": findings,
        "recommendations": recs,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    })


# ---------------------------------------------------------------------------
# Chat — Weiterleitung an KyberAssist
# ---------------------------------------------------------------------------
@router.post("/chat")
@limiter.limit("20/minute")
async def chat(request: Request, session_container=Depends(verify_session())):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Ungültige Anfrage"})

    async with httpx.AsyncClient(timeout=httpx.Timeout(60.0)) as client:
        try:
            resp = await client.post(
                "http://172.18.0.1:8000/api/dashboard/kyberassist",
                json=body,
                headers={"Cookie": request.headers.get("cookie", ""),
                         "Content-Type": "application/json"},
            )
            return JSONResponse(resp.json(), status_code=resp.status_code)
        except Exception as e:
            logger.error("chat weiterleitung Fehler: %s", e)
            return JSONResponse(status_code=503, content={"error": "KyberAssist nicht erreichbar"})


# asm_scan_status ist in routers/public_feeds.py (public, kein Auth)


# ---------------------------------------------------------------------------
# MFA — Stub-Endpoints (SuperTokens TOTP ist separat konfiguriert)
# ---------------------------------------------------------------------------
@router.get("/auth/mfa/status")
@limiter.limit("20/minute")
async def mfa_status(request: Request, session_container=Depends(verify_session())):
    user_id = _get_user_id(session_container.get_user_id())
    if not user_id:
        return JSONResponse({"enabled": False})
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute("SELECT mfa_enabled FROM users WHERE id = %s", (user_id,))
            row = cur.fetchone()
        conn.close()
        return JSONResponse({"enabled": bool(row[0]) if row else False})
    except Exception as e:
        logger.error("mfa_status Fehler: %s", e)
        return JSONResponse({"enabled": False})


@router.get("/auth/mfa/devices")
@limiter.limit("10/minute")
async def mfa_devices(request: Request, session_container=Depends(verify_session())):
    return JSONResponse({"devices": []})


@router.post("/auth/mfa/toggle")
@limiter.limit("5/minute")
async def mfa_toggle(request: Request, session_container=Depends(verify_session())):
    return JSONResponse({"ok": True, "message": "MFA-Konfiguration über Konto-Einstellungen vornehmen"})


# ---------------------------------------------------------------------------
# GET /api/threat-intel  — Threat-Intelligence-Feed (Dashboard-Widget)
# ---------------------------------------------------------------------------
_threat_intel_cache: TTLCache = TTLCache(maxsize=8, ttl=1800)  # 30 Minuten


@router.get("/threat-intel")
@limiter.limit("30/minute")
async def threat_intel(request: Request, session_container=Depends(verify_session())):
    sector = request.query_params.get("sector", "all")[:50]
    cache_key = f"ti_{sector}"
    if cache_key in _threat_intel_cache:
        return JSONResponse(_threat_intel_cache[cache_key])

    user_id = _get_user_id(session_container.get_user_id())
    events: list[dict] = []
    stats = {"total_iocs": 0, "active_campaigns": 0, "affected_sectors": 0, "critical_vulns": 0}

    # Lokale Quellen: sentinel_alerts + IOC-Watcher-Daten aus DB
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                """SELECT alert_type, detail, found_at
                   FROM sentinel_alerts
                   ORDER BY found_at DESC LIMIT 20"""
            )
            rows = cur.fetchall()
            for r in rows:
                events.append({
                    "type": "sentinel",
                    "category": r[0] or "lookalike",
                    "description": r[1] or "",
                    "severity": "HIGH",
                    "timestamp": r[2].isoformat() if r[2] else None,
                    "source": "SPHINX-Sentinel",
                })

            # IOC-Watcher: neueste Alerts
            cur.execute(
                """SELECT asset_value, ioc_source, severity, detail, first_seen
                   FROM ioc_alerts
                   ORDER BY first_seen DESC LIMIT 10"""
            )
            ioc_rows = cur.fetchall()
            for r in ioc_rows:
                events.append({
                    "type": "ioc",
                    "category": "ioc",
                    "description": f"IOC erkannt: {(r[0] or '')[:60]}",
                    "severity": (r[2] or "MEDIUM").upper(),
                    "timestamp": r[4].isoformat() if r[4] else None,
                    "source": r[1] or "IOC-Watcher",
                })

            # Anzahl aktiver IOCs für Stats
            cur.execute("SELECT COUNT(*) FROM ioc_alerts WHERE first_seen > NOW() - INTERVAL '7 days'")
            stats["total_iocs"] = (cur.fetchone() or [0])[0]

        conn.close()
    except Exception as e:
        logger.warning("threat_intel DB-Fehler: %s", e)

    # Statische aktuelle Bedrohungs-Kampagnen (immer verfügbar, keine externe API)
    static_campaigns = [
        {"type": "campaign", "category": "ransomware", "description": "LockBit 3.0 — aktive Kampagne gegen KMU (DACH-Region)",
         "severity": "CRITICAL", "timestamp": None, "source": "BSI/CISA-Mapping"},
        {"type": "campaign", "category": "phishing", "description": "Business Email Compromise via Teams/Outlook-Impersonation",
         "severity": "HIGH", "timestamp": None, "source": "GUARDIAN Intelligence"},
        {"type": "campaign", "category": "supply_chain", "description": "NPM/PyPI-Paket-Poisoning aktiv (2026 Q2)",
         "severity": "HIGH", "timestamp": None, "source": "GUARDIAN Intelligence"},
    ]
    events.extend(static_campaigns)
    stats["active_campaigns"] = len(static_campaigns)
    stats["affected_sectors"] = 5
    stats["critical_vulns"] = 12

    # Threat Actors (statisch, MITRE/BSI-Mapping)
    _THREAT_ACTORS = [
        {
            "name": "APT28 (Fancy Bear)",
            "origin": "RU",
            "threat_level": "CRITICAL",
            "description": "Russische Hackergruppe (GRU), bekannt für Phishing-Kampagnen gegen Regierungen und kritische Infrastruktur.",
            "ttps": ["T1566", "T1078", "T1486"],
            "targets": ["Regierung", "Energie", "Verteidigung"],
        },
        {
            "name": "Lazarus Group",
            "origin": "KP",
            "threat_level": "HIGH",
            "description": "Nordkoreanische APT-Gruppe, fokussiert auf Finanzbetrug, Krypto-Diebstahl und Ransomware.",
            "ttps": ["T1059", "T1486", "T1071"],
            "targets": ["Finanzwesen", "Krypto", "IT"],
        },
        {
            "name": "Cl0p",
            "origin": "UA",
            "threat_level": "HIGH",
            "description": "Ransomware-Gruppe, bekannt für MOVEit- und GoAnywhere-Exploitation. Aktiv 2026.",
            "ttps": ["T1190", "T1486", "T1567"],
            "targets": ["KMU", "Gesundheit", "Bildung"],
        },
    ]

    # Ransomware-Vorfälle von ransomlook.io (30 Minuten Cache)
    recent_ransomware: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(8.0)) as client:
            resp = await client.get("https://api.ransomlook.io/recent")
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    for item in data[:10]:
                        recent_ransomware.append({
                            "victim": (item.get("post_title") or "Unbekannt")[:80],
                            "group": (item.get("group_name") or "Unbekannt")[:40],
                            "date": item.get("discovered", ""),
                            "country": item.get("country", ""),
                        })
    except Exception as e:
        logger.warning("threat_intel ransomlook Fehler: %s", e)

    # Sektor-Filter
    if sector != "all":
        events = [e for e in events if sector.lower() in (e.get("category", "") + " " + e.get("description", "")).lower()]

    result = {
        "events": events[:30],
        "stats": stats,
        # Felder direkt für Frontend-Kompatibilität
        "active_iocs": stats["total_iocs"],
        "ransomware_incidents": len(recent_ransomware),
        "threat_actors": _THREAT_ACTORS,
        "recent_ransomware": recent_ransomware,
        "sector": sector,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "source": "KyberGuard Threat Intelligence",
    }
    _threat_intel_cache[cache_key] = result
    return JSONResponse(result)
