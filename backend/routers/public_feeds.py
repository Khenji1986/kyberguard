"""KyberGuard — Public Feed Endpoints: CVE-Radar, Ransomware-Monitor, ASM-Status.
Alle Endpunkte hier sind bewusst ohne Auth — öffentliche Daten für Dashboard-Widgets."""

import asyncio
import logging
import os
from datetime import datetime, timezone

import httpx
import psycopg2
from cachetools import TTLCache
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address

logger = logging.getLogger(__name__)
limiter = Limiter(key_func=get_remote_address)
router = APIRouter()

DATABASE_URL = os.environ.get("DATABASE_URL", "")

_cve_cache: TTLCache = TTLCache(maxsize=4, ttl=21600)   # 6 Stunden
_ransom_cache: TTLCache = TTLCache(maxsize=4, ttl=1800)  # 30 Minuten

_EPSS_API = "https://api.first.org/data/v1/epss"
_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_HEADERS = {"User-Agent": "KyberGuard/2.0 (security research; contact@kyberguard.de)"}


async def _nvd_description(client: httpx.AsyncClient, cve_id: str) -> str:
    try:
        r = await client.get(
            _NVD_API,
            params={"cveId": cve_id},
            headers=_NVD_HEADERS,
            timeout=httpx.Timeout(5.0),
        )
        if r.status_code == 200:
            vulns = r.json().get("vulnerabilities", [])
            if vulns:
                descs = vulns[0]["cve"]["descriptions"]
                en = next((d["value"] for d in descs if d["lang"] == "en"), "")
                return en[:200]
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------------------
# GET /api/cve-radar  — CVEs sortiert nach EPSS-Score (FIRST.org, public)
# ---------------------------------------------------------------------------
@router.get("/cve-radar")
@limiter.limit("30/minute")
async def cve_radar(request: Request):
    if "cve" in _cve_cache:
        return JSONResponse(_cve_cache["cve"])

    top: list[dict] = []
    total_high_risk = 0

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
            # Top-20 CVEs nach EPSS-Score (absteigend)
            epss_resp = await client.get(
                _EPSS_API,
                params={"order": "!epss", "limit": "20"},
                headers=_NVD_HEADERS,
            )
            # Anzahl CVEs mit EPSS > 50%
            count_resp = await client.get(
                _EPSS_API,
                params={"order": "!epss", "limit": "1", "epss-gt": "0.5"},
                headers=_NVD_HEADERS,
            )

            if epss_resp.status_code == 200:
                epss_data = epss_resp.json()
                cves_raw = epss_data.get("data", [])

                if count_resp.status_code == 200:
                    total_high_risk = count_resp.json().get("total", 0)

                # Beschreibungen für Top-8 CVEs parallel von NVD abrufen
                top_ids = [item["cve"] for item in cves_raw[:8]]
                desc_tasks = [_nvd_description(client, cve_id) for cve_id in top_ids]
                descriptions = await asyncio.gather(*desc_tasks, return_exceptions=True)

                for i, item in enumerate(cves_raw[:8]):
                    cve_id = item.get("cve", "")
                    epss_val = round(float(item.get("epss", 0)) * 100, 1)
                    desc = descriptions[i] if i < len(descriptions) and isinstance(descriptions[i], str) else ""
                    top.append({
                        "cve": cve_id,
                        "epss": epss_val,
                        "description": desc,
                        "published": "",
                        "cvss": None,
                    })
    except Exception as e:
        logger.warning("CVE-Radar EPSS Fehler: %s", e)

    result = {
        "total_high_risk": total_high_risk,
        "top": top,
        "source": "FIRST.org EPSS v3",
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    _cve_cache["cve"] = result
    return JSONResponse(result)


# ---------------------------------------------------------------------------
# GET /api/ransomware-monitor  — Aktuelle Ransomware-Opfer (public endpoint)
# ---------------------------------------------------------------------------
@router.get("/ransomware-monitor")
@limiter.limit("30/minute")
async def ransomware_monitor(request: Request):
    if "ransom" in _ransom_cache:
        return JSONResponse(_ransom_cache["ransom"])

    alerts: list[dict] = []
    total = 0

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(8.0)) as client:
            resp = await client.get("https://api.ransomlook.io/recent")
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    total = len(data)
                    for item in data[:20]:
                        alerts.append({
                            "group": item.get("group_name", "Unbekannt"),
                            "victim": item.get("post_title", "Unbekannt"),
                            "date": item.get("discovered", ""),
                            "country": item.get("country", ""),
                        })
    except Exception as e:
        logger.warning("Ransomware-Monitor Fehler: %s", e)

    result = {"alerts": alerts, "total": total,
              "updated_at": datetime.now(timezone.utc).isoformat()}
    _ransom_cache["ransom"] = result
    return JSONResponse(result)


# ---------------------------------------------------------------------------
# GET /api/asm/scan-status  — Letzter ASM-Scan-Zeitstempel (public endpoint)
# ---------------------------------------------------------------------------
@router.get("/asm/scan-status")
@limiter.limit("30/minute")
async def asm_scan_status(request: Request):
    try:
        conn = psycopg2.connect(DATABASE_URL)
        with conn.cursor() as cur:
            cur.execute("SELECT MAX(scanned_at) FROM asm_scans")
            row = cur.fetchone()
        conn.close()
        last = row[0].isoformat() if row and row[0] else None
        return JSONResponse({"last_scan": last})
    except Exception as e:
        logger.error("asm_scan_status Fehler: %s", e)
        return JSONResponse({"last_scan": None})
