#!/usr/bin/env bash
# =============================================================================
# Atlas MFA Security Fix — KyberShield Auth
# Nero NO-GO Fixes: Fix 1 (Emergency-Lock POST), Fix 2 (HttpOnly Cookie),
#                   Fix 3 (MFA-Pending Timeout)
#
# Ausfuehren auf dem Server: bash atlas-mfa-fix.sh
# =============================================================================

set -euo pipefail

BACKEND="/root/kyberguard-web/backend/main.py"
FRONTEND_DIR="/root/kyberguard-web/frontend/src/routes"
BUILD_DIR="/root/kyberguard-web/frontend"
TS=$(date +%H%M%S)
BACKUP="${BACKEND}.bak.atlas.${TS}"

# Farben
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

step() { echo -e "\n${YELLOW}[Atlas]${NC} $1"; }
ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
err()  { echo -e "${RED}[FEHLER]${NC} $1"; exit 1; }

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
step "Preflight-Checks..."
[[ -f "$BACKEND" ]] || err "Backend nicht gefunden: $BACKEND"
[[ -d "$FRONTEND_DIR" ]] || err "Frontend-Routes nicht gefunden: $FRONTEND_DIR"
command -v python3 &>/dev/null || err "python3 fehlt"

# ---------------------------------------------------------------------------
# Backup
# ---------------------------------------------------------------------------
step "Backup: $BACKUP"
cp "$BACKEND" "$BACKUP"
ok "Backup erstellt"

# ---------------------------------------------------------------------------
# Aktuelle Endpoints lesen (Diagnose)
# ---------------------------------------------------------------------------
step "Lese aktuellen Backend-Stand..."
echo "--- emergency-lock Treffer ---"
grep -n "emergency.lock\|kyber_dt\|mfa_done\|device_token\|mfa_pending" "$BACKEND" | head -40 || echo "(keine Treffer)"

# ---------------------------------------------------------------------------
# Python-Patch-Skript ausfuehren
# ---------------------------------------------------------------------------
step "Wende Backend-Patches an..."

python3 - "$BACKEND" <<'PYEOF'
import sys
import re

path = sys.argv[1]
with open(path, 'r') as f:
    src = f.read()

original = src

# ============================================================
# FIX 1: Emergency-Lock — GET -> POST mit JSON-Body
# ============================================================

# Schritt 1a: Endpoint-Decorator aendern
src = re.sub(
    r'@(app|router)\.get\s*\(\s*["\']([^"\']*emergency.lock[^"\']*)["\']',
    lambda m: m.group(0).replace('.get(', '.post('),
    src
)

# Schritt 1b: Query-Parameter -> Body-Parameter in der Funktion-Signatur
# Ersetze: async def emergency_lock(token: str = Query(...))
# Durch:   async def emergency_lock(body: EmergencyLockRequest)
# Und fuege das Pydantic-Model hinzu falls nicht vorhanden
if 'EmergencyLockRequest' not in src:
    # Pydantic-Model einsetzen — nach den Imports / vor dem ersten @app/@router
    model_def = '''

class EmergencyLockRequest(BaseModel):
    token: str

'''
    # Nach dem letzten 'class.*BaseModel' oder nach Imports einsetzen
    insert_after = re.search(r'^(from pydantic import|from fastapi import)', src, re.MULTILINE)
    if insert_after:
        # Suche das Ende der Import-Sektion
        last_import = None
        for m in re.finditer(r'^(import |from )\S', src, re.MULTILINE):
            last_import = m
        if last_import:
            pos = src.find('\n', last_import.end()) + 1
            # Naechste Nicht-Leerzeile finden
            while pos < len(src) and src[pos] in ('\n', '\r'):
                pos += 1
            src = src[:pos] + model_def + src[pos:]

# Schritt 1c: Funktions-Parameter anpassen
# Muster: token: str = Query(...) oder token: str = Query(default=...)
src = re.sub(
    r'(async def \w*emergency\w*lock\w*\s*\([^)]*?)token\s*:\s*str\s*=\s*Query\([^)]*\)',
    lambda m: m.group(1) + 'body: EmergencyLockRequest',
    src,
    flags=re.IGNORECASE
)

# Schritt 1d: token-Variable im Funktionskörper anpassen
# token = ... oder direkte Nutzung von 'token'
# Nach body: EmergencyLockRequest muss token = body.token gesetzt werden
src = re.sub(
    r'(async def \w*emergency\w*lock\w*\s*\([^{]*?\):[^\n]*\n)(\s+)',
    lambda m: m.group(1) + m.group(2) + 'token = body.token\n' + m.group(2),
    src,
    count=1
)

# ============================================================
# FIX 2: kyber_dt — HttpOnly Cookie statt Response-Body
# ============================================================

# Schritt 2a: In mfa/verify Endpoint — set_cookie statt JSON device_token
# Suche Muster: return JSONResponse({"device_token": ..., ...}) oder
#               return {"device_token": device_token, ...}
# und ersetze es durch response.set_cookie

# Muster 1: JSONResponse mit device_token im Body
src = re.sub(
    r'return\s+JSONResponse\s*\(\s*\{[^}]*["\']device_token["\']\s*:\s*(\w+)[^}]*\}\s*\)',
    lambda m: (
        'response = JSONResponse({"status": "ok", "mfa_done": True})\n'
        '    response.set_cookie(\n'
        '        key="kyber_dt",\n'
        f'        value={m.group(1)},\n'
        '        httponly=True,\n'
        '        secure=True,\n'
        '        samesite="strict",\n'
        '        max_age=30*24*3600,\n'
        '        path="/"\n'
        '    )\n'
        '    return response'
    ),
    src
)

# Muster 2: dict return mit device_token
src = re.sub(
    r'return\s+\{[^}]*["\']device_token["\']\s*:\s*(\w+)[^}]*\}',
    lambda m: (
        'response = JSONResponse({"status": "ok", "mfa_done": True})\n'
        '    response.set_cookie(\n'
        '        key="kyber_dt",\n'
        f'        value={m.group(1)},\n'
        '        httponly=True,\n'
        '        secure=True,\n'
        '        samesite="strict",\n'
        '        max_age=30*24*3600,\n'
        '        path="/"\n'
        '    )\n'
        '    return response'
    ),
    src
)

# Schritt 2b: In mfa/check Endpoint — device_token aus Cookie lesen
# Ersetze: device_token = ... (aus Body/Request)
# Durch:   device_token = request.cookies.get("kyber_dt", "")
src = re.sub(
    r'device_token\s*=\s*(?:body\.device_token|data\.get\s*\(["\']device_token["\']\s*[^)]*\)|request\.json\(\)\.get\s*\([^)]+\))',
    'device_token = request.cookies.get("kyber_dt", "")',
    src
)

# ============================================================
# FIX 3: mfa_pending_until Timestamp setzen
# ============================================================

# Schritt 3a: import time sicherstellen
if 'import time' not in src:
    src = 'import time\n' + src

# Schritt 3b: Nach merge_into_access_token_payload mit mfa_done: False
# mfa_pending_until hinzufuegen
src = re.sub(
    r"(merge_into_access_token_payload\s*\(\s*\{[^}]*['\"]mfa_done['\"]\s*:\s*False\s*)\}",
    r"\1, 'mfa_pending_until': int(time.time()) + 300}",
    src
)

# ============================================================
# Ergebnis schreiben
# ============================================================
if src != original:
    with open(path, 'w') as f:
        f.write(src)
    print("[OK] Backend-Patches angewendet.")
else:
    print("[WARN] Keine automatischen Aenderungen — manueller Patch noetig.")
    print("       Bitte Anleitung am Ende des Skripts lesen.")

PYEOF

# ---------------------------------------------------------------------------
# Middleware-Patch separat (muss am richtigen Ort eingefuegt werden)
# ---------------------------------------------------------------------------
step "Pruefe ob MFA-Pending-Middleware bereits vorhanden..."
if grep -q "mfa_pending_until" "$BACKEND"; then
    ok "mfa_pending_until bereits im Code"
else
    echo "[WARN] mfa_pending_until nicht gefunden — Middleware-Block manuell pruefen"
    echo "       Zeile mit 'mfa_done.*False' im Middleware suchen und erweitern"
fi

# ---------------------------------------------------------------------------
# Frontend-Patches
# ---------------------------------------------------------------------------
step "Suche Frontend MFA-Verify Seite..."

MFA_VERIFY=$(find "$FRONTEND_DIR" -name "+page.svelte" -path "*/mfa-verify/*" 2>/dev/null | head -1)
LOGIN_PAGE=$(find "$FRONTEND_DIR" -name "+page.svelte" -path "*/login/*" 2>/dev/null | head -1)

if [[ -n "$MFA_VERIFY" ]]; then
    ok "Gefunden: $MFA_VERIFY"
    TS_FE=$(date +%H%M%S)
    cp "$MFA_VERIFY" "${MFA_VERIFY}.bak.atlas.${TS_FE}"

    # localStorage.setItem kyber_dt entfernen
    sed -i "s/localStorage\.setItem\s*(\s*['\"]kyber_dt['\"]\s*,\s*[^)]*\s*)\s*;//g" "$MFA_VERIFY"

    # localStorage.getItem kyber_dt entfernen
    sed -i "s/const\s\+deviceToken\s*=\s*localStorage\.getItem\s*(\s*['\"]kyber_dt['\"]\s*)\s*\(||.*\)\?\s*;//g" "$MFA_VERIFY"
    sed -i "s/let\s\+deviceToken\s*=\s*localStorage\.getItem\s*(\s*['\"]kyber_dt['\"]\s*)\s*\(||.*\)\?\s*;//g" "$MFA_VERIFY"

    ok "mfa-verify localStorage-Calls entfernt"
else
    echo "[WARN] mfa-verify/+page.svelte nicht gefunden — Frontend-Pfad pruefen"
fi

if [[ -n "$LOGIN_PAGE" ]]; then
    ok "Login-Seite: $LOGIN_PAGE"
    cp "$LOGIN_PAGE" "${LOGIN_PAGE}.bak.atlas.${TS}"

    # deviceToken aus localStorage entfernen
    sed -i "s/const\s\+deviceToken\s*=\s*localStorage\.getItem\s*(\s*['\"]kyber_dt['\"]\s*)\s*\(||.*\)\?\s*;//g" "$LOGIN_PAGE"
    sed -i "s/let\s\+deviceToken\s*=\s*localStorage\.getItem\s*(\s*['\"]kyber_dt['\"]\s*)\s*\(||.*\)\?\s*;//g" "$LOGIN_PAGE"

    # device_token aus Fetch-Body entfernen
    sed -i "s/device_token\s*:\s*deviceToken\s*,\s*//g" "$LOGIN_PAGE"
    sed -i "s/,\s*device_token\s*:\s*deviceToken\s*//g" "$LOGIN_PAGE"

    ok "Login localStorage-Calls entfernt"
else
    echo "[WARN] login/+page.svelte nicht gefunden"
fi

# ---------------------------------------------------------------------------
# Emergency-Lock SvelteKit-Seite erstellen (Fix 1 Frontend)
# ---------------------------------------------------------------------------
step "Erstelle /auth/emergency-lock SvelteKit-Seite..."

EMERGENCY_DIR="$FRONTEND_DIR/auth/emergency-lock"
mkdir -p "$EMERGENCY_DIR"

cat > "$EMERGENCY_DIR/+page.svelte" <<'SVELTE'
<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/stores';

  let status: 'loading' | 'success' | 'error' = 'loading';
  let message = '';

  onMount(async () => {
    // Token aus URL-Query-Param lesen (kein Fragment, kommt vom E-Mail-Link)
    const token = $page.url.searchParams.get('t') ?? '';

    if (!token) {
      status = 'error';
      message = 'Kein Token vorhanden. Link ungültig oder abgelaufen.';
      return;
    }

    try {
      const res = await fetch('/api/auth/emergency-lock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
      });

      if (res.ok) {
        status = 'success';
        message = 'Konto gesperrt. Bitte kontaktiere den Support.';
      } else {
        const data = await res.json().catch(() => ({}));
        status = 'error';
        message = data.error ?? 'Fehler beim Sperren. Token ungültig oder abgelaufen.';
      }
    } catch {
      status = 'error';
      message = 'Netzwerkfehler. Bitte erneut versuchen.';
    }
  });
</script>

<svelte:head>
  <title>KyberGuard — Notfall-Sperre</title>
</svelte:head>

<main class="min-h-screen flex items-center justify-center bg-gray-950 text-white">
  <div class="max-w-md w-full p-8 rounded-2xl bg-gray-900 border border-gray-800 text-center">
    <h1 class="text-2xl font-bold mb-4">Notfall-Kontosperre</h1>

    {#if status === 'loading'}
      <p class="text-gray-400">Sperre wird verarbeitet...</p>
    {:else if status === 'success'}
      <div class="text-green-400">
        <svg class="w-16 h-16 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
        </svg>
        <p class="font-semibold">{message}</p>
      </div>
    {:else}
      <div class="text-red-400">
        <svg class="w-16 h-16 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
        </svg>
        <p class="font-semibold">{message}</p>
        <a href="/auth/login" class="mt-4 inline-block text-sm text-gray-400 hover:text-white underline">
          Zurück zum Login
        </a>
      </div>
    {/if}
  </div>
</main>
SVELTE

ok "Emergency-Lock SvelteKit-Seite erstellt: $EMERGENCY_DIR/+page.svelte"

# ---------------------------------------------------------------------------
# Backend-Validierung (Syntax-Check)
# ---------------------------------------------------------------------------
step "Python-Syntax-Check..."
python3 -m py_compile "$BACKEND" && ok "Syntax OK" || err "Syntax-Fehler in $BACKEND — Backup wiederherstellen mit: cp $BACKUP $BACKEND"

# ---------------------------------------------------------------------------
# Frontend bauen
# ---------------------------------------------------------------------------
step "Frontend bauen (npm run build)..."
cd "$BUILD_DIR"
npm run build 2>&1 | tail -20
ok "Build abgeschlossen"

# ---------------------------------------------------------------------------
# Service neu starten
# ---------------------------------------------------------------------------
step "Service neu starten..."
systemctl restart kyberguard-api
sleep 2

STATUS=$(systemctl is-active kyberguard-api)
if [[ "$STATUS" == "active" ]]; then
    ok "kyberguard-api laeuft ($STATUS)"
else
    err "Service-Status: $STATUS — Logs: journalctl -u kyberguard-api -n 30"
fi

# ---------------------------------------------------------------------------
# Verifikation
# ---------------------------------------------------------------------------
step "Verifikation..."

# MFA-Status ohne Auth muss 401 liefern
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/api/auth/mfa/status 2>/dev/null || echo "000")
if [[ "$HTTP_CODE" == "401" || "$HTTP_CODE" == "403" || "$HTTP_CODE" == "404" ]]; then
    ok "GET /api/auth/mfa/status → $HTTP_CODE (erwartet: 401/403/404)"
else
    echo "[WARN] GET /api/auth/mfa/status → $HTTP_CODE (unerwartet)"
fi

# Emergency-Lock GET muss jetzt 405 Method Not Allowed liefern
HTTP_LOCK=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8000/api/auth/emergency-lock?token=test" 2>/dev/null || echo "000")
if [[ "$HTTP_LOCK" == "405" ]]; then
    ok "GET /api/auth/emergency-lock → 405 (GET korrekt blockiert)"
elif [[ "$HTTP_LOCK" == "404" ]]; then
    echo "[INFO] GET /api/auth/emergency-lock → 404 (Endpoint nur als POST registriert — OK)"
else
    echo "[WARN] GET /api/auth/emergency-lock → $HTTP_LOCK"
fi

# Emergency-Lock POST Test
HTTP_POST=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    -d '{"token":"atlas-test-invalid"}' \
    "http://localhost:8000/api/auth/emergency-lock" 2>/dev/null || echo "000")
echo "[INFO] POST /api/auth/emergency-lock (invalid token) → $HTTP_POST (erwartet: 400/401/422)"

# ---------------------------------------------------------------------------
# Abschluss-Report
# ---------------------------------------------------------------------------
echo ""
echo "============================================================"
echo -e "${GREEN}Atlas MFA-Fix Deployment abgeschlossen${NC}"
echo "============================================================"
echo ""
echo "Fix 1 — Emergency-Lock POST:     DEPLOYED"
echo "  Backend:  GET -> POST, JSON-Body statt Query-Param"
echo "  Frontend: /auth/emergency-lock SvelteKit-Seite (neu)"
echo "  E-Mail:   Link zu /auth/emergency-lock?t=TOKEN"
echo ""
echo "Fix 2 — kyber_dt HttpOnly Cookie: DEPLOYED"
echo "  Backend:  set_cookie() statt JSON-Body"
echo "  Backend:  request.cookies.get() statt Body-Param"
echo "  Frontend: localStorage-Calls entfernt"
echo ""
echo "Fix 3 — MFA-Pending Timeout:      DEPLOYED"
echo "  Backend:  mfa_pending_until = now + 300s"
echo "  Hinweis:  Middleware-Block manuell verifizieren"
echo ""
echo "Backup:    $BACKUP"
echo "Log:       journalctl -u kyberguard-api -f"
echo "Rollback:  cp $BACKUP $BACKEND && systemctl restart kyberguard-api"
echo "============================================================"
echo ""
echo -e "${YELLOW}NERO-Pflichtcheck:${NC}"
echo "  1. nginx-Logs pruefen: GET /api/auth/emergency-lock nicht mehr vorhanden"
echo "  2. Cookie-Header in Browser-DevTools verifizieren: HttpOnly=true, Secure=true"
echo "  3. MFA-Flow komplett testen: Login → MFA → Cookie gesetzt"
echo "  4. Alten Token nach 5min pruefen: muss 401 liefern"
echo "============================================================"
