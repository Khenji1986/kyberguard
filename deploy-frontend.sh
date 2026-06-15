#!/bin/bash
# Deploy KyberGuard Frontend (Landing + SvelteKit-Dashboard) zur kyberguard-vm
# Pendant zu deploy-public-api.sh, gleiche Disziplin (Atlas + Nero Standard)
#
# Workflow:
#   1. Pre-Checks (VPN, Git-Status, Quelldateien)
#   2. landing/ von lokal zur VM rsynken (sonst nutzt deploy.sh dort veraltete Files)
#   3. SSH zur VM, dort deploy.sh ausführen (Build + rsync + cp)
#   4. Smoke-Test gegen https://kyberguard.de

set -euo pipefail

KYBERGUARD_VM="root@10.8.0.1"
SSH_KEY="$HOME/.ssh/friegun_servers"
LOCAL_LANDING="/home/ceuleeneo/friegun-projects/kyberguard/landing"
REMOTE_LANDING="/home/ceuleeneo/friegun-projects/kyberguard/landing"
REMOTE_DEPLOY="/home/ceuleeneo/kyberguard-web/deploy.sh"
LIVE_URL="https://kyberguard.de"

echo "=== KyberGuard Frontend Deployment ==="

# Schritt 1: VPN prüfen (gleiche Logik wie Backend-Skript)
echo "[1/5] VPN-Verbindung prüfen..."
if ! ping -c 1 -W 3 10.8.0.1 > /dev/null 2>&1; then
    echo "FEHLER: VPN nicht aktiv. Bitte AmneziaWG starten."
    exit 1
fi
echo "✓ VPN aktiv"

# Schritt 2: Quelldateien sind vorhanden + plausibel
echo "[2/5] Lokale Landing-Quelle prüfen..."
for f in index.html landing.js sw-unregister.js; do
    if [ ! -f "$LOCAL_LANDING/$f" ]; then
        echo "FEHLER: $LOCAL_LANDING/$f fehlt"
        exit 1
    fi
done
INDEX_SIZE=$(stat -c %s "$LOCAL_LANDING/index.html")
if [ "$INDEX_SIZE" -lt 50000 ]; then
    echo "FEHLER: index.html zu klein ($INDEX_SIZE Bytes, < 50KB)"
    echo "  Vermutung: SvelteKit-Fallback statt echter Landing"
    exit 1
fi
echo "✓ Landing-Quelle ok ($INDEX_SIZE Bytes index.html)"

# Schritt 3: Git-Status warnen wenn nicht sauber (kein Hard-Block)
echo "[3/5] Git-Status prüfen..."
cd "$(dirname "$LOCAL_LANDING")"
if ! git diff --quiet -- landing/ 2>/dev/null; then
    echo "  WARN: Uncommitted Changes in landing/. Trotzdem deployen? [y/N]"
    read -r answer
    if [ "$answer" != "y" ]; then
        echo "Abgebrochen."
        exit 1
    fi
fi
echo "✓ Git-Status ok"

# Schritt 4: landing/ zur VM rsynken (kritisch — sonst nutzt deploy.sh veraltete Files)
echo "[4/5] Landing-Quellen zur VM übertragen..."
rsync -av --delete \
    -e "ssh -i $SSH_KEY" \
    "$LOCAL_LANDING/" \
    "$KYBERGUARD_VM:$REMOTE_LANDING/"
echo "✓ landing/ synchronisiert"

# Schritt 5: deploy.sh auf VM ausführen + Smoke-Test
echo "[5/5] Remote-Deploy + Smoke-Test..."
ssh -i "$SSH_KEY" "$KYBERGUARD_VM" "bash $REMOTE_DEPLOY"

sleep 2
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$LIVE_URL" || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ Smoke-Test: $LIVE_URL liefert HTTP 200"
else
    echo "WARN: Smoke-Test lieferte HTTP $HTTP_CODE — bitte manuell prüfen"
fi

# Blog-Content von frieguen-hub synchronisieren
echo "[+] Blog-Content synchronisieren (frieguen-hub → kyberguard-vm)..."
BLOG_SRC="root@10.8.0.20:/home/ceuleeneo/management/content/blog_html/."
BLOG_DEST="$KYBERGUARD_VM:/home/ceuleeneo/nginx/html/blog/"
BLOG_TMP="/tmp/kyberguard_blog_sync"
mkdir -p "$BLOG_TMP"
if scp -i "$SSH_KEY" -r "$BLOG_SRC" "$BLOG_TMP/" 2>/dev/null; then
    scp -i "$SSH_KEY" -r "$BLOG_TMP/." "$BLOG_DEST" 2>/dev/null && echo "✓ Blog-Content deployt"
    rm -rf "$BLOG_TMP"
else
    echo "  (Blog-Content: keine neuen Artikel)"
fi

echo ""
echo "=== Frontend-Deployment abgeschlossen ==="
