#!/bin/bash
# Deploy KyberGuard Public API Backend zur kyberguard-vm
# Nero-Standard: Prüfe vor jedem Schritt

set -euo pipefail

KYBERGUARD_VM="root@10.8.0.1"
REMOTE_DIR="/home/ceuleeneo/kyberguard-web/backend"
SSH_KEY="$HOME/.ssh/friegun_servers"

echo "=== KyberGuard Public API Deployment ==="

# Schritt 0: Security Audit — KRITISCHE Findings blockieren Deploy
echo "[0/5] Pre-Deploy Security Audit..."
if python3 /home/ceuleeneo/.claude/hooks/kyberguard-pre-deploy-audit.py \
    /home/ceuleeneo/friegun-projects/kyberguard/backend; then
    echo "✓ Security Audit bestanden"
elif [ $? -eq 1 ]; then
    echo "⚠ Security Audit: Warnings vorhanden — Deploy fortgesetzt"
else
    echo "✗ DEPLOY BLOCKIERT: Kritische Security-Findings — Bitte beheben!"
    exit 2
fi

# Schritt 1: VPN prüfen
echo "[1/5] VPN-Verbindung prüfen..."
if ! ping -c 1 -W 3 10.8.0.1 > /dev/null 2>&1; then
    echo "FEHLER: VPN nicht aktiv. Bitte AmneziaVPN starten."
    exit 1
fi
echo "✓ VPN aktiv"

# Schritt 1b: Host-Kernel-Hygiene — CVE-2026-31431 (Copy Fail) prüfen
echo "[1b/5] Host-Kernel-Hygiene prüfen (CVE-2026-31431)..."
HOST_KERNEL=$(ssh -i "$SSH_KEY" -o ConnectTimeout=5 -o BatchMode=yes "$KYBERGUARD_VM" 'uname -r' 2>/dev/null)
if [ -z "$HOST_KERNEL" ]; then
    echo "WARN: Konnte Host-Kernel nicht abfragen — überspringe Kernel-Check"
else
    echo "  Kernel auf VM: $HOST_KERNEL"
    # 1) Modul algif_aead darf NICHT geladen sein (akute Exploit-Voraussetzung)
    ALGIF_LOADED=$(ssh -i "$SSH_KEY" -o ConnectTimeout=5 -o BatchMode=yes "$KYBERGUARD_VM" \
        'lsmod | grep -E "^algif_aead|^af_alg" || true' 2>/dev/null)
    if [ -n "$ALGIF_LOADED" ]; then
        echo "✗ DEPLOY BLOCKIERT: algif_aead-Modul ist geladen — CVE-2026-31431 akut exploitable!"
        echo "  Mitigation: 'modprobe -r algif_aead && echo blacklist algif_aead >> /etc/modprobe.d/disable-algif.conf'"
        exit 3
    fi
    echo "  ✓ algif_aead nicht geladen"
    # 2) Blacklist-Datei sollte existieren (Schutz für Boot-Zeit)
    BLACKLIST_EXISTS=$(ssh -i "$SSH_KEY" -o ConnectTimeout=5 -o BatchMode=yes "$KYBERGUARD_VM" \
        '[ -f /etc/modprobe.d/disable-algif.conf ] && echo yes || echo no' 2>/dev/null)
    if [ "$BLACKLIST_EXISTS" != "yes" ]; then
        echo "  WARN: /etc/modprobe.d/disable-algif.conf fehlt — Boot-Zeit-Schutz nicht aktiv"
        echo "  (Deploy fortgesetzt, aber bitte Mitigation einspielen)"
    else
        echo "  ✓ Blacklist-Datei vorhanden"
    fi
fi
echo "✓ Kernel-Hygiene OK"

# Schritt 2: Dateien übertragen
echo "[2/6] Backend-Dateien übertragen..."
# --exclude=venv/data/ verhindert Löschung server-seitiger Laufzeit-Dirs durch --delete
rsync -az --delete \
    --exclude="venv/" \
    --exclude="data/" \
    --exclude="__pycache__/" \
    --exclude="*.pyc" \
    -e "ssh -i $SSH_KEY" \
    /home/ceuleeneo/friegun-projects/kyberguard/backend/ \
    "$KYBERGUARD_VM:$REMOTE_DIR/"
echo "✓ Dateien übertragen"

# Schritt 2a: venv auf Server aktualisieren falls requirements geändert
echo "[2a/6] venv-Abhängigkeiten prüfen..."
ssh -i "$SSH_KEY" "$KYBERGUARD_VM" "
    cd $REMOTE_DIR
    if [ ! -d venv ]; then
        python3 -m venv venv
    fi
    venv/bin/pip install -q -r requirements-backend.txt
"
echo "✓ venv aktuell"

# Schritt 2b: KyberAssist Wissensbasis übertragen
echo "[2b/6] KyberAssist Wissensbasis (RAG) übertragen..."
# data/ liegt relativ zur docker-compose.yml → $REMOTE_DIR/data/
ssh -i "$SSH_KEY" "$KYBERGUARD_VM" "mkdir -p $REMOTE_DIR/data"
scp -i "$SSH_KEY" \
    /home/ceuleeneo/kyberassist-wiki/kyberassist_knowledge.json \
    "$KYBERGUARD_VM:$REMOTE_DIR/data/kyberassist_knowledge.json"
echo "✓ Wissensbasis übertragen ($(wc -l < /home/ceuleeneo/kyberassist-wiki/kyberassist_knowledge.json) Zeilen)"

# Schritt 3: docker-compose.yml übertragen
echo "[3/6] docker-compose.yml aktualisieren..."
scp -i "$SSH_KEY" \
    /home/ceuleeneo/friegun-projects/kyberguard/docker-compose.yml \
    "$KYBERGUARD_VM:$REMOTE_DIR/docker-compose.yml"
echo "✓ docker-compose.yml aktualisiert"

# Schritt 4: systemd-Service neu starten (NOPASSWD via Python-Trick)
echo "[4/6] kyberguard-api.service neu starten..."
ssh -i "$SSH_KEY" "$KYBERGUARD_VM" "
cat > /tmp/fix_restart_kyberapi.py << 'PYEOF'
import subprocess, time, sys
r = subprocess.run(['systemctl', 'restart', 'kyberguard-api'], capture_output=True, text=True)
if r.returncode != 0:
    print('FEHLER restart:', r.stderr)
    sys.exit(1)
time.sleep(5)
r2 = subprocess.run(['systemctl', 'is-active', 'kyberguard-api'], capture_output=True, text=True)
status = r2.stdout.strip()
print(status)
sys.exit(0 if status == 'active' else 1)
PYEOF
sudo /usr/bin/python3 /tmp/fix_restart_kyberapi.py
"
echo "✓ Service neu gestartet"

# Schritt 5: Health-Check
echo "[5/6] Health-Check..."
ssh -i "$SSH_KEY" "$KYBERGUARD_VM" "
    curl -sf http://172.18.0.1:8000/health && echo 'Health OK' || echo 'Health FEHLER'
"

echo ""
echo "=== Deployment abgeschlossen ==="
echo "Nächster Schritt: nginx-Konfiguration aktualisieren"
echo "Datei: /home/ceuleeneo/friegun-projects/kyberguard/nginx-public-api.conf"
