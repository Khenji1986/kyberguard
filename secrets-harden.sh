#!/bin/bash
# SecureBot AI - Secrets Hardening Script
# Fuehre dieses Script auf der GCP VM aus: bash secrets-harden.sh
# Ein Produkt von Frieguen fuer Lee.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

BOT_DIR="/home/ceuleeneo/friegun-projects/security-bot"
ENV_FILE="${BOT_DIR}/.env"
BACKUP_DIR="${BOT_DIR}/backups"

echo "============================================"
echo "  SecureBot AI - Secrets Hardening v1.0"
echo "============================================"
echo ""

# 1. .env Permissions
echo -e "${YELLOW}[1/5] .env Permissions...${NC}"
if [ -f "$ENV_FILE" ]; then
    chmod 600 "$ENV_FILE"
    chown "$(whoami):$(whoami)" "$ENV_FILE"
    echo -e "${GREEN}  .env: 600 (nur Owner lesen/schreiben)${NC}"
else
    echo -e "${RED}  FEHLER: .env nicht gefunden!${NC}"
    exit 1
fi

# 2. Backup-Verzeichnis sichern
echo -e "${YELLOW}[2/5] Backup-Verzeichnis...${NC}"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
echo -e "${GREEN}  backups/: 700 (nur Owner)${NC}"

# 3. Data-Verzeichnis sichern
echo -e "${YELLOW}[3/5] Data-Verzeichnis...${NC}"
mkdir -p "${BOT_DIR}/data"
chmod 700 "${BOT_DIR}/data"
echo -e "${GREEN}  data/: 700 (nur Owner)${NC}"

# 4. Encrypted .env Backup
echo -e "${YELLOW}[4/5] Verschluesseltes .env Backup...${NC}"
if command -v gpg &> /dev/null; then
    ENCRYPTED="${BACKUP_DIR}/.env.gpg"
    gpg --batch --yes --symmetric --cipher-algo AES256 \
        --passphrase-fd 0 -o "$ENCRYPTED" "$ENV_FILE" <<< "$(read -rsp 'GPG-Passwort fuer .env Backup: ' pw; echo "$pw")"
    chmod 600 "$ENCRYPTED"
    echo ""
    echo -e "${GREEN}  Verschluesseltes Backup: ${ENCRYPTED}${NC}"
    echo -e "  Wiederherstellen: gpg -d ${ENCRYPTED} > .env"
else
    echo -e "${YELLOW}  GPG nicht installiert. Installiere mit: sudo apt install gnupg${NC}"
    echo -e "${YELLOW}  Ueberspringe verschluesseltes Backup.${NC}"
fi

# 5. Git-Check: Keine Secrets in History
echo -e "${YELLOW}[5/5] Git-History Check...${NC}"
if command -v git &> /dev/null && [ -d "${BOT_DIR}/.git" ]; then
    LEAKED=0
    for pattern in "TELEGRAM_TOKEN=" "ANTHROPIC_API_KEY=" "STRIPE_API_KEY=" "sk-ant-" "sk_live_" "sk_test_"; do
        if git -C "$BOT_DIR" log --all -p 2>/dev/null | grep -q "$pattern"; then
            echo -e "${RED}  WARNUNG: '${pattern}' in Git-History gefunden!${NC}"
            LEAKED=1
        fi
    done
    if [ "$LEAKED" -eq 0 ]; then
        echo -e "${GREEN}  Keine Secrets in Git-History gefunden.${NC}"
    else
        echo -e "${RED}  Empfehlung: git filter-branch oder BFG Repo Cleaner nutzen!${NC}"
    fi
else
    echo -e "${YELLOW}  Kein Git-Repository oder git nicht installiert.${NC}"
fi

echo ""
echo "============================================"
echo -e "${GREEN}Hardening abgeschlossen!${NC}"
echo ""
echo "Zusammenfassung:"
ls -la "$ENV_FILE" 2>/dev/null || true
echo ""
echo "Naechste Schritte:"
echo "  1. Starte Bot + Guardian: docker-compose up -d --build"
echo "  2. Pruefe Status: docker-compose ps"
echo "  3. Teste /soc im Bot"
echo "============================================"
