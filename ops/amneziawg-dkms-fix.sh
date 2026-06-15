#!/bin/bash
# AmneizaWG DKMS Fix -- Kernel-Update-Resilienz
# Nero | 18.05.2026
# Ziel: VPN-Modul ueberlebt Kernel-Updates ohne manuellen Rescue-Modus
# Ausfuehren NUR auf: frieguen-hub (162.55.217.13)
# VORAUSSETZUNG: Internetzugang, sudo-Rechte

set -e
echo "[$(date '+%Y-%m-%d %H:%M:%S')] AmneizaWG DKMS Fix gestartet"

# 1. Abhängigkeiten
echo "=== Abhaengigkeiten installieren ==="
sudo apt-get update -y
sudo apt-get install -y dkms build-essential linux-headers-$(uname -r) git

# 2. Repo klonen
echo "=== AmneizaWG Quellcode laden ==="
TMPDIR=$(mktemp -d)
cd "$TMPDIR"
git clone --depth 1 --branch v1.0.0 \
  https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git
cd amneziawg-linux-kernel-module

# 3. DKMS registrieren und bauen
echo "=== DKMS Build ==="
sudo dkms add .
sudo dkms build amneziawg/1.0.0
sudo dkms install amneziawg/1.0.0

# 4. Verifizieren
echo "=== Verifikation ==="
if modinfo amneziawg &>/dev/null; then
  echo "amneziawg Modul: OK"
else
  echo "FEHLER: Modul nicht gefunden"
  exit 1
fi

# 5. DKMS Status pruefen
dkms status amneziawg

# 6. VPN neu starten
echo "=== VPN Neustart ==="
sudo systemctl restart awg-quick@awg0
sleep 3
sudo systemctl status awg-quick@awg0 --no-pager

# 7. Ping-Test
echo "=== VPN Verbindungstest ==="
if ping -c 2 10.8.0.1 &>/dev/null; then
  echo "VPN: Verbindung OK (10.8.0.1 erreichbar)"
else
  echo "WARNUNG: Ping zu 10.8.0.1 fehlgeschlagen -- VPN-Tunnel pruefen"
fi

# 8. Aufraeumen
cd /
rm -rf "$TMPDIR"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] AmneizaWG DKMS Fix abgeschlossen"
echo "Naechster Kernel-Update: awg0 startet automatisch via DKMS"
