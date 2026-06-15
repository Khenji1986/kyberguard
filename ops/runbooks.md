# KyberGuard Infra-Runbooks
## Mia (SOC-Operations) | 18.05.2026
## Fuer: kyberguard-vm + frieguen-hub

---

## Szenario 1 -- kyberguard-vm nicht erreichbar (kein SSH)

**Symptom:** SSH-Verbindung schlaegt fehl, kyberguard.de nicht erreichbar.

```bash
# Schritt 1: Hetzner Cloud Console oeffnen
# console.hetzner.cloud -> kyberguard-vm -> Power-Status pruefen

# Schritt 2: VM gestoppt?
# -> "Power On" in der Console

# Schritt 3: VM laeuft, SSH trotzdem tot?
# -> Console-Login nutzen (Hetzner Web-Console)

# Schritt 4: Nach Console-Login -- Logs pruefen
sudo journalctl -xe --since "10 minutes ago" | tail -50

# Schritt 5: Docker-Stack pruefen
docker ps -a

# Schritt 6: Wenn alle Container "Up" -- nginx reload
sudo systemctl reload nginx

# Schritt 7: Wenn Container "Exit"
cd /home/ceuleeneo
docker compose up -d

# Schritt 8: Smoke-Test
curl -s -o /dev/null -w "%{http_code}" https://kyberguard.de
# Erwartet: 200 oder 301
```

---

## Szenario 2 -- 502 Bad Gateway (FastAPI antwortet nicht)

**Symptom:** kyberguard.de erreichbar, Dashboard wirft 502.

```bash
# Schritt 1: SSH auf kyberguard-vm
# Schritt 2: Container-Status pruefen
docker ps -a | grep -E "kyberguard|fastapi|api"

# Schritt 3: Wenn Container "Exit" -- Logs lesen
docker logs kyberguard-api --tail 50

# Schritt 4: Container neu starten
cd /home/ceuleeneo
docker compose restart kyberguard-api
sleep 10

# Schritt 5: Health-Check
curl -s http://172.18.0.1:8000/health
# Erwartet: {"status":"ok"}

# Schritt 6: Wenn Datenbank-Fehler in Logs
docker logs postgres-kyberguard --tail 20

# Schritt 7: Wenn Postgres "Exit" -- Neu starten
docker compose restart postgres-kyberguard
sleep 15
docker compose restart kyberguard-api
```

---

## Szenario 3 -- VPN-Verbindung zu frieguen-hub tot

**Symptom:** KyberAssist antwortet nicht, SOAR/n8n offline, awg0 down.

```bash
# Schritt 1: SSH direkt auf frieguen-hub (nicht ueber VPN)
ssh ceuleeneo@162.55.217.13

# Schritt 2: VPN-Status
sudo systemctl status awg-quick@awg0

# Schritt 3: Wenn "inactive/dead" -- Neustart
sudo systemctl start awg-quick@awg0
sleep 5
sudo systemctl status awg-quick@awg0

# Schritt 4: Wenn Kernel-Modul fehlt ("Module not found"):
# -> DKMS-Fix ausfuehren: bash /home/ceuleeneo/friegun-projects/kyberguard/ops/amneziawg-dkms-fix.sh
# -> ODER: Hetzner Rescue-Modus + GRUB auf 6.8.0-90-generic (alter Notfall-Weg)

# Schritt 5: Nach VPN-Start -- Ping-Test
ping -c 3 10.8.0.20   # frieguen-hub via VPN
ping -c 3 10.8.0.1    # kyberguard-vm via VPN

# Schritt 6: Wenn VPN oben, Dienste auf frieguen-hub pruefen
docker ps | grep -E "n8n|wazuh|soar"
```

---

## Szenario 4 -- TLS-Zertifikat laeuft ab (Frueherkennung)

**Symptom:** Browser warnt vor abgelaufenem Cert. Naechstes Ablaufdatum: 12.08.2026

```bash
# Schritt 1: Ablaufdatum pruefen
sudo certbot certificates

# Schritt 2: Wenn < 30 Tage -- Erneuern
sudo certbot renew --force-renewal

# Schritt 3: nginx neu laden
sudo systemctl reload nginx

# Schritt 4: Automatische Erneuerung testen
sudo certbot renew --dry-run
# Erwartung: "No renewals were attempted" oder "Simulating renewal"

# Schritt 5: Wenn certbot fehlschlaegt -- Port 80 pruefen
sudo ufw status | grep 80
# Falls blockiert: sudo ufw allow 80/tcp (temporaer, nur fuer Renewal)
# Nach erfolgreichem Renewal: sudo ufw delete allow 80/tcp
```

---

## Szenario 5 -- live_data_worker abgestuerzt (HYDRA-EYE)

**Symptom:** Landing-Page zeigt "Daten nicht verfuegbar" bei allen Live-Kennzahlen.

```bash
# Schritt 1: Worker-Status
sudo systemctl status kyberguard-live-worker

# Schritt 2: Logs der letzten Stunde
sudo journalctl -u kyberguard-live-worker --since "1 hour ago" | tail -40

# Schritt 3: Neustart
sudo systemctl restart kyberguard-live-worker
sleep 10
sudo systemctl status kyberguard-live-worker

# Schritt 4: Wenn Redis-Fehler -- Redis pruefen
sudo systemctl status redis-server
# Wenn "inactive": sudo systemctl restart redis-server
# Dann Worker neu: sudo systemctl restart kyberguard-live-worker

# Schritt 5: Wenn Quelle ausgefallen (CISA, ransomware.live)
# -> KEIN Handlungsbedarf. Honest-Fail-Pattern zeigt "Daten nicht verfuegbar"
# -> Nicht mit Fake-Zahlen ersetzen (Doktrin feedback_keine_fake_kennzahlen)

# Schritt 6: Redis-Daten pruefen
redis-cli -n 3 keys "hydra:live:*"
redis-cli -n 3 get "hydra:live:crowdsec_blocks_total"
```

---

## Notfall-Kontakte

| System | Kontakt/URL |
|---|---|
| Hetzner Cloud Console | console.hetzner.cloud |
| kyberguard-vm direkt | ssh ceuleeneo@kyberguard-vm (via VPN) |
| frieguen-hub direkt | ssh ceuleeneo@162.55.217.13 |
| DNS-Verwaltung | console.hetzner.cloud (nicht dns.hetzner.com!) |
| Mollie Dashboard | app.mollie.com |

## Kritische Dateipfade

| Datei | Zweck |
|---|---|
| /home/ceuleeneo/.kyberguard-api.env | Alle Env-Keys (NVD, Wazuh, etc.) |
| /home/ceuleeneo/docker-compose.yml | Haupt-Stack |
| /home/ceuleeneo/kyberguard-web/backend/live_data_worker.py | HYDRA-EYE Worker |
| /etc/nginx/sites-enabled/ | nginx-Vhosts |
| /etc/systemd/system/kyberguard-live-worker.service | Worker-Systemd |
