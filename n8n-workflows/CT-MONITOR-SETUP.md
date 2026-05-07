# KyberGuard CT-Log Monitor — Setup

> **Zweck:** stündlich neue Subdomains aus Certificate-Transparency-Logs (crt.sh) für überwachte Apex-Domains erkennen und Lee per E-Mail alarmieren.
> **Wozu:** Schatten-IT- + Phishing-Detection. Wenn jemand `phishing-kyberguard.de` registriert und ein Cert holt, sehen wir es innerhalb 1h.
> **Stand:** 07.05.2026 — Workflow-JSON liegt vor, Domain-Liste kommt aus KyberGuard-DB (Tabelle `verified_domains`).

## Architektur
```
Cron 1h → ASM-Targets (DB) → Domain-Extract → crt.sh Query → Diff vs Last Run
                                                                    │
                                                                    ▼
                                                          Neue Subdomains? ── Ja ──► E-Mail an Lee
                                                                    │
                                                                    └── Nein ──► silent
```

- **Quelle:** `GET /internal/asm/targets` (Bearer-Auth) auf KyberGuard-API liefert alle `verified=true`-Einträge aus `verified_domains` aktiver User.
- **Persistenz Diff:** n8n-eigenes `workflowStaticData` — kein extra DB-Schema nötig.

## Setup auf frieguen-hub

### 1. n8n-Web-UI öffnen
- VPN aktiv (awg0)
- https://kyberguard.de/n8n/ aufrufen ODER http://10.8.0.20:5678 direkt
- Login

### 2. Workflow importieren
- Sidebar → **+ Add workflow** → Menü **⋯** → **Import from file**
- Datei: `kyberguard/n8n-workflows/ct-monitor-workflow.json`

### 3. SMTP-Credentials anlegen (falls noch nicht vorhanden)
- Sidebar → **Credentials** → **+ New** → "SMTP"
- Name: `mailbox.org SMTP`
- Host: `smtp.mailbox.org`, Port: 465 (SSL/TLS) oder 587 (STARTTLS)
- User: `alert@kyberguard.de`, Passwort: aus `~/.kyberguard-api.env` (`SMTP_PASS`)
- Sicher (TLS) aktivieren

### 4. ASM-Internal-Bearer-Credential anlegen (NEU — Phase 4)
- Sidebar → **Credentials** → **+ New** → **Header Auth**
- Name: `ASM Internal Bearer`
- **Header Name:** `Authorization`
- **Header Value:** `Bearer <ASM_INTERNAL_TOKEN>` — Token aus `/home/ceuleeneo/.kyberguard-api.env` (Variable `ASM_INTERNAL_TOKEN`)
- **WICHTIG:** Wert muss `Bearer ` (mit Space) plus Token enthalten

### 5. Credentials den Knoten zuordnen
- Knoten **"ASM-Targets aus DB"** öffnen → "Credential" → `ASM Internal Bearer` wählen
- Knoten **"E-Mail an Lee"** öffnen → "Credential" → `mailbox.org SMTP` wählen

### 6. URL prüfen / anpassen
Der Workflow nutzt per Default `http://10.8.0.1:8000/internal/asm/targets`.
- Wenn n8n-Container nicht direkt aufs VPN-Interface der KyberGuard-VM zugreifen kann, IP/Port anpassen (z.B. interner Docker-Hostname).
- Alternativ: nginx auf KyberGuard so konfigurieren, dass `/internal/asm/targets` vom VPN-Netz weitergeleitet wird (aktuell nicht der Fall).

### 7. Aktivieren
- Workflow-Schalter oben rechts auf **Active** stellen
- Erste Execution wartet bis volle Stunde, oder manuell **Execute Workflow** klicken

### 8. Test
- Manueller Run muss im **ASM-Targets aus DB**-Knoten 200 + JSON `{"targets":[{"domain":"kyberguard.de",...}], "count":1}` zurückgeben
- Bei 403: Bearer-Token oder n8n-Quell-IP nicht in Whitelist (`10.8.0.0/8` oder `172.18.0.0/16`)
- Bei 404: Endpoint nicht erreichbar — URL prüfen

## Domain hinzufügen / entfernen (Phase 4 Self-Service folgt)
Bis das Self-Service-UI live ist, geht's direkt via SQL auf der KyberGuard-VM:
```sql
-- Neue verifizierte Domain für User-ID 5 hinzufügen:
INSERT INTO verified_domains (user_id, domain, token, verified, verified_at)
VALUES (5, 'neue-domain.de', 'manual-seed-2026-05-07', TRUE, NOW())
ON CONFLICT (user_id, domain) DO UPDATE SET verified=TRUE, verified_at=NOW();

-- Entfernen:
DELETE FROM verified_domains WHERE user_id=5 AND domain='alte-domain.de';
```

Nach Insert wird die Domain beim nächsten Cron-Run automatisch geprüft.

## Sicherheit / DSGVO
- crt.sh ist Public-Service, wir senden nur Domain-Namen (kein PII).
- ASM-Bearer-Token rotieren, falls n8n-Backup oder Workflow-Export geleakt wird (`ASM_INTERNAL_TOKEN` in env).
- E-Mail-Adresse `ceuleeneo@gmail.com` als Empfänger — bewusst Lees private Adresse, nicht Kundendaten.
- workflowStaticData liegt verschlüsselt in n8n-DB auf frieguen-hub.

## Notfall / Reset
- Bei Fehl-Alarmen oder zu vielen E-Mails: Workflow auf **Inactive** schalten.
- Static-Data zurücksetzen: Workflow → Settings → "Reset Static Data" (oder neu importieren).

## Erweiterungen (Phase 5+)
- **Self-Service-UI:** Dashboard-Modal "Domain für CT-Monitor hinzufügen" + Owner-Verify-Flow → automatischer Insert in `verified_domains`
- **Per-User-Email:** statt Lees Privat-Mail → die Email aus `users.email` der jeweiligen verifizierten Domain (steht schon im API-Response als `email`-Feld)
- **Severity-Stufen:** Phishing-Lookalike-Heuristik aus public.py wiederverwenden um neue Subdomains zu klassifizieren
- **Slack/Discord** falls Friegün interne Channels einführt
