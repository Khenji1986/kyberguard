# KyberAssist Landing-Page Workflow — Setup-Anleitung

**Stand:** 18.04.2026
**Ziel:** n8n-Workflow fuer anonyme Landing-Page-Besucher (kein Login, rate-limited via nginx)

---

## Voraussetzungen

- VPN (AmneziaVPN) aktiv — frieguen-hub erreichbar unter 10.8.0.20
- n8n erreichbar: http://10.8.0.20:5678
- Anthropic API Key vorhanden (console.anthropic.com)

---

## Schritt 1: n8n oeffnen

Browser: `http://10.8.0.20:5678`

VPN muss aktiv sein (awg0). Falls nicht erreichbar:
```bash
# WSL2 — VPN-Status pruefen
ip route show | grep 10.8.0
```

---

## Schritt 2: Workflow importieren

1. n8n oeffnen → linkes Menue → **Workflows**
2. Oben rechts: **Import** (oder: Drei-Punkte-Menue → "Import from file")
3. Datei auswaehlen:
   `/home/ceuleeneo/friegun-projects/kyberguard/n8n-workflows/kyberassist-landing-workflow.json`
4. Workflow wird als **"KyberAssist Landing Page"** importiert
5. Noch NICHT aktivieren — erst Credential anlegen (Schritt 3)

---

## Schritt 3: Anthropic Credential anlegen

1. Linkes Menue → **Credentials** → **New Credential**
2. Suchen: `HTTP Header Auth`
3. Felder ausfuellen:
   - **Name:** `Anthropic API Key`
   - **Name** (Header-Feld): `x-api-key`
   - **Value:** `sk-ant-xxxxxxxxxxxxx` (dein Anthropic API Key)
4. **Save** klicken

Danach im Workflow alle 6 "Anthropic: *"-Nodes aufmachen und sicherstellen,
dass das Credential "Anthropic API Key" ausgewaehlt ist.

### Hinweis zu den HTTP-Nodes

Die 6 Anthropic-Nodes nutzen `HTTP Header Auth`. Der `x-api-key`-Header
wird automatisch gesetzt. Zusaetzlich ist der Header `anthropic-version: 2023-06-01`
hardcoded im Workflow — das ist korrekt und muss nicht geaendert werden.

---

## Schritt 4: Webhook-URL notieren

1. Workflow oeffnen → auf den **Webhook**-Node klicken
2. Unter "Webhook URLs" steht die aktive URL:
   ```
   http://10.8.0.20:5678/webhook/landing-kyberassist
   ```
3. Fuer die Landing Page wird die URL nach aussen exponiert via nginx-Proxy:
   ```
   https://kyberguard.de/n8n/webhook/landing-kyberassist
   ```

---

## Schritt 5: Workflow aktivieren

1. Oben rechts den **Toggle** auf "Active" stellen
2. Status wechselt auf gruen — Webhook ist jetzt aktiv

---

## Schritt 6: Test-Request senden

Vom lokalen WSL2 (VPN muss aktiv sein):

```bash
curl -s -X POST http://10.8.0.20:5678/webhook/landing-kyberassist \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "550e8400-e29b-41d4-a716-446655440000",
    "message": "Was ist NIS2 und bin ich als kleines Unternehmen betroffen?"
  }' | python3 -m json.tool
```

Erwartete Antwort (Beispiel):
```json
{
  "message": "NIS2 ist eine EU-Richtlinie...",
  "category": "NIS2_QUESTION",
  "cta": {
    "text": "Kostenlos testen",
    "url": "https://kyberguard.de/register"
  }
}
```

Test fuer ungueltige Eingabe:
```bash
curl -s -X POST http://10.8.0.20:5678/webhook/landing-kyberassist \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "invalid-uuid",
    "message": "Test"
  }'
# Erwartet: HTTP 400 mit error-Feld
```

---

## Nginx-Proxy-Konfiguration (kyberguard-vm)

Der Workflow laeuft auf frieguen-hub (10.8.0.20). Die Landing Page ist auf
kyberguard.de. Der nginx auf kyberguard-vm muss als Reverse-Proxy dienen.

### Rate-Limiting zuerst definieren

In `/etc/nginx/nginx.conf` (im `http {}`-Block, AUSSERHALB von `server {}`):

```nginx
# Rate-Limiting fuer KyberAssist Landing (anonyme Nutzer)
limit_req_zone $binary_remote_addr zone=kyberassist_landing:10m rate=5r/m;
```

5 Requests pro Minute pro IP — ausreichend fuer echte Nutzer, stoppt Bots.

### Proxy-Block in der kyberguard-vhost-Konfiguration

In `/etc/nginx/sites-available/kyberguard` (oder kyberguard.conf),
im `server`-Block fuer HTTPS (Port 443):

```nginx
# KyberAssist Landing Page Proxy → frieguen-hub n8n
location /n8n/webhook/landing-kyberassist {

    # Rate-Limiting anwenden
    limit_req zone=kyberassist_landing burst=3 nodelay;
    limit_req_status 429;

    # Nur POST erlauben
    limit_except POST {
        deny all;
    }

    # Body-Groesse limitieren (max 2KB reicht fuer 500 Zeichen)
    client_max_body_size 2k;

    # CORS — nur von kyberguard.de
    add_header 'Access-Control-Allow-Origin' 'https://kyberguard.de' always;
    add_header 'Access-Control-Allow-Methods' 'POST, OPTIONS' always;
    add_header 'Access-Control-Allow-Headers' 'Content-Type' always;

    if ($request_method = OPTIONS) {
        return 204;
    }

    # Proxy an frieguen-hub via VPN
    proxy_pass http://10.8.0.20:5678/webhook/landing-kyberassist;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # Timeout fuer Anthropic API (max 20s)
    proxy_read_timeout 20s;
    proxy_connect_timeout 5s;
    proxy_send_timeout 10s;
}
```

### Nginx neu laden

```bash
# Syntax pruefen
nginx -t

# Neu laden (kein Downtime)
systemctl reload nginx
```

---

## Frontend-Integration

### session_id generieren (localStorage)

```javascript
// utils/session.js — in die Landing Page einbinden
function generateUUIDv4() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

export function getOrCreateSessionId() {
  let sessionId = localStorage.getItem('kyberassist_session');
  if (!sessionId) {
    sessionId = generateUUIDv4();
    localStorage.setItem('kyberassist_session', sessionId);
  }
  return sessionId;
}
```

### Fetch-Call fuer die Landing Page

```javascript
// KyberAssist Chat-Funktion fuer die Landing Page
async function sendKyberAssistMessage(userMessage) {
  const ENDPOINT = 'https://kyberguard.de/n8n/webhook/landing-kyberassist';

  try {
    const response = await fetch(ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        session_id: getOrCreateSessionId(),
        message: userMessage.slice(0, 500) // Sicherheitshalber client-seitig kuerzen
      })
    });

    if (response.status === 429) {
      return {
        message: 'Bitte warten Sie einen Moment, bevor Sie die naechste Frage stellen.',
        category: 'RATE_LIMITED',
        cta: { text: 'Kostenlos testen', url: 'https://kyberguard.de/register' }
      };
    }

    if (!response.ok) {
      return {
        message: 'Ich bin gerade nicht verfuegbar. Bitte versuchen Sie es spaeter.',
        category: 'ERROR',
        cta: { text: 'Kostenlos testen', url: 'https://kyberguard.de/register' }
      };
    }

    return await response.json();

  } catch (error) {
    console.error('KyberAssist Fehler:', error);
    return {
      message: 'Verbindungsfehler. Bitte pruefen Sie Ihre Internetverbindung.',
      category: 'ERROR',
      cta: { text: 'Kostenlos testen', url: 'https://kyberguard.de/register' }
    };
  }
}
```

### Svelte-Komponente (Beispiel fuer kyberguard-landing)

```svelte
<!-- src/lib/components/KyberAssistLanding.svelte -->
<script>
  import { getOrCreateSessionId } from '$lib/utils/session.js';

  let message = '';
  let response = null;
  let loading = false;
  let error = null;

  async function handleSubmit() {
    if (!message.trim() || loading) return;

    loading = true;
    error = null;

    try {
      const res = await fetch('/n8n/webhook/landing-kyberassist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: getOrCreateSessionId(),
          message: message.trim()
        })
      });

      if (res.status === 429) {
        error = 'Bitte warten Sie kurz und stellen Sie dann Ihre naechste Frage.';
        return;
      }

      response = await res.json();
      message = '';
    } catch (e) {
      error = 'Verbindungsfehler. Bitte versuchen Sie es erneut.';
    } finally {
      loading = false;
    }
  }
</script>

<div class="kyberassist-widget">
  <form on:submit|preventDefault={handleSubmit}>
    <input
      bind:value={message}
      placeholder="Fragen Sie KyberAssist..."
      maxlength="500"
      disabled={loading}
    />
    <button type="submit" disabled={loading || !message.trim()}>
      {loading ? 'Antwort wird geladen...' : 'Fragen'}
    </button>
  </form>

  {#if error}
    <p class="error">{error}</p>
  {/if}

  {#if response}
    <div class="response">
      <p>{response.message}</p>
      <a href={response.cta.url} class="cta-button">{response.cta.text}</a>
    </div>
  {/if}
</div>
```

---

## Sicherheits-Checkliste

- [x] Input max 500 Zeichen (Code Node Validierung)
- [x] HTML-Tags aus Input entfernt (Regex-Strip)
- [x] SQL-Keywords entfernt (Basisschutz)
- [x] UUID-Validierung fuer session_id (Regex)
- [x] Steuerzeichen entfernt
- [x] Anthropic API Key in n8n Credential (nicht hardcoded)
- [x] Fehler-Fallback ohne Stack-Trace (try/catch in Response-Nodes)
- [x] Rate-Limiting via nginx (5 req/min pro IP)
- [x] Nur POST erlaubt (nginx: limit_except)
- [x] Body-Groesse begrenzt (nginx: client_max_body_size 2k)
- [x] CORS auf kyberguard.de beschraenkt
- [x] session_id nur als Logging-Referenz (nicht an Anthropic gesendet)

---

## Troubleshooting

| Problem | Loesung |
|---------|---------|
| Workflow reagiert nicht | VPN aktiv? `ip route | grep 10.8.0` |
| 401 von Anthropic | Credential pruefen: Name muss `x-api-key` sein |
| 429 Rate-Limit | Nginx-Config: `limit_req_zone` korrekt gesetzt? |
| Leere Antwort | n8n Logs pruefen: http://10.8.0.20:5678 → Executions |
| CORS-Fehler | nginx Access-Control-Allow-Origin korrekt? |
| Anthropic 404 | Model-Name pruefen: `claude-haiku-4-5-20251001` |

---

## Modell-Kosten (Orientierung)

- **Model:** `claude-haiku-4-5-20251001`
- Input: ~$0.80 / 1M Tokens
- Output: ~$4.00 / 1M Tokens
- Pro Request ca. 400-600 Input + 200-300 Output Tokens
- Kosten: ~$0.0016 pro Request
- Bei 1.000 Anfragen/Tag: ca. $1.60/Tag
