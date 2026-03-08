#!/usr/bin/env python3
"""
Unit-Tests für die 3 neuen Features von SecureBot AI
- Phishing-Checker (Feature 1)
- Security Audit (Feature 2)
- Incident Response (Feature 3)

Testet Kernfunktionen OHNE Telegram-Bot oder API-Keys.
"""

import re
import sys
import sqlite3
import tempfile
import os
from urllib.parse import urlparse

# ============================================================
# Code direkt aus bot.py übernommen (nur die reinen Funktionen)
# ============================================================

URL_PATTERN = re.compile(
    r'https?://[^\s<>"{}|\\^`\[\]]+|'
    r'(?:www\.)[^\s<>"{}|\\^`\[\]]+'
, re.IGNORECASE)

QUESTION_WORDS = ['wie', 'was ', 'warum', 'wann', 'wer ', 'welch', 'kann ', 'soll',
                  'how ', 'what ', 'why ', 'when ', 'who ', 'which', 'can ', 'should',
                  'erkläre', 'explain', 'hilf', 'help', 'zeig', 'show', 'ist es']

SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
                   '.click', '.link', '.work', '.date', '.racing', '.win', '.buzz']

BRAND_TYPOS = {
    'paypal': ['paypa1', 'paypai', 'paypal-', 'paypaI', 'peypal', 'payp4l'],
    'google': ['g00gle', 'googe', 'googie', 'google-login', 'g0ogle'],
    'microsoft': ['micros0ft', 'microsft', 'microsoft-', 'micr0soft'],
    'amazon': ['amaz0n', 'arnazon', 'amazom', 'amazon-'],
    'apple': ['app1e', 'appie', 'apple-id-', 'app1e-'],
    'facebook': ['faceb00k', 'facebok', 'facebook-'],
    'netflix': ['netf1ix', 'netfiix', 'netflix-'],
    'sparkasse': ['sparkasse-', 'sparkase', 'sparlasse'],
    'volksbank': ['volksbank-', 'volkebank'],
    'commerzbank': ['commerzbank-', 'comerzbank'],
    'postbank': ['postbank-', 'p0stbank'],
    'dhl': ['dhl-paket', 'dh1-', 'dhl-track'],
    'deutsche-bank': ['deutsche-bank-', 'deutschebank-'],
}

AUDIT_QUESTIONS = [
    {'id': 1, 'cat': 'Passwörter', 'q': 'Verwendest du einen Passwort-Manager?',
     'opts': [('Ja, für alle Konten', 3), ('Ja, teilweise', 2), ('Nein, merke mir Passwörter', 1), ('Überall das gleiche Passwort', 0)]},
    {'id': 2, 'cat': '2FA', 'q': 'Nutzt du Zwei-Faktor-Authentifizierung?',
     'opts': [('Ja, überall', 3), ('Nur bei wichtigen Konten', 2), ('Nur bei einem', 1), ('Was ist 2FA?', 0)]},
    {'id': 3, 'cat': 'Updates', 'q': 'Wie hältst du Software aktuell?',
     'opts': [('Auto-Updates überall', 3), ('Regelmäßig manuell', 2), ('Gelegentlich', 1), ('Selten bis nie', 0)]},
    {'id': 4, 'cat': 'Backup', 'q': 'Wie sicherst du wichtige Daten?',
     'opts': [('3-2-1 Backup-Regel', 3), ('Cloud-Backups', 2), ('Gelegentlich', 1), ('Gar nicht', 0)]},
    {'id': 5, 'cat': 'Netzwerk', 'q': 'Wie schützt du dein Heimnetzwerk?',
     'opts': [('Eigenes PW + Gastnetz + Firewall', 3), ('Router-PW geändert', 2), ('Standard-Einstellungen', 1), ('Weiß nicht', 0)]},
    {'id': 6, 'cat': 'E-Mail', 'q': 'Wie gehst du mit verdächtigen E-Mails um?',
     'opts': [('Prüfe Header & Links, melde', 3), ('Lösche sofort', 2), ('Schaue mir Inhalt an', 1), ('Öffne sie manchmal', 0)]},
    {'id': 7, 'cat': 'VPN', 'q': 'Nutzt du VPN in öffentlichen WLANs?',
     'opts': [('Immer', 3), ('Meistens', 2), ('Selten', 1), ('Was ist VPN?', 0)]},
    {'id': 8, 'cat': 'Datenschutz', 'q': 'Wie gehst du mit App-Berechtigungen um?',
     'opts': [('Prüfe und minimiere', 3), ('Schaue bei neuen Apps', 2), ('Akzeptiere meistens', 1), ('Denke nie darüber nach', 0)]},
    {'id': 9, 'cat': 'Verschlüsselung', 'q': 'Sind deine Geräte verschlüsselt?',
     'opts': [('Ja, alle', 3), ('Nur Smartphone', 2), ('Nicht sicher', 1), ('Nein', 0)]},
    {'id': 10, 'cat': 'Awareness', 'q': 'Wie informierst du dich über Security?',
     'opts': [('Aktiv: Blogs, BSI, Newsletter', 3), ('Gelegentlich Nachrichten', 2), ('Nur nach Vorfällen', 1), ('Gar nicht', 0)]},
]

INCIDENT_TYPES = [
    {'id': 'malware', 'emoji': '🦠', 'label': 'Malware/Ransomware'},
    {'id': 'phishing_hit', 'emoji': '🎣', 'label': 'Phishing-Link geklickt'},
    {'id': 'account_hack', 'emoji': '🔓', 'label': 'Account gehackt'},
    {'id': 'data_breach', 'emoji': '💾', 'label': 'Datenleck/Datenverlust'},
    {'id': 'ddos', 'emoji': '🌊', 'label': 'DDoS-Angriff'},
    {'id': 'other', 'emoji': '⚡', 'label': 'Sonstiger Vorfall'},
]

IR_PHASES = [
    {'id': 'identify', 'emoji': '🔍', 'label': 'Identifizieren', 'desc': 'Was genau ist passiert?'},
    {'id': 'contain', 'emoji': '🛑', 'label': 'Eindämmen', 'desc': 'Schaden begrenzen'},
    {'id': 'eradicate', 'emoji': '🧹', 'label': 'Beseitigen', 'desc': 'Ursache entfernen'},
    {'id': 'recover', 'emoji': '🔄', 'label': 'Wiederherstellen', 'desc': 'Normalbetrieb'},
    {'id': 'lessons', 'emoji': '📝', 'label': 'Lessons Learned', 'desc': 'Aus Vorfall lernen'},
]


def analyze_url_local(url: str) -> dict:
    score = 0
    findings = []
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
    except Exception:
        return {'score': 5, 'findings': ['URL konnte nicht geparst werden'], 'domain': url, 'url': url}

    if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
        score += 3
        findings.append("IP-Adresse statt Domain")
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 2
            findings.append(f"Verdächtige Top-Level-Domain ({tld})")
            break
    for brand, typos in BRAND_TYPOS.items():
        for typo in typos:
            if typo in domain:
                score += 4
                findings.append(f"Typosquatting: '{typo}' imitiert '{brand}'")
                break
    if domain.count('.') >= 4:
        score += 2
        findings.append(f"Ungewöhnlich viele Subdomains ({domain.count('.')})")
    sus_paths = ['login', 'signin', 'verify', 'confirm', 'secure', 'account', 'banking', 'password']
    for sus in sus_paths:
        if sus in path:
            score += 1
            findings.append(f"Verdächtiger Pfad: '{sus}'")
            break
    if len(url) > 100:
        score += 1
        findings.append("Ungewöhnlich lange URL")
    if url.count('%') > 3:
        score += 2
        findings.append("Starke URL-Kodierung (Verschleierung)")
    if '@' in parsed.netloc:
        score += 3
        findings.append("@-Zeichen in URL (User-Info-Angriff)")
    if parsed.scheme == 'http':
        score += 1
        findings.append("Kein HTTPS")
    if any(ord(c) > 127 for c in domain):
        score += 3
        findings.append("Internationalisierte Zeichen (Homograph-Angriff)")
    if parsed.port and parsed.port not in [80, 443]:
        score += 1
        findings.append(f"Nicht-Standard Port: {parsed.port}")
    return {'score': min(score, 10), 'findings': findings, 'domain': domain, 'url': url}


def analyze_text_for_phishing(text: str) -> dict:
    score = 0
    findings = []
    text_lower = text.lower()
    urgency = ['sofort', 'dringend', 'innerhalb von 24', 'immediately', 'urgent',
               'konto wird gesperrt', 'account suspended', 'letzte mahnung', 'letzte warnung']
    for u in urgency:
        if u in text_lower:
            score += 2
            findings.append(f"Dringlichkeits-Taktik: '{u}'")
            break
    cred_patterns = ['passwort', 'password', 'pin eingeben', 'tan', 'zugangsdaten',
                     'kreditkarte', 'bankdaten', 'verifizieren', 'bestätigen sie ihre']
    for c in cred_patterns:
        if c in text_lower:
            score += 2
            findings.append(f"Abfrage sensibler Daten: '{c}'")
            break
    authority = ['polizei', 'finanzamt', 'staatsanwaltschaft', 'gericht', 'bundeskriminalamt', 'europol']
    for a in authority:
        if a in text_lower:
            score += 2
            findings.append(f"Autoritäts-Imitation: '{a}'")
            break
    return {'score': min(score, 10), 'findings': findings}


def calculate_audit_grade(total_score: int) -> tuple:
    pct = (total_score / 30) * 100
    if pct >= 90: return 'A', pct, 'Ausgezeichnet! Sehr gut aufgestellt.'
    if pct >= 75: return 'B', pct, 'Gut! Einige Verbesserungen möglich.'
    if pct >= 60: return 'C', pct, 'Befriedigend. Mehrere Lücken.'
    if pct >= 40: return 'D', pct, 'Mangelhaft. Dringender Handlungsbedarf!'
    return 'F', pct, 'Kritisch! Sofortiger Handlungsbedarf!'


# ============================================================
# TEST SUITE
# ============================================================

passed = 0
failed = 0

def test(name, condition, detail=""):
    global passed, failed
    if condition:
        print(f"  ✅ {name}")
        passed += 1
    else:
        print(f"  ❌ {name} {detail}")
        failed += 1


print("=" * 60)
print("SecureBot AI - Feature-Tests")
print("=" * 60)

# ---- TEST 1: URL_PATTERN Regex ----
print("\n🔗 TEST 1: URL_PATTERN Regex")

urls_should_match = [
    "https://google.com",
    "http://evil.tk/login",
    "https://paypa1.com/verify?id=123",
    "www.sparkasse-online.de",
    "https://192.168.1.1/admin",
    "https://sub.domain.example.com/path",
]

for url in urls_should_match:
    matches = URL_PATTERN.findall(url)
    test(f"Erkennt: {url}", len(matches) > 0, f"(keine Treffer)")

# URLs die NICHT matchen sollen (reiner Text ohne URL-Muster)
no_match = [
    "Hallo wie geht es dir",
    "Was ist eine Firewall?",
    "email@example.com",
]
for text in no_match:
    matches = URL_PATTERN.findall(text)
    test(f"Ignoriert: '{text[:40]}'", len(matches) == 0, f"(Falsch-Positiv: {matches})")

# URLs in gemischtem Text
mixed = "Schau mal https://evil.tk/login das sieht komisch aus"
matches = URL_PATTERN.findall(mixed)
test(f"Extrahiert URL aus Text", len(matches) == 1 and 'evil.tk' in matches[0])

# ---- TEST 2: Question-Word Filter ----
print("\n❓ TEST 2: Frage-Erkennung (QUESTION_WORDS)")

questions_with_urls = [
    "Wie sicher ist https://google.com als Passwort-Manager und sollte ich den nutzen?",
    "Was ist https://example.com für eine Seite und kann man der vertrauen?",
    "Erkläre mir bitte was genau https://owasp.org macht und wofür das nützlich ist",
    "Hilf mir bitte dabei https://github.com besser zu verstehen und einzusetzen",
]

for q in questions_with_urls:
    q_lower = q.lower()
    is_question = len(q) > 50 and any(w in q_lower for w in QUESTION_WORDS)
    test(f"Frage erkannt: '{q[:50]}...'", is_question)

# Phishing-Nachrichten sollen NICHT als Frage erkannt werden
phishing_msgs = [
    "https://paypa1.com/verify",
    "Klicke hier: https://evil.tk",
    "http://192.168.1.1/admin",
]
for p in phishing_msgs:
    p_lower = p.lower()
    is_question = len(p) > 50 and any(w in p_lower for w in QUESTION_WORDS)
    test(f"Nicht als Frage: '{p[:40]}'", not is_question)


# ---- TEST 3: Phishing URL-Analyse ----
print("\n🛡️ TEST 3: analyze_url_local()")

# Saubere URLs (niedrig)
clean_urls = [
    ("https://google.com", 0, 2),
    ("https://github.com/repo", 0, 2),
    ("https://www.bsi.bund.de", 0, 2),
]
for url, min_s, max_s in clean_urls:
    r = analyze_url_local(url)
    test(f"Sicher: {url} -> Score {r['score']}", min_s <= r['score'] <= max_s, f"(Erwartet {min_s}-{max_s})")

# Verdächtige URLs (mittel bis hoch)
suspicious_urls = [
    ("https://paypa1.com/login", 4, 10, "Typosquatting + Login"),
    ("http://192.168.1.1/verify", 3, 10, "IP + verdächtiger Pfad + kein HTTPS"),
    ("https://evil.tk", 2, 10, "Verdächtige TLD"),
    ("https://a.b.c.d.evil.com", 2, 10, "Viele Subdomains"),
    ("http://g00gle.com/signin", 4, 10, "Typosquatting Google"),
]
for url, min_s, max_s, reason in suspicious_urls:
    r = analyze_url_local(url)
    test(f"Verdächtig: {url} -> Score {r['score']} ({reason})", min_s <= r['score'] <= max_s, f"(Erwartet {min_s}-{max_s})")

# Spezielle Angriffsvektoren
r = analyze_url_local("https://evil.com@google.com/path")
test(f"@-Angriff erkannt -> Score {r['score']}", r['score'] >= 3)

r = analyze_url_local("http://evil.com:8080/login")
test(f"Non-standard Port erkannt -> Score {r['score']}", r['score'] >= 2)

# URL mit vielen %-Encodings
r = analyze_url_local("https://evil.com/%70%61%79%70%61%6C")
test(f"URL-Verschleierung erkannt -> Score {r['score']}", r['score'] >= 2)

# Score-Cap bei 10
r = analyze_url_local("http://paypa1.com.a.b.c.d.evil.tk/login/verify?x=%20%20%20%20")
test(f"Score gedeckelt bei max 10 -> Score {r['score']}", r['score'] == 10)


# ---- TEST 4: Text-Phishing-Analyse ----
print("\n📧 TEST 4: analyze_text_for_phishing()")

# Sauberer Text
r = analyze_text_for_phishing("Hallo, wie geht es dir?")
test("Sauberer Text -> Score 0", r['score'] == 0)

# Dringlichkeit
r = analyze_text_for_phishing("Ihr Konto wird gesperrt! Sofort verifizieren!")
test(f"Dringlichkeit erkannt -> Score {r['score']}", r['score'] >= 2)
test("Dringlichkeits-Finding vorhanden", any('Dringlichkeit' in f for f in r['findings']))

# Credentials
r = analyze_text_for_phishing("Bitte geben Sie Ihr Passwort ein um fortzufahren.")
test(f"Credential-Abfrage erkannt -> Score {r['score']}", r['score'] >= 2)

# Autoritäts-Imitation
r = analyze_text_for_phishing("Die Polizei bittet um Ihre Daten.")
test(f"Autoritäts-Imitation erkannt -> Score {r['score']}", r['score'] >= 2)

# Kombination: Dringlichkeit + Credentials + Autorität
r = analyze_text_for_phishing("DRINGEND: Die Polizei verlangt Ihr Passwort sofort!")
test(f"Dreifach-Treffer -> Score {r['score']}", r['score'] >= 6)

# Score max 10
r = analyze_text_for_phishing("Sofort Passwort eingeben! Polizei! Konto wird gesperrt! Finanzamt! Verifizieren!")
test(f"Text-Score gedeckelt bei max 10 -> Score {r['score']}", r['score'] <= 10)


# ---- TEST 5: Audit Grading ----
print("\n📋 TEST 5: calculate_audit_grade()")

grade_tests = [
    (30, 'A', 100.0),   # Perfekt
    (27, 'A', 90.0),    # 90%
    (25, 'B', None),     # ~83%
    (22, 'C', None),     # 73.3% < 75 -> C
    (20, 'C', None),     # ~67%
    (15, 'D', None),     # 50% < 60 -> D
    (12, 'D', None),     # 40%
    (5, 'F', None),      # ~17%
    (0, 'F', 0.0),       # 0%
]

for score, expected_grade, expected_pct in grade_tests:
    grade, pct, desc = calculate_audit_grade(score)
    grade_ok = grade == expected_grade
    pct_ok = expected_pct is None or abs(pct - expected_pct) < 0.1
    test(f"Score {score:2d}/30 -> {grade} ({pct:.0f}%)", grade_ok and pct_ok,
         f"(Erwartet {expected_grade}, bekam {grade} {pct:.1f}%)")

# Grenzwerte exakt testen
grade, pct, _ = calculate_audit_grade(27)  # 90.0% -> A
test("Grenze 90% -> A", grade == 'A')
grade, pct, _ = calculate_audit_grade(26)  # 86.7% -> B
test("Grenze 86.7% -> B", grade == 'B')
grade, pct, _ = calculate_audit_grade(22)  # 73.3% -> C
test("Grenze 73.3% -> C", grade == 'C')
grade, pct, _ = calculate_audit_grade(18)  # 60.0% -> C
test("Grenze 60.0% -> C", grade == 'C')
grade, pct, _ = calculate_audit_grade(17)  # 56.7% -> D
test("Grenze 56.7% -> D", grade == 'D')
grade, pct, _ = calculate_audit_grade(12)  # 40.0% -> D
test("Grenze 40.0% -> D", grade == 'D')
grade, pct, _ = calculate_audit_grade(11)  # 36.7% -> F
test("Grenze 36.7% -> F", grade == 'F')


# ---- TEST 6: Audit Questions Struktur ----
print("\n📝 TEST 6: AUDIT_QUESTIONS Struktur")

test(f"10 Fragen vorhanden", len(AUDIT_QUESTIONS) == 10)
for i, q in enumerate(AUDIT_QUESTIONS):
    test(f"Frage {i+1}: hat id, cat, q, opts", all(k in q for k in ['id', 'cat', 'q', 'opts']))
    test(f"Frage {i+1}: 4 Optionen", len(q['opts']) == 4)
    scores = [opt[1] for opt in q['opts']]
    test(f"Frage {i+1}: Scores [3,2,1,0]", sorted(scores, reverse=True) == [3, 2, 1, 0])


# ---- TEST 7: Incident Response Struktur ----
print("\n🚨 TEST 7: Incident Response Struktur")

test(f"6 Vorfallstypen", len(INCIDENT_TYPES) == 6)
test(f"5 NIST-Phasen", len(IR_PHASES) == 5)

for it in INCIDENT_TYPES:
    test(f"Typ '{it['id']}': id, emoji, label", all(k in it for k in ['id', 'emoji', 'label']))

for phase in IR_PHASES:
    test(f"Phase '{phase['id']}': id, emoji, label, desc", all(k in phase for k in ['id', 'emoji', 'label', 'desc']))

# Phase IDs prüfen (NIST)
expected_phases = ['identify', 'contain', 'eradicate', 'recover', 'lessons']
actual_phases = [p['id'] for p in IR_PHASES]
test("NIST-Phasen korrekt", actual_phases == expected_phases)


# ---- TEST 8: Datenbank-Tabellen ----
print("\n💾 TEST 8: Datenbank-Tabellen (init_db)")

with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
    test_db = f.name

try:
    conn = sqlite3.connect(test_db)
    c = conn.cursor()

    # Simuliere init_db() für die 3 neuen Tabellen
    c.execute('''CREATE TABLE IF NOT EXISTS phishing_checks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER, input_text TEXT, urls_found TEXT,
        risk_score INTEGER, findings TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS security_audits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER, grade TEXT, score INTEGER,
        max_score INTEGER, answers TEXT, recommendations TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS incident_responses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER, incident_type TEXT,
        phases_completed INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.commit()

    # Tabellen prüfen
    c.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r[0] for r in c.fetchall()]
    test("phishing_checks Tabelle existiert", 'phishing_checks' in tables)
    test("security_audits Tabelle existiert", 'security_audits' in tables)
    test("incident_responses Tabelle existiert", 'incident_responses' in tables)

    # Insert-Test: Phishing
    import json
    c.execute('INSERT INTO phishing_checks (user_id, input_text, urls_found, risk_score, findings) VALUES (?, ?, ?, ?, ?)',
              (12345, 'test url', json.dumps(['https://evil.tk']), 7, json.dumps(['Verdächtige TLD'])))
    conn.commit()
    c.execute('SELECT * FROM phishing_checks WHERE user_id = 12345')
    row = c.fetchone()
    test("Phishing-Check INSERT/SELECT", row is not None and row[4] == 7)

    # Insert-Test: Audit
    c.execute('INSERT INTO security_audits (user_id, grade, score, max_score, answers) VALUES (?, ?, ?, ?, ?)',
              (12345, 'B', 23, 30, json.dumps([2,3,2,2,3,2,2,3,2,2])))
    conn.commit()
    c.execute('SELECT * FROM security_audits WHERE user_id = 12345')
    row = c.fetchone()
    test("Audit INSERT/SELECT", row is not None and row[2] == 'B')

    # Insert-Test: Incident Response
    c.execute('INSERT INTO incident_responses (user_id, incident_type, phases_completed) VALUES (?, ?, ?)',
              (12345, 'malware', 3))
    conn.commit()
    c.execute('SELECT * FROM incident_responses WHERE user_id = 12345')
    row = c.fetchone()
    test("Incident Response INSERT/SELECT", row is not None and row[2] == 'malware')

    conn.close()
finally:
    os.unlink(test_db)


# ============================================================
# ERGEBNIS
# ============================================================
print("\n" + "=" * 60)
total = passed + failed
print(f"ERGEBNIS: {passed}/{total} Tests bestanden")
if failed > 0:
    print(f"⚠️  {failed} Test(s) fehlgeschlagen!")
    sys.exit(1)
else:
    print("✅ Alle Tests bestanden!")
    sys.exit(0)
