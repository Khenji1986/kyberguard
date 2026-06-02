# AI-Voice-Phishing 2026 — Awareness-Block für KMU

> **Stand:** 06.05.2026 | **Zielgruppe:** KyberGuard-Kunden (KMU, NIS2-pflichtig nach §38 BSIG-neu)
> **Position:** Awareness-Modul, Phishing-Sektion → neuer Block "AI-Voice-Phishing"

---

## Was ist passiert?

Seit 2024 gibt es Open-Source-Tools, die jede Stimme aus 10 Sekunden Audio-Material klonen können. **2026 ist diese Technologie kein Hype mehr — sie ist commodified.**

- **OpenVoice** (MIT-Lizenz, MIT + MyShell): kostenfrei, kommerzielle Nutzung erlaubt, kein API-Key nötig.
- **XTTS, Tortoise, Resemble.AI** und Dutzende Forks ziehen nach.
- 10 Sekunden Audio reichen — und die kommen heute aus jedem LinkedIn-Vortrag, jedem Podcast-Auftritt, jedem Voice-Mail-Sample.

**Konsequenz für KMU:** Der "Anruf vom Chef" ist 2026 kein Vertrauensbeweis mehr.

---

## Typische Angriffsszenarien (2026)

| Szenario | Was passiert | Wer ist Ziel |
|---|---|---|
| **CEO-Fraud 2.0** | Buchhaltung erhält Anruf von der Geschäftsführer-Stimme: "Bitte sofort 47.000 € überweisen, sonst platzt der Deal." | Buchhaltung, Assistenz |
| **Bank-Voice-Bot** | Stimme des "Bankberaters" fragt nach SMS-TAN — angeblich für eine Sicherheitsverifikation. | Geschäftsführer, Mitarbeitende |
| **Tech-Support-Vishing** | Stimme der "IT-Abteilung" bittet um Remote-Zugang oder Passwort-Reset. | Alle Mitarbeitenden |
| **Familien-Notfall-Scam** | Stimme des Kindes oder Partners ruft an: "Ich hatte einen Unfall, ich brauche sofort Geld." | Geschäftsführer privat |

---

## Wie erkennt man AI-Voice-Phishing?

Die schlechte Nachricht: **An der Stimme allein ist es 2026 nicht mehr zuverlässig erkennbar.** Die gute Nachricht: An den Verhaltensmustern schon.

**Rote Flaggen — bei Anrufen:**
1. **Unerwartete Dringlichkeit** ("muss heute, sonst ist alles weg")
2. **Geheimhaltung** ("sagen Sie niemandem davon")
3. **Bitte um Geld, TAN, Login oder Daten** — egal wie überzeugend
4. **Anruf von unbekannter oder unterdrückter Nummer**
5. **Hintergrundgeräusche fehlen** oder klingen synthetisch
6. **Antwort auf konkrete Rückfragen wirkt zögerlich** (bei AI: "Wo waren wir letzten Donnerstag essen?")

---

## Schutzmaßnahmen — operativ umsetzbar

### Für die Geschäftsführung
- **Code-Wort etablieren:** Ein Wort, das nur Sie und Vertraute kennen. Wer es nicht nennen kann, ist nicht authentisch — egal wie die Stimme klingt.
- **Rückruf-Pflicht:** Bei jedem ungewöhnlichen Auftrag immer auf der bekannten dienstlichen Nummer zurückrufen, nie auf der angezeigten.
- **Schriftliche Bestätigung:** Geldverkehr nur nach E-Mail/Signal-Bestätigung — nie ausschließlich telefonisch.

### Für Mitarbeitende (Buchhaltung, Assistenz)
- **4-Augen-Prinzip** für jede Überweisung > 5.000 €.
- **Niemals SMS-TAN am Telefon weitergeben** — auch nicht zur "Verifikation".
- **Bei Unsicherheit:** Kollegen oder Vorgesetzte eskalieren. Lieber peinlich rückfragen als 50.000 € verloren.

### Für die IT
- **MFA mit Token oder Passkey**, nicht SMS.
- **Helpdesk-Auth-Prozess:** Mitarbeitende, die anrufen, müssen sich über etablierten Identitäts-Faktor verifizieren (z.B. Mitarbeiter-ID + Geburtstag oder etabliertes Q&A).
- **Voice-Biometrie kann umgangen werden** — als Sicherheitsfaktor obsolet.

---

## NIS2-Relevanz (Art. 21 Abs. 2)

NIS2 verlangt von wesentlichen und wichtigen Einrichtungen u.a. **Schulungs- und Awareness-Maßnahmen**. AI-Voice-Phishing ist 2026 ein realistisch dokumentiertes Bedrohungsszenario und muss in jedem Awareness-Programm adressiert sein.

KyberGuard-Beratung empfiehlt:
- **Quartalsweise Awareness-Übung** mit Simulationsanruf (auch ohne AI).
- **Aufnahme im Risiko-Register** als eigenständiges Bedrohungsszenario.
- **Notfall-Prozess "Verdacht auf Voice-Fraud"** dokumentiert (wer wird wann eskaliert).

---

## Marketing-Hook (für KyberGuard)

> **"Cyberangriff? Nicht bei unseren Kunden — auch wenn der Anrufer wie der Chef klingt."**

---

## Quellen
- OpenVoice: https://github.com/myshell-ai/OpenVoice (MIT)
- arXiv: https://arxiv.org/abs/2312.01479
- BSI Lagebericht 2026 (CEO-Fraud-Anstieg)
- Friegün-Recherche 06.05.2026 (research_voice_clone_vishing_threat_2026.md)
