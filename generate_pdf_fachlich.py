"""
KyberGuard — Fachlicher Produktüberblick (IT-Partner Version)
Stand: Juni 2026 | Externe Version ohne interne Geheimnisse
"""
from fpdf import FPDF
import os

FONT_R = "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf"
FONT_B = "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf"
FONT_I = "/usr/share/fonts/truetype/liberation/LiberationSans-Italic.ttf"

# Farben
BG       = (13, 17, 23)
BG2      = (20, 30, 48)
BG3      = (16, 26, 42)
TH       = (10, 40, 70)
CYAN     = (0, 180, 216)
CYAN2    = (0, 150, 190)
WHITE    = (226, 232, 240)
GRAY     = (148, 163, 184)
GRAY2    = (100, 120, 145)
GREEN    = (34, 197, 94)
YELLOW   = (234, 179, 8)
RED_SOFT = (220, 80, 80)
BORDER   = (30, 55, 90)


class KPdf(FPDF):
    def __init__(self):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.set_auto_page_break(auto=False)
        self.add_font("Lib", "", FONT_R)
        self.add_font("Lib", "B", FONT_B)
        self.add_font("Lib", "I", FONT_I)
        self._page_num = 0

    # ── Helpers ─────────────────────────────────────────────────────────────
    def _bg(self):
        self.set_fill_color(*BG)
        self.rect(0, 0, 210, 297, "F")

    def _header_bar(self):
        self.set_fill_color(*BG2)
        self.rect(0, 0, 210, 12, "F")
        self.set_text_color(*GRAY)
        self.set_font("Lib", "", 7.5)
        self.set_xy(8, 3.5)
        self.cell(100, 5, "KyberGuard.de — Fachlicher Produktüberblick 2026", ln=False)
        self.set_xy(110, 3.5)
        self.cell(92, 5, "AP Digital Solution — Hamburg", align="R", ln=False)
        # Accent-Linie
        self.set_fill_color(*CYAN)
        self.rect(0, 12, 210, 0.5, "F")

    def _footer_bar(self, page_num=None, note="NIS2-konform. KMU-zentriert. Made in Germany."):
        self.set_fill_color(*BG2)
        self.rect(0, 283, 210, 14, "F")
        self.set_fill_color(*CYAN)
        self.rect(0, 283, 210, 0.4, "F")
        self.set_text_color(*GRAY)
        self.set_font("Lib", "", 7.5)
        self.set_xy(8, 287)
        self.cell(60, 5, "kyberguard.de", ln=False)
        if page_num:
            self.set_xy(90, 287)
            self.cell(30, 5, f"Seite {page_num}", align="C", ln=False)
        self.set_xy(110, 287)
        self.cell(92, 5, note, align="R", ln=False)

    def _section(self, x, y, w, h, color=BG2):
        self.set_fill_color(*color)
        self.rect(x, y, w, h, "F")

    def _accent_line(self, y, w=80):
        self.set_fill_color(*CYAN)
        self.rect(8, y, w, 0.8, "F")

    def _tag(self, x, y, text, color=CYAN):
        self.set_font("Lib", "B", 7)
        tw = self.get_string_width(text) + 4
        self.set_fill_color(*color)
        self.rect(x, y, tw, 4.5, "F")
        self.set_text_color(*BG)
        self.set_xy(x + 1.5, y + 0.3)
        self.cell(tw - 3, 4, text, ln=False)

    def _h1(self, x, y, text):
        self.set_font("Lib", "B", 18)
        self.set_text_color(*CYAN)
        self.set_xy(x, y)
        self.cell(0, 10, text, ln=False)

    def _h2(self, x, y, text):
        self.set_font("Lib", "B", 13)
        self.set_text_color(*CYAN)
        self.set_xy(x, y)
        self.cell(0, 8, text, ln=False)

    def _h3(self, x, y, text):
        self.set_font("Lib", "B", 10.5)
        self.set_text_color(*WHITE)
        self.set_xy(x, y)
        self.cell(0, 6, text, ln=False)

    def _body(self, x, y, w, text, size=9, color=WHITE, line_h=5.2):
        self.set_font("Lib", "", size)
        self.set_text_color(*color)
        self.set_xy(x, y)
        self.multi_cell(w, line_h, text)

    def _bold_inline(self, x, y, label, value, size=8.5):
        self.set_font("Lib", "B", size)
        self.set_text_color(*CYAN)
        self.set_xy(x, y)
        lw = self.get_string_width(label + " ")
        self.cell(lw, 5, label, ln=False)
        self.set_font("Lib", "", size)
        self.set_text_color(*WHITE)
        self.cell(0, 5, value, ln=False)

    def _table_header(self, x, y, cols):
        h = 6.5
        self.set_fill_color(*TH)
        self.rect(x, y, sum(c[1] for c in cols), h, "F")
        cx = x
        for label, w in cols:
            self.set_font("Lib", "B", 8)
            self.set_text_color(*CYAN)
            self.set_xy(cx + 1.5, y + 0.5)
            self.cell(w - 3, 5.5, label, ln=False)
            cx += w
        return y + h

    def _table_row(self, x, y, cells, alt=False, row_h=6, font_sizes=None):
        self.set_fill_color(*(BG3 if alt else BG2))
        total_w = sum(c[1] for c in cells)
        self.rect(x, y, total_w, row_h, "F")
        # thin border
        self.set_draw_color(*BORDER)
        self.rect(x, y, total_w, row_h)
        cx = x
        for i, (text, w) in enumerate(cells):
            fs = font_sizes[i] if font_sizes else 8
            self.set_font("Lib", "", fs)
            self.set_text_color(*WHITE)
            self.set_xy(cx + 1.5, y + 0.5)
            self.cell(w - 3, row_h - 1, text, ln=False)
            cx += w
        return y + row_h

    def _callout(self, x, y, w, label, text, color=CYAN):
        h = 12
        self.set_fill_color(*BG3)
        self.rect(x, y, w, h, "F")
        self.set_fill_color(*color)
        self.rect(x, y, 2, h, "F")
        self.set_font("Lib", "B", 8)
        self.set_text_color(*color)
        self.set_xy(x + 4, y + 1.5)
        self.cell(w - 6, 4, label, ln=False)
        self.set_font("Lib", "", 8)
        self.set_text_color(*WHITE)
        self.set_xy(x + 4, y + 6)
        self.cell(w - 6, 4.5, text, ln=False)
        return y + h + 2

    def _callout_multi(self, x, y, w, label, text, color=CYAN):
        self.set_font("Lib", "", 8)
        lines = self.multi_cell(w - 6, 4.5, text, dry_run=True, output="LINES")
        h = max(10, 6 + len(lines) * 4.5)
        self.set_fill_color(*BG3)
        self.rect(x, y, w, h, "F")
        self.set_fill_color(*color)
        self.rect(x, y, 2, h, "F")
        self.set_font("Lib", "B", 8)
        self.set_text_color(*color)
        self.set_xy(x + 4, y + 1.5)
        self.cell(w - 6, 4, label, ln=False)
        self.set_font("Lib", "", 8)
        self.set_text_color(*WHITE)
        self.set_xy(x + 4, y + 6)
        self.multi_cell(w - 6, 4.5, text)
        return y + h + 2


# ============================================================
# PAGE BUILDERS
# ============================================================

def page_title(pdf):
    pdf.add_page()
    pdf._bg()
    # Accent bar top
    pdf.set_fill_color(*CYAN)
    pdf.rect(8, 18, 50, 1.2, "F")
    # Logo-Zeile
    pdf.set_font("Lib", "B", 36)
    pdf.set_text_color(*WHITE)
    pdf.set_xy(8, 55)
    pdf.cell(0, 20, "KyberGuard", ln=False)
    pdf.set_text_color(*CYAN)
    pdf.set_font("Lib", "B", 36)
    lw = pdf.get_string_width("KyberGuard")
    pdf.set_xy(8 + lw, 55)
    pdf.cell(0, 20, ".", ln=False)
    # Subtitle
    pdf.set_font("Lib", "", 14)
    pdf.set_text_color(*CYAN)
    pdf.set_xy(8, 78)
    pdf.cell(0, 8, "Fachlicher Produktüberblick & Kundennutzen", ln=False)
    # Divider
    pdf.set_fill_color(*BORDER)
    pdf.rect(8, 91, 194, 0.5, "F")
    # Intro-Text
    intro = (
        "KyberGuard ist eine cloudbasierte Cybersecurity-Plattform fuer kleine und mittelstaendische "
        "Unternehmen (KMU), die NIS2-Konformitaet, kontinuierliches Angriffsflaechen-management, "
        "Dark-Web-Monitoring und KI-gestuetzte Bedrohungsanalyse in einer einheitlichen SaaS-Loesung vereint."
    )
    pdf.set_font("Lib", "", 9.5)
    pdf.set_text_color(*WHITE)
    pdf.set_xy(8, 96)
    pdf.multi_cell(194, 5.5, intro)
    desc = (
        "Dieses Dokument beschreibt alle Produkt-Module technisch praezise und erlaeutert den konkreten "
        "Mehrwert fuer Kunden. Zielgruppe: IT-Verantwortliche, Compliance-Beauftragte, GmbH-Geschaeftsfuehrungen "
        "und IT-Dienstleister."
    )
    pdf.set_xy(8, 114)
    pdf.multi_cell(194, 5.5, desc)
    # Info-Tabelle
    y = 135
    cols = [("Feature-Module", 48), ("Zielgruppe", 48), ("Compliance", 48), ("Verfuegbar", 50)]
    y2 = pdf._table_header(8, y, cols)
    row = [("12+ aktive Module", 48), ("KMU 5-500 MA", 48), ("NIS2 Art. 21", 48), ("Live - EU-Server", 50)]
    pdf._table_row(8, y2, row, alt=False)
    # Hinweis
    pdf.set_font("Lib", "I", 8)
    pdf.set_text_color(*GRAY)
    pdf.set_xy(8, 162)
    pdf.cell(
        194, 5,
        "Alle Server-Standorte: Hetzner Frankfurt, Deutschland. DSGVO-konform. Keine US-Cloud. Keine chinesischen Komponenten.",
        align="C", ln=False
    )
    pdf._footer_bar(1)


def page_architektur(pdf):
    pdf.add_page()
    pdf._bg()
    pdf._header_bar()
    pdf._h1(8, 17, "1. Was ist KyberGuard?")
    pdf.set_font("Lib", "", 8.5)
    pdf.set_text_color(*GRAY)
    pdf.set_xy(8, 28)
    pdf.cell(0, 5, "Plattform-Uebersicht, Architektur und Positionierung", ln=False)
    intro = (
        "KyberGuard ist eine vollstaendig cloudbasierte SaaS-Plattform, die Cybersicherheits-Funktionen "
        "fuer KMU benutzbar und erschwinglich macht. Statt teurer On-Premise-Software bietet KyberGuard "
        "einen zentralen Ort fuer alle sicherheitsrelevanten Aufgaben."
    )
    pdf.set_font("Lib", "", 9)
    pdf.set_text_color(*WHITE)
    pdf.set_xy(8, 34)
    pdf.multi_cell(194, 5.2, intro)
    # Kernprinzipien
    pdf._h3(8, 52, "Kernprinzipien der Plattform")
    callouts = [
        ("NIS2-First:", "Alle Module sind auf die Anforderungen der EU NIS2-Richtlinie (Artikel 21) ausgerichtet."),
        ("Proaktiv statt reaktiv:", "KyberGuard sucht aktiv nach Schwachstellen und geleakten Credentials - bevor Angreifer sie ausnutzen."),
        ("KI-gestuetzt:", "Integrierte KI (KyberAssist) erklaert Befunde, priorisiert Massnahmen und erstellt Handlungsplaene ohne Expertenwissen."),
        ("Privacy by Design:", "Alle Daten bleiben auf deutschen Servern (Hetzner Frankfurt). Kein Tracking, keine US-Cloud, vollstaendig DSGVO-konform."),
    ]
    y = 58
    for label, text in callouts:
        y = pdf._callout(8, y, 194, label, text)
    # Architektur-Tabelle
    pdf._h3(8, y + 2, "Technische Architektur (Ueberblick)")
    cols = [("Schicht", 38), ("Technologie", 72), ("Zweck", 84)]
    y2 = pdf._table_header(8, y + 9, cols)
    rows = [
        ("Frontend",        "SvelteKit + TypeScript",         "Reaktive Web-App, kein App-Download noetig"),
        ("Backend API",     "FastAPI + Python 3.11",           "REST-Endpunkte, Auth, Business-Logik"),
        ("Datenbank",       "PostgreSQL 16",                   "Kunden, Scans, Compliance-Daten"),
        ("Auth",            "SuperTokens (Self-Hosted)",       "Session-Management, MFA, Passwortos"),
        ("WAF",             "ModSecurity + OWASP CRS 3.3",     "Web Application Firewall, DDoS-Schutz"),
        ("Infrastruktur",   "Hetzner Frankfurt (DE)",          "EU-Rechenzentrum, DSGVO, ISO 27001"),
        ("Monitoring",      "GUARDIAN SOC (16 Agenten)",       "24/7 Bedrohungserkennung, IOC-Abgleich"),
        ("Threat Intel",    "HYDRA-EYE (9 Quellen)",           "Abuse.ch, CISA, URLhaus, MISP, RansomLook"),
        ("KI-Analyse",      "Claude Haiku (EU-Routing)",       "KyberAssist Chat, Befund-Erklaerung, IR-Playbook"),
        ("Scan-Engine",     "NUCLEI v3.8 + Eigene Signaturen", "Vulnerability-Scanning fuer Business+-Kunden"),
        ("Zahlungsabwicklung", "Mollie (NL)",                  "PCI-DSS, SEPA, Kreditkarte, iDEAL"),
    ]
    for i, (s, t, z) in enumerate(rows):
        cells = [(s, 38), (t, 72), (z, 84)]
        y2 = pdf._table_row(8, y2, cells, alt=(i % 2 == 1))
    betrieb = (
        "Betrieb: KyberGuard laeuft auf Hetzner-Servern in Frankfurt am Main (Deutschland). "
        "Alle Verbindungen sind TLS 1.3-verschluesselt. Die Plattform steht 24/7 zur Verfuegung."
    )
    pdf.set_font("Lib", "B", 8)
    pdf.set_text_color(*WHITE)
    pdf.set_xy(8, y2 + 3)
    tw = pdf.get_string_width("Betrieb: ")
    pdf.cell(tw, 4.5, "Betrieb: ", ln=False)
    pdf.set_font("Lib", "", 8)
    pdf.set_text_color(*GRAY)
    pdf.set_xy(8 + tw, y2 + 3)
    pdf.multi_cell(186, 4.5, betrieb[9:])
    pdf._footer_bar(2)


def page_zielgruppe(pdf):
    pdf.add_page()
    pdf._bg()
    pdf._header_bar()
    pdf._h1(8, 17, "2. Zielgruppe & Anwendungsfaelle")
    pdf.set_font("Lib", "", 8.5)
    pdf.set_text_color(*GRAY)
    pdf.set_xy(8, 28)
    pdf.cell(0, 5, "Fuer wen ist KyberGuard konzipiert?", ln=False)
    intro = (
        "KyberGuard richtet sich an Organisationen, die keine dedizierte IT-Sicherheitsabteilung haben, "
        "aber dennoch professionelle Cybersicherheit benoetigen - sei es aus gesetzlichen Gruenden "
        "(NIS2, DSGVO) oder zum Schutz ihrer Geschaeftsprozesse."
    )
    pdf.set_font("Lib", "", 9)
    pdf.set_text_color(*WHITE)
    pdf.set_xy(8, 34)
    pdf.multi_cell(194, 5.2, intro)
    cols = [("Zielgruppe", 52), ("Typisches Problem", 72), ("KyberGuard-Loesung", 70)]
    y2 = pdf._table_header(8, 53, cols)
    rows = [
        ("GmbH / GmbH & Co. KG\n5-200 Mitarbeiter",
         "NIS2-Pflicht unklar, kein IT-Security-Budget fuer externe Berater",
         "NIS2-Check, Compliance-Score, Massnahmenplan"),
        ("E-Commerce / Online-Haendler",
         "Phishing, geleakte Kundendaten, Domainmissbrauch",
         "Phishing-Check, Dark Web Monitor, Domain-Scanner"),
        ("Steuerberater / Anwaelte / Arztpraxen",
         "Hochsensible Daten, DSGVO-Pflichten, Angreifer bevorzugen Kanzleien",
         "Breach-Check, KI-Assistenz, IR-Playbook"),
        ("Mittelstand / Produktion",
         "Ransomware-Risiko, OT-Sicherheit, Lieferkette",
         "Ransomware-Alerts, CVE-Radar, Supplier-Risk-Check"),
        ("IT-Dienstleister / MSP",
         "Kunden-Reporting, Skalierung ohne Personalmehraufwand",
         "Partner-API, White-Label-Reports, Massenscans"),
        ("Kommunen / Oeffentliche Stellen",
         "NIS2-Pflicht, beschraenktes IT-Budget, hohe Angriffslast",
         "NIS2-Pruefung, ASM-Dashboard, NUCLEI-Scan"),
    ]
    for i, (z, p, k) in enumerate(rows):
        cells = [(z, 52), (p, 72), (k, 70)]
        y2 = pdf._table_row(8, y2, cells, alt=(i % 2 == 1), row_h=9)
    pdf.set_font("Lib", "", 8.5)
    pdf.set_text_color(*WHITE)
    pdf.set_xy(8, y2 + 5)
    pdf.write(5, "Alle KyberGuard-Module sind ")
    pdf.set_font("Lib", "B", 8.5)
    pdf.set_text_color(*CYAN)
    pdf.write(5, "ohne tiefes Fachwissen bedienbar")
    pdf.set_font("Lib", "", 8.5)
    pdf.set_text_color(*WHITE)
    pdf.write(5, ". Befunde werden in verstaendlicher Sprache erklaert, Massnahmen priorisiert und mit Schritt-fuer-Schritt-Anleitungen hinterlegt.")
    pdf._footer_bar(3)


def page_phishing_darkweb(pdf):
    pdf.add_page()
    pdf._bg()
    pdf._header_bar()
    pdf._h1(8, 17, "3. Feature-Module im Detail")
    pdf.set_font("Lib", "", 8.5)
    pdf.set_text_color(*GRAY)
    pdf.set_xy(8, 28)
    pdf.cell(0, 5, "Technische Erklaerung und Kundennutzen aller Kernfunktionen", ln=False)
    # 3.1
    pdf._h2(8, 34, "3.1 Phishing- und URL-Analyse")
    pdf._tag(8, 44, "FREE")
    pdf.set_font("Lib", "I", 8.5)
    pdf.set_text_color(*GRAY)
    pdf.set_xy(24, 44)
    pdf.cell(0, 4.5, "Kostenlos nutzbar - keine Anmeldung erforderlich", ln=False)
    desc = (
        "Der Phishing-Check analysiert URLs und Webseiten in Echtzeit auf schaedliche Inhalte. "
        "Er kombiniert sechs unabhaengige Erkennungsschichten zu einem aggregierten Risiko-Score."
    )
    pdf.set_font("Lib", "", 8.5)
    pdf.set_text_color(*WHITE)
    pdf.set_xy(8, 50)
    pdf.multi_cell(194, 5.0, desc)
    pdf._h3(8, 60, "Erkennungsschichten (Multi-Layer):")
    cols = [("Schicht", 38), ("Verfahren", 80), ("Erkannte Bedrohungen", 76)]
    y2 = pdf._table_header(8, 67, cols)
    rows = [
        ("1. Reputations-Check",     "Abgleich mit GUARDIAN IOC-Datenbank (25.000+ Eintraege)", "Bekannte C2-IPs, Malware-Domains, Phishing-Hostnamen"),
        ("2. SSL/TLS-Analyse",       "Zertifikatvalidierung, Ausstellerdatum, SANs, Cipher-Suites", "Gefaelschte Zertifikate, kurzlebige Domains, schwache Verschluesselung"),
        ("3. Lexikalische Analyse",  "URL-Struktur, Subdomain-Tiefe, Tippfehler-Domains, Punycode", "Homograph-Angriffe, Brand-Spoofing, IDN-Missbrauch"),
        ("4. Content-Analyse",       "Seiteninhalt, Login-Felder, JavaScript-Patterns, Weiterleitungen", "Credential-Harvesting, Drive-by-Downloads, Redirection-Chains"),
        ("5. WHOIS / Domain-Alter",  "Registrierungsdatum, Registrar, Namensserver, Ablaufdatum", "Frisch registrierte Angriffsdomains (< 30 Tage)"),
        ("6. KI-Tie-Breaker",        "KI-Bewertung bei unklaren Scores (Claude Haiku, EU-Routing)", "Grenzfaelle, neue Angriffsmuster ohne bekannte Signatur"),
    ]
    for i, r in enumerate(rows):
        y2 = pdf._table_row(8, y2, [(r[0], 38), (r[1], 80), (r[2], 76)], alt=(i % 2 == 1))
    pdf.set_font("Lib", "B", 8)
    pdf.set_text_color(*CYAN)
    pdf.set_xy(8, y2 + 3)
    pdf.cell(25, 4.5, "Kundennutzen: ", ln=False)
    pdf.set_font("Lib", "", 8)
    pdf.set_text_color(*WHITE)
    pdf.cell(169, 4.5, "Mitarbeiter koennen unbekannte Links vor dem Klicken sicher pruefen. Ideal fuer Security-Awareness.", ln=False)
    # 3.2
    pdf._h2(8, y2 + 12, "3.2 Dark Web Monitor & Breach-Erkennung")
    pdf._tag(8, y2 + 22, "PERSONAL", (40, 80, 160))
    pdf._tag(28, y2 + 22, "FAMILY", (60, 100, 50))
    pdf._tag(48, y2 + 22, "PRO+")
    desc2 = (
        "Das Dark Web Monitoring ueberwacht kontinuierlich, ob E-Mail-Adressen oder Credentials eines "
        "Unternehmens in Datenlecks, Darknet-Foren oder Paste-Sites aufgetaucht sind. Bei neuen Treffern "
        "wird der Kunde automatisch benachrichtigt."
    )
    pdf.set_font("Lib", "", 8.5)
    pdf.set_text_color(*WHITE)
    pdf.set_xy(8, y2 + 28)
    pdf.multi_cell(194, 5.0, desc2)
    y_c = y2 + 43
    y_c = pdf._callout(8, y_c, 194, "HaveIBeenPwned (HIBP):",
                       "Weltgroesste Breach-Datenbank mit 14+ Milliarden Eintraegen. KI-Anonymitaet via k-Anonymity-API.")
    y_c = pdf._callout(8, y_c, 194, "H8MAIL Multi-Source Check (Pro+):",
                       "Kombiniert HIBP mit weiteren Quellen wie Paste-Sites und spezialisierten Breach-Aggregatoren.")
    pdf._callout(8, y_c, 194, "Automatische Alerts:",
                 "Neue Treffer werden sofort als Dashboard-Notification und (konfigurierbar) per E-Mail gemeldet.")
    pdf._footer_bar(4)


def page_domain_nis2(pdf):
    pdf.add_page()
    pdf._bg()
    pdf._header_bar()
    pdf._h2(8, 17, "3.3 Domain-Scanner & Angriffsflaechen-management (ASM)")
    pdf.set_font("Lib", "I", 8.5)
    pdf.set_text_color(*GRAY)
    pdf.set_xy(8, 26)
    pdf.cell(0, 5, "Vollstaendige Internet-Sichtbarkeit auf Angreiferebene", ln=False)
    pdf._tag(8, 32, "PRO+")
    pdf.set_font("Lib", "", 8)
    pdf.set_text_color(*GRAY)
    pdf.set_xy(22, 32)
    pdf.cell(0, 4.5, "Pro-Plan und hoeher", ln=False)
    desc = (
        "Der Domain-Scanner analysiert die gesamte Internet-Praesenz eines Unternehmens und deckt "
        "Schwachstellen auf, bevor Angreifer sie finden. Er kombiniert passive Reconnaissance mit aktiven Pruefungen."
    )
    pdf.set_font("Lib", "", 8.5)
    pdf.set_text_color(*WHITE)
    pdf.set_xy(8, 38)
    pdf.multi_cell(194, 5.0, desc)
    cols = [("Modul", 48), ("Was wird geprueft", 80), ("Sicherheitsrelevanz", 66)]
    y2 = pdf._table_header(8, 48, cols)
    rows = [
        ("DNS-Analyse",             "MX, SPF, DKIM, DMARC, DNSSEC, Wildcard-Records",       "E-Mail-Spoofing, fehlende Anti-Spam-Konfiguration"),
        ("MTA-STS / DANE",          "Mail Transfer Agent Strict Transport Security, TLSA-Records", "Man-in-the-Middle auf E-Mail-Transport"),
        ("TLS/SSL-Analyse",         "Zertifikatskette, Ablaufdatum, TLS 1.0/1.1 aktiv, HSTS", "Schwache Verschluesselung, abgelaufene Zertifikate"),
        ("Subdomain-Enumeration",   "crt.sh Certificate Transparency, AXFR-Zone-Transfer",  "Vergessene Staging-Systeme, Subdomain-Takeover"),
        ("HTTP-Security-Header",    "CSP, HSTS, X-Frame-Options, Referrer-Policy",           "XSS, Clickjacking, Information-Disclosure"),
        ("Technologie-Fingerprint", "60+ Signaturen: CMS, Frameworks, Server-Versionen",     "Veraltete Software mit bekannten CVEs"),
        ("WHOIS / Domain-Eigentuemer", "Registrar, Ablaufdatum, DNSSEC-Status",              "Domain-Ablauf, fehlende DNSSEC-Signierung"),
        ("Wayback Machine",         "Archivierte URLs, alte Endpoints, geleakte Pfade",       "Offengelegte APIs aus frueheren Versionen"),
        ("Domain-Verifizierung",    "DNS-TXT-Record-Validierung fuer Eigentuemer",           "Sicherheitsnachweis, erweiterte Scan-Tiefe"),
    ]
    for i, r in enumerate(rows):
        y2 = pdf._table_row(8, y2, [(r[0], 48), (r[1], 80), (r[2], 66)], alt=(i % 2 == 1))
    pdf.set_font("Lib", "B", 8)
    pdf.set_text_color(*CYAN)
    pdf.set_xy(8, y2 + 3)
    pdf.cell(25, 4.5, "Kundennutzen: ", ln=False)
    pdf.set_font("Lib", "", 8)
    pdf.set_text_color(*WHITE)
    pdf.multi_cell(169, 4.5, "Ein KMU hat 15-30 Subdomains und DNS-Fehlkonfigurationen, von denen es nichts weiss. Der Domain-Scanner liefert vollstaendige Sicht in wenigen Minuten - inklusive PDF-Report (Business+).")
    # 3.4
    pdf._h2(8, y2 + 18, "3.4 NIS2-Compliance-Pruefung")
    pdf._tag(8, y2 + 28, "PRO+")
    pdf.set_font("Lib", "", 8)
    pdf.set_text_color(*GRAY)
    pdf.set_xy(22, y2 + 28)
    pdf.cell(0, 4.5, "EU-Richtlinie 2022/2555 - Artikel 21 Massnahmen", ln=False)
    desc2 = (
        "Die NIS2-Richtlinie (EU 2022/2555) ist seit Oktober 2024 nationales Recht. Unternehmen ab 50 "
        "Mitarbeitern oder 10 Mio. EUR Jahresumsatz in kritischen Sektoren sind verpflichtet, technische "
        "Sicherheitsmassnahmen umzusetzen. Bussgelder: bis zu 10 Mio. EUR oder 2% des weltweiten Jahresumsatzes."
    )
    pdf.set_font("Lib", "", 8.5)
    pdf.set_text_color(*WHITE)
    pdf.set_xy(8, y2 + 34)
    pdf.multi_cell(194, 5.0, desc2)
    callouts2 = [
        ("Betroffenheit (Eligibility):", "Automatische Einstufung nach Sektor, Groesse und Umsatz"),
        ("Risikomanagement (Art. 21a):", "Richtlinien, Prozesse, technische Massnahmen fuer Risikoanalyse"),
        ("Incident Response (Art. 21b):", "Vorhandensein von IR-Plan, Meldewegen, CIRT/CSIRT-Anbindung"),
        ("Business Continuity (Art. 21c):", "Backup-Strategie, Notfallplan, Recovery-Faehigkeit (RPO/RTO)"),
        ("Supply-Chain-Sicherheit (Art. 21d):", "Sicherheit von Lieferanten und Dienstleistern, Vertragspflichten"),
        ("Netzwerksicherheit (Art. 21e):", "Segmentierung, Zugangskontrolle, Monitoring, Verschluesselung"),
    ]
    yc = y2 + 56
    for label, text in callouts2:
        pdf.set_font("Lib", "B", 8)
        pdf.set_text_color(*CYAN)
        pdf.set_xy(8, yc)
        lw = pdf.get_string_width(label + " ")
        pdf.cell(lw, 4.5, label, ln=False)
        pdf.set_font("Lib", "", 8)
        pdf.set_text_color(*WHITE)
        pdf.cell(0, 4.5, text, ln=False)
        yc += 5
    pdf.set_font("Lib", "B", 8)
    pdf.set_text_color(*CYAN)
    pdf.set_xy(8, yc + 2)
    pdf.cell(25, 4.5, "Kundennutzen: ", ln=False)
    pdf.set_font("Lib", "", 8)
    pdf.set_text_color(*WHITE)
    pdf.cell(169, 4.5, "NIS2-betroffene Unternehmen reduzieren den Beratungsaufwand erheblich. Check dauert 15-20 Min. mit konkretem Massnahmenplan und PDF-Report (Business+).", ln=False)
    pdf._footer_bar(5)


def page_weitere_module(pdf):
    pdf.add_page()
    pdf._bg()
    pdf._header_bar()
    pdf._h1(8, 17, "3.5 - 3.15 Weitere Module im Ueberblick")
    cols = [("Modul", 48), ("Plan", 26), ("Funktion & Kundennutzen", 120)]
    y2 = pdf._table_header(8, 27, cols)
    rows = [
        ("CVE-Radar", "PRO+",
         "Schwachstellen-Fruehwarnung aus NVD + CISA KEV. Filter nach Produkt, CVSS >= 7.0, aktiv ausgenutzte CVEs. Kein manuelles Lesen von Security-Newslettern mehr."),
        ("Ransomware-Monitor", "BUSINESS+",
         "Aktuelle Ransomware-Gruppen, Opfer und TTPs aus RansomLook + Feodo Tracker. Fruehwarnung ermoeglicht proaktive Gegenmassnahmen vor dem Angriff."),
        ("NUCLEI Vuln-Scan", "BUSINESS+/ENTERPRISE",
         "Templatebasiertes Schwachstellen-Scanning (50.000+ CVE-Templates). Business: 1x pro Woche. Enterprise: taeglich. Ersetzt aufwaendige manuelle Pentests."),
        ("Post-Quanten-Assessment", "PRO+",
         "Prueft Krypto-Algorithmen auf Quantenresilienz. Migrationsempfehlungen zu NIST PQC-Standards (Kyber, Dilithium). Schuetzt langfristige Geheimnisse."),
        ("KI Incident-Response-Playbook", "PRO+",
         "KI-generierter Reaktionsplan fuer konkrete Vorfaelle (Ransomware, Datenleck, Account-Kompromittierung). Schritt-fuer-Schritt-Anleitung, Meldepflichten, Wiederherstellung."),
        ("Telefon-Check", "FREE",
         "Spam-, Betrugs- und Vishing-Erkennung fuer Telefonnummern. Community-Reports + bekannte Scam-Datenbanken. Schutz vor CEO-Fraud und Social-Engineering-Anrufen."),
        ("WiFi-Sicherheitsanalyse", "FREE",
         "Fragebogen-basierte Bewertung der Netzwerkkonfiguration: WPA2/3, Segmentierung, Router-Credentials, Firmware, VPN. Deckt groebste Luecken ohne Hardware-Audit auf."),
        ("KyberAssist KI-Chat v2.2", "PERSONAL",
         "Integrierter KI-Sicherheitsberater (Claude Haiku, EU-Routing). Erklaert Scan-Befunde, beantwortet NIS2-Fragen. NEU: 30-Min-Sitzungsgedaechtnis, Prompt Caching. Kein KI-Training mit Kundendaten."),
        ("ASM-Dashboard", "BUSINESS+",
         "Kontinuierlicher Ueberblick aller exponierten Assets: Domain-Scan + Subdomain-Tracking + Zertifikats-Monitoring + CVE-Mapping. Auto-Scan taeglich 03:30 UTC."),
        ("Supplier Risk", "PRO+",
         "NIS2 Art. 21(d): Automatische Bewertung von Drittanbietern nach Domain-Sicherheit, Sicherheitsrichtlinien und bekannten Schwachstellen. Kein manueller Fragebogen-Versand."),
        ("MFA & Account-Schutz", "FREE",
         "TOTP-basierte Multi-Faktor-Authentifizierung fuer alle Accounts. Emergency-Lock bei Verdacht auf Kompromittierung, Device-Management, Session-Invalidierung."),
    ]
    for i, (modul, plan, text) in enumerate(rows):
        y2 = pdf._table_row(8, y2, [(modul, 48), (plan, 26), (text, 120)], alt=(i % 2 == 1), row_h=9)
    pdf._footer_bar(6)


def page_plaene_1(pdf):
    pdf.add_page()
    pdf._bg()
    pdf._header_bar()
    pdf._h1(8, 17, "4. Produktplaene & Preise")
    pdf.set_font("Lib", "I", 8.5)
    pdf.set_text_color(*GRAY)
    pdf.set_xy(8, 28)
    pdf.cell(0, 5, "Alle Preise inkl. MwSt. - monatliche Kuendigung moeglich", ln=False)

    plan_data = [
        ("Free", None, [
            "Phishing-Check (URL-Analyse, 6 Schichten)",
            "Telefon-Check & Spam-Meldung",
            "WiFi-Sicherheitsanalyse (Fragebogen)",
            "MFA & Account-Schutz",
            "Blog / Security-News",
        ], "Einstieg ohne Risiko. Sofortiger Mehrwert fuer Mitarbeiter-Awareness."),
        ("Personal", "4,99 EUR/Mo.", [
            "Alles aus Free",
            "Dark Web Monitor (1 E-Mail-Adresse)",
            "H8MAIL Breach-Check (Multi-Source)",
            "KyberAssist KI-Chat (Basis)",
            "Alert-Benachrichtigungen",
        ], "Selbstschutz fuer Einzelpersonen, Freelancer und Solo-Gruender."),
        ("Family", "9,99 EUR/Mo.", [
            "Alles aus Personal",
            "Dark Web Monitor fuer 5 E-Mail-Adressen",
            "Gemeinsames Dashboard",
            "Ideal fuer kleine Teams oder Familien",
        ], "Schutz fuer mehrere Personen / Team-Mitglieder ohne Mehraufwand."),
        ("Pro", "34,99 EUR/Mo.", [
            "Alles aus Family",
            "Domain-Scanner v2 (volles ASM-Modul)",
            "NIS2-Compliance-Check + PDF-Report (Business+)",
            "CVE-Radar mit Filter",
            "Post-Quanten-Assessment",
            "KI-Incident-Response-Playbook",
            "Supplier-Risk-Bewertung",
            "OSINT-Scanner",
            "Compliance-Score-Dashboard",
            "KyberAssist Vollzugang",
        ], "Das zentrale Sicherheits-Cockpit fuer KMU mit NIS2-Pflicht."),
    ]

    y = 35
    for name, price, features, note in plan_data:
        block_h = 8 + len(features) * 6 + 8
        pdf._section(8, y, 194, block_h, BG2)
        pdf.set_fill_color(*CYAN if name == "Pro" else GRAY2)
        pdf.rect(8, y, 194, 7, "F")
        pdf.set_font("Lib", "B", 10)
        pdf.set_text_color(*BG if name == "Pro" else WHITE)
        pdf.set_xy(11, y + 1.2)
        pdf.cell(80, 5, name, ln=False)
        if price:
            pdf.set_font("Lib", "B", 9)
            pdf.set_text_color(*BG if name == "Pro" else CYAN)
            pdf.set_xy(150, y + 1.2)
            pdf.cell(50, 5, price, align="R", ln=False)
        fy = y + 9
        for feat in features:
            pdf.set_fill_color(*CYAN)
            pdf.rect(12, fy + 1.5, 1.5, 1.5, "F")
            pdf.set_font("Lib", "", 8.5)
            pdf.set_text_color(*WHITE)
            pdf.set_xy(16, fy)
            pdf.cell(180, 5.5, feat, ln=False)
            fy += 6
        pdf.set_font("Lib", "I", 7.5)
        pdf.set_text_color(*GRAY)
        pdf.set_xy(11, fy + 1)
        pdf.cell(180, 4, note, ln=False)
        y += block_h + 3

    pdf._footer_bar(7)


def page_plaene_2(pdf):
    pdf.add_page()
    pdf._bg()
    pdf._header_bar()

    plan_data = [
        ("Business", "99,99 EUR/Mo.", [
            "Alles aus Pro",
            "Ransomware-Monitor & Threat Intelligence",
            "ASM-Dashboard (kontinuierlich, Auto-Scan)",
            "NUCLEI Vulnerability-Scan (1x pro Woche)",
            "H8MAIL Breach-Check fuer Firmen-Domains",
            "PDF-Reports fuer Domain-Scan & NIS2",
            "Priority Support (Antwort < 24h)",
        ], "Professionelle Sicherheitsplattform fuer wachsende Unternehmen mit erhoehtem Risikoprofil."),
        ("Enterprise", "299 EUR/Mo.", [
            "Alles aus Business",
            "NUCLEI Vulnerability-Scan taeglich",
            "Individuell angepasste Scan-Templates",
            "Dedizierter Account-Manager",
            "SLA-garantierter Support (< 4h Reaktionszeit)",
            "Partner-API-Zugang fuer MSPs",
            "White-Label-Reporting",
            "On-Demand-Scans unbegrenzt",
        ], "Maximale Absicherung und individuelle Betreuung fuer Unternehmen mit hohen Compliance-Anforderungen."),
    ]

    y = 17
    for name, price, features, note in plan_data:
        block_h = 8 + len(features) * 6 + 8
        pdf._section(8, y, 194, block_h, BG2)
        pdf.set_fill_color(*CYAN)
        pdf.rect(8, y, 194, 7, "F")
        pdf.set_font("Lib", "B", 10)
        pdf.set_text_color(*BG)
        pdf.set_xy(11, y + 1.2)
        pdf.cell(80, 5, name, ln=False)
        pdf.set_font("Lib", "B", 9)
        pdf.set_text_color(*BG)
        pdf.set_xy(150, y + 1.2)
        pdf.cell(50, 5, price, align="R", ln=False)
        fy = y + 9
        for feat in features:
            pdf.set_fill_color(*CYAN)
            pdf.rect(12, fy + 1.5, 1.5, 1.5, "F")
            pdf.set_font("Lib", "", 8.5)
            pdf.set_text_color(*WHITE)
            pdf.set_xy(16, fy)
            pdf.cell(180, 5.5, feat, ln=False)
            fy += 6
        pdf.set_font("Lib", "I", 7.5)
        pdf.set_text_color(*GRAY)
        pdf.set_xy(11, fy + 1)
        pdf.cell(180, 4, note, ln=False)
        y += block_h + 3

    # Jahrespreise
    pdf._section(8, y + 4, 194, 28, BG3)
    pdf.set_font("Lib", "B", 9)
    pdf.set_text_color(*CYAN)
    pdf.set_xy(11, y + 7)
    pdf.cell(0, 5, "Jahres-Abonnement (2 Monate kostenlos bei Pro & Business):", ln=False)
    yr_rows = [
        ("Pro", "349,90 EUR/Jahr (statt 419,88 EUR)"),
        ("Business", "999,90 EUR/Jahr (statt 1.199,88 EUR)"),
        ("Enterprise", "2.690 EUR/Jahr (1 Monat gratis)"),
    ]
    yp = y + 14
    for plan, preis in yr_rows:
        pdf.set_fill_color(*CYAN)
        pdf.rect(12, yp + 1.5, 1.5, 1.5, "F")
        pdf.set_font("Lib", "B", 8.5)
        pdf.set_text_color(*WHITE)
        pdf.set_xy(16, yp)
        tw = pdf.get_string_width(plan + ": ")
        pdf.cell(tw, 5, plan + ": ", ln=False)
        pdf.set_font("Lib", "", 8.5)
        pdf.cell(160, 5, preis, ln=False)
        yp += 6

    pdf._footer_bar(8)


def page_infrastruktur(pdf):
    pdf.add_page()
    pdf._bg()
    pdf._header_bar()
    pdf._h1(8, 17, "5. Technische Infrastruktur & Sicherheitsnachweise")
    pdf.set_font("Lib", "", 8.5)
    pdf.set_text_color(*GRAY)
    pdf.set_xy(8, 28)
    pdf.cell(0, 5, "Server, Zertifizierungen und Datenschutz", ln=False)
    pdf._h3(8, 35, "Server-Infrastruktur")
    cols = [("Komponente", 55), ("Details", 139)]
    y2 = pdf._table_header(8, 42, cols)
    rows = [
        ("Hosting-Provider",       "Hetzner Online GmbH, Rechenzentrum Frankfurt am Main (DE)"),
        ("Zertifizierung",         "ISO 27001, SOC 2 Type II, EN 50600 (Rechenzentrum)"),
        ("Verschluesselung (Transit)", "TLS 1.3 (bevorzugt), TLS 1.2 (Fallback), HSTS, MTA-STS"),
        ("Verschluesselung (Storage)", "AES-256-GCM fuer sensible Felder, Passwort-Hashing mit bcrypt (cost=12)"),
        ("WAF",                    "ModSecurity + OWASP CRS 3.3.8, BLOCKING Mode, PARANOIA Level 1"),
        ("Backup",                 "Taeglich verschluesselt, georedundant, getestete Recovery"),
        ("Monitoring",             "24/7 GUARDIAN SOC, 16 Sicherheitsagenten, 25.000+ IOCs"),
        ("DDoS-Schutz",            "Hetzner-nativ + ModSecurity Rate-Limiting, IP-Reputation"),
        ("Subprozessoren",         "Ausschliesslich EU/EEA-basiert: Hetzner (DE), Mollie (NL)"),
    ]
    for i, (k, v) in enumerate(rows):
        y2 = pdf._table_row(8, y2, [(k, 55), (v, 139)], alt=(i % 2 == 1))
    pdf._h3(8, y2 + 5, "Datenschutz & DSGVO")
    dsgvo = (
        "KyberGuard verarbeitet ausschliesslich die Daten, die fuer den jeweiligen Dienst zwingend "
        "erforderlich sind. Es gibt keine Weitergabe an Dritte ausserhalb der EU, kein Profiling und "
        "kein Tracking. Kunden koennen ihren Account und alle Daten jederzeit selbst loeschen."
    )
    pdf.set_font("Lib", "", 8.5)
    pdf.set_text_color(*WHITE)
    pdf.set_xy(8, y2 + 12)
    pdf.multi_cell(194, 5.2, dsgvo)
    yc = y2 + 30
    yc = pdf._callout(8, yc, 194, "AVV (Auftragsverarbeitungsvertrag):",
                      "Auf Anfrage wird ein DSGVO-konformer AVV bereitgestellt (erforderlich fuer B2B-Kunden).")
    pdf._callout(8, yc, 194, "Loeschung:",
                 "Vollstaendige Datenloesch innerhalb von 30 Tagen nach Kuendigung. Datenexport im maschinenlesbaren Format auf Anfrage.")
    pdf._footer_bar(9)


def page_guardian(pdf):
    pdf.add_page()
    pdf._bg()
    pdf._header_bar()
    pdf._h1(8, 17, "6. GUARDIAN SOC & HYDRA-EYE Intelligence")
    pdf.set_font("Lib", "", 8.5)
    pdf.set_text_color(*GRAY)
    pdf.set_xy(8, 28)
    pdf.cell(0, 5, "KyberGuards interne Sicherheitsinfrastruktur", ln=False)
    intro = (
        "Hinter KyberGuard arbeiten zwei selbst entwickelte Systeme, die fuer Kunden unsichtbar, "
        "aber entscheidend sind: das GUARDIAN Security Operations Center und die HYDRA-EYE "
        "Threat-Intelligence-Pipeline."
    )
    pdf.set_font("Lib", "", 8.5)
    pdf.set_text_color(*WHITE)
    pdf.set_xy(8, 34)
    pdf.multi_cell(194, 5.2, intro)
    # GUARDIAN
    pdf._h3(8, 47, "GUARDIAN SOC - 16 Sicherheitsagenten")
    cols = [("Funktion", 70), ("Aufgabenbereich", 124)]
    y2 = pdf._table_header(8, 54, cols)
    rows = [
        ("Red-Team-Analyse",            "Angriffs-Simulation, Schwachstellenbewertung, adversariales Testen"),
        ("Incident-Koordination",       "Alert-Eskalation, SOC-Steuerung, Incident-Management"),
        ("Data Fusion & Anomalieerkennung", "Pattern Recognition, statistische Anomalieerkennung, Korrelation"),
        ("Threat-Prognose",             "Strategische Einschaetzung, Architektur-Bewertung, Risiko-Modellierung"),
        ("Threat-Hunting",              "APT-Tracking, spezialisierte TTP-Analyse, MITRE ATT&CK-Mapping"),
        ("Deception-Management",        "Honeypot-Betrieb, Fehlalarm-Filterung, Deception-Sensor-Netz"),
        ("Perimeter-Monitoring",        "Firewall-Korrelation, Netzwerk-Anomalien, Geo-IP-Analyse"),
        ("Kommunikations-Sicherheit",   "DNS-Monitoring, Protokoll-Analyse, C2-Erkennung"),
        ("Access-Control & Compliance", "Audit-Log, Zugangsueberwachung, Compliance-Enforcement"),
    ]
    for i, (f, a) in enumerate(rows):
        y2 = pdf._table_row(8, y2, [(f, 70), (a, 124)], alt=(i % 2 == 1))
    pdf.set_font("Lib", "B", 8)
    pdf.set_text_color(*CYAN)
    pdf.set_xy(8, y2 + 3)
    pdf.cell(30, 4.5, "IOC-Datenbank: ", ln=False)
    pdf.set_font("Lib", "", 8)
    pdf.set_text_color(*WHITE)
    pdf.cell(164, 4.5, "25.000+ Indikatoren fuer Kompromittierung (IPs, Domains, Hashes, URLs). Taegl. Aktualisierung aus 9 Quellen.", ln=False)
    # HYDRA-EYE
    pdf._h3(8, y2 + 12, "HYDRA-EYE Threat Intelligence - 9 Datenquellen")
    cols2 = [("Quelle", 48), ("Daten & Typ", 80), ("Genutzt in", 66)]
    y3 = pdf._table_header(8, y2 + 19, cols2)
    rows2 = [
        ("abuse.ch / URLhaus",   "500.000+ Malware-URLs, Live-Feed",             "Phishing-Check, IOC-Abgleich"),
        ("CISA KEV",             "Aktiv ausgenutzte CVEs (US-Behoerde)",          "CVE-Radar, NUCLEI-Priorisierung"),
        ("Feodo Tracker",        "Botnet C2-Server, Banking-Trojaner",            "Ransomware-Monitor, IOC-DB"),
        ("RansomLook API",       "Ransomware-Gruppen, Opfer, TTPs",              "Ransomware-Monitor"),
        ("MaxMind GeoLite2",     "IP-Geolokation, ASN-Daten",                    "Domain-Scanner, Threat Intel"),
        ("MISP Community",       "Strukturierte Threat-Intelligence",            "SOC-Agenten, Korrelation"),
        ("NVD (NIST)",           "CVE-Datenbank, CVSS-Scores",                  "CVE-Radar"),
        ("crt.sh (CT-Logs)",     "Alle oeffentlichen TLS-Zertifikate",           "Domain-Scanner, Subdomain-Enum"),
        ("ThreatFox (abuse.ch)", "Malware-IOCs, aktuelle Kampagnen",            "IOC-Datenbank, Phishing-Check"),
    ]
    for i, r in enumerate(rows2):
        y3 = pdf._table_row(8, y3, [(r[0], 48), (r[1], 80), (r[2], 66)], alt=(i % 2 == 1))
    pdf._footer_bar(10)


def page_roi(pdf):
    pdf.add_page()
    pdf._bg()
    pdf._header_bar()
    pdf._h1(8, 17, "7. ROI & Wirtschaftlicher Nutzen")
    pdf.set_font("Lib", "", 8.5)
    pdf.set_text_color(*GRAY)
    pdf.set_xy(8, 28)
    pdf.cell(0, 5, "Was kostet Cybersicherheit ohne KyberGuard - und was mit?", ln=False)
    intro = (
        'Die Frage "Was kostet Cybersicherheit?" wird oft falsch gestellt. '
        'Die richtige Frage lautet: Was kostet ein Sicherheitsvorfall ohne ausreichende Massnahmen?'
    )
    pdf.set_font("Lib", "", 8.5)
    pdf.set_text_color(*WHITE)
    pdf.set_xy(8, 34)
    pdf.multi_cell(194, 5.2, intro)
    cols = [("Massnahme", 62), ("Marktpreis ohne KyberGuard", 70), ("In KyberGuard enthalten", 62)]
    y2 = pdf._table_header(8, 46, cols)
    rows = [
        ("NIS2-Erstberatung",               "1.500 - 5.000 EUR einmalig",    "Pro-Plan (34,99 EUR/Mo.)"),
        ("Domain- & Infrastruktur-Pentest", "3.000 - 15.000 EUR / Jahr",     "Business-Plan (99,99 EUR/Mo.)"),
        ("Dark Web Monitoring (Enterprise)", "2.400 - 12.000 EUR / Jahr",    "Ab Personal (4,99 EUR/Mo.)"),
        ("Vulnerability Scanner (Lizenz)",  "5.000 - 20.000 EUR / Jahr",     "Business-Plan (NUCLEI)"),
        ("SOC-as-a-Service",                "24.000 - 60.000 EUR / Jahr",    "KyberGuard-intern (GUARDIAN)"),
        ("IR-Berater im Ernstfall",         "1.500 - 5.000 EUR / Tag",       "KI-IR-Playbook in Pro"),
    ]
    for i, r in enumerate(rows):
        y2 = pdf._table_row(8, y2, [(r[0], 62), (r[1], 70), (r[2], 62)], alt=(i % 2 == 1))
    pdf._h3(8, y2 + 6, "Durchschnittliche Kosten eines Cybervorfalls fuer KMU (Deutschland 2025):")
    cols2 = [("Vorfallstyp", 60), ("Direktschaden", 72), ("Reputationsschaden", 62)]
    y3 = pdf._table_header(8, y2 + 14, cols2)
    rows2 = [
        ("Ransomware-Angriff",          "50.000 - 2 Mio. EUR",             "Hoch (Kundenvertrauensverlust)"),
        ("Datenpanne (DSGVO)",          "Bussgeld + Schadenersatz: bis 20 Mio.", "Mittel bis sehr hoch"),
        ("CEO-Fraud / BEC",             "Ø 50.000 - 500.000 EUR",          "Mittel"),
        ("Betriebsunterbrechung (3 Tage)", "Ø 75.000 EUR fuer KMU",        "Gering bis mittel"),
        ("NIS2-Bussgeld",               "Bis 10 Mio. EUR oder 2% Umsatz",  "Hoch"),
    ]
    for i, r in enumerate(rows2):
        y3 = pdf._table_row(8, y3, [(r[0], 60), (r[1], 72), (r[2], 62)], alt=(i % 2 == 1))
    fazit = (
        "KyberGuard Business (99,99 EUR/Monat = 999,90 EUR/Jahr) ersetzt Einzelloesungen im Wert von "
        "30.000-50.000 EUR/Jahr. Selbst der Pro-Plan (349,90 EUR/Jahr) deckt NIS2-Compliance, "
        "Schwachstellen-Scanning und Dark Web Monitoring ab - Leistungen, fuer die KMU andernfalls "
        "Berater im vierstelligen Bereich engagieren."
    )
    pdf.set_font("Lib", "B", 8)
    pdf.set_text_color(*CYAN)
    pdf.set_xy(8, y3 + 5)
    pdf.cell(12, 4.5, "Fazit: ", ln=False)
    pdf.set_font("Lib", "", 8)
    pdf.set_text_color(*WHITE)
    pdf.multi_cell(182, 4.5, fazit)
    pdf._footer_bar(11)


def page_faq(pdf):
    pdf.add_page()
    pdf._bg()
    pdf._header_bar()
    pdf._h1(8, 17, "8. Haeufige Fragen")
    pdf.set_font("Lib", "", 8.5)
    pdf.set_text_color(*GRAY)
    pdf.set_xy(8, 28)
    pdf.cell(0, 5, "FAQ fuer IT-Verantwortliche und Entscheider", ln=False)

    faqs = [
        ("F: Bin ich als KMU wirklich von NIS2 betroffen?",
         "A: NIS2 gilt fuer Unternehmen ab 50 Mitarbeitern ODER 10 Mio. EUR Jahresumsatz in bestimmten Sektoren "
         "(Energie, Transport, Gesundheit, digitale Infrastruktur, Fertigung u.a.). Kleine Unternehmen in "
         "kritischen Sektoren koennen ebenfalls betroffen sein. Der KyberGuard NIS2-Eligibility-Check gibt in "
         "5 Minuten Klarheit - kostenlos im Pro-Plan."),
        ("F: Werden meine Daten in die USA uebertragen?",
         "A: Nein. Alle Server stehen in Frankfurt am Main (Hetzner). Kein US-Cloud-Provider, keine "
         "Subprozessoren ausserhalb der EU. Die KI-Analyse erfolgt ueber EU-geroutetes API-Routing "
         "(keine direkte US-Datenverarbeitung)."),
        ("F: Wie lange dauert ein Domain-Scan?",
         "A: Einfache Domains: 2-5 Minuten. Grosse Domaenen mit vielen Subdomains: bis 15 Minuten. "
         "Ergebnisse werden live im Dashboard angezeigt. PDF-Report fuer Business+-Kunden verfuegbar."),
        ("F: Kann KyberGuard meine vorhandene Sicherheitssoftware ersetzen?",
         "A: KyberGuard ergaenzt vorhandene Loesungen (Endpoint-Security, Firewall) um Aussensicht, "
         "Compliance und Intelligence. Es ersetzt keinen Endpoint-Scanner, ergaenzt ihn aber um die "
         "Perspektive, die Angreifer auf Ihr Unternehmen haben."),
        ("F: Was passiert im Ernstfall - gibt es Support?",
         "A: Business- und Enterprise-Kunden erhalten priorisierten Support (< 24h bzw. < 4h). Der "
         "KI-IR-Playbook-Generator liefert sofort einen strukturierten Reaktionsplan. Enterprise-Kunden "
         "haben einen dedizierten Account-Manager."),
        ("F: Wie sicher ist KyberGuard selbst?",
         "A: KyberGuard betreibt eine ModSecurity WAF (OWASP CRS, Blocking Mode), TLS 1.3-Verschluesselung, "
         "regelmaessige NUCLEI-Selbstscans und ein 24/7 SOC (GUARDIAN) mit 16 Sicherheitsagenten und 25.000+ IOCs."),
        ("F: Unterstuetzt KyberGuard White-Label fuer MSPs und IT-Dienstleister?",
         "A: Ja. Enterprise-Kunden erhalten White-Label-Reporting und Partner-API-Zugang. MSPs koennen "
         "KyberGuard-Berichte unter eigenem Branding an ihre Endkunden weitergeben. Kontakt: info@kyberguard.de"),
    ]
    y = 35
    for q, a in faqs:
        pdf.set_font("Lib", "B", 8.5)
        pdf.set_text_color(*WHITE)
        pdf.set_xy(8, y)
        pdf.multi_cell(194, 5.2, q)
        y = pdf.get_y() + 1
        pdf.set_font("Lib", "", 8.5)
        pdf.set_text_color(*GRAY)
        pdf.set_xy(8, y)
        pdf.multi_cell(194, 5.0, a)
        y = pdf.get_y() + 5
    pdf._footer_bar(12)


def page_kontakt(pdf):
    pdf.add_page()
    pdf._bg()
    pdf._header_bar()
    pdf._h1(8, 17, "9. Kontakt & Naechste Schritte")
    pdf.set_font("Lib", "I", 8.5)
    pdf.set_text_color(*GRAY)
    pdf.set_xy(8, 28)
    pdf.cell(0, 5, "Jetzt starten - ohne Risiko", ln=False)
    cta = (
        "KyberGuard ist sofort verfuegbar. Der Free-Plan erfordert keine Kreditkarte und gibt unmittelbaren "
        "Zugang zu Phishing-Check, Telefon-Check und WiFi-Analyse. Bezahlte Plaene koennen jederzeit "
        "monatlich gekuendigt werden."
    )
    pdf.set_font("Lib", "", 8.5)
    pdf.set_text_color(*WHITE)
    pdf.set_xy(8, 34)
    pdf.multi_cell(194, 5.2, cta)
    cols = [("Schritt", 20), ("Aktion", 124), ("Zeitaufwand", 50)]
    y2 = pdf._table_header(8, 50, cols)
    steps = [
        ("1", "Kostenlos registrieren auf kyberguard.de",                    "2 Minuten"),
        ("2", "Ersten Phishing-Check ohne Login durchfuehren",               "30 Sekunden"),
        ("3", "Pro-Plan aktivieren, Domain verifizieren",                    "5 Minuten"),
        ("4", "NIS2-Check ausfuellen, Compliance-Score ermitteln",           "15-20 Minuten"),
        ("5", "Domain-Scanner starten, ersten Report erhalten",              "5 Minuten warten"),
        ("6", "Massnahmen priorisieren mit KyberAssist-Unterstuetzung",       "Fortlaufend"),
    ]
    for i, (s, a, z) in enumerate(steps):
        y2 = pdf._table_row(8, y2, [(s, 20), (a, 124), (z, 50)], alt=(i % 2 == 1))
    # Kontakt-Tabelle
    pdf._h3(8, y2 + 8, "Kontakt")
    cols2 = [("Kanal", 50), ("Kontakt", 144)]
    y3 = pdf._table_header(8, y2 + 15, cols2)
    contacts = [
        ("Website",               "kyberguard.de"),
        ("E-Mail",                "info@kyberguard.de"),
        ("Business-Anfragen",     "info@kyberguard.de - Betreff: Business-Anfrage"),
        ("Impressum / Datenschutz", "kyberguard.de/impressum | kyberguard.de/datenschutz"),
        ("Herausgeber",           "AP Digital Solution, Hamburg, Deutschland"),
    ]
    for i, (k, v) in enumerate(contacts):
        y3 = pdf._table_row(8, y3, [(k, 50), (v, 144)], alt=(i % 2 == 1))
    # Schlusslinie
    pdf.set_fill_color(*BORDER)
    pdf.rect(8, y3 + 12, 194, 0.5, "F")
    pdf.set_font("Lib", "I", 7.5)
    pdf.set_text_color(*GRAY)
    pdf.set_xy(8, y3 + 16)
    pdf.multi_cell(194, 4.5,
        "Dieses Dokument beschreibt den aktuellen Funktionsstand von KyberGuard (Stand: Juni 2026). "
        "Aenderungen vorbehalten. Alle Angaben ohne Gewaehr.", align="C")
    pdf._footer_bar(13)


# ============================================================
# MAIN
# ============================================================
def build():
    pdf = KPdf()
    page_title(pdf)
    page_architektur(pdf)
    page_zielgruppe(pdf)
    page_phishing_darkweb(pdf)
    page_domain_nis2(pdf)
    page_weitere_module(pdf)
    page_plaene_1(pdf)
    page_plaene_2(pdf)
    page_infrastruktur(pdf)
    page_guardian(pdf)
    page_roi(pdf)
    page_faq(pdf)
    page_kontakt(pdf)

    out = "/mnt/c/Users/ceule/Downloads/kyberguard-fachlicher-ueberblick-2026-v2.pdf"
    pdf.output(out)
    print(f"PDF erstellt: {out}")


if __name__ == "__main__":
    build()
