"""
KyberGuard Phone Audit Engine
Analysiert installierte Android-Apps auf Sicherheitsrisiken.
Gibt Dual-Score: Klassisch + Quantum-Ready
"""

# ============================================================
# RISIKO-DATENBANK
# Jeder Eintrag: package_name -> {risk, name, reason, category}
# risk: "critical" | "high" | "medium" | "low" | "safe"
# ============================================================

RISK_DB = {
    # ---- XIAOMI TRACKING (Critical) ----
    "com.xiaomi.joyose":            {"risk": "critical", "name": "Xiaomi Joyose",          "reason": "Sammelt App-Nutzungsdaten, sendet zu Xiaomi-Servern. Kamera/Mikrofon-Zugriff.",      "category": "spyware"},
    "com.miui.analytics":           {"risk": "critical", "name": "MIUI Analytics",          "reason": "Tracking-Dienst mit Standortzugriff, sendet Daten zu Xiaomi.",                         "category": "spyware"},
    "com.miui.misightservice":      {"risk": "critical", "name": "MiSight Service",          "reason": "Telemetrie mit aktivem Kamera + Mikrofon-Foreground-Service.",                         "category": "spyware"},
    "com.miui.msa.global":          {"risk": "critical", "name": "Xiaomi Ad Service",        "reason": "Xiaomi Werbeplattform mit SYSTEM_ALERT_WINDOW und WRITE_SECURE_SETTINGS.",             "category": "adware"},
    "com.miui.daemon":              {"risk": "high",     "name": "MIUI Daemon",              "reason": "Privilegierter Systemdaemon mit Kamera/Mikrofon-Foreground-Berechtigung.",             "category": "tracking"},
    "com.miui.guardprovider":       {"risk": "medium",   "name": "MIUI Guard Provider",      "reason": "Weitreichende Systemrechte, chinesisches Framework.",                                  "category": "tracking"},
    "com.xiaomi.xmsf":              {"risk": "medium",   "name": "Xiaomi Push Service",      "reason": "Persistente Verbindung zu Xiaomi-Servern.",                                            "category": "tracking"},
    "com.miui.cloudservice":        {"risk": "medium",   "name": "Mi Cloud",                 "reason": "Synchronisiert Daten zu Xiaomi-Servern (China).",                                      "category": "cloud"},
    "com.mi.globalminusscreen":     {"risk": "medium",   "name": "Mi Minus Screen",          "reason": "Ruft Google Advertising ID für Xiaomi ab.",                                            "category": "adware"},
    "com.xiaomi.aicr":              {"risk": "medium",   "name": "Xiaomi AI Cognition",      "reason": "Unbekannte KI-Funktion, läuft als Hintergrunddienst.",                                 "category": "tracking"},

    # ---- META / FACEBOOK (High) ----
    "com.facebook.katana":          {"risk": "high",     "name": "Facebook",                 "reason": "Umfangreiches Tracking, persistente Hintergrunddienste, Profiling.",                  "category": "tracking"},
    "com.facebook.orca":            {"risk": "high",     "name": "Facebook Messenger",       "reason": "READ_SMS + READ_CONTACTS, persistente MQTT-Verbindung, umfangreiches Tracking.",      "category": "tracking"},
    "com.instagram.android":        {"risk": "high",     "name": "Instagram",                "reason": "Permanenter Hintergrundabruf, 282MB RAM, Kamera/Mikrofon-Zugriff.",                   "category": "tracking"},
    "com.facebook.services":        {"risk": "medium",   "name": "Facebook Services",        "reason": "Hintergrunddienste für Meta-Produkte.",                                               "category": "tracking"},

    # ---- TIKTOK / BYTEDANCE (High) ----
    "com.zhiliaoapp.musically":     {"risk": "high",     "name": "TikTok",                   "reason": "Datentransfer zu ByteDance-Servern (China), umfangreicher Gerätezugriff.",            "category": "spyware"},
    "com.ss.android.ugc.trill":     {"risk": "high",     "name": "TikTok (Global)",           "reason": "Datentransfer zu ByteDance-Servern (China), umfangreicher Gerätezugriff.",            "category": "spyware"},

    # ---- BEKANNTE ADWARE / STALKERWARE (Critical) ----
    "com.cerberus.application":     {"risk": "critical", "name": "Cerberus Spyware",          "reason": "Bekannte Stalkerware / Remote-Access-Tool.",                                          "category": "stalkerware"},
    "com.flexispy.android":         {"risk": "critical", "name": "FlexiSpy",                  "reason": "Bekannte kommerzielle Spyware.",                                                       "category": "stalkerware"},
    "com.mspy.android":             {"risk": "critical", "name": "mSpy",                      "reason": "Bekannte kommerzielle Stalkerware.",                                                   "category": "stalkerware"},
    "com.hoverwatch":               {"risk": "critical", "name": "Hoverwatch",                "reason": "Versteckte Überwachungs-App.",                                                        "category": "stalkerware"},
    "com.thetruthspy":              {"risk": "critical", "name": "TruthSpy",                  "reason": "Bekannte Stalkerware, massive Datenlecks gemeldet.",                                  "category": "stalkerware"},
    "org.puremessaging":            {"risk": "high",     "name": "Pure Instant Messenger",   "reason": "Verbreitung von Adware dokumentiert.",                                                "category": "adware"},

    # ---- CHINESISCHE APPS (Medium-High) ----
    "com.alibaba.aliexpresshd":     {"risk": "medium",   "name": "AliExpress",               "reason": "Umfangreiches Tracking, Verbindungen zu Alibaba-Servern (China).",                    "category": "tracking"},
    "com.taobao.taobao":            {"risk": "high",     "name": "Taobao",                   "reason": "Umfangreiches Tracking, chinesische Server, bekannte Privacy-Probleme.",              "category": "tracking"},
    "com.tencent.mm":               {"risk": "high",     "name": "WeChat",                   "reason": "Chinesische Überwachungspflichten für Tencent, umfanglicher Datenzugriff.",           "category": "spyware"},
    "com.shein.rome":               {"risk": "medium",   "name": "SHEIN",                    "reason": "Tracking, Verbindungen zu chinesischen Servern.",                                     "category": "tracking"},
    "com.pinduoduo.android":        {"risk": "critical", "name": "Pinduoduo/Temu",           "reason": "Offiziell von Google aus Play Store entfernt wegen Malware-Verdacht (2023).",        "category": "malware"},
    "com.temu.android":             {"risk": "high",     "name": "Temu",                     "reason": "Schwester-App von Pinduoduo, umfangreiches Geräte-Fingerprinting.",                  "category": "tracking"},

    # ---- VERDÄCHTIGE UNBEKANNTE APPS (aus Lees Analyse) ----
    "com.josepha":                  {"risk": "critical", "name": "Unbekannte App (josepha)", "reason": "Kein erkennbarer Publisher, React Native + Firebase, kürzlich aktualisiert.",        "category": "unknown"},
    "com.onlinedezormovies.streamtvshows": {"risk": "high", "name": "Streaming-App (unbekannt)", "reason": "Nicht im Play Store, verdächtiger Package-Name, veraltet (targetSdk=32).",       "category": "unknown"},
    "plus.adaptive.goatchat":       {"risk": "medium",   "name": "GoatChat",                 "reason": "Unbekannte Chat-App, keine nachweisbare Reputation.",                                 "category": "unknown"},
    "ai.one.algos.algosone":        {"risk": "medium",   "name": "AlgosOne AI",              "reason": "Unbekannter KI/Trading-Dienst, keine verifizierten Reviews.",                        "category": "unknown"},

    # ---- CRYPTO-RISIKO (Medium - wegen Angriffsfläche) ----
    "io.metamask":                  {"risk": "medium",   "name": "MetaMask",                 "reason": "Krypto-Wallet auf Smartphone = hohes Diebstahl-Risiko. Hardware-Wallet empfohlen.",   "category": "crypto_risk"},
    "com.nexowallet":               {"risk": "medium",   "name": "Nexo Wallet",              "reason": "Krypto-Wallet auf Smartphone. Hardware-Wallet empfohlen.",                            "category": "crypto_risk"},
    "org.toshi":                    {"risk": "medium",   "name": "Coinbase Wallet",          "reason": "Krypto-Wallet auf Smartphone. Hardware-Wallet empfohlen.",                            "category": "crypto_risk"},
    "app.phantom":                  {"risk": "medium",   "name": "Phantom Wallet",           "reason": "Krypto-Wallet auf Smartphone. Hardware-Wallet empfohlen.",                            "category": "crypto_risk"},
    "com.cakedefi.app":             {"risk": "medium",   "name": "Cake DeFi",                "reason": "Krypto-Wallet auf Smartphone. Hardware-Wallet empfohlen.",                            "category": "crypto_risk"},
    "piuk.blockchain.android":      {"risk": "medium",   "name": "Blockchain.com Wallet",    "reason": "Krypto-Wallet auf Smartphone. Hardware-Wallet empfohlen.",                            "category": "crypto_risk"},
    "com.livingroomofsatoshi.wallet": {"risk": "medium", "name": "Living Room of Satoshi",  "reason": "Krypto-Dienst auf Smartphone. Hardware-Wallet empfohlen.",                            "category": "crypto_risk"},

    # ---- SICHERHEITS-BONUS (Gut) ----
    "org.thoughtcrime.securesms":   {"risk": "safe",     "name": "Signal",                   "reason": "Ende-zu-Ende-verschlüsselt, Open Source, Best-in-Class Messaging.",                  "category": "security_good"},
    "com.brave.browser":            {"risk": "safe",     "name": "Brave Browser",            "reason": "Privacy-Browser mit eingebautem Ad/Tracker-Blocker.",                                "category": "security_good"},
    "net.mullvad.mullvadvpn":       {"risk": "safe",     "name": "Mullvad VPN",              "reason": "No-Log VPN, auditiert, empfohlen von Security-Experten.",                            "category": "security_good"},
    "com.protonvpn.android":        {"risk": "safe",     "name": "ProtonVPN",                "reason": "No-Log VPN aus der Schweiz, Open Source, auditiert.",                                "category": "security_good"},
    "com.tailscale.ipn.android":    {"risk": "safe",     "name": "Tailscale",                "reason": "Sicheres WireGuard-basiertes Mesh-VPN.",                                             "category": "security_good"},
    "org.torproject.android":       {"risk": "safe",     "name": "Tor Browser",              "reason": "Anonymes Browsen über das Tor-Netzwerk.",                                            "category": "security_good"},
    "com.nextcloud.client":         {"risk": "safe",     "name": "Nextcloud",                "reason": "Self-hosted Cloud-Lösung, eigene Kontrolle über Daten.",                             "category": "security_good"},
    "com.bitwarden.mobile":         {"risk": "safe",     "name": "Bitwarden",                "reason": "Open-Source Passwort-Manager, auditiert.",                                           "category": "security_good"},
    "com.ledger.live":              {"risk": "safe",     "name": "Ledger Live",              "reason": "Hardware-Wallet App — sichere Verwaltung von Krypto.",                               "category": "security_good"},
    "com.avast.android.mobilesecurity": {"risk": "safe", "name": "Avast Mobile Security",   "reason": "Bekannte Sicherheits-App, Accessibility-Service für Web-Schutz aktiv.",             "category": "security_good"},
    "com.bitdefender.security":     {"risk": "safe",     "name": "Bitdefender Mobile",       "reason": "Bekannte Sicherheits-App.",                                                          "category": "security_good"},
}

# Score-Penaltys
PENALTY = {
    "critical": 20,
    "high":     12,
    "medium":   5,
    "low":      2,
}

# Quantum-Ready Faktoren: Welche Apps/Eigenschaften geben Quantum-Score-Bonus?
QUANTUM_POSITIVE_KEYWORDS = [
    "vpn", "signal", "proton", "mullvad", "tailscale", "tor", "brave", "bitwarden"
]
QUANTUM_NEGATIVE_KEYWORDS = [
    "facebook", "instagram", "tiktok", "xiaomi", "miui", "joyose", "analytics"
]


def analyze_packages(package_list: list[str], is_pro: bool) -> dict:
    """
    Analysiert eine Liste von Package-Namen.
    Gibt strukturierten Report zurück.
    """
    findings = {"critical": [], "high": [], "medium": [], "safe": []}
    classic_score = 100
    quantum_score = 50  # Basis
    crypto_count = 0
    security_app_count = 0

    for pkg in package_list:
        pkg = pkg.strip().lower()
        if not pkg:
            continue

        entry = RISK_DB.get(pkg)
        if not entry:
            # Heuristik: verdächtige Package-Namen erkennen
            entry = _heuristic_check(pkg)

        if entry:
            risk = entry["risk"]
            if risk in PENALTY:
                classic_score -= PENALTY[risk]
                findings[risk].append(entry)
            elif risk == "safe":
                classic_score = min(100, classic_score + 3)
                security_app_count += 1
                findings["safe"].append(entry)

            if entry.get("category") == "crypto_risk":
                crypto_count += 1

        # Quantum-Score Heuristik
        for kw in QUANTUM_POSITIVE_KEYWORDS:
            if kw in pkg:
                quantum_score = min(100, quantum_score + 5)
        for kw in QUANTUM_NEGATIVE_KEYWORDS:
            if kw in pkg:
                quantum_score = max(0, quantum_score - 8)

    # Krypto-Penalty: Viele Wallets ohne Hardware-Wallet = Risiko
    if crypto_count >= 5:
        classic_score -= 10
        quantum_score -= 15
    elif crypto_count >= 3:
        classic_score -= 5
        quantum_score -= 8

    # Sicherheits-Apps als Bonus
    if security_app_count >= 2:
        quantum_score = min(100, quantum_score + 10)

    classic_score = max(0, min(100, classic_score))
    quantum_score = max(0, min(100, quantum_score))

    return {
        "classic_score": classic_score,
        "quantum_score": quantum_score,
        "findings": findings,
        "crypto_count": crypto_count,
        "total_analyzed": len([p for p in package_list if p.strip()]),
        "is_pro": is_pro,
    }


def _heuristic_check(pkg: str) -> dict | None:
    """Erkennt verdächtige Apps anhand Package-Namen-Heuristiken."""
    suspicious_keywords = ["spy", "track", "monitor", "keylog", "stalk", "hidden", "invisible"]
    for kw in suspicious_keywords:
        if kw in pkg:
            return {
                "risk": "high",
                "name": pkg,
                "reason": f"Package-Name enthält verdächtiges Keyword: '{kw}'.",
                "category": "suspicious",
            }
    # Sehr kurze, generische Package-Namen (wie com.josepha)
    parts = pkg.split(".")
    if len(parts) == 2 and len(parts[1]) < 8:
        return {
            "risk": "medium",
            "name": pkg,
            "reason": "Ungewöhnlich kurzer/generischer Package-Name — Herkunft prüfen.",
            "category": "unknown",
        }
    return None


def _score_bar(score: int, length: int = 10) -> str:
    filled = round(score / 100 * length)
    return "█" * filled + "░" * (length - filled)


def _grade(score: int) -> str:
    if score >= 90: return "A+"
    if score >= 80: return "A"
    if score >= 70: return "B"
    if score >= 60: return "C"
    if score >= 50: return "D"
    return "F"


def format_report(result: dict) -> str:
    """Formatiert den Audit-Report als Telegram-Nachricht."""
    cs = result["classic_score"]
    qs = result["quantum_score"]
    findings = result["findings"]
    is_pro = result["is_pro"]
    total = result["total_analyzed"]

    critical = findings["critical"]
    high = findings["high"]
    medium = findings["medium"]
    safe_apps = findings["safe"]
    total_risks = len(critical) + len(high) + len(medium)

    lines = [
        "🔍 *KyberGuard Phone Audit*\n",
        f"📱 Analysierte Apps: {total}",
        f"⚠️ Risiken gefunden: {total_risks}\n",
        "━━━━━━━━━━━━━━━━━━━━",
        "*SICHERHEITS-SCORE*\n",
        f"Klassisch (2026):      `[{_score_bar(cs)}]` {cs}/100 — Note {_grade(cs)}",
        f"Quantum-Ready (2030+): `[{_score_bar(qs)}]` {qs}/100 — Note {_grade(qs)}",
        "━━━━━━━━━━━━━━━━━━━━",
    ]

    if critical:
        lines.append(f"\n🔴 *KRITISCH ({len(critical)}):*")
        for app in critical[:3 if not is_pro else 10]:
            lines.append(f"• *{app['name']}*\n  _{app['reason']}_")
        if not is_pro and len(critical) > 3:
            lines.append(f"_+{len(critical)-3} weitere — vollständiger Report mit /upgrade_")

    if high:
        lines.append(f"\n🟠 *HOCH ({len(high)}):*")
        for app in high[:2 if not is_pro else 10]:
            lines.append(f"• *{app['name']}*\n  _{app['reason']}_")
        if not is_pro and len(high) > 2:
            lines.append(f"_+{len(high)-2} weitere — vollständiger Report mit /upgrade_")

    if is_pro and medium:
        lines.append(f"\n🟡 *MITTEL ({len(medium)}):*")
        for app in medium[:5]:
            lines.append(f"• *{app['name']}* — _{app['reason']}_")

    if safe_apps:
        lines.append(f"\n🟢 *POSITIV ({len(safe_apps)}):*")
        for app in safe_apps[:3]:
            lines.append(f"• {app['name']} ✅")

    # Krypto-Warnung
    if result["crypto_count"] >= 3:
        lines.append(
            f"\n💰 *Krypto-Warnung:* {result['crypto_count']} Wallets auf Smartphone erkannt.\n"
            "Hardware-Wallet (z.B. Ledger) dringend empfohlen!"
        )

    # Top-Empfehlungen
    lines.append("\n━━━━━━━━━━━━━━━━━━━━")
    lines.append("💡 *TOP EMPFEHLUNGEN:*\n")
    recs = _get_recommendations(result)
    for i, rec in enumerate(recs[:3], 1):
        lines.append(f"{i}. {rec}")

    if not is_pro:
        lines.append(
            "\n🔒 *Pro/Business:* Vollständiger Report mit allen Risiken, "
            "Quantum-Score Analyse und persönlichen Maßnahmen.\n👉 /upgrade"
        )

    lines.append("\n_KyberGuard Phone Audit — @KyberGuardBot_")
    return "\n".join(lines)


def _get_recommendations(result: dict) -> list[str]:
    recs = []
    findings = result["findings"]

    if findings["critical"]:
        recs.append("🔴 Kritische Apps sofort deinstallieren oder deaktivieren.")
    if result["crypto_count"] >= 3:
        recs.append("💰 Hardware-Wallet (Ledger Nano) für Krypto-Assets nutzen.")
    if result["quantum_score"] < 50:
        recs.append("🛡️ Quantum-Safe VPN einrichten — dein Schutz für 2030.")
    if not any("vpn" in a["name"].lower() for a in findings["safe"]):
        recs.append("🌐 Vertrauenswürdiges VPN installieren (ProtonVPN, Mullvad).")
    if not any("signal" in a["name"].lower() for a in findings["safe"]):
        recs.append("💬 Signal statt WhatsApp/Messenger für sichere Kommunikation.")
    if result["classic_score"] < 70:
        recs.append("📱 USB-Debugging deaktivieren wenn nicht aktiv genutzt.")
    recs.append("🔒 Entwickleroptionen nach Analyse deaktivieren.")
    return recs
