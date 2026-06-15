"""
Cassandra — Phishing Emotion-Indikator Layer
Basiert auf Longinus "On the Sublime" (~1. Jh.):
Phishing invertiert erhabene Rhetorik — falsche Autorität statt echter Bedeutung,
künstliche Dringlichkeit statt echter Leidenschaft, Angst statt Inspiration.
7 Emotion-Cluster identifizieren diese Inversion.

Integration: In public.py als neue Schicht aufrufen:
    from phishing_emotion_layer import analyze_emotion_indicators
    emotion = analyze_emotion_indicators(text)
    score += emotion["risk_contribution"]
    result["emotion_indicators"] = emotion
"""
import re
from typing import Optional

# ---------------------------------------------------------------------------
# Cluster-Definitionen (DE + EN, lowercase)
# Longinus-Mapping in Kommentaren
# ---------------------------------------------------------------------------

_CLUSTERS: dict[str, dict] = {
    # Longinus: "Starke und begeisterte Leidenschaften" — Phishing: künstliche Dringlichkeit
    "urgency": {
        "weight": 1.2,
        "de": [
            "sofort", "unverzüglich", "dringend", "dringende", "letzte chance",
            "läuft ab", "abgelaufen", "ablauf", "frist", "innerhalb von",
            "innerhalb 24", "heute noch", "noch heute", "jetzt handeln",
            "umgehend", "sofortige", "zeitkritisch",
        ],
        "en": [
            "immediately", "urgent", "urgently", "last chance", "expires",
            "expiring", "deadline", "within 24", "act now", "right away",
            "asap", "time-sensitive", "today only",
        ],
    },
    # Longinus: "Kraft der großen Gedanken" — Phishing: Angst als Manipulation
    "fear": {
        "weight": 1.4,
        "de": [
            "gesperrt", "blockiert", "deaktiviert", "gelöscht", "eingefroren",
            "beschlagnahmt", "verloren", "gefährdet", "kompromittiert",
            "gehackt", "unbefugter zugriff", "verdächtige aktivität",
            "sicherheitsverstoß", "nicht mehr zugreifen",
        ],
        "en": [
            "locked", "blocked", "deactivated", "deleted", "suspended",
            "frozen", "seized", "compromised", "hacked", "unauthorized access",
            "suspicious activity", "security breach", "unusual activity",
        ],
    },
    # Longinus: "Edle Ausdrucksweise" — Phishing: Institution impersonation
    "authority": {
        "weight": 1.3,
        "de": [
            "ihre bank", "volksbank", "sparkasse", "deutsche bank", "commerzbank",
            "postbank", "ing", "finanzamt", "bundeszentralamt", "bsi",
            "polizei", "staatsanwaltschaft", "gericht", "ministerium",
            "behörde", "zoll", "bundesregierung",
            "paypal", "amazon", "microsoft", "apple", "dhl", "fedex", "ups",
            "netflix", "ebay", "facebook", "google",
        ],
        "en": [
            "your bank", "irs", "fbi", "cia", "nsa", "government", "court",
            "attorney general", "police", "microsoft", "apple", "amazon",
            "paypal", "ebay", "netflix", "google", "facebook",
        ],
    },
    # Longinus: "Verlockung durch Gewinn" — Phishing: Gier-Trigger
    "greed": {
        "weight": 1.0,
        "de": [
            "gewonnen", "herzlichen glückwunsch", "preis", "gewinn",
            "gutschein", "rückerstattung", "erstattung", "bonus", "cashback",
            "kostenlos", "gratis", "geschenk", "belohnung", "erbschaft",
            "erbschaft", "lotterie", "jackpot",
        ],
        "en": [
            "you have won", "congratulations", "prize", "refund", "cashback",
            "bonus", "free", "gift", "reward", "inheritance", "lottery",
            "jackpot", "unclaimed",
        ],
    },
    # Longinus: "Würdige Komposition" — Phishing: Vertrauens-Simulation
    "social_proof": {
        "weight": 1.1,
        "de": [
            "ihr konto", "ihre bestellung", "ihr profil", "ihre daten",
            "ihr gerät", "wir haben festgestellt", "wir möchten sie informieren",
            "wir haben bemerkt", "ihre zahlung", "ihr passwort",
            "ihr zugang", "ihre identität",
        ],
        "en": [
            "your account", "your order", "your profile", "your device",
            "we detected", "we noticed", "we have identified", "your payment",
            "your password", "your identity", "we inform you",
        ],
    },
    # Longinus: "Überwältigende Kraft" — Phishing: rechtliche Drohung
    "threat": {
        "weight": 1.5,
        "de": [
            "anzeige", "strafanzeige", "klage", "strafverfolgung",
            "rechtliche schritte", "bußgeld", "strafe", "inkasso",
            "pfändung", "vollstreckung", "haftung", "schadensersatz",
        ],
        "en": [
            "lawsuit", "legal action", "criminal charges", "prosecution",
            "fine", "penalty", "debt collection", "enforcement", "liability",
            "damages", "report to authorities",
        ],
    },
    # Longinus: "Rhetorische Figuren" — Phishing: Handlungs-Zwang
    "action_compulsion": {
        "weight": 0.8,
        "de": [
            "klicken sie hier", "klicken sie auf", "bestätigen sie",
            "verifizieren sie", "aktualisieren sie", "überprüfen sie",
            "loggen sie sich ein", "melden sie sich an",
            "geben sie ihre daten ein", "link unten",
        ],
        "en": [
            "click here", "click below", "click the link", "confirm now",
            "verify your", "update your", "log in now", "sign in",
            "enter your details", "follow the link",
        ],
    },
}

# Score-Schwellen → risk_contribution für Phishing-Scanner
_RISK_LEVELS = [
    (0.7, -1.5),   # sehr hoch
    (0.5, -1.0),   # hoch
    (0.3, -0.5),   # mittel
    (0.0,  0.0),   # niedrig
]


def analyze_emotion_indicators(text: str, lang: Optional[str] = None) -> dict:
    """
    Analysiert Text auf emotionale Manipulations-Indikatoren.

    Args:
        text: Zu analysierender Text (HTML/Plaintext, DE oder EN)
        lang: Optional "de" oder "en" — wenn None, beide Sprachen geprüft

    Returns:
        {
            "emotion_score": float (0.0-1.0),
            "detected_clusters": {cluster: count},
            "dominant_emotion": str | None,
            "active_cluster_count": int,
            "risk_contribution": float (negativ, als Penalty für Phishing-Score),
            "top_matches": [str],  # bis zu 5 Treffer zur Erklärung
        }
    """
    text_lower = text.lower()
    # HTML-Tags grob entfernen für sauberes Matching
    text_clean = re.sub(r"<[^>]+>", " ", text_lower)
    text_clean = re.sub(r"\s+", " ", text_clean)

    detected: dict[str, int] = {}
    top_matches: list[str] = []
    cluster_scores: dict[str, float] = {}

    check_langs = [lang] if lang in ("de", "en") else ["de", "en"]

    for cluster_name, cluster in _CLUSTERS.items():
        hits = 0
        for lng in check_langs:
            for keyword in cluster[lng]:
                if keyword in text_clean:
                    hits += 1
                    if len(top_matches) < 5:
                        top_matches.append(f"{cluster_name}:{keyword}")

        if hits > 0:
            detected[cluster_name] = hits
            # Pro Cluster: bis zu 0.5 Punkte, Hits gewichtet, mit Cluster-Gewicht
            raw = min(hits * 0.15, 0.5) * cluster["weight"]
            cluster_scores[cluster_name] = round(raw, 3)

    # Kombinations-Bonus: mehrere Cluster aktiv erhöht Score (APT-Phishing kombiniert immer)
    active = len(detected)
    combo_bonus = 0.0
    if active >= 3:
        combo_bonus = 0.1 * (active - 2)   # +0.1 pro zusätzlichem Cluster ab 3

    raw_score = sum(cluster_scores.values()) + combo_bonus
    emotion_score = round(min(raw_score, 1.0), 3)

    dominant = max(cluster_scores, key=cluster_scores.get) if cluster_scores else None

    risk_contribution = 0.0
    for threshold, penalty in _RISK_LEVELS:
        if emotion_score >= threshold:
            risk_contribution = penalty
            break

    return {
        "emotion_score": emotion_score,
        "detected_clusters": detected,
        "dominant_emotion": dominant,
        "active_cluster_count": active,
        "risk_contribution": risk_contribution,
        "top_matches": top_matches,
    }
