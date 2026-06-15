#!/usr/bin/env python3
"""
KyberGuard — Internal Marketing Analytics
Interne Auswertungen fuer Marketing-KPIs, Kampagnen-Performance und Lead-Analyse.

SECURITY-HISTORY:
  2026-04-24: SQL INTERVAL-Pattern mit String-Interpolation gemeldet (Nero Audit)
  2026-04-26: Fix — INTERVAL-Werte sind jetzt Enum-basiert, keine User-Interpolation moeglich
"""

import logging
import sqlite3
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------
DB_PATH = "/app/data/kyberguard.db"


# ---------------------------------------------------------------------------
# Sichere Enum fuer Zeitraeume
# ---------------------------------------------------------------------------
class TimeWindow(str, Enum):
    """Erlaubte Zeitfenster fuer Marketing-Analysen.

    FIX (2026-04-26): Statt User-String direkt in SQL-INTERVAL zu interpolieren,
    werden nur diese validierten Enum-Werte akzeptiert.
    Die INTERVAL-Werte sind hartcodiert in der Query-Map — keine Injection moeglich.
    """
    LAST_7_DAYS = "7d"
    LAST_30_DAYS = "30d"
    LAST_90_DAYS = "90d"
    LAST_365_DAYS = "365d"


# Mapping von Enum-Wert zu SQLite-kompatiblem Datum-Offset
# SQLite hat kein INTERVAL — wir nutzen date('now', '-N days')
_TIME_WINDOW_DAYS: dict[TimeWindow, int] = {
    TimeWindow.LAST_7_DAYS: 7,
    TimeWindow.LAST_30_DAYS: 30,
    TimeWindow.LAST_90_DAYS: 90,
    TimeWindow.LAST_365_DAYS: 365,
}


def _get_db_connection() -> sqlite3.Connection:
    """Erstellt eine DB-Verbindung mit row_factory fuer Dict-Ergebnisse."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_campaign_performance(
    campaign_id: int,
    time_window: TimeWindow = TimeWindow.LAST_30_DAYS,
) -> Optional[dict]:
    """Liefert Performance-Metriken einer Kampagne fuer ein Zeitfenster.

    FIX (2026-04-26): time_window ist ein TimeWindow-Enum.
    Der INTERVAL-Wert (Anzahl Tage) kommt aus einer hartcodierten Map —
    niemals aus User-Input. Das verhindert SQL-Injection ueber INTERVAL.

    Args:
        campaign_id: ID der Kampagne (Integer, parameterisiert)
        time_window: Zeitfenster als validierter Enum-Wert

    Returns:
        Dict mit KPIs oder None bei nicht gefundener Kampagne.
    """
    days = _TIME_WINDOW_DAYS[time_window]

    # SICHER: campaign_id als Parameter (kein f-string)
    # SICHER: days kommt aus hartcodierter Map, nicht aus User-Input
    query = """
        SELECT
            c.id,
            c.name,
            COUNT(l.id) AS lead_count,
            SUM(CASE WHEN l.converted = 1 THEN 1 ELSE 0 END) AS conversions,
            AVG(l.lead_score) AS avg_score
        FROM campaigns c
        LEFT JOIN leads l
            ON l.campaign_id = c.id
            AND l.created_at >= date('now', ? )
        WHERE c.id = ?
        GROUP BY c.id, c.name
    """
    # Parameter: date-Offset als sicherer String aus hartcodierter Map
    date_offset = f"-{days} days"

    try:
        with _get_db_connection() as conn:
            cursor = conn.cursor()
            # Beide Parameter sind sicher: date_offset aus Enum-Map, campaign_id als int
            cursor.execute(query, (date_offset, campaign_id))
            row = cursor.fetchone()
            if row is None:
                return None
            return dict(row)
    except sqlite3.DatabaseError as exc:
        logger.error("DB-Fehler bei campaign_performance (campaign_id=%d): %s", campaign_id, exc)
        return None


def get_lead_funnel(
    time_window: TimeWindow = TimeWindow.LAST_30_DAYS,
) -> list[dict]:
    """Liefert den Lead-Funnel fuer einen Zeitraum.

    Args:
        time_window: Zeitfenster als validierter Enum-Wert

    Returns:
        Liste von Funnel-Stufen mit Counts.
    """
    days = _TIME_WINDOW_DAYS[time_window]
    date_offset = f"-{days} days"

    query = """
        SELECT
            stage,
            COUNT(*) AS count,
            AVG(lead_score) AS avg_score
        FROM leads
        WHERE created_at >= date('now', ?)
        GROUP BY stage
        ORDER BY
            CASE stage
                WHEN 'awareness' THEN 1
                WHEN 'interest' THEN 2
                WHEN 'decision' THEN 3
                WHEN 'action' THEN 4
                ELSE 5
            END
    """

    try:
        with _get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (date_offset,))
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.DatabaseError as exc:
        logger.error("DB-Fehler bei get_lead_funnel: %s", exc)
        return []


def get_top_sources(
    limit: int = 10,
    time_window: TimeWindow = TimeWindow.LAST_30_DAYS,
) -> list[dict]:
    """Liefert die Top-Traffic-Quellen nach Lead-Anzahl.

    Args:
        limit: Maximale Anzahl zurueckzugebender Quellen (1-100)
        time_window: Zeitfenster als validierter Enum-Wert

    Returns:
        Liste von Quellen mit Lead-Counts.
    """
    # limit ebenfalls absichern
    safe_limit = max(1, min(100, int(limit)))
    days = _TIME_WINDOW_DAYS[time_window]
    date_offset = f"-{days} days"

    query = """
        SELECT
            source,
            COUNT(*) AS lead_count,
            SUM(CASE WHEN converted = 1 THEN 1 ELSE 0 END) AS conversions
        FROM leads
        WHERE created_at >= date('now', ?)
        GROUP BY source
        ORDER BY lead_count DESC
        LIMIT ?
    """

    try:
        with _get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (date_offset, safe_limit))
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.DatabaseError as exc:
        logger.error("DB-Fehler bei get_top_sources: %s", exc)
        return []
