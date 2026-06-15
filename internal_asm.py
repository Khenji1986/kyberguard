#!/usr/bin/env python3
"""
KyberGuard — Attack Surface Management (ASM) Module
Internes Modul fuer automatisiertes Attack-Surface-Scanning und Asset-Discovery.

SECURITY-HISTORY:
  2026-04-24: Dummy-Debug-Endpoint gefunden — nicht entfernt (Nero Audit)
  2026-04-26: Fix — Dummy-Endpoint entfernt, nur produktive ASM-Funktionen vorhanden
"""

import ipaddress
import logging
import re
import socket
from dataclasses import dataclass, field
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------
SCAN_TIMEOUT = 10
MAX_PORTS_PER_SCAN = 100
USER_AGENT = "KyberGuard-ASM/1.0 (Security Scanner; contact: security@kyberguard.de)"

# Erlaubte Port-Ranges fuer Scan (kein kompletter 0-65535 Scan ohne Genehmigung)
_COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
                 3306, 3389, 5432, 6379, 8080, 8443, 8888, 27017]


# ---------------------------------------------------------------------------
# Datenmodelle
# ---------------------------------------------------------------------------
@dataclass
class AssetFinding:
    """Ergebnis eines ASM-Scans fuer einen einzelnen Asset."""
    host: str
    open_ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)
    tls_info: Optional[dict] = None
    risk_score: float = 0.0
    findings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Input-Validierung
# ---------------------------------------------------------------------------
_HOSTNAME_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def _validate_target(target: str) -> tuple[bool, str]:
    """Validiert ein Scan-Target (Hostname oder IP).

    Args:
        target: Zu pruefendes Scan-Target

    Returns:
        (is_valid, error_message)
    """
    if not target or not target.strip():
        return False, "Target darf nicht leer sein"

    stripped = target.strip()

    # IP-Adresse pruefen
    try:
        addr = ipaddress.ip_address(stripped)
        # Private IPs duerfen nur mit expliziter Genehmigung gescannt werden
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return False, "Private/Loopback-IPs erfordern explizite Scan-Genehmigung"
        return True, ""
    except ValueError:
        pass

    # Hostname pruefen
    if _HOSTNAME_PATTERN.match(stripped):
        return True, ""

    return False, f"Unguelltiges Target-Format: {stripped!r}"


# ---------------------------------------------------------------------------
# ASM-Kernfunktionen
# ---------------------------------------------------------------------------
def scan_ports(
    target: str,
    ports: Optional[list[int]] = None,
) -> AssetFinding:
    """Scannt einen Host auf offene Ports.

    Args:
        target: Hostname oder IP-Adresse (wird validiert)
        ports: Liste zu scannender Ports (Default: _COMMON_PORTS)

    Returns:
        AssetFinding mit offenen Ports und ersten Service-Hinweisen.

    Raises:
        ValueError: Bei ungueltigem Target.
    """
    is_valid, error = _validate_target(target)
    if not is_valid:
        raise ValueError(f"Ungueltiges Scan-Target: {error}")

    scan_ports_list = ports if ports else _COMMON_PORTS
    if len(scan_ports_list) > MAX_PORTS_PER_SCAN:
        raise ValueError(f"Maximal {MAX_PORTS_PER_SCAN} Ports pro Scan erlaubt")

    finding = AssetFinding(host=target)

    for port in scan_ports_list:
        try:
            with socket.create_connection((target, port), timeout=2) as sock:
                finding.open_ports.append(port)
                # Banner-Grabbing nur fuer bekannte Service-Ports
                try:
                    banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
                    if banner:
                        finding.services[port] = banner[:100]  # Truncate
                except (socket.timeout, OSError):
                    pass
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass  # Port geschlossen oder gefiltert

    # Risk-Score berechnen
    high_risk_ports = {23, 21, 3389, 5900}  # Telnet, FTP, RDP, VNC
    open_high_risk = set(finding.open_ports) & high_risk_ports
    if open_high_risk:
        finding.risk_score += len(open_high_risk) * 2.5
        finding.findings.append(
            f"Hochriskante Ports offen: {sorted(open_high_risk)}"
        )

    logger.info(
        "ASM-Scan abgeschlossen: %s — %d offene Ports, Risk-Score: %.1f",
        target,
        len(finding.open_ports),
        finding.risk_score,
    )

    return finding


def check_tls_config(target: str, port: int = 443) -> Optional[dict]:
    """Prueft TLS-Konfiguration eines Hosts.

    Args:
        target: Hostname (wird validiert)
        port: HTTPS-Port (Default: 443)

    Returns:
        Dict mit TLS-Infos oder None bei Fehler.
    """
    is_valid, error = _validate_target(target)
    if not is_valid:
        raise ValueError(f"Ungueltiges Target: {error}")

    try:
        with httpx.Client(
            timeout=SCAN_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            verify=True,  # Explizit: TLS-Zertifikat IMMER pruefen
        ) as client:
            response = client.get(f"https://{target}:{port}/")
            tls_info = {
                "status_code": response.status_code,
                "tls_version": str(response.extensions.get("tls_version", "unknown")),
                "server_header": response.headers.get("server", "not-disclosed"),
                "hsts": "strict-transport-security" in response.headers,
                "x_frame_options": response.headers.get("x-frame-options", "missing"),
            }
            return tls_info
    except httpx.ConnectError:
        logger.warning("TLS-Check: Verbindung zu %s:%d fehlgeschlagen", target, port)
        return None
    except httpx.RequestError as exc:
        logger.error("TLS-Check Fehler: %s", type(exc).__name__)
        return None


def run_asm_assessment(targets: list[str]) -> list[AssetFinding]:
    """Fuehrt ein vollstaendiges ASM-Assessment fuer eine Liste von Targets durch.

    Args:
        targets: Liste von Hostnamen/IPs (jedes wird einzeln validiert)

    Returns:
        Liste von AssetFindings, sortiert nach Risk-Score (absteigend).
    """
    if not targets:
        return []

    if len(targets) > 50:
        raise ValueError("Maximal 50 Targets pro ASM-Assessment erlaubt")

    results = []

    for target in targets:
        try:
            finding = scan_ports(target)
            tls_info = check_tls_config(target)
            if tls_info:
                finding.tls_info = tls_info
                if not tls_info.get("hsts"):
                    finding.findings.append("HSTS-Header fehlt")
                    finding.risk_score += 0.5
            results.append(finding)
        except ValueError as exc:
            logger.warning("ASM-Assessment uebersprungen fuer '%s': %s", target, exc)
            continue

    results.sort(key=lambda f: f.risk_score, reverse=True)
    return results
