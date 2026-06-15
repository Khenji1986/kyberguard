#!/usr/bin/env python3
"""
Atlas MFA Manual Patch Helper — KyberShield Auth
Liest main.py und zeigt genau was geaendert werden muss,
falls das automatische Skript nicht alle Patterns erkennt.

Ausfuehren auf dem Server:
    python3 atlas-mfa-fix-manual.py /root/kyberguard-web/backend/main.py
"""

import sys
import re

def analyze(path: str) -> None:
    with open(path) as f:
        lines = f.readlines()

    src = "".join(lines)

    print("=" * 70)
    print("Atlas MFA Patch Analyzer")
    print("=" * 70)

    # Fix 1: Emergency-Lock
    print("\n[FIX 1] Emergency-Lock GET->POST")
    for i, line in enumerate(lines, 1):
        if "emergency" in line.lower() and ("get" in line.lower() or "token" in line.lower()):
            print(f"  Zeile {i}: {line.rstrip()}")

    # Fix 2: kyber_dt / device_token
    print("\n[FIX 2] kyber_dt / device_token Stellen")
    for i, line in enumerate(lines, 1):
        if "kyber_dt" in line or "device_token" in line:
            print(f"  Zeile {i}: {line.rstrip()}")

    # Fix 3: mfa_done / merge_into_access_token_payload
    print("\n[FIX 3] mfa_done / merge_into_access_token_payload")
    for i, line in enumerate(lines, 1):
        if "mfa_done" in line or "merge_into_access_token_payload" in line:
            print(f"  Zeile {i}: {line.rstrip()}")

    # Middleware-Check
    print("\n[FIX 3 Middleware] mfa_pending_until")
    for i, line in enumerate(lines, 1):
        if "mfa_pending" in line:
            print(f"  Zeile {i}: {line.rstrip()}")
    if "mfa_pending_until" not in src:
        print("  NICHT GEFUNDEN — muss manuell in Middleware eingefuegt werden")
        print()
        print("  Suche die Stelle wo 'mfa_done' False geprueft wird und fuege ein:")
        print("""
  # In merge_into_access_token_payload Block:
  await session_container.merge_into_access_token_payload({
      'mfa_done': False,
      'mfa_pending_until': int(time.time()) + 300   # <-- NEU
  })

  # In der Middleware die mfa_done=False prueft:
  if payload.get('mfa_done') is False:
      pending_until = payload.get('mfa_pending_until', 0)
      if time.time() > pending_until:
          await session_container.revoke_session()
          return JSONResponse({"error": "MFA session expired"}, status_code=401)
""")

    # localStorage
    print("\n[FIX 2 Frontend] localStorage kyber_dt")
    import subprocess
    try:
        result = subprocess.run(
            ["grep", "-rn", "kyber_dt\|device_token",
             "/root/kyberguard-web/frontend/src/"],
            capture_output=True, text=True
        )
        if result.stdout:
            print(result.stdout[:3000])
        else:
            print("  Keine localStorage-Treffer im Frontend")
    except Exception as e:
        print(f"  grep fehlgeschlagen: {e}")

    print("\n" + "=" * 70)
    print("Analyse abgeschlossen. Alle Zeilen oben manuell pruefen.")
    print("=" * 70)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} /path/to/main.py")
        sys.exit(1)
    analyze(sys.argv[1])
