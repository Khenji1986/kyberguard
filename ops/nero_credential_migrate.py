#!/usr/bin/env python3
"""
Nero-Migration: ANTHROPIC_API_KEY -> systemd LoadCredential
Läuft als root auf kyberguard-vm. Liest aus .env, schreibt in /etc/credstore/.
Zeigt KEINEN Key-Wert in der Ausgabe.
"""
import os
import sys
import stat

ENV_FILE = "/home/ceuleeneo/.kyberguard-api.env"
CREDSTORE_DIR = "/etc/credstore"
CRED_FILE = os.path.join(CREDSTORE_DIR, "anthropic_key")
KEY_NAME = "ANTHROPIC_API_KEY"

# credstore-Verzeichnis anlegen (root:root, 700)
os.makedirs(CREDSTORE_DIR, exist_ok=True)
os.chmod(CREDSTORE_DIR, stat.S_IRWXU)
os.chown(CREDSTORE_DIR, 0, 0)

# Key aus .env lesen
key_value = None
with open(ENV_FILE, "r") as f:
    for line in f:
        line = line.strip()
        if line.startswith(KEY_NAME + "="):
            key_value = line.split("=", 1)[1].strip()
            break

if not key_value:
    print(f"FEHLER: {KEY_NAME} nicht in {ENV_FILE} gefunden", file=sys.stderr)
    sys.exit(1)

# Credential-Datei schreiben (root:root, 600)
with open(CRED_FILE, "w") as cf:
    cf.write(key_value)

os.chmod(CRED_FILE, stat.S_IRUSR | stat.S_IWUSR)
os.chown(CRED_FILE, 0, 0)

# Key aus .env entfernen
with open(ENV_FILE, "r") as f:
    lines = f.readlines()

with open(ENV_FILE, "w") as f:
    for line in lines:
        if not line.startswith(KEY_NAME + "="):
            f.write(line)

print(f"OK: Credential in {CRED_FILE} gespeichert ({len(key_value)} Bytes)")
print(f"OK: {KEY_NAME} aus {ENV_FILE} entfernt")
print(f"OK: {CREDSTORE_DIR} Permissions: {oct(stat.S_IMODE(os.stat(CREDSTORE_DIR).st_mode))}")
print(f"OK: {CRED_FILE} Permissions: {oct(stat.S_IMODE(os.stat(CRED_FILE).st_mode))}")
