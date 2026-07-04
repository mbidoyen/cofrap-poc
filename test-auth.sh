#!/bin/bash
# Test rapide d'authentification - lit test-user.json,
# calcule le code TOTP actuel, appelle authenticate.

set -e

CREDS_FILE="$(dirname "$0")/test-user.json"

if [ ! -f "$CREDS_FILE" ]; then
    echo "Erreur : $CREDS_FILE introuvable."
    exit 1
fi

python3 << PYEOF
import json
import pyotp

with open("$CREDS_FILE") as f:
    creds = json.load(f)

totp = pyotp.TOTP(creds["totp_secret"])
payload = {
    "username": creds["username"],
    "password": creds["password"],
    "totp_code": totp.now()
}

with open("/tmp/auth_payload.json", "w") as f:
    json.dump(payload, f)

print(f"Username   : {creds['username']}")
print(f"Code TOTP  : {totp.now()}")
PYEOF

echo ""
echo "Reponse authenticate :"
curl -s -X POST http://127.0.0.1:8080/function/authenticate \
  -H 'Content-Type: application/json' \
  -d @/tmp/auth_payload.json | jq
