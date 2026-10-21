#!/usr/bin/env bash
# Print an access token for a test user of the local lab.
# Usage: scripts/get-token.sh <alice|bob|carol>
# The password is the local-only test password from keycloak/notes-realm.json.
set -euo pipefail

user="${1:?usage: $0 <user>}"
root="$(cd "$(dirname "$0")/.." && pwd)"
kc="${KEYCLOAK_URL:-http://localhost:8180}"

password="$(python3 - "$root/keycloak/notes-realm.json" "$user" <<'PY'
import json, sys
realm = json.load(open(sys.argv[1]))
for u in realm["users"]:
    if u["username"] == sys.argv[2]:
        print(next(c["value"] for c in u["credentials"] if c["type"] == "password"))
        break
else:
    sys.exit(f"user {sys.argv[2]} not found in realm file")
PY
)"

curl -sf \
  --data-urlencode client_id=notes-cli \
  --data-urlencode grant_type=password \
  --data-urlencode "username=$user" \
  --data-urlencode "password=$password" \
  "$kc/realms/notes/protocol/openid-connect/token" \
  | python3 -c 'import json, sys; print(json.load(sys.stdin)["access_token"])'
