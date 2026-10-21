#!/usr/bin/env bash
# Smoke test for the running lab: alice creates a note, bob must not be able to read it.
# Start the stack first: podman compose up -d --build
set -euo pipefail

dir="$(cd "$(dirname "$0")" && pwd)"
api="${API_URL:-http://localhost:8080}"

alice="$("$dir/get-token.sh" alice)"
bob="$("$dir/get-token.sh" bob)"

created="$(curl -sf -X POST "$api/api/notes" \
  -H "Authorization: Bearer $alice" -H 'Content-Type: application/json' \
  -d '{"title":"smoke test","body":"only alice can read this"}')"
id="$(echo "$created" | python3 -c 'import json, sys; print(json.load(sys.stdin)["id"])')"
echo "alice created note $id"

code="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $alice" "$api/api/notes/$id")"
[ "$code" = 200 ] || { echo "FAIL: alice got $code on her own note"; exit 1; }
echo "alice reads note $id: $code"

code="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $bob" "$api/api/notes/$id")"
[ "$code" = 404 ] || { echo "FAIL: bob got $code on alice's note, expected 404"; exit 1; }
echo "bob reads note $id: $code"

code="$(curl -s -o /dev/null -w '%{http_code}' "$api/api/notes/$id")"
[ "$code" = 401 ] || { echo "FAIL: no token got $code, expected 401"; exit 1; }
echo "no token: $code"

echo "PASS"
