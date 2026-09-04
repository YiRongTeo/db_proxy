#!/bin/bash
# Reproduction: mssql kill-query with sqlcmd client — observe client-visible behavior
# JWT-era auth (2026-09-05 conversion): the MAKER account (admin) mints the DB
# token; the CHECKER account watches + kills (strict SoD — control.yaml
# auth.allow_maker_watch: false, so the maker cannot touch the checker surface).
set -u
cd /d/AI/hermes/Project/Project-D
API=http://127.0.0.1:8080
# Dev credentials from .env (env override wins; .env.example defaults below).
MAKER_JWT=$(curl -s -X POST $API/api/login -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ZT_AUTH_PASSWORD:-admin123}\"}" \
  | python -c 'import sys,json;print(json.load(sys.stdin)["token"])')
CHECKER_JWT=$(curl -s -X POST $API/api/login -H 'Content-Type: application/json' \
  -d "{\"username\":\"checker\",\"password\":\"${ZT_AUTH_CHECKER_PASSWORD:-checker123}\"}" \
  | python -c 'import sys,json;print(json.load(sys.stdin)["token"])')
[ -n "$MAKER_JWT" ] && [ -n "$CHECKER_JWT" ] || { echo "FATAL: /api/login failed — is the control plane up?"; exit 1; }

T=$(curl -s -X POST $API/api/token -H "Authorization: Bearer $MAKER_JWT" -H 'Content-Type: application/json' \
  -d '{"username":"admin","db_user":"rw_user","db_ip":"127.0.0.1","db_port":"1434","db_type":"mssql","ticket_id":"E2E-MSSQL-KILL-REPRO"}' \
  | python -c 'import sys,json;print(json.load(sys.stdin)["token"])')
sleep 0.8
S=$(curl -s -H "Authorization: Bearer $CHECKER_JWT" $API/api/sessions | python -c '
import sys,json
d=json.load(sys.stdin)
pend=[s for s in d if s.get("status")=="pending"]
print(pend[-1]["session_id"] if pend else "")')
echo "TOKEN=${T:0:12}... SID=$S"
node tests/zt-ws-listen.js "sess:$S" "$CHECKER_JWT" 40000 > /tmp/repro.ws.log 2>&1 &
WP=$!
sleep 3
echo "watch: $(docker exec valkey valkey-cli --scan --pattern "watch:$S:*" | wc -l | tr -d ' ') (1 = armed)"
echo "== maker: WAITFOR 10s then SELECT on same conn =="
printf "WAITFOR DELAY '00:00:10'\nSELECT 1 AS after_kill\n" | docker exec -i mssql-test /opt/mssql-tools18/bin/sqlcmd -S host.docker.internal,3306 -U "$T" -P x -N o -d appdb > /tmp/repro.client.log 2>&1 &
MK=$!
sleep 4
echo "== kill query at +4s =="
curl -s -H "Authorization: Bearer $CHECKER_JWT" -X POST $API/api/kill -H 'Content-Type: application/json' \
  -d "{\"session_id\":\"$S\",\"mode\":\"query\"}" -w ' HTTP %{http_code}\n'
wait $MK
echo "== client output =="
cat /tmp/repro.client.log
echo "== client exit=$? =="
kill $WP 2>/dev/null
echo "== checker events for this session =="
grep -E "WAITFOR|after_kill|ended|started" /tmp/repro.ws.log | sed 's/^{"id[^,]*,"ts":"[^"]*","//;s/","client_addr[^}]*//' | head -8
