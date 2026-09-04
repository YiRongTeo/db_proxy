#!/bin/bash
# E2E MSSQL RW session: kill-query (session survives) + kill-connection (session drops)
# JWT-era auth (2026-09-05 conversion): the MAKER account (admin) mints DB
# tokens; the CHECKER account watches/lists/kills (strict SoD — control.yaml
# auth.allow_maker_watch: false, so the maker cannot touch the checker
# surface and every kill is a DIFFERENT principal than the session's maker).
set -u
cd /d/AI/hermes/Project/Project-D
API=http://127.0.0.1:8080
D=/tmp/rwdemo2; mkdir -p $D
# Dev credentials from .env (env override wins; .env.example defaults below).
MAKER_JWT=$(curl -s -X POST $API/api/login -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ZT_AUTH_PASSWORD:-admin123}\"}" \
  | python -c 'import sys,json;print(json.load(sys.stdin)["token"])')
CHECKER_JWT=$(curl -s -X POST $API/api/login -H 'Content-Type: application/json' \
  -d "{\"username\":\"checker\",\"password\":\"${ZT_AUTH_CHECKER_PASSWORD:-checker123}\"}" \
  | python -c 'import sys,json;print(json.load(sys.stdin)["token"])')
[ -n "$MAKER_JWT" ] && [ -n "$CHECKER_JWT" ] || { echo "FATAL: /api/login failed — is the control plane up?"; exit 1; }

issue_sid() { # $1=label  -> echoes TOKEN|SID
  local T=$(curl -s -X POST $API/api/token -H "Authorization: Bearer $MAKER_JWT" -H 'Content-Type: application/json' \
    -d '{"username":"admin","db_user":"rw_user","db_ip":"127.0.0.1","db_port":"1434","db_type":"mssql","ticket_id":"E2E-MSSQL-KILL"}' \
    | python -c 'import sys,json;print(json.load(sys.stdin)["token"])')
  sleep 0.8
  local S=$(curl -s -H "Authorization: Bearer $CHECKER_JWT" $API/api/sessions | python -c '
import sys,json
d=json.load(sys.stdin)
pend=[s for s in d if s.get("status")=="pending"]
print(pend[-1]["session_id"] if pend else "")')
  echo "$T|$S"
}

echo "== session A: kill query =="
IFS='|' read -r T1 S1 <<< "$(issue_sid)"
echo "TOKEN=${T1:0:12}... SID=$S1"
node tests/zt-ws-listen.js "sess:$S1" "$CHECKER_JWT" 60000 > $D/wsA.log 2>&1 &
WA=$!; sleep 3
echo "watchA: $(docker exec valkey valkey-cli --scan --pattern "watch:$S1:*" | wc -l | tr -d ' ') (1 = armed)"
printf "WAITFOR DELAY '00:00:30'\nSELECT 1 AS after_kill\n" | docker exec -i mssql-test /opt/mssql-tools18/bin/sqlcmd -S host.docker.internal,3306 -U "$T1" -P x -N o -d appdb > $D/killq.log 2>&1 &
MK=$!
sleep 6
echo "== kill query (mode=query) =="
curl -s -H "Authorization: Bearer $CHECKER_JWT" -X POST $API/api/kill -H 'Content-Type: application/json' \
  -d "{\"session_id\":\"$S1\",\"mode\":\"query\"}" -w '\nHTTP %{http_code}\n'
wait $MK
echo "--- maker output (aborted batch + surviving session) ---"
cat $D/killq.log
echo "sessionA still listed: $(curl -s -H "Authorization: Bearer $CHECKER_JWT" $API/api/sessions | grep -c "$S1")"

echo "== session B: kill connection =="
IFS='|' read -r T2 S2 <<< "$(issue_sid)"
echo "TOKEN=${T2:0:12}... SID=$S2"
node tests/zt-ws-listen.js "sess:$S2" "$CHECKER_JWT" 60000 > $D/wsB.log 2>&1 &
WB=$!; sleep 3
echo "watchB: $(docker exec valkey valkey-cli --scan --pattern "watch:$S2:*" | wc -l | tr -d ' ') (1 = armed)"
printf "WAITFOR DELAY '00:01:00'\nSELECT 1\n" | docker exec -i mssql-test /opt/mssql-tools18/bin/sqlcmd -S host.docker.internal,3306 -U "$T2" -P x -N o -d appdb > $D/killc.log 2>&1 &
MK2=$!
sleep 6
echo "== kill connection (mode=connection) =="
curl -s -H "Authorization: Bearer $CHECKER_JWT" -X POST $API/api/kill -H 'Content-Type: application/json' \
  -d "{\"session_id\":\"$S2\",\"mode\":\"connection\"}" -w '\nHTTP %{http_code}\n'
wait $MK2
echo "--- maker output (expected drop) ---"
cat $D/killc.log
echo "sessionB still listed: $(curl -s -H "Authorization: Bearer $CHECKER_JWT" $API/api/sessions | grep -c "$S2")"
kill $WA $WB 2>/dev/null
echo DONE
