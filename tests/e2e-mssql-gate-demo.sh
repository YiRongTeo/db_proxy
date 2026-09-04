#!/bin/bash
# E2E: (C) write-gate blocks unwatched rw session — 20s grace hold -> 18456 drain
#      (D) kill connection drops the maker mid-batch, session leaves directory
# JWT-era auth (2026-09-05 conversion): the MAKER account (admin) mints DB
# tokens; the CHECKER account watches/lists/kills (strict SoD — control.yaml
# auth.allow_maker_watch: false, so the maker cannot touch the checker
# surface and every kill is a DIFFERENT principal than the session's maker).
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

issue_sid() {
  local T=$(curl -s -X POST $API/api/token -H "Authorization: Bearer $MAKER_JWT" -H 'Content-Type: application/json' \
    -d '{"username":"admin","db_user":"rw_user","db_ip":"127.0.0.1","db_port":"1434","db_type":"mssql","ticket_id":"E2E-MSSQL-GATE"}' \
    | python -c 'import sys,json;print(json.load(sys.stdin)["token"])')
  sleep 0.8
  local S=$(curl -s -H "Authorization: Bearer $CHECKER_JWT" $API/api/sessions | python -c '
import sys,json
d=json.load(sys.stdin)
pend=[s for s in d if s.get("status")=="pending"]
print(pend[-1]["session_id"] if pend else "")')
  echo "$T|$S"
}

echo "===== (C) rw session with NO checker: gate blocks ====="
IFS='|' read -r T S <<< "$(issue_sid)"
echo "TOKEN=${T:0:12}... SID=$S (no watcher attached)"
echo "watch: $(docker exec valkey valkey-cli --scan --pattern "watch:$S:*" | wc -l | tr -d ' ')  (0 = no checker = must block)"
T0=$(date +%s)
docker exec mssql-test /opt/mssql-tools18/bin/sqlcmd -S host.docker.internal,3306 -U "$T" -P x -N o -d appdb -b -Q "INSERT INTO demo_items VALUES (77,'blocked')" > /tmp/gateC.log 2>&1
CE=$?
T1=$(date +%s)
echo "elapsed=$((T1-T0))s exit=$CE (expect ~20s + exit 1)"
echo '--- maker output ---'; cat /tmp/gateC.log
echo "row 77 present? $(docker exec mssql-test /opt/mssql-tools18/bin/sqlcmd -S localhost -U rw_user -P rw_pw -d appdb -C -h -1 -Q "SET NOCOUNT ON; SELECT COUNT(*) FROM demo_items WHERE id=77" | tr -d ' \r') (expect 0 = never reached backend)"

echo "===== (D) kill connection: maker dropped mid-batch, session leaves directory ====="
IFS='|' read -r T2 S2 <<< "$(issue_sid)"
echo "TOKEN=${T2:0:12}... SID=$S2"
node tests/zt-ws-listen.js "sess:$S2" "$CHECKER_JWT" 45000 > /tmp/gateD.ws.log 2>&1 &
WP=$!
sleep 3
echo "watch: $(docker exec valkey valkey-cli --scan --pattern "watch:$S2:*" | wc -l | tr -d ' ') (1 = armed)"
printf "WAITFOR DELAY '00:01:00'\nSELECT 1\n" | docker exec -i mssql-test /opt/mssql-tools18/bin/sqlcmd -S host.docker.internal,3306 -U "$T2" -P x -N o -d appdb > /tmp/gateD.client.log 2>&1 &
MK=$!
sleep 5
echo "listed while active: $(curl -s -H "Authorization: Bearer $CHECKER_JWT" $API/api/sessions | grep -c "$S2")"
curl -s -H "Authorization: Bearer $CHECKER_JWT" -X POST $API/api/kill -H 'Content-Type: application/json' \
  -d "{\"session_id\":\"$S2\",\"mode\":\"connection\"}" -w ' HTTP %{http_code}\n'
wait $MK
echo "--- maker output (expect connection drop) ---"; cat /tmp/gateD.client.log
echo "listed after kill: $(curl -s -H "Authorization: Bearer $CHECKER_JWT" $API/api/sessions | grep -c "$S2") (expect 0)"
kill $WP 2>/dev/null
echo DONE
