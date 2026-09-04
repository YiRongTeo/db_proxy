#!/bin/bash
# E2E MSSQL RW session: kill-query (session survives) + kill-connection (session drops)
set -u
cd /d/AI/hermes/Project/Project-D
API=http://127.0.0.1:8080
KEY='dev-key-change-me'
COOKIE=$(cat "$HOME/zt.cookie")
D=/tmp/rwdemo2; mkdir -p $D

issue_sid() { # $1=label  -> echoes TOKEN|SID
  local T=$(curl -s -X POST $API/api/token -H "X-Api-Key: $KEY" -H 'Content-Type: application/json' \
    -d '{"username":"alice","db_user":"rw_user","db_ip":"127.0.0.1","db_port":"1434","db_type":"mssql","ticket_id":"E2E-MSSQL-KILL"}' \
    | python -c 'import sys,json;print(json.load(sys.stdin)["token"])')
  sleep 0.8
  local S=$(curl -s -H "Cookie: zt_session=$COOKIE" $API/api/sessions | python -c '
import sys,json
d=json.load(sys.stdin)
pend=[s for s in d if s.get("status")=="pending"]
print(pend[-1]["session_id"] if pend else "")')
  echo "$T|$S"
}

echo "== session A: kill query =="
IFS='|' read -r T1 S1 <<< "$(issue_sid)"
echo "TOKEN=${T1:0:12}... SID=$S1"
node tests/zt-ws-listen.js "sess:$S1" "$COOKIE" 60000 > $D/wsA.log 2>&1 &
WA=$!; sleep 3
echo "watchA: $(docker exec valkey valkey-cli --scan --pattern "watch:$S1:*" | wc -l | tr -d ' ') (1 = armed)"
printf "WAITFOR DELAY '00:00:30'\nSELECT 1 AS after_kill\n" | docker exec -i mssql-test /opt/mssql-tools18/bin/sqlcmd -S host.docker.internal,3306 -U "$T1" -P x -N o -d appdb > $D/killq.log 2>&1 &
MK=$!
sleep 6
echo "== kill query (mode=query) =="
curl -s -H "Cookie: zt_session=$COOKIE" -X POST $API/api/kill -H 'Content-Type: application/json' \
  -d "{\"session_id\":\"$S1\",\"mode\":\"query\"}" -w '\nHTTP %{http_code}\n'
wait $MK
echo "--- maker output (aborted batch + surviving session) ---"
cat $D/killq.log
echo "sessionA still listed: $(curl -s -H "Cookie: zt_session=$COOKIE" $API/api/sessions | grep -c "$S1")"

echo "== session B: kill connection =="
IFS='|' read -r T2 S2 <<< "$(issue_sid)"
echo "TOKEN=${T2:0:12}... SID=$S2"
node tests/zt-ws-listen.js "sess:$S2" "$COOKIE" 60000 > $D/wsB.log 2>&1 &
WB=$!; sleep 3
echo "watchB: $(docker exec valkey valkey-cli --scan --pattern "watch:$S2:*" | wc -l | tr -d ' ') (1 = armed)"
printf "WAITFOR DELAY '00:01:00'\nSELECT 1\n" | docker exec -i mssql-test /opt/mssql-tools18/bin/sqlcmd -S host.docker.internal,3306 -U "$T2" -P x -N o -d appdb > $D/killc.log 2>&1 &
MK2=$!
sleep 6
echo "== kill connection (mode=connection) =="
curl -s -H "Cookie: zt_session=$COOKIE" -X POST $API/api/kill -H 'Content-Type: application/json' \
  -d "{\"session_id\":\"$S2\",\"mode\":\"connection\"}" -w '\nHTTP %{http_code}\n'
wait $MK2
echo "--- maker output (expected drop) ---"
cat $D/killc.log
echo "sessionB still listed: $(curl -s -H "Cookie: zt_session=$COOKIE" $API/api/sessions | grep -c "$S2")"
kill $WA $WB 2>/dev/null
echo DONE
