#!/bin/bash
# Task 8.14 Step 3a — MAKER-FIRST grace: maker connects + queries BEFORE any
# checker → client stays connected (held) → watcher attaches within the 5s
# window → the held query RUNS and returns rows.
set -u
cd /d/AI/hermes/Project/Project-D
COOKIE=d99b887ae2b5e7c56a0c14e25b37d1b8
API=http://127.0.0.1:8080
KEY=gate8key
STEP=step3a-holdrun
mkdir -p /tmp/t8.14
curl -s $API/api/sessions -H "Cookie: zt_session=$COOKIE" | python -c 'import sys,json;[print(s["session_id"]) for s in json.load(sys.stdin)]' > /tmp/t8.14/$STEP.before
TOKEN=$(curl -s -X POST $API/api/token -H "X-Api-Key: $KEY" -H 'Content-Type: application/json' -d '{"username":"maker8","db_user":"rw_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"t8.14-step3a-holdrun"}' | python -c 'import sys,json;print(json.load(sys.stdin)["token"])')
sleep 0.6
SID=$(curl -s $API/api/sessions -H "Cookie: zt_session=$COOKIE" | BEFORE="$(cat /tmp/t8.14/$STEP.before | tr '\n' ' ')" python -c '
import sys,json,os
before=set(os.environ["BEFORE"].split())
d=json.load(sys.stdin)
new=[s["session_id"] for s in d if s["session_id"] not in before and s.get("status")=="pending"]
print(new[-1] if new else "")
')
echo "TOKEN=$TOKEN SID=$SID"
echo "T=$(date +%s.%N) maker connects FIRST (no watcher anywhere)"
printf '{"at":800,"sql":"SELECT 1 AS held_ok"}\n' > /tmp/t8.14/$STEP.cmds
node tests/zt-raw-mysql.js $TOKEN < /tmp/t8.14/$STEP.cmds > /tmp/t8.14/$STEP.client.log 2>&1 &
CPID=$!
sleep 2.5
if kill -0 $CPID 2>/dev/null; then echo "T=$(date +%s.%N) MAKER STILL CONNECTED at +2.5s (held, no error yet)"; else echo "T=$(date +%s.%N) MAKER EXITED EARLY — FAIL"; fi
if grep -qE "RESP (ROWS|ERR|COLUMNS)" /tmp/t8.14/$STEP.client.log; then echo "UNEXPECTED: response before watcher"; else echo "no response yet at +2.5s (query is held)"; fi
echo "watch-key-before=$(docker exec valkey valkey-cli EXISTS watch:$SID | tr -d '\r')"
echo "T=$(date +%s.%N) attaching WATCHER now (sess:$SID)"
node tests/zt-ws-listen.js "sess:$SID" $COOKIE 10000 > /tmp/t8.14/$STEP.ws.log 2>&1 &
WSPID=$!
for i in $(seq 1 25); do
  W=$(docker exec valkey valkey-cli EXISTS watch:$SID 2>/dev/null | tr -d '\r')
  [ "$W" = "1" ] && break
  sleep 0.4
done
echo "watch-key-after=$(docker exec valkey valkey-cli EXISTS watch:$SID | tr -d '\r') T=$(date +%s.%N)"
wait $CPID; CE=$?
echo "client_exit=$CE T=$(date +%s.%N)"
kill $WSPID 2>/dev/null; wait $WSPID 2>/dev/null
echo "=== CLIENT OUTPUT (held query result) ==="; cat /tmp/t8.14/$STEP.client.log
echo "=== WS EVENTS (sess:$SID) ==="; cat /tmp/t8.14/$STEP.ws.log
echo "=== DATA LOG tail ==="; tail -6 /tmp/zt-data.log
