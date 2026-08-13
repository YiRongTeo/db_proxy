#!/bin/bash
# Task 8.14 Step 6 — ro token exempt: pending record + issued event still
# appear (uniformity), but the query runs with NO watcher (never gated).
set -u
cd /d/AI/hermes/Project/Project-D
COOKIE=d99b887ae2b5e7c56a0c14e25b37d1b8
API=http://127.0.0.1:8080
KEY=gate8key
STEP=step6-ro
mkdir -p /tmp/t8.14
curl -s $API/api/sessions -H "Cookie: zt_session=$COOKIE" | python -c 'import sys,json;[print(s["session_id"]) for s in json.load(sys.stdin)]' > /tmp/t8.14/$STEP.before
TOKEN=$(curl -s -X POST $API/api/token -H "X-Api-Key: $KEY" -H 'Content-Type: application/json' -d '{"username":"maker8","db_user":"ro_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"t8.14-step6-ro"}' | python -c 'import sys,json;print(json.load(sys.stdin)["token"])')
sleep 0.6
SID=$(curl -s $API/api/sessions -H "Cookie: zt_session=$COOKIE" | BEFORE="$(cat /tmp/t8.14/$STEP.before | tr '\n' ' ')" python -c '
import sys,json,os
before=set(os.environ["BEFORE"].split())
d=json.load(sys.stdin)
new=[s["session_id"] for s in d if s["session_id"] not in before and s.get("status")=="pending"]
print(new[-1] if new else "")
')
echo "TOKEN=$TOKEN SID=$SID (ro_user, access=read)"
echo "pending-at-issue: $(curl -s $API/api/sessions -H "Cookie: zt_session=$COOKIE" | python -c "
import sys,json
d=json.load(sys.stdin)
s=[x for x in d if x['session_id']=='$SID']
print(json.dumps(s[0]) if s else 'NOT LISTED')
")"
# audit capture on channel=* — capture the action=issued event (uniformity)
node tests/zt-ws-listen.js "*" $COOKIE 12000 > /tmp/t8.14/$STEP.ws.log 2>&1 &
WSPID=$!
sleep 1.0
printf '{"at":800,"sql":"SELECT 1 AS ro_ok"}\n{"at":1500,"sql":"SELECT 2 AS ro_ok2"}\n' > /tmp/t8.14/$STEP.cmds
echo "T=$(date +%s.%N) ro maker connects, NO watcher"
node tests/zt-raw-mysql.js $TOKEN < /tmp/t8.14/$STEP.cmds > /tmp/t8.14/$STEP.client.log 2>&1
CE=$?
echo "client_exit=$CE T=$(date +%s.%N)"
echo "watch-key-ever=$(docker exec valkey valkey-cli EXISTS watch:$SID | tr -d '\r') (0 = never watched)"
kill $WSPID 2>/dev/null; wait $WSPID 2>/dev/null
echo "=== CLIENT OUTPUT ==="; cat /tmp/t8.14/$STEP.client.log
echo "=== WS EVENTS channel=* (issued event expected) ==="; cat /tmp/t8.14/$STEP.ws.log
echo "=== DATA LOG tail ==="; tail -6 /tmp/zt-data.log
