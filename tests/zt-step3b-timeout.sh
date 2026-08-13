#!/bin/bash
# Task 8.14 Step 3b — maker-first with NO watcher: query held, then at window
# expiry (5s) the client gets ERR 1045 + audit events; session LATCHES
# fail-closed — a watcher attached AFTER the latch does NOT unblock it: the
# next command is rejected immediately even with the watch key present.
set -u
cd /d/AI/hermes/Project/Project-D
COOKIE=d99b887ae2b5e7c56a0c14e25b37d1b8
API=http://127.0.0.1:8080
KEY=gate8key
STEP=step3b-timeout
mkdir -p /tmp/t8.14
curl -s $API/api/sessions -H "Cookie: zt_session=$COOKIE" | python -c 'import sys,json;[print(s["session_id"]) for s in json.load(sys.stdin)]' > /tmp/t8.14/$STEP.before
TOKEN=$(curl -s -X POST $API/api/token -H "X-Api-Key: $KEY" -H 'Content-Type: application/json' -d '{"username":"maker8","db_user":"rw_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"t8.14-step3b-timeout"}' | python -c 'import sys,json;print(json.load(sys.stdin)["token"])')
sleep 0.6
SID=$(curl -s $API/api/sessions -H "Cookie: zt_session=$COOKIE" | BEFORE="$(cat /tmp/t8.14/$STEP.before | tr '\n' ' ')" python -c '
import sys,json,os
before=set(os.environ["BEFORE"].split())
d=json.load(sys.stdin)
new=[s["session_id"] for s in d if s["session_id"] not in before and s.get("status")=="pending"]
print(new[-1] if new else "")
')
echo "TOKEN=$TOKEN SID=$SID"
echo "T=$(date +%s.%N) maker connects FIRST; NO watcher will exist for 8s"
# audit capture on channel=* (all-queries feed — NOT a watcher: no sess: channel)
node tests/zt-ws-listen.js "*" $COOKIE 20000 > /tmp/t8.14/$STEP.ws-all.log 2>&1 &
WSALL=$!
# SELECT 1 at +0.8s (held), SELECT 2 at +8.5s (sent AFTER watcher attaches at ~8s)
printf '{"at":800,"sql":"SELECT 1 AS first"}\n{"at":8500,"sql":"SELECT 2 AS after_latch"}\n' > /tmp/t8.14/$STEP.cmds
node tests/zt-raw-mysql.js $TOKEN < /tmp/t8.14/$STEP.cmds > /tmp/t8.14/$STEP.client.log 2>&1 &
CPID=$!
sleep 2.5
if kill -0 $CPID 2>/dev/null; then echo "T=$(date +%s.%N) MAKER STILL CONNECTED at +2.5s (held)"; else echo "T=$(date +%s.%N) MAKER EXITED EARLY — FAIL"; fi
grep -qE "RESP (ROWS|ERR|COLUMNS)" /tmp/t8.14/$STEP.client.log && echo "UNEXPECTED: response before window" || echo "no response yet at +2.5s (held)"
sleep 4.2   # now ≈ +6.7s: the 5s window drained SELECT 1 around +5.8s
echo "=== client log at +6.7s (after window expiry): ==="; cat /tmp/t8.14/$STEP.client.log
if kill -0 $CPID 2>/dev/null; then echo "T=$(date +%s.%N) client STILL CONNECTED after the 1045 drain (latch window open)"; else echo "client exited after drain"; fi
sleep 1.3   # now ≈ +8.0s
echo "T=$(date +%s.%N) attaching WATCHER AFTER the latch (sess:$SID)"
node tests/zt-ws-listen.js "sess:$SID" $COOKIE 9000 > /tmp/t8.14/$STEP.ws-sess.log 2>&1 &
WSSESS=$!
for i in $(seq 1 25); do
  W=$(docker exec valkey valkey-cli EXISTS watch:$SID 2>/dev/null | tr -d '\r')
  [ "$W" = "1" ] && break
  sleep 0.4
done
echo "watch-key-present=$(docker exec valkey valkey-cli EXISTS watch:$SID | tr -d '\r') T=$(date +%s.%N)"
# SELECT 2 arrives at ≈ +8.5s (client clock) — session is latched: expect
# IMMEDIATE ERR 1045 (not a run, and not another 5s hold)
wait $CPID; CE=$?
echo "client_exit=$CE T=$(date +%s.%N) — exit ≈ +9s means immediate latch rejection"
kill $WSALL $WSSESS 2>/dev/null; wait $WSALL $WSSESS 2>/dev/null
echo "=== CLIENT OUTPUT (full) ==="; cat /tmp/t8.14/$STEP.client.log
echo "=== WS EVENTS channel=* (audit) ==="; cat /tmp/t8.14/$STEP.ws-all.log
echo "=== WS EVENTS sess:$SID (watcher attached after latch) ==="; cat /tmp/t8.14/$STEP.ws-sess.log
echo "=== DATA LOG tail ==="; tail -8 /tmp/zt-data.log
