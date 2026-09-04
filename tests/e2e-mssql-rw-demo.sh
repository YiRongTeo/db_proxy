#!/bin/bash
# E2E MSSQL READ/WRITE session demo — maker alice (API key), checker admin (WS watch)
# Steps: issue rw token -> attach checker within 60s -> rw SQL flows -> kill query -> kill conn
set -u
cd /d/AI/hermes/Project/Project-D
API=http://127.0.0.1:8080
KEY='dev-key-change-me'
COOKIE=$(cat "$HOME/zt.cookie")
D=/tmp/rwdemo; mkdir -p $D

echo "== [1] issue rw token (maker=alice, mssql rw_user) =="
TOKEN=$(curl -s -X POST $API/api/token -H "X-Api-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{"username":"alice","db_user":"rw_user","db_ip":"127.0.0.1","db_port":"1434","db_type":"mssql","ticket_id":"E2E-MSSQL-RW-2"}' \
  | python -c 'import sys,json;print(json.load(sys.stdin)["token"])')
echo "TOKEN=${TOKEN:0:14}..."
sleep 0.8
SID=$(curl -s -H "Cookie: zt_session=$COOKIE" $API/api/sessions | python -c '
import sys,json
d=json.load(sys.stdin)
pend=[s for s in d if s.get("status")=="pending"]
print(pend[-1]["session_id"] if pend else "")')
echo "SID=$SID"
echo "$TOKEN" > $D/token; echo "$SID" > $D/sid

echo "== [2] attach checker watcher (admin) =="
node tests/zt-ws-listen.js "sess:$SID" "$COOKIE" 80000 > $D/ws.log 2>&1 &
WSPID=$!
sleep 3
echo "watch EXISTS: $(docker exec valkey valkey-cli --scan --pattern "watch:$SID:*" | wc -l | tr -d ' ') (1 = checker watcher armed)"

echo "== [3] maker connects (rw_user): INSERT/UPDATE/DELETE/SELECT in one session =="
docker exec mssql-test /opt/mssql-tools18/bin/sqlcmd -S host.docker.internal,3306 -U "$TOKEN" -P x -N o -d appdb -b -Q "
INSERT INTO demo_items VALUES (5,'delta');
UPDATE demo_items SET name='delta2' WHERE id=5;
SELECT COUNT(*) AS after_insert FROM demo_items;
DELETE FROM demo_items WHERE id=5;
SELECT COUNT(*) AS after_delete FROM demo_items;"
echo "rw-session-exit=$?"
sleep 1
echo "== [4] checker feed events (query events for the rw session) =="
grep -o '"stmt_type":"[a-z]*"' $D/ws.log | sort | uniq -c
grep -c 'EVENT' $D/ws.log
echo "WSPID=$WSPID SID=$SID"
