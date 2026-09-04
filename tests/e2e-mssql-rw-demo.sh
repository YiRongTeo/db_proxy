#!/bin/bash
# E2E MSSQL READ/WRITE session demo — maker admin (JWT login), checker account (WS watch)
# Steps: issue rw token (maker) -> attach checker watcher -> rw SQL flows -> verify checker feed events
# JWT-era auth (2026-09-05 conversion): the MAKER account (admin) mints DB
# tokens; the CHECKER account watches/lists/kills (strict SoD — control.yaml
# auth.allow_maker_watch: false, so the maker cannot touch the checker surface).
set -u
cd /d/AI/hermes/Project/Project-D
API=http://127.0.0.1:8080
D=/tmp/rwdemo; mkdir -p $D
# Dev credentials from .env (env override wins; .env.example defaults below).
MAKER_JWT=$(curl -s -X POST $API/api/login -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ZT_AUTH_PASSWORD:-admin123}\"}" \
  | python -c 'import sys,json;print(json.load(sys.stdin)["token"])')
CHECKER_JWT=$(curl -s -X POST $API/api/login -H 'Content-Type: application/json' \
  -d "{\"username\":\"checker\",\"password\":\"${ZT_AUTH_CHECKER_PASSWORD:-checker123}\"}" \
  | python -c 'import sys,json;print(json.load(sys.stdin)["token"])')
[ -n "$MAKER_JWT" ] && [ -n "$CHECKER_JWT" ] || { echo "FATAL: /api/login failed — is the control plane up?"; exit 1; }

echo "== [1] issue rw token (maker=admin, mssql rw_user) =="
TOKEN=$(curl -s -X POST $API/api/token -H "Authorization: Bearer $MAKER_JWT" -H 'Content-Type: application/json' \
  -d '{"username":"admin","db_user":"rw_user","db_ip":"127.0.0.1","db_port":"1434","db_type":"mssql","ticket_id":"E2E-MSSQL-RW-2"}' \
  | python -c 'import sys,json;print(json.load(sys.stdin)["token"])')
echo "TOKEN=${TOKEN:0:14}..."
sleep 0.8
SID=$(curl -s -H "Authorization: Bearer $CHECKER_JWT" $API/api/sessions | python -c '
import sys,json
d=json.load(sys.stdin)
pend=[s for s in d if s.get("status")=="pending"]
print(pend[-1]["session_id"] if pend else "")')
echo "SID=$SID"
echo "$TOKEN" > $D/token; echo "$SID" > $D/sid

echo "== [2] attach checker watcher (checker account) =="
node tests/zt-ws-listen.js "sess:$SID" "$CHECKER_JWT" 80000 > $D/ws.log 2>&1 &
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
