#!/bin/bash
# Control experiment: sqlcmd vs REAL SQL Server KILL (no proxy) — same WAITFOR pattern
set -u
cd /d/AI/hermes/Project/Project-D
SPID=$(docker exec mssql-test /opt/mssql-tools18/bin/sqlcmd -S localhost -U rw_user -P rw_pw -d appdb -C -h -1 -Q "SET NOCOUNT ON; SELECT @@SPID" | tr -d ' \r')
echo "backend SPID=$SPID"
printf "WAITFOR DELAY '00:00:30'\nSELECT 1 AS after_kill\n" | docker exec -i mssql-test /opt/mssql-tools18/bin/sqlcmd -S localhost -U rw_user -P rw_pw -d appdb -C > /tmp/control.client.log 2>&1 &
MK=$!
sleep 4
docker exec mssql-test /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P 'SqlSrv_2022!' -C -Q "KILL $SPID"
wait $MK
echo "client-exit=$?"
echo '--- control client output ---'
cat /tmp/control.client.log
