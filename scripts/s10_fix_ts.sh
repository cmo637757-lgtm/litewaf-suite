#!/usr/bin/env bash
# 修掉「秒级时间戳被当毫秒入库」的 5 条脏数据，并让新代码重采 access.log。
# 用法：sudo bash /mnt/hgfs/share/scripts/s10_fix_ts.sh
set -uo pipefail
cat > /tmp/fix_ts.sql <<'SQL'
DELETE FROM requests WHERE event_time_ms < 1000000000000;
DELETE FROM ingest_cursors WHERE source_id = (SELECT id FROM ingest_sources WHERE name = 'nginx_access');
SELECT (SELECT COUNT(*) FROM requests) AS req_total;
SQL
python3 /mnt/hgfs/share/scripts/db_query.py < /tmp/fix_ts.sql

cd /opt/litewaf/platform/collector
sudo -u kali python3 lwaf_collect.py --config config.ini --once 2>&1 | tail -3

cat > /tmp/verify_ts.sql <<'SQL'
SELECT id, event_time_ms, FROM_UNIXTIME(event_time_ms/1000) AS cst, client_ip, uri, status
FROM requests ORDER BY id DESC LIMIT 5;
SELECT COUNT(*) AS in_24h FROM requests
WHERE event_time_ms >= (UNIX_TIMESTAMP() * 1000 - 86400000) AND event_time_ms < (UNIX_TIMESTAMP() * 1000);
SQL
python3 /mnt/hgfs/share/scripts/db_query.py < /tmp/verify_ts.sql
