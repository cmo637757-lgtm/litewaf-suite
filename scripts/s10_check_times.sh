#!/usr/bin/env bash
# 排查：requests 表的时间分布与 24 小时窗口内的计数
set -uo pipefail
cat > /tmp/q.sql <<'SQL'
SELECT COUNT(*) AS n, MIN(event_time_ms) AS min_ms, MAX(event_time_ms) AS max_ms FROM requests;
SELECT id, event_time_ms, FROM_UNIXTIME(event_time_ms/1000) AS cst, client_ip, status FROM requests ORDER BY id DESC LIMIT 5;
SELECT COUNT(*) AS in_24h FROM requests WHERE event_time_ms >= (UNIX_TIMESTAMP() * 1000 - 86400000) AND event_time_ms < (UNIX_TIMESTAMP() * 1000);
SELECT COUNT(*) AS waf_in_24h FROM waf_events WHERE event_time_ms >= (UNIX_TIMESTAMP() * 1000 - 86400000) AND event_time_ms < (UNIX_TIMESTAMP() * 1000);
SQL
python3 /mnt/hgfs/share/scripts/db_query.py < /tmp/q.sql
