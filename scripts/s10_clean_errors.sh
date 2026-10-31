#!/usr/bin/env bash
# 清掉「combined 格式导致的 JSONDecodeError」错误行，并重置 access 游标。
# 用法：sudo bash /mnt/hgfs/share/scripts/s10_clean_errors.sh
set -uo pipefail
cat > /tmp/clean_errors.sql <<'SQL'
DELETE FROM ingest_errors WHERE error LIKE 'JSONDecodeError%';
DELETE FROM ingest_cursors WHERE source_id = (SELECT id FROM ingest_sources WHERE name = 'nginx_access');
SELECT (SELECT COUNT(*) FROM requests) AS req_total,
       (SELECT COUNT(*) FROM ingest_errors) AS err_total,
       (SELECT COUNT(*) FROM waf_events) AS ev_total;
SQL
python3 /mnt/hgfs/share/scripts/db_query.py < /tmp/clean_errors.sql
