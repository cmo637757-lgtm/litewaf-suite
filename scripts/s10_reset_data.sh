#!/usr/bin/env bash
# 把采集类数据恢复到「自洽」状态：两个日志文件清空后重新灌 F20 固定集，
# 再让采集器把真实请求读进来。起因：access.log 清空过而 waf_audit.log 保留
# 了历史，导致「拦截数 / 请求数」跨表算出来 7900%，演示时很扎眼。
# 用法：sudo bash /mnt/hgfs/share/scripts/s10_reset_data.sh
set -uo pipefail

echo "==> 1/4 清空采集类数据（告警实例保留）"
cat > /tmp/reset.sql <<'SQL'
SET FOREIGN_KEY_CHECKS = 0;
TRUNCATE TABLE requests;
TRUNCATE TABLE waf_events;
TRUNCATE TABLE ingest_errors;
TRUNCATE TABLE ingest_cursors;
TRUNCATE TABLE alert_events;
SET FOREIGN_KEY_CHECKS = 1;
SQL
python3 /mnt/hgfs/share/scripts/db_query.py < /tmp/reset.sql

echo "==> 2/4 清空两份运行日志（避免再采到旧行）"
: > /opt/litewaf/runtime/logs/access.log
: > /opt/litewaf/runtime/logs/waf_audit.log

echo "==> 3/4 重新灌 F20 固定集"
cd /opt/litewaf/platform/collector
sudo -u kali python3 verify_f20.py 2>&1 | tail -3

echo "==> 4/4 打 4 条真实请求（1 正常 + 3 攻击），让采集器采进来"
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36'
for u in "/" "/?id=1%20UNION%20SELECT%20password%20FROM%20users" \
         "/?q=%3Cscript%3Ealert(1)%3C/script%3E" "/../../etc/passwd"; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "http://127.0.0.1:18010$u")
  echo "  $code  $u"
done
sleep 2
cat > /tmp/after.sql <<'SQL'
SELECT (SELECT COUNT(*) FROM requests) AS req,
       (SELECT COUNT(*) FROM waf_events) AS ev,
       (SELECT COUNT(*) FROM ingest_errors) AS err;
SQL
python3 /mnt/hgfs/share/scripts/db_query.py < /tmp/after.sql
