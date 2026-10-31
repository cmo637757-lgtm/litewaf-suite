#!/usr/bin/env bash
# S10 收尾自检：服务在不在、数据对不对、页面能不能开。
set -uo pipefail
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36'

echo "== 端口 =="
for p in 18010 18080 18081 18082 5173 3306; do
  if ss -lnt 2>/dev/null | grep -q ":$p "; then echo "  $p  LISTEN"; else echo "  $p  -"; fi
done

echo "== 三处入口 =="
printf '  WAF 实例(18010) 正常请求  %s\n' "$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" http://127.0.0.1:18010/p1)"
printf '  WAF 实例(18010) SQLi      %s\n' "$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" 'http://127.0.0.1:18010/?id=1%20UNION%20SELECT%20x%20FROM%20users')"
printf '  平台(18080) health        %s\n' "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/api/health)"
printf '  静态站(18082) 首页        %s\n' "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18082/)"
printf '  静态站(18082) SPA 路由    %s\n' "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18082/rules)"
printf '  Vite dev(5173)            %s\n' "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5173/)"

echo "== 数据自洽 =="
# 用 mktemp：这个脚本常被 root 跑，固定 /tmp/chk.sql 会撞上别人留下的属主，
# 报 "Permission denied"（SQL 照样能跑，但日志里一行红字很难看）。
CHK=$(mktemp /tmp/chk.XXXXXX.sql)
cat > "$CHK" <<'SQL'
SELECT (SELECT COUNT(*) FROM requests) AS requests,
       (SELECT COUNT(*) FROM waf_events) AS waf_events,
       (SELECT COUNT(*) FROM ingest_errors) AS ingest_errors,
       (SELECT COUNT(*) FROM false_positive_marks) AS fp_marks,
       (SELECT COUNT(*) FROM alerts) AS alerts;
SQL
python3 /mnt/hgfs/share/scripts/db_query.py < "$CHK"
rm -f "$CHK"

echo "== 采集器状态 =="
cat /opt/litewaf/runtime/logs/collector_status.json 2>/dev/null | head -c 500
echo
