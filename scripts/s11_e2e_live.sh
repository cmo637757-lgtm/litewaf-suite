#!/usr/bin/env bash
# 真实链路端到端：从「打一条攻击」到「页面能查到」，中间不手工插数据。
# 验证：WAF 拦截 → JSONL 日志 → 采集器 → MariaDB → 平台接口。
set -uo pipefail
DB="python3 /mnt/hgfs/share/scripts/db_query.py"
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36'
MARK="e2e-$RANDOM$RANDOM"

echo "==> 1/5 记录基线"
$DB <<SQL | tail -3
SELECT (SELECT COUNT(*) FROM requests) AS req,
       (SELECT COUNT(*) FROM waf_events) AS ev;
SQL

echo "==> 2/5 打三条请求（1 正常 + 2 攻击），UA=$MARK 的兄弟随便带"
curl -s -o /dev/null -w '  正常  %{http_code}\n' -A "$UA" "http://127.0.0.1:18010/p0?mark=$MARK"
curl -s -o /dev/null -w '  SQLi  %{http_code}\n' -A "$UA" "http://127.0.0.1:18010/p0?id=1%20UNION%20SELECT%201,2,3&mark=$MARK"
curl -s -o /dev/null -w '  XSS   %{http_code}\n' -A "$UA" "http://127.0.0.1:18010/p0?q=%3Cscript%3Ealert(1)%3C/script%3E&mark=$MARK"

echo "==> 3/5 等采集器（1 秒一轮，给 4 秒）"
sleep 4

echo "==> 4/5 复查库"
$DB <<SQL | tail -4
SELECT (SELECT COUNT(*) FROM requests) AS req,
       (SELECT COUNT(*) FROM waf_events) AS ev;
SELECT id, event_time_ms, client_ip, uri, category_display, rule_id
FROM waf_events WHERE uri LIKE '%mark=$MARK%' ORDER BY id DESC LIMIT 3;
SQL

echo "==> 5/5 走平台接口查（模拟页面）"
TOKEN=$(curl -s -X POST http://127.0.0.1:18080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"LiteWaf@2026"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
curl -s -H "Authorization: Bearer $TOKEN" \
  'http://127.0.0.1:18080/api/events?page=1&page_size=3&sortby=time&order=desc' \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print("  total =",d["total"]);[print("   ",e["uri"][:60],"|",e["category_display"]) for e in d["items"] if "mark=" in e["uri"]]'
