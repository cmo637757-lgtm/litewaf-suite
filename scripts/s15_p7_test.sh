#!/usr/bin/env bash
# 干净验证 blacklist：先重启 runtime 清空 CC 动态封禁残留，再测
# 打 location /（有 lite_waf on），不要打 /waf-marker（那个 location 不开 WAF）
set -uo pipefail
TOKEN=$(cat /opt/litewaf/runtime/engine.token)
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36'
code() { curl -s -o /dev/null -w '%{http_code}' -A "$UA" "http://127.0.0.1:18010$1"; }
bl() { curl -s -X POST http://127.0.0.1:18081/blocklist -H "X-Engine-Token: $TOKEN" \
       -H 'Content-Type: application/json' -d "{\"ip\":\"127.0.0.1\",\"action\":\"$1\"}"; }

echo "==> 1/4 重启 runtime（清 CC 封禁残留）"
systemctl restart litewaf-runtime
sleep 3
echo "   / = $(code /)（期望 200）"

echo "==> 2/4 加入黑名单"
bl add; echo
sleep 2
echo "   / = $(code /)（期望 403）"
grep -c '"reason":"blacklist"' /opt/litewaf/runtime/logs/waf_audit.log | sed 's/^/   blacklist 日志条数：/'

echo "==> 3/4 移出黑名单"
bl remove; echo
sleep 2
echo "   / = $(code /)（期望 200）"

echo "==> 4/4 黑名单文件"
cat /opt/litewaf/runtime/conf/blacklist.conf
