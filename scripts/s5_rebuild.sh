#!/usr/bin/env bash
# S5：改完规则解析器后重编 addon + 重启 runtime 实例 + 验证
set -uo pipefail

RT=/opt/litewaf/runtime
SRC=/opt/litewaf/src/WAF-lite
NGXD=/opt/litewaf/build/nginx-check/nginx-1.24.0
NFX=$NGXD/objs/nginx

echo "==> 1/6 同步源码到 /opt/litewaf/src"
rsync -a --delete --exclude .git /mnt/hgfs/share/WAF-lite/ "$SRC/"

echo "==> 2/6 规则引擎单测"
cd "$SRC" && make test 2>&1 | tail -3

echo "==> 3/6 重编 nginx（含 addon）"
cd "$NGXD" && make -j4 2>&1 | tail -4
ls -l "$NFX"

echo "==> 4/6 重启 runtime 实例（18010）"
"$NFX" -p "$RT" -c conf/nginx.conf -s quit 2>/dev/null || true
sleep 1
"$NFX" -p "$RT" -c conf/nginx.conf
sleep 1
"$NFX" -p "$RT" -c conf/nginx.conf -t 2>&1 | tail -1

echo "==> 5/6 冒烟"
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36'
echo "  正常：$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" 'http://127.0.0.1:18010/index.html')（期望 200）"
echo "  SQLi：$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" 'http://127.0.0.1:18010/?id=1%20UNION%20SELECT%20password%20FROM%20users')（期望 403）"
echo "  marker：$(curl -s -o /dev/null -w '%{http_code}' 'http://127.0.0.1:18010/waf-marker')（期望 200）"

echo "==> 6/6 坏前缀是否已被拒绝"
printf 'rule 1000 SQL str "union select"\n' > /tmp/badprefix.conf
cp "$RT/rules/litewaf_rules.conf" /tmp/rules.keep
cp /tmp/badprefix.conf "$RT/rules/litewaf_rules.conf"
"$NFX" -p "$RT" -c conf/nginx.conf -t 2>&1 | grep -E 'emerg|failed|successful' | head -3
cp /tmp/rules.keep "$RT/rules/litewaf_rules.conf"
echo "（已恢复原规则）"
