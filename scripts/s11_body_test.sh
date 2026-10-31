#!/usr/bin/env bash
# 验证请求体硬上限（⑪）：超过上限直接 413，不再"截断后只查前 8KB"。
# 用法：bash /mnt/hgfs/share/scripts/s11_body_test.sh
set -uo pipefail
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36'

small=/tmp/lwaf_small.txt
big=/tmp/lwaf_big.txt
attack=/tmp/lwaf_big_attack.txt

printf 'hello=world' > "$small"

# 9KB 纯填充：旧行为会截断检测放行（200），新行为应 413
head -c 9216 /dev/zero | tr '\0' 'a' > "$big"

# 8KB 填充 + 攻击载荷：检验"垫填充绕过"是否被堵住
head -c 9216 /dev/zero | tr '\0' 'a' > "$attack"
printf ' UNION SELECT password FROM users' >> "$attack"

post() {
  curl -s -o /dev/null -w '%{http_code}' -A "$UA" -X POST \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-binary @"$1" "http://127.0.0.1:18010/"
}

printf '%-6s %-10s %s\n' '状态' '大小' '场景'
printf '%-6s %-10s %s\n' "$(post "$small")" "$(wc -c < "$small")B" '小表单（应 200）'
printf '%-6s %-10s %s\n' "$(post "$big")" "$(wc -c < "$big")B" '9KB 纯填充（应 413）'
printf '%-6s %-10s %s\n' "$(post "$attack")" "$(wc -c < "$attack")B" '9KB 填充+SQL（应 413）'

echo '--- 最近 3 条审计日志 ---'
tail -3 /opt/litewaf/runtime/logs/waf_audit.log
