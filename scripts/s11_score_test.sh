#!/usr/bin/env bash
# 验证「按命中次数计分」改动的实际效果。
# 用法：bash /mnt/hgfs/share/scripts/s11_score_test.sh
set -uo pipefail
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36'
probe() { curl -s -o /dev/null -w '%{http_code}' -A "$UA" "http://127.0.0.1:18010$1"; }

printf '%-6s %s\n' '状态' '请求'
for u in \
  '/' \
  '/?id=1%20SELECT%20*%20FROM%20users' \
  '/?id=1%20select%20name%20from%20users%20where%20id=1' \
  '/?id=1%20union%20select%201' \
  '/?q=hello%20world' \
  '/?page=2&size=20&sort=time'; do
  printf '%-6s %s\n' "$(probe "$u")" "$u"
done
