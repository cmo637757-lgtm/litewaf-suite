#!/usr/bin/env bash
# P7 验证（整个脚本要以 root 跑：echo kali | sudo -S bash 本脚本）
# 执行器必须 root：do_blocklist 要写 /opt/litewaf/runtime/conf/ 并 reload nginx
set -uo pipefail
RT=/opt/litewaf/runtime
LW=/opt/litewaf
LOG=/opt/litewaf/state/engine_exec.log
TOKEN=$(cat $RT/engine.token 2>/dev/null || echo "")
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36'

if [ "$(id -u)" != "0" ]; then echo "需要 root 跑"; exit 1; fi

echo "==> 1/4 同步并重启执行器（root 身份）"
rsync -a /mnt/hgfs/share/platform/engine/ "$LW/engine/"
pkill -f engine_exec.py 2>/dev/null
sleep 1
cd "$LW/engine" || exit 3
setsid nohup python3 engine_exec.py > "$LOG" 2>&1 < /dev/null &
disown 2>/dev/null || true
for i in $(seq 1 20); do
  if ss -ltn 2>/dev/null | grep -q ':18081'; then echo "   18081 已监听"; break; fi
  sleep 1
done
ps -o user=,cmd= -C python3 2>/dev/null | grep engine_exec | head -1
tail -1 "$LOG" 2>/dev/null || true

echo "==> 2/4 封 127.0.0.1"
r=$(curl -s -X POST http://127.0.0.1:18081/blocklist -H "X-Engine-Token: $TOKEN" \
    -H 'Content-Type: application/json' -d '{"ip":"127.0.0.1","action":"add"}')
echo "   add → $r"
sleep 2
code1=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" http://127.0.0.1:18010/waf-marker)
echo "   封后 marker = $code1（期望 403）"

echo "==> 3/4 解封"
r2=$(curl -s -X POST http://127.0.0.1:18081/blocklist -H "X-Engine-Token: $TOKEN" \
     -H 'Content-Type: application/json' -d '{"ip":"127.0.0.1","action":"remove"}')
echo "   remove → $r2"
sleep 2
code2=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" http://127.0.0.1:18010/waf-marker)
echo "   解封后 marker = $code2（期望 200）"

echo "==> 4/4 黑名单文件"
cat "$RT/conf/blacklist.conf"
