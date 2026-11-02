#!/usr/bin/env bash
# P7 初始化：启用引擎的静态黑名单通道
#   1. 在 runtime nginx.conf 的 server 块里 include 一个 blacklist.conf（幂等）
#   2. 空文件先建好，nginx -t 通过后 reload
#   3. 重启执行器加载 /blocklist 动作
#   4. 验证：封 127.0.0.1 应立刻 403，解封后恢复 200
# 注意：所有 sudo 调用都不能让 heredoc 抢 stdin（踩过：echo pw | sudo -S python3 <<PY 会卡死）
set -uo pipefail
PW="${KALI_PWD:-kali}"
RT=/opt/litewaf/runtime
CONF=$RT/conf/nginx.conf
BL=$RT/conf/blacklist.conf
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36'
NGINX=$(command -v nginx || echo /usr/sbin/nginx)
TOKEN=$(cat $RT/engine.token 2>/dev/null || echo "")
SUDO() { echo "$PW" | sudo -S "$@" 2>/dev/null; }

echo "==> 1/5 在 nginx.conf 里 include blacklist.conf（幂等）"
SUDO python3 /mnt/hgfs/share/scripts/_p7_include.py "$CONF"

echo "==> 2/5 建空黑名单文件"
if [ ! -f "$BL" ]; then
  # 先写到一个 kali 可写的位置，再 sudo 拷过去（避免 tee 与密码抢 stdin）
  cat > /tmp/blacklist.seed <<'EOF'
# 自动封禁名单：红色告警触发时由平台写入，执行器 reload 后生效
# 手动加一条也行，格式：lite_waf_blacklist <ip>/32;
EOF
  SUDO cp /tmp/blacklist.seed "$BL"
  SUDO chmod 644 "$BL"
  echo "   已创建 $BL"
else
  echo "   已存在，保留现有内容"
fi

echo "==> 3/5 nginx -t + reload"
SUDO "$NGINX" -p $RT -c conf/nginx.conf -t 2>&1 | tail -2
SUDO "$NGINX" -p $RT -c conf/nginx.conf -s reload 2>&1 | tail -2
sleep 2
code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" http://127.0.0.1:18010/waf-marker)
echo "   正常请求 = $code（期望 200）"

echo "==> 4/5 重启执行器（加载 /blocklist 动作）"
SUDO pkill -f engine_exec.py
sleep 1
cat > /tmp/p7_exec.sh <<'EOF'
cd /opt/litewaf/engine && setsid nohup python3 engine_exec.py > /opt/litewaf/runtime/logs/engine_exec.log 2>&1 < /dev/null &
EOF
SUDO bash /tmp/p7_exec.sh
sleep 3
curl -s -o /dev/null -w "   执行器 = %{http_code}\n" -H "X-Engine-Token: $TOKEN" http://127.0.0.1:18081/status

echo "==> 5/5 封 / 解封验证（用 127.0.0.1 自己试）"
r=$(curl -s -X POST http://127.0.0.1:18081/blocklist -H "X-Engine-Token: $TOKEN" \
    -H 'Content-Type: application/json' -d '{"ip":"127.0.0.1","action":"add"}')
echo "   add → $r"
sleep 1
code1=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" http://127.0.0.1:18010/waf-marker)
echo "   封后请求 = $code1（期望 403）"
r2=$(curl -s -X POST http://127.0.0.1:18081/blocklist -H "X-Engine-Token: $TOKEN" \
     -H 'Content-Type: application/json' -d '{"ip":"127.0.0.1","action":"remove"}')
echo "   remove → $r2"
sleep 1
code2=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" http://127.0.0.1:18010/waf-marker)
echo "   解封后请求 = $code2（期望 200）"

echo "--- blacklist.conf ---"
cat "$BL"
