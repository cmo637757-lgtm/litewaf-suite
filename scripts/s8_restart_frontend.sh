#!/usr/bin/env bash
# 重启 Vite dev server（顺带看一眼内存，Kali 只给 6GB，java+vite 一起容易 OOM）
set -u

echo "== 内存 =="
free -h

echo
echo "== 停掉旧进程 =="
fuser -k 5173/tcp 2>/dev/null && echo "  已停 5173" || echo "  5173 本来就没在跑"
pkill -f "vite" 2>/dev/null || true
sleep 2

echo
echo "== 启动 =="
cd /opt/litewaf/platform/frontend
setsid nohup ./node_modules/.bin/vite --host 0.0.0.0 --port 5173 \
  > /tmp/vite.log 2>&1 < /dev/null &
for i in $(seq 1 30); do
  sleep 1
  if curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5173/ | grep -q 200; then
    echo "[OK] vite 起来了（${i}s）"
    tail -5 /tmp/vite.log
    exit 0
  fi
done
echo "[FAIL] 没起来，日志："
tail -20 /tmp/vite.log
exit 1
