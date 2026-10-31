#!/usr/bin/env bash
# 重新编译并重启后端；同时把执行器令牌调成后端用户可读（root:kali 640）
set -uo pipefail

BE=/opt/litewaf/platform/backend
TOKEN=/opt/litewaf/runtime/engine.token

echo "==> 1/4 令牌权限（root:kali 640，后端以 kali 运行也能读）"
chown root:kali "$TOKEN" 2>/dev/null || true
chmod 640 "$TOKEN"
ls -l "$TOKEN"

echo "==> 2/4 编译后端"
cd "$BE"
sudo -u kali mvn -q -B package -DskipTests 2>&1 | tail -15 || { echo "[FAIL] 编译失败"; exit 1; }
ls -l target/platform-0.1.0.jar

echo "==> 3/4 重启后端"
fuser -k 18080/tcp 2>/dev/null || true
sleep 2
cd "$BE"
LOG=/opt/litewaf/platform.log
setsid sudo -u kali java -jar target/platform-0.1.0.jar > "$LOG" 2>&1 < /dev/null &
sleep 12
tail -2 "$LOG"

echo "==> 4/4 探活"
curl -s -o /dev/null -w 'health=%{http_code}\n' http://127.0.0.1:18080/api/health
