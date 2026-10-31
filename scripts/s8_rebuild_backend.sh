#!/usr/bin/env bash
# 同步后端源码 → Maven 打包（跳过测试）→ 重启 18080
set -euo pipefail

SHARE=/mnt/hgfs/share
DST=/opt/litewaf/platform/backend

echo "== 同步源码 =="
rsync -a --delete --exclude target --exclude node_modules \
      "$SHARE/platform/backend/" "$DST/"

echo "== 打包 =="
cd "$DST"
mvn -o -q -DskipTests package 2>&1 | tail -25 || {
  echo "[FAIL] 打包失败"; exit 1; }
ls -l target/platform-0.1.0.jar

echo "== 重启后端 =="
fuser -k 18080/tcp 2>/dev/null || true
sleep 2
setsid java -jar target/platform-0.1.0.jar > /opt/litewaf/platform.log 2>&1 < /dev/null &
for i in $(seq 1 40); do
  sleep 1
  if curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/api/health | grep -q 200; then
    echo "[OK] 后端起来了（${i}s）"
    exit 0
  fi
done
echo "[FAIL] 40 秒内没起来，看日志："
tail -30 /opt/litewaf/platform.log
exit 1
