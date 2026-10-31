#!/usr/bin/env bash
# 10 号脚本：把「后端 + 采集器」最新源码同步到 /opt 并重启。
# 六项功能（备份/静态托管/采集器健康/性能页/规则试打/崩溃演练）之后统一用它部署。
# 用法：sudo bash /mnt/hgfs/share/scripts/s10_deploy.sh
set -uo pipefail

SHARE=${LITEWAF_SHARE:-/mnt/hgfs/share}
BE=/opt/litewaf/platform/backend
COL=/opt/litewaf/platform/collector

echo "==> 1/5 同步源码（共享盘 → /opt）"
rsync -a --delete "$SHARE/platform/backend/src/" "$BE/src/"
cp "$SHARE/platform/backend/pom.xml" "$BE/pom.xml"
rsync -a "$SHARE/platform/collector/" "$COL/" --exclude __pycache__ --exclude '*.log'
echo "[OK] backend/src + collector 已同步"

echo "==> 2/5 编译后端"
cd "$BE" || { echo "[FAIL] $BE 不存在"; exit 1; }
if ! sudo -u kali mvn -q -B package -DskipTests 2>&1 | tail -12; then
  echo "[FAIL] 编译失败"; exit 1
fi
ls -l target/platform-0.1.0.jar || { echo "[FAIL] 没产出 jar"; exit 1; }

echo "==> 3/5 重启后端（18080）"
fuser -k 18080/tcp 2>/dev/null || true
sleep 2
setsid sudo -u kali java -jar target/platform-0.1.0.jar > /opt/litewaf/platform.log 2>&1 < /dev/null &
sleep 12
curl -s -o /dev/null -w '[OK] health=%{http_code}\n' http://127.0.0.1:18080/api/health
tail -2 /opt/litewaf/platform.log

echo "==> 4/5 重启采集器"
pkill -f 'lwaf_collect.py' 2>/dev/null || true
sleep 1
cd "$COL" || { echo "[FAIL] $COL 不存在"; exit 1; }
setsid sudo -u kali python3 lwaf_collect.py --config config.ini > /tmp/collector.log 2>&1 < /dev/null &
sleep 4
tail -3 /tmp/collector.log

echo "==> 5/5 状态文件"
if [ -f /opt/litewaf/runtime/logs/collector_status.json ]; then
  ls -l /opt/litewaf/runtime/logs/collector_status.json
  python3 -c "import json;d=json.load(open('/opt/litewaf/runtime/logs/collector_status.json'));print('[OK] rounds=%s ingested=%s errors=%s sources=%s' % (d['rounds'], d['ingested_total'], d['errors_total'], len(d['sources'])))"
else
  echo "[WARN] 还没有状态文件：检查 /tmp/collector.log"
fi
