#!/usr/bin/env bash
# 重新打包后端并重启（application.yml 里的 ${LITEWAF_JWT_SECRET:默认} / ${LITEWAF_DB_PASSWORD:默认} 才会进 jar）。
# 用法：
#   sudo bash s12_backend_rebuild.sh                    # 用默认演示密钥
#   LITEWAF_JWT_SECRET=xxx sudo -E bash s12_backend_rebuild.sh   # 注入真实密钥
set -uo pipefail
LW=/opt/litewaf

echo "==> 1/4 同步后端源码（含 application.yml）"
rsync -a --delete --exclude target /mnt/hgfs/share/platform/backend/ "$LW/platform/backend/"
chown -R kali:kali "$LW/platform/backend"

echo "==> 2/4 打包（跳过测试，约 1 分钟）"
cd "$LW/platform/backend" || exit 3
if ! sudo -u kali mvn -q -o -DskipTests package > /tmp/mvn_pkg.log 2>&1; then
    echo "  [FAIL] 打包失败，最后 15 行："
    tail -15 /tmp/mvn_pkg.log | sed 's/^/    /'
    exit 1
fi
ls -l target/platform-0.1.0.jar | sed 's/^/    /'
echo "  [OK] application.yml 里的 secret 现在是："
grep -E 'secret:|password:' src/main/resources/application.yml | sed 's/^/    /'

echo "==> 3/4 重启后端（带密钥变量透传）"
fuser -k 18080/tcp 2>/dev/null || true
sleep 2
setsid nohup sudo -u kali --preserve-env=LITEWAF_JWT_SECRET,LITEWAF_DB_PASSWORD \
  java -jar target/platform-0.1.0.jar \
  --app.collector.status-file="$LW/state/collector_status.json" \
  > "$LW/platform.log" 2>&1 < /dev/null &
disown 2>/dev/null || true
for i in $(seq 1 45); do
  curl -sf -o /dev/null http://127.0.0.1:18080/api/health && break
  sleep 1
done

echo "==> 4/4 自检"
echo -n "    health="
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18080/api/health
echo -n "    登录="
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:18080/api/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"admin","password":"LiteWaf@2026"}'
echo "    --- 进程环境（确认 sudo 没把变量吃掉）---"
PID=$(pgrep -f 'platform-0.1.0.jar' | head -1)
if [ -n "${PID:-}" ]; then
  tr '\0' '\n' < "/proc/$PID/environ" | grep -E '^LITEWAF_' | sed 's/=.*/=<已设置>/' || echo "    （未设置 LITEWAF_*，走 yml 默认值）"
fi
