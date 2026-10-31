#!/usr/bin/env bash
# 验证 LITEWAF_JWT_SECRET 环境变量确实被 Spring 读进去（换个随机密钥重启，仍能正常登录）。
set -uo pipefail
LW=/opt/litewaf
cd "$LW/platform/backend" || exit 3

SECRET="verify-$(date +%s)-$(openssl rand -hex 8)"
echo "注入 secret 前缀: ${SECRET:0:24}..."

fuser -k 18080/tcp 2>/dev/null || true
sleep 2

LITEWAF_JWT_SECRET="$SECRET" setsid nohup sudo -E -u kali --preserve-env=LITEWAF_JWT_SECRET \
  java -jar target/platform-0.1.0.jar \
  --app.collector.status-file="$LW/state/collector_status.json" \
  > "$LW/platform-envtest.log" 2>&1 < /dev/null &

for i in $(seq 1 45); do
  curl -sf -o /dev/null http://127.0.0.1:18080/api/health && break
  sleep 1
done

PID=$(pgrep -f 'platform-0.1.0.jar' | head -1)
echo -n "进程环境 LITEWAF_JWT_SECRET = "
tr '\0' '\n' < "/proc/$PID/environ" | grep '^LITEWAF_JWT_SECRET=' | cut -c1-32
echo -n "登录状态码 = "
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:18080/api/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"admin","password":"LiteWaf@2026"}'
echo "（健康 200 + 登录 200 说明占位符已生效；换密钥后旧 token 会失效，这是预期行为）"
