#!/usr/bin/env bash
# 一键启动 LiteWAF 全部服务（幂等：已在跑的自动跳过）。
# 顺序有讲究：先库、再引擎、再执行器/后端、最后采集器与静态站。
# 用法：sudo bash /mnt/hgfs/share/scripts/s10_start_all.sh
set -uo pipefail
LW=/opt/litewaf
say() { printf '%s\n' "$*"; }

has_port() { ss -ltn 2>/dev/null | awk 'NR>1{print $4}' | grep -qE "[:.]$1$"; }
wait_port() {
  local p=$1 n=${2:-25} i=0
  while [ $i -lt $n ]; do has_port "$p" && return 0; i=$((i+1)); sleep 1; done
  return 1
}

say "==> 1/6 MariaDB"
if systemctl is-active --quiet mariadb; then
  say "  已在运行"
else
  systemctl start mariadb && say "  已启动"
fi
wait_port 3306 30 || { say "  [FAIL] 3306 没起来"; systemctl status mariadb --no-pager | tail -5; exit 2; }

say "==> 2/6 WAF 引擎实例（18010，systemd 守护）"
if systemctl is-active --quiet litewaf-runtime; then
  say "  已在运行"
else
  systemctl start litewaf-runtime && say "  已启动"
fi
wait_port 18010 20 || { say "  [FAIL] 18010 没起来"; journalctl -u litewaf-runtime -n 10 --no-pager; exit 2; }

say "==> 3/6 执行器（18081）"
if has_port 18081; then
  say "  已在运行"
else
  cd "$LW/engine" || exit 3
  setsid nohup python3 engine_exec.py > "$LW/engine.log" 2>&1 < /dev/null &
  disown 2>/dev/null || true
  wait_port 18081 20 && say "  已启动" || { say "  [FAIL] 18081 没起来，看 $LW/engine.log"; exit 2; }
fi

say "==> 4/6 平台后端（18080）"
if has_port 18080; then
  say "  已在运行"
else
  cd "$LW/platform/backend" || exit 3
  # status-file 用启动参数覆盖：心跳文件在 /opt/litewaf/state（logs/ 要 root:root 755 才能被 logrotate 轮转）
  #
  # 密钥：application.yml 里是 ${LITEWAF_JWT_SECRET:默认} / ${LITEWAF_DB_PASSWORD:默认}，
  # 想改成自己的就 export 这两个变量再跑本脚本（或写进 /etc/litewaf/secrets.env）：
  #   LITEWAF_JWT_SECRET="$(openssl rand -base64 48)" LITEWAF_DB_PASSWORD='你的库口令'
  # 不设就走演示默认值，页面照样能用。
  setsid nohup sudo -u kali --preserve-env=LITEWAF_JWT_SECRET,LITEWAF_DB_PASSWORD \
    java -jar target/platform-0.1.0.jar \
    --app.collector.status-file=/opt/litewaf/state/collector_status.json \
    > "$LW/platform.log" 2>&1 < /dev/null &
  disown 2>/dev/null || true
  wait_port 18080 60 && say "  已启动" || { say "  [FAIL] 18080 没起来，看 $LW/platform.log"; exit 2; }
fi

say "==> 5/6 采集器"
if pgrep -f 'lwaf_collect\.py' > /dev/null 2>&1; then
  say "  已在运行"
else
  cd "$LW/platform/collector" || exit 3
  setsid nohup sudo -u kali python3 lwaf_collect.py --config config.ini \
    > "$LW/collector.log" 2>&1 < /dev/null &
  disown 2>/dev/null || true
  sleep 2
  pgrep -f 'lwaf_collect\.py' > /dev/null 2>&1 && say "  已启动" || { say "  [FAIL] 采集器没起来，看 $LW/collector.log"; exit 2; }
fi

say "==> 6/7 控制台静态站（18082，推荐演示入口）"
if has_port 18082; then
  say "  已在运行"
else
  bash /mnt/hgfs/share/scripts/console_static.sh start 2>&1 | tail -6
  wait_port 18082 15 || say "  [WARN] 18082 没起来"
fi

say "==> 7/7 Vite dev（5173，开发用；SKIP_VITE=1 可跳过）"
if [ "${SKIP_VITE:-0}" = "1" ]; then
  say "  按 SKIP_VITE=1 跳过"
elif has_port 5173; then
  say "  已在运行"
else
  cd "$LW/platform/frontend" || exit 3
  VLOG=$(mktemp /tmp/vite.XXXXXX.log)
  setsid nohup sudo -u kali ./node_modules/.bin/vite --host 0.0.0.0 --port 5173 \
    > "$VLOG" 2>&1 < /dev/null &
  disown 2>/dev/null || true
  wait_port 5173 25 && say "  已启动（日志 $VLOG）" || say "  [WARN] 5173 没起来，看 $VLOG"
fi

echo
say "== 自检 =="
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36'
printf '  引擎正常请求        %s\n' "$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" http://127.0.0.1:18010/)"
printf '  引擎拦截 SQLi       %s\n' "$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" 'http://127.0.0.1:18010/?id=1%20UNION%20SELECT%201')"
printf '  平台 health         %s\n' "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/api/health)"
printf '  静态站首页          %s\n' "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18082/)"
printf '  采集器进程          %s\n' "$(pgrep -f 'lwaf_collect\.py' > /dev/null 2>&1 && echo 在 || echo 不在)"
echo
say "控制台： http://192.168.134.140:18082   （账号 admin / LiteWaf@2026）"
