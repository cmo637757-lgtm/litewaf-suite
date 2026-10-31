#!/usr/bin/env bash
# ==============================================================================
# 控制台静态站点：构建 dist + 用系统 nginx（18082）托管
#
# 和 Vite dev（5173）的关系：
#   · 5173 = 开发模式，改代码即时生效，但依赖 node_modules，答辩演示不建议用
#   · 18082 = 生产模式，纯静态文件 + 反代 /api，配置好之后不依赖 Node
#
# 用法（需要 root，因为要写 /opt/litewaf 和起 nginx）：
#   sudo bash /mnt/hgfs/share/scripts/console_static.sh build     # 只构建
#   sudo bash /mnt/hgfs/share/scripts/console_static.sh start     # 构建并启动
#   sudo bash /mnt/hgfs/share/scripts/console_static.sh restart   # 重建并重载
#   sudo bash /mnt/hgfs/share/scripts/console_static.sh stop
#   sudo bash /mnt/hgfs/share/scripts/console_static.sh status
# ==============================================================================
set -uo pipefail

FE_DIR="/opt/litewaf/platform/frontend"
CONF="${FE_DIR}/nginx-static.conf"
PIDF="/opt/litewaf/runtime/logs/static_nginx.pid"
PORT=18082
ACTION="${1:-start}"

build() {
  echo "==> 构建前端（vite build）"
  cd "$FE_DIR" || exit 1
  # 日志必须用 mktemp：这个脚本常被 root 跑，固定的 /tmp/vite_build.log 一旦被
  # 非 root 用户留下，重定向就会 "Permission denied"（踩过两次）。
  local LOG
  LOG=$(mktemp /tmp/vite_build.XXXXXX.log)
  # 以 kali 身份跑，避免 dist 变成 root 属主；用本地二进制，避免 PATH 里别的版本
  if id kali >/dev/null 2>&1; then
    sudo -u kali ./node_modules/.bin/vite build >"$LOG" 2>&1
  else
    ./node_modules/.bin/vite build >"$LOG" 2>&1
  fi
  if [ $? -ne 0 ]; then
    echo "[WARN] 构建失败，日志：$LOG"
    tail -20 "$LOG"
    # dist 还在就用旧的，别让一条构建警告把整个静态站挡死
    if [ -f "${FE_DIR}/dist/index.html" ]; then
      echo "    仍使用现有 dist 继续启动"
      return 0
    fi
    exit 1
  fi
  echo "    [OK] dist 已生成（$(du -sh "$FE_DIR/dist" | cut -f1)）"
  chmod -R a+rX "$FE_DIR/dist" 2>/dev/null || true
}

prepare_dirs() {
  # nginx 的临时目录默认指向 /var/lib/nginx/*，Kali 上属主不对会直接 [emerg] mkdir() failed。
  # 配置里已改到 runtime/tmp，这里保证目录存在且 worker（www-data）可写。
  mkdir -p /opt/litewaf/runtime/tmp/body \
           /opt/litewaf/runtime/tmp/proxy \
           /opt/litewaf/runtime/tmp/fastcgi \
           /opt/litewaf/runtime/tmp/uwsgi \
           /opt/litewaf/runtime/tmp/scgi
  chown -R www-data:www-data /opt/litewaf/runtime/tmp 2>/dev/null || true
}

start() {
  prepare_dirs
  if [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF" 2>/dev/null)" 2>/dev/null; then
    echo "已在运行（pid $(cat "$PIDF")），执行 reload"
    /usr/sbin/nginx -c "$CONF" -s reload && echo "    [OK] reload 完成"
    return
  fi
  echo "==> 启动静态站点 ${PORT}"
  if ! /usr/sbin/nginx -c "$CONF"; then
    echo "[FAIL] 启动失败，看 /opt/litewaf/runtime/logs/static_error.log"
    tail -10 /opt/litewaf/runtime/logs/static_error.log 2>/dev/null
    exit 1
  fi
  sleep 1
  echo "    [OK] pid $(cat "$PIDF" 2>/dev/null)"
}

case "$ACTION" in
  build)   build ;;
  start)   build; start ;;
  restart) build
           /usr/sbin/nginx -c "$CONF" -s quit 2>/dev/null; sleep 1
           start ;;
  stop)    /usr/sbin/nginx -c "$CONF" -s quit 2>/dev/null && echo "已停止" || echo "没在跑" ;;
  status)  if [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF" 2>/dev/null)" 2>/dev/null; then
             echo "运行中，pid $(cat "$PIDF")，端口 ${PORT}"
           else
             echo "未运行"
           fi ;;
  *) echo "用法：$0 {build|start|restart|stop|status}"; exit 2 ;;
esac

if [ "$ACTION" != "stop" ] && [ "$ACTION" != "status" ]; then
  echo
  echo "==> 自检"
  printf '    GET /            -> %s\n' "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/" || echo 000)"
  printf '    GET /api/health  -> %s\n' "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/api/health" || echo 000)"
  printf '    GET /events/1    -> %s (SPA 路由回退)\n' "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/events/1" || echo 000)"
  echo
  echo "浏览器访问：http://192.168.134.140:${PORT}"
fi
