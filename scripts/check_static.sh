#!/usr/bin/env bash
# 控制台静态站点自检：首页、接口反代、SPA 路由回退、assets 缓存头
PORT=18082
B="http://127.0.0.1:${PORT}"

code() { curl -s -o /dev/null -w '%{http_code}' "$1" 2>/dev/null || echo 000; }

echo "== 18082 自检 =="
printf '  首页           %s\n' "$(code "$B/")"
printf '  登录页路由     %s\n' "$(code "$B/login")"
printf '  事件详情路由   %s\n' "$(code "$B/events/1")"
printf '  接口反代       %s\n' "$(code "$B/api/health")"
printf '  404 资源       %s\n' "$(code "$B/nope.js")"

echo
echo "== 首页引用 =="
curl -s "$B/" | tr -d '\r' | grep -oE '(assets/[^"]+|src="[^"]+")' | head -5 | sed 's/^/  /'

echo
echo "== assets 缓存头 =="
A=$(curl -s "$B/" | tr -d '\r' | grep -oE '/assets/[^"]+\.js' | head -1)
if [ -n "$A" ]; then
  curl -sI "$B$A" | tr -d '\r' | grep -iE '^(HTTP|cache-control|content-type)' | sed 's/^/  /'
else
  echo "  （首页没引用到 js，检查 dist 是否生成）"
fi

echo
echo "== gzip 是否生效 =="
if [ -n "$A" ]; then
  ENC=$(curl -sI -H 'Accept-Encoding: gzip' "$B$A" | tr -d '\r' | grep -i '^content-encoding' | awk '{print $2}')
  echo "  ${A} content-encoding: ${ENC:-none}"
fi
