#!/usr/bin/env bash
# 打一条带唯一标记的攻击，用来验证「SSE 实时滚入」——跑完 3 秒内页面最近拦截表第一行应该就是它。
set -uo pipefail
UA='Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0 Safari/537.36'
MARK="live-$(date +%H%M%S)"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" \
  "http://127.0.0.1:18010/p1?id=1%20and%201=1%20--%20${MARK}")
echo "code=${CODE} marker=${MARK}"
sleep 3
echo "--- 数据库里最新一条 ---"
mariadb --skip-ssl -ulitewaf -p'LiteWaf@2026' litewaf -N -e \
  "SELECT id, FROM_UNIXTIME(event_time_ms/1000), uri, category_display FROM waf_events ORDER BY id DESC LIMIT 2;" 2>/dev/null
