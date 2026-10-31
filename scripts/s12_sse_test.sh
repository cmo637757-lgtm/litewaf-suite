#!/usr/bin/env bash
# 验证 SSE：未带 token 应 401；带 token 应收到 tick 事件（2 秒一帧）。
set -uo pipefail
BASE=http://127.0.0.1:18080

echo "==> 1/3 未带 token（期望 401）"
curl -s -o /dev/null -w '    HTTP %{http_code}\n' "$BASE/api/stats/stream"

echo "==> 2/3 登录拿 token"
TOKEN=$(curl -s -X POST "$BASE/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"LiteWaf@2026"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
echo "    token 长度 = ${#TOKEN}"

echo "==> 3/3 连 6 秒，数 tick 帧数"
timeout 6 curl -sN "$BASE/api/stats/stream?token=$TOKEN" > /tmp/sse_out.txt 2>&1 || true
echo -n "    tick 事件数 = "
grep -c '^event:tick' /tmp/sse_out.txt || true
echo "    首帧内容（截断 300 字符）："
head -3 /tmp/sse_out.txt | cut -c1-300 | sed 's/^/    /'
echo "    --- 连接数（后端日志）---"
grep -c 'SSE 连接建立' /opt/litewaf/platform.log 2>/dev/null | sed 's/^/    /' || echo "    （DEBUG 日志未开）"
