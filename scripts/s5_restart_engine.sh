#!/usr/bin/env bash
# 重启 engine-exec（root），日志落 /tmp/engine.log 避免权限问题
set -uo pipefail
fuser -k 18081/tcp 2>/dev/null || true
sleep 1
setsid /usr/bin/python3 /opt/litewaf/engine/engine_exec.py > /tmp/engine.log 2>&1 < /dev/null &
sleep 2
tail -2 /tmp/engine.log
TOKEN=$(cat /opt/litewaf/runtime/engine.token)
curl -s -H "X-Engine-Token: $TOKEN" http://127.0.0.1:18081/status | head -c 300
echo
