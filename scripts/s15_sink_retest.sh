#!/usr/bin/env bash
# 起 webhook sink（本地接收器）后跑告警闭环回归
set -uo pipefail
pkill -f webhook_sink.py 2>/dev/null
sleep 1
cd /mnt/hgfs/share/platform/tools
setsid nohup python3 webhook_sink.py --port 18099 --out /tmp/webhook_received.jsonl \
  > /tmp/sink.log 2>&1 < /dev/null &
disown
sleep 3
echo "-- sink 监听："
ss -ltn 2>/dev/null | grep 18099 || echo "   no listener"
echo "-- 跑告警回归："
cd /mnt/hgfs/share/scripts
timeout 150 python3 s6_alert_test.py 2>&1 | tail -8
