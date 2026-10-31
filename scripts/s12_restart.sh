#!/usr/bin/env bash
# 让「心跳文件迁到 /opt/litewaf/state」与「logs 收紧到 root:root 755」生效：
# 同步采集器配置 → 重启采集器 → 重启后端（带新的 status-file 参数）。
set -uo pipefail
LW=/opt/litewaf

echo "==> 1/5 同步采集器"
rsync -a --delete --exclude __pycache__ /mnt/hgfs/share/platform/collector/ "$LW/platform/collector/"
chown -R kali:kali "$LW/platform/collector"
grep -n 'status_file' "$LW/platform/collector/config.ini" | sed 's/^/    /'

echo "==> 2/5 建 state 目录并授权"
install -d -m 775 -o root -g kali "$LW/state"
chown -R kali:kali "$LW/state"
ls -ld "$LW/state" | sed 's/^/    /'

echo "==> 3/5 重启采集器"
pkill -f 'lwaf_collect\.py' 2>/dev/null || true
sleep 1
cd "$LW/platform/collector" || exit 3
setsid nohup sudo -u kali python3 lwaf_collect.py --config config.ini \
  > "$LW/collector.log" 2>&1 < /dev/null &
disown 2>/dev/null || true
sleep 4
pgrep -fa 'lwaf_collect\.py' | sed 's/^/    /' | head -2

echo "==> 4/5 重启后端（18080，带 status-file 覆盖）"
fuser -k 18080/tcp 2>/dev/null || true
sleep 2
cd "$LW/platform/backend" || exit 3
setsid nohup sudo -u kali java -jar target/platform-0.1.0.jar \
  --app.collector.status-file="$LW/state/collector_status.json" \
  > "$LW/platform.log" 2>&1 < /dev/null &
disown 2>/dev/null || true
for i in $(seq 1 40); do
  curl -sf -o /dev/null http://127.0.0.1:18080/api/health && break
  sleep 1
done

echo "==> 5/5 自检"
echo -n "    health="
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18080/api/health
echo -n "    collector="
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18080/api/collector/status
echo "    --- 心跳文件 ---"
python3 - <<'PY'
import json
p = "/opt/litewaf/state/collector_status.json"
try:
    s = json.load(open(p))
    print("    rounds=%s ingested=%s errors=%s" % (s.get("rounds"), s.get("ingested_total"), s.get("errors_total")))
    for src in s.get("sources", []):
        print("    %-14s offset=%-9s size=%-9s lag=%s" % (
            src.get("name"), src.get("offset"), src.get("size"), src.get("lag_bytes")))
except Exception as e:
    print("    [WARN]", e)
PY
echo "    --- 日志目录 ---"
ls -l "$LW/runtime/logs" | grep -E '\.log' | head -6 | sed 's/^/    /'
