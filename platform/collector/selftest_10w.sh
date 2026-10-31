#!/bin/bash
# selftest_10w.sh —— S2 采集器自检：10 万行吞吐 + 崩溃恢复（可重复跑）
#
# 跑法：sudo bash /mnt/hgfs/share/platform/collector/selftest_10w.sh
#
# 检查项：
#   1. 生成 10 万行访问日志，单次采集耗时（目标 < 60 秒）
#   2. 行数核对：requests = 100000，ingest_errors = 0
#   3. 追加 2 万行后常驻模式跑 3 秒，kill -9 模拟崩溃；
#      再重启续采，最终 requests = 120000 且无重复（游标保证）
set -uo pipefail

BIG=/tmp/lwaf_big
COL=/opt/litewaf/platform/collector
DB="mariadb --skip-ssl"
LOG=$BIG/access.log

step() { echo; echo "==> $*"; }

step "1/6 生成 10 万行访问日志"
mkdir -p "$BIG"
python3 - "$LOG" <<'PY'
import json, sys
n = 100000
base = 1789862400000
with open(sys.argv[1], "w", encoding="utf-8", newline="\n") as f:
    for i in range(n):
        f.write(json.dumps({
            "time": base + i * 100,
            "client_ip": "10.1.0.%d" % (i % 250 + 1),
            "method": "GET",
            "uri": "/x%d" % i,
            "status": 200,
            "body_bytes_sent": 1000,
            "request_time": (i % 1000) / 1000,
        }, separators=(",", ":")) + "\n")
PY
ls -lh "$LOG" | awk '{print "  文件大小:", $5}'

step "2/6 重置表并写入测试配置"
$DB litewaf -e 'TRUNCATE requests; TRUNCATE waf_events; TRUNCATE ingest_errors; TRUNCATE ingest_cursors; TRUNCATE ingest_sources;' && echo "  已清空"
cat > "$COL/config.big.ini" <<EOF
[db]
host = 127.0.0.1
port = 3306
user = litewaf
password = LiteWaf@2026
database = litewaf

[collector]
poll_interval = 0.2
batch_max = 500

[sources]
big_access = $LOG|access
EOF
echo "  config.big.ini 就绪"

step "3/6 单次采集 10 万行（测吞吐）"
SECONDS=0
python3 "$COL/lwaf_collect.py" --config "$COL/config.big.ini" --once
echo "  耗时 ${SECONDS} 秒"
$DB litewaf -e 'SELECT COUNT(*) AS requests FROM requests; SELECT COUNT(*) AS errors FROM ingest_errors;'

step "4/6 追加 2 万行"
python3 - "$LOG" <<'PY'
import json, sys
base = 1789862400000 + 100000 * 100
with open(sys.argv[1], "a", encoding="utf-8", newline="\n") as f:
    for i in range(100000, 120000):
        f.write(json.dumps({
            "time": base + (i - 100000) * 100,
            "client_ip": "10.1.0.%d" % (i % 250 + 1),
            "method": "GET",
            "uri": "/x%d" % i,
            "status": 200,
            "body_bytes_sent": 1000,
            "request_time": (i % 1000) / 1000,
        }, separators=(",", ":")) + "\n")
PY
echo "  文件现在有 $(wc -l < "$LOG") 行"

step "5/6 常驻模式跑 3 秒后 kill -9（模拟崩溃）"
python3 "$COL/lwaf_collect.py" --config "$COL/config.big.ini" &
PID=$!
sleep 3
kill -9 "$PID" 2>/dev/null
wait "$PID" 2>/dev/null
echo "  已 kill 采集器（pid=$PID）"
$DB litewaf -e 'SELECT COUNT(*) AS 崩溃时已入库 FROM requests'

step "6/6 重启续采并核对总数"
python3 "$COL/lwaf_collect.py" --config "$COL/config.big.ini" --once
$DB litewaf -e 'SELECT COUNT(*) AS requests_total FROM requests; SELECT COUNT(*) AS errors FROM ingest_errors; SELECT source_id, generation, byte_offset, inode_size FROM ingest_cursors;'

echo
echo "==> 自检完成。期望：requests_total = 120000，errors = 0，游标 byte_offset = 文件大小"
