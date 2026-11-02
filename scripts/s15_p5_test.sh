#!/usr/bin/env bash
# P5 验收：突增检测 + 分级告警
# 场景：把 CC 规则阈值调到 5、突增倍数调到 2.0，造一段历史基线（每窗 5 条），
#       再在当前窗口灌 12 条 —— 第 5 条按阈值触发（yellow），第 10 条 ≥ 2×阈值 转红。
set -uo pipefail
PW="${KALI_PWD:-kali}"

q() { python3 /mnt/hgfs/share/scripts/db_query.py <<<"$1"; }

echo "==> 1/5 清场：删掉本次要用的告警与关联，规则 2 改成 threshold=5 ratio=2.0"
q "DELETE FROM alert_events WHERE alert_id IN (SELECT id FROM alerts WHERE rule_id=2);
DELETE FROM alert_deliveries WHERE alert_id IN (SELECT id FROM alerts WHERE rule_id=2);
DELETE FROM alerts WHERE rule_id=2;
UPDATE alert_rules SET threshold=5, ratio=2.0, window_s=60, suppress_s=120, severity='yellow' WHERE id=2;"

echo "==> 2/5 造历史基线：过去 5 个窗口各 5 条 CC 事件（20~16 分钟前）"
python3 - <<'PY'
import time, subprocess, os
now = int(time.time() * 1000)
rows = []
for minutes in (40, 35, 30, 25, 20):
    base = now - minutes * 60 * 1000
    for j in range(5):
        rows.append((base + j * 1000, "10.77.0.9", "CC", "dynamic_block"))
vals = ",".join(
    f"({t},'{ip}','GET','/p{j}','CC','CC','score_threshold',0,0,'deny',403,300,1)"
    for j, (t, ip, cat, reason) in enumerate(rows)
)
sql = ("INSERT INTO waf_events (event_time_ms, client_ip, method, uri, category, category_display, "
       "reason, rule_id, total_score, action, status, cost_us, source_id) VALUES " + vals + ";")
subprocess.run(["python3", "/mnt/hgfs/share/scripts/db_query.py"], input=sql, text=True, check=True)
print(f"   inserted {len(rows)} baseline events")
PY

echo "==> 3/5 当前窗口灌 12 条（把消费器游标退回到它们之前，让它逐条消费）"
python3 - <<'PY'
import time, subprocess
now = int(time.time() * 1000)
vals = ",".join(
    f"({now - (12 - j) * 700},'10.77.0.9','GET','/live{j}','CC','CC','score_threshold',0,0,'deny',403,300,1)"
    for j in range(12)
)
sql = ("INSERT INTO waf_events (event_time_ms, client_ip, method, uri, category, category_display, "
       "reason, rule_id, total_score, action, status, cost_us, source_id) VALUES " + vals + ";\n"
       "UPDATE alert_consumer_cursor SET last_event_id = (SELECT MIN(id) - 1 FROM waf_events "
       "WHERE client_ip='10.77.0.9' AND uri LIKE '/live%') WHERE id = 1;")
subprocess.run(["python3", "/mnt/hgfs/share/scripts/db_query.py"], input=sql, text=True, check=True)
print("   inserted 12 events, cursor rewound")
PY

echo "==> 4/5 等消费器跑两轮（约 5 秒）"
sleep 6

echo "==> 5/5 查结果"
q "SELECT id, rule_id, client_ip, category, metric, trigger_count, event_count, severity,
         ROUND(burst_ratio,2) AS burst, suppressed_until_ms
  FROM alerts WHERE rule_id=2 ORDER BY id DESC LIMIT 3;"

echo "--- 预期：1 条告警，trigger_count≈7（第 5 条起阈值触发，第 10 条起红），severity=red，burst ≈ 2.0 ---"
