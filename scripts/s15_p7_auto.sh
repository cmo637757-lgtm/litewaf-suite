#!/usr/bin/env bash
# P7 平台侧验证：建表 → 造红色告警 → 平台应自动调执行器封禁来源 IP
set -uo pipefail
PW="${KALI_PWD:-kali}"
Q() { echo "$PW" | sudo -S mariadb --skip-ssl -u litewaf -pLiteWaf@2026 litewaf -N -B "$@" 2>/dev/null; }

echo "==> 1/5 建 blocklist 表"
echo "$PW" | sudo -S mariadb --skip-ssl -u litewaf -pLiteWaf@2026 litewaf \
  < /mnt/hgfs/share/platform/backend/src/main/resources/sql/blocklist.sql 2>/dev/null
echo "$PW" | sudo -S mariadb --skip-ssl -u litewaf -pLiteWaf@2026 litewaf -N -B \
  -e "SHOW TABLES LIKE 'blocklist'" 2>/dev/null

echo "==> 2/5 清空历史（避免干扰）"
Q -e "TRUNCATE TABLE blocklist;"
echo "   blocklist = $(Q -e 'SELECT COUNT(*) FROM blocklist;')"
# 引擎侧黑名单也清空
echo "$PW" | sudo -S tee /opt/litewaf/runtime/conf/blacklist.conf > /dev/null <<'EOF'
# 自动封禁名单：红色告警触发时由平台写入，执行器 reload 后生效
# 手动加一条也行，格式：lite_waf_blacklist <ip>/32;
EOF
systemctl restart litewaf-runtime
sleep 2

echo "==> 3/5 造 12 条 CC 事件（threshold=5, 第 10 条起应转红）"
NOW=$(($(date +%s%3N)))
IP=10.88.0.7
for i in $(seq 1 12); do
  T=$((NOW - 11000 + i * 500))
  Q -e "INSERT INTO waf_events (event_time_ms, client_ip, method, uri, reason, rule_id, rule_name, zone,
        category, category_display, score, total_score, action, status, cost_us, source_id)
        VALUES ($T, '$IP', 'GET', '/x$i', 'dynamic_block', 0, 'dynamic block', 'ARGS',
        'CC', 'CC', 0, 0, 'deny', 403, 200, 1);"
done
echo "   事件数 = $(Q -e "SELECT COUNT(*) FROM waf_events WHERE client_ip='$IP';")"
# 回退游标，让消费者重新处理这批
MINID=$(Q -e "SELECT MIN(id) FROM waf_events WHERE client_ip='$IP';")
Q -e "UPDATE alert_consumer_cursor SET last_event_id = $MINID - 1 WHERE id = 1;"

echo "==> 4/5 等消费器（约 6 秒）"
sleep 6
echo "   告警："
Q -e "SELECT id, client_ip, severity, trigger_count FROM alerts ORDER BY id DESC LIMIT 2;"
echo "   blocklist 表："
Q -e "SELECT id, client_ip, reason, alert_id, active FROM blocklist;"

echo "==> 5/5 引擎侧黑名单文件"
cat /opt/litewaf/runtime/conf/blacklist.conf
echo "   --- 接口 ---"
TOKEN=$(cat /opt/litewaf/runtime/engine.token)
curl -s -H "X-Engine-Token: $TOKEN" http://127.0.0.1:18081/blocklist | head -c 300; echo
