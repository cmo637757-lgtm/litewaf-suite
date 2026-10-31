#!/usr/bin/env bash
# 日志轮转 + 数据保留（答辩问"跑一个月会怎样"时直接甩这个脚本的结果）。
#
# 设计取舍：
#   * 用 copytruncate 而不是 rename。rename 模式下采集器只跟配置里那个路径，
#     旧文件被改名成 .1 之后里面没读到的行就再也不会被采（最多丢一个扫描周期）。
#     copytruncate 是"先拷贝再清空原文件"，采集器靠 inode 不变但 size 变小
#     识别为"被截断"，会开新代次从头读（见 lwaf_collect.py 的 _cursor_state）。
#   * nginx 的 access/audit 是逐行 open/write/close，copytruncate 天然兼容；
#     error.log 是常开 fd，copytruncate 同样不需要 reload。
# 用法：sudo bash /mnt/hgfs/share/scripts/s12_logrotate.sh
set -uo pipefail

LOG_DIR=/opt/litewaf/runtime/logs
STATE_DIR=/opt/litewaf/state
ROTATE_CONF=/etc/logrotate.d/litewaf
RETAIN_SH=/usr/local/bin/litewaf-retain

echo "==> 0/5 修正目录属主（logrotate 拒绝轮转 world/组可写的父目录）"
install -d -m 755 -o root -g root "$LOG_DIR"
install -d -m 775 -o root -g kali "$STATE_DIR"
# 采集器心跳文件从 logs/ 挪到 state/（采集器以 kali 跑，logs/ 已收紧到 root:root 755）
if [ -f "$LOG_DIR/collector_status.json" ]; then
    mv -f "$LOG_DIR/collector_status.json" "$STATE_DIR/collector_status.json"
    chown kali:kali "$STATE_DIR/collector_status.json"
    echo "    [OK] collector_status.json 已迁移到 $STATE_DIR"
fi
echo "    [OK] $LOG_DIR 755 root:root；$STATE_DIR 775 root:kali"

echo "==> 1/4 写入 logrotate 配置 $ROTATE_CONF"
cat > "$ROTATE_CONF" <<'CONF'
/opt/litewaf/runtime/logs/access.log
/opt/litewaf/runtime/logs/waf_audit.log
/opt/litewaf/runtime/logs/error.log
/opt/litewaf/runtime/logs/static_access.log
/opt/litewaf/runtime/logs/static_error.log
{
    daily
    rotate 7
    size 20M
    missingok
    notifempty
    compress
    delaycompress
    dateext
    dateformat -%Y%m%d-%s
    copytruncate
    su root root
}
CONF
chmod 644 "$ROTATE_CONF"
echo "    [OK] $(wc -l < "$ROTATE_CONF") 行"

echo "==> 2/4 写入数据库保留脚本 $RETAIN_SH（默认保留 30 天）"
cat > "$RETAIN_SH" <<'SH'
#!/usr/bin/env bash
# 清理超过保留期的采集数据。默认 30 天，可用 LITEWAF_RETAIN_DAYS 覆盖。
set -uo pipefail
RETAIN_DAYS="${LITEWAF_RETAIN_DAYS:-30}"
BASE="$(date -d "-${RETAIN_DAYS} days" +%s%3N)"

# 先删孤儿关联（避免外键挡住 waf_events 的删除），再删两张主表
mariadb --skip-ssl -ulitewaf -p'LiteWaf@2026' litewaf -e "
DELETE ae FROM alert_events ae
  LEFT JOIN waf_events e ON e.id = ae.event_id
  WHERE e.id IS NULL;
DELETE FROM requests  WHERE event_time_ms < ${BASE} LIMIT 50000;
DELETE FROM waf_events WHERE event_time_ms < ${BASE} LIMIT 50000;
" 2>/dev/null

# 采集错误只留最近 2000 条（这是排障用的，不需要长期堆积）
mariadb --skip-ssl -ulitewaf -p'LiteWaf@2026' litewaf -e "
DELETE FROM ingest_errors
  WHERE id < (SELECT floor_id FROM (SELECT MIN(id) AS floor_id FROM
      (SELECT id FROM ingest_errors ORDER BY id DESC LIMIT 2000) t) x)
" 2>/dev/null
SH
chmod 755 "$RETAIN_SH"
echo "    [OK] 默认保留 ${LITEWAF_RETAIN_DAYS:-30} 天"

echo "==> 3/4 挂到 cron.d（每天 04:10 清库；logrotate 由系统 cron.daily 驱动）"
cat > /etc/cron.d/litewaf-retain <<'CRON'
# 清理超期采集数据（保留天数见 /usr/local/bin/litewaf-retain）
10 4 * * * root /usr/local/bin/litewaf-retain >/dev/null 2>&1
CRON
chmod 644 /etc/cron.d/litewaf-retain
echo "    [OK] /etc/cron.d/litewaf-retain"

echo "==> 4/4 立刻强制轮转一次做验证"
before=$(ls -1 "$LOG_DIR"/*.log 2>/dev/null | wc -l)
logrotate -f "$ROTATE_CONF" 2>&1 | sed 's/^/    /'
echo "--- 轮转后目录 ---"
ls -la "$LOG_DIR" | grep -E '\.log' | sed 's/^/    /'
after=$(ls -1 "$LOG_DIR"/*-* 2>/dev/null | wc -l)
echo "--- 归档文件数: $after（原始 $before 个文件）---"

echo "==> 等 6 秒，看采集器有没有被截断搞挂"
sleep 6
python3 - <<'PY'
import json
p = "/opt/litewaf/runtime/logs/collector_status.json"
try:
    s = json.load(open(p))
    print("    rounds=%s ingested=%s errors=%s" % (s.get("rounds"), s.get("ingested_total"), s.get("errors_total")))
    for src in s.get("sources", []):
        print("    %-14s offset=%-8s size=%-8s lag=%s" % (
            src.get("name"), src.get("offset"), src.get("size"), src.get("lag_bytes")))
except Exception as e:
    print("    [WARN] 读状态失败:", e)
PY
echo "==> 完成。以后每天 3:00 前后自动轮转，保留 7 份并压缩；每天 04:10 清 30 天前数据。"
