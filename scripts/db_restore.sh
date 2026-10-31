#!/usr/bin/env bash
# ==============================================================================
# LiteWAF 数据库恢复 —— 从备份文件把库灌回去
#
# 用法：
#   sudo bash /mnt/hgfs/share/scripts/db_restore.sh                       # 列出可用备份
#   sudo bash .../db_restore.sh /opt/litewaf/backups/litewaf-20261022-130000.sql.gz
#   sudo bash .../db_restore.sh <file> --yes                              # 跳过确认
#
# 安全措施：
#   · 恢复前自动给当前库做一次「恢复点」备份（回滚用）
#   · 需要输入 yes 确认，避免手滑
#   · 恢复后校验 6 张核心表的行数
# ==============================================================================
set -uo pipefail

DB_NAME="${DB_NAME:-litewaf}"
DB_USER="${DB_USER:-litewaf}"
DB_PASS="${DB_PASS:-LiteWaf@2026}"
OUT_DIR="/opt/litewaf/backups"
SRC="${1:-}"
CONFIRM="${2:-}"

if [ -z "$SRC" ] || [ ! -f "$SRC" ]; then
  echo "当前可用备份（${OUT_DIR}）："
  ls -1lh "${OUT_DIR}"/*.sql.gz 2>/dev/null | awk '{print "  " $9 "  " $5}' || echo "  （没有）"
  echo
  echo "用法：sudo bash $0 <备份文件> [--yes]"
  exit 2
fi

echo "==> 将用 ${SRC} 覆盖数据库 ${DB_NAME}"
if [ "$CONFIRM" != "--yes" ]; then
  printf '确认继续？输入 yes 回车：'
  read -r ans
  [ "$ans" = "yes" ] || { echo "已取消"; exit 1; }
fi

# 恢复点：先把当前状态备份一份，万一恢复到一半发现选错文件还能退回去
RP="${OUT_DIR}/restore-point-$(date '+%Y%m%d-%H%M%S').sql.gz"
echo "==> 先给当前库做恢复点：${RP}"
if mariadb-dump --skip-ssl -u "$DB_USER" -p"$DB_PASS" --single-transaction --quick \
      --default-character-set=utf8mb4 "$DB_NAME" 2>/dev/null | gzip -9 > "$RP"; then
  echo "    [OK] $(du -h "$RP" | cut -f1)"
else
  echo "    [WARN] 恢复点失败，继续（但你就没有退路了）"
fi

echo "==> 校验备份文件完整性"
if ! gzip -t "$SRC" 2>/dev/null; then
  echo "[FAIL] 备份文件损坏，中止" >&2
  exit 1
fi

echo "==> 恢复中（先删表再灌，避免旧数据混进来）"
# DROP 掉再灌：备份文件里是 CREATE TABLE，不先清会撞「表已存在」
mariadb --skip-ssl -u "$DB_USER" -p"$DB_PASS" -e "
  SET FOREIGN_KEY_CHECKS=0;
  DROP TABLE IF EXISTS requests, waf_events, ingest_sources, ingest_cursors, ingest_errors,
                       false_positive_marks, alerts, alert_events, alert_deliveries,
                       alert_rules, alert_consumer_cursor, operations, users, config_versions;
  SET FOREIGN_KEY_CHECKS=1;" 2>/dev/null

if ! gunzip -c "$SRC" | mariadb --skip-ssl -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" 2>/tmp/db_restore.err; then
  echo "[FAIL] 恢复失败：" >&2
  sed -n '1,8p' /tmp/db_restore.err >&2
  echo "       恢复点在 ${RP}，可再执行本脚本指回它" >&2
  exit 1
fi

echo "==> 校验行数"
mariadb --skip-ssl -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" -N -e "
  SELECT 'requests', COUNT(*) FROM requests
  UNION ALL SELECT 'waf_events', COUNT(*) FROM waf_events
  UNION ALL SELECT 'alerts', COUNT(*) FROM alerts
  UNION ALL SELECT 'false_positive_marks', COUNT(*) FROM false_positive_marks
  UNION ALL SELECT 'operations', COUNT(*) FROM operations
  UNION ALL SELECT 'alert_rules', COUNT(*) FROM alert_rules;" 2>/dev/null |
  awk '{printf "    %-22s %s\n", $1, $2}'

echo "[OK] 恢复完成。若平台/采集器在跑，建议重启一下让连接池重建："
echo "     sudo fuser -k 18080/tcp 18081/tcp; # 再按使用说明第 1 节拉起"
