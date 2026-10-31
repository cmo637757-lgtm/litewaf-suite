#!/bin/bash
# ============================================================================
# S6 初始化：建告警相关表 + 预置两条规则
#
# 用法（Kali 里，root 权限）：
#   sudo bash /mnt/hgfs/share/scripts/s6_init_db.sh
# 或者从 Windows 侧：
#   echo kali | sudo -S bash /mnt/hgfs/share/scripts/s6_init_db.sh
# ============================================================================
set -euo pipefail

SRC=/mnt/hgfs/share/platform/backend/src/main/resources/sql/alerts.sql
DST=/opt/litewaf/platform/backend/src/main/resources/sql/alerts.sql

echo "==> 1/3 同步 SQL 到 /opt（去掉 CRLF，MariaDB 对行尾敏感）"
mkdir -p "$(dirname "$DST")"
sed 's/\r$//' "$SRC" > "$DST"
echo "    $DST  $(wc -l < "$DST") 行"

echo "==> 2/3 建表"
mariadb --skip-ssl litewaf < "$DST"

echo "==> 3/3 校验"
mariadb --skip-ssl -N -e "SHOW TABLES FROM litewaf" | grep -E '^(alert|cursor)' | sed 's/^/    /'
mariadb --skip-ssl -N -e "SELECT id, name, category, threshold, window_s, suppress_s FROM litewaf.alert_rules" | sed 's/^/    规则: /'
echo "完成"
