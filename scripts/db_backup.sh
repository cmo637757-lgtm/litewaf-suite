#!/usr/bin/env bash
# ==============================================================================
# LiteWAF 数据库备份 —— 一条命令把整个库导成带时间戳的 .sql.gz
#
# 用法：
#   sudo bash /mnt/hgfs/share/scripts/db_backup.sh              # 默认备份到 /opt/litewaf/backups
#   sudo bash .../db_backup.sh --out /tmp/bk                   # 换目录
#   sudo bash .../db_backup.sh --keep 14                       # 只保留最近 14 份（默认 10）
#
# 为什么不用 /tmp：/tmp 重启就没了，演示前备份等于没备。
# 为什么带 --skip-ssl：MariaDB 11.8 客户端默认尝试 TLS，本地 socket 环境会握手失败。
# ==============================================================================
set -uo pipefail

DB_NAME="${DB_NAME:-litewaf}"
DB_USER="${DB_USER:-litewaf}"
DB_PASS="${DB_PASS:-LiteWaf@2026}"
OUT_DIR="/opt/litewaf/backups"
KEEP=10

while [ $# -gt 0 ]; do
  case "$1" in
    --out)  OUT_DIR="$2"; shift 2 ;;
    --keep) KEEP="$2"; shift 2 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "未知参数：$1" >&2; exit 2 ;;
  esac
done

mkdir -p "$OUT_DIR"
TS=$(date '+%Y%m%d-%H%M%S')
FILE="${OUT_DIR}/${DB_NAME}-${TS}.sql.gz"

echo "==> 备份 ${DB_NAME} → ${FILE}"

# --single-transaction：InnoDB 下拿到一致性快照，且不锁表（采集器还能继续写）
# --routines --triggers --events：把存储过程/触发器/事件一起带走
if ! mariadb-dump --skip-ssl \
      -u "$DB_USER" -p"$DB_PASS" \
      --single-transaction --quick --routines --triggers --events \
      --default-character-set=utf8mb4 \
      "$DB_NAME" 2>/tmp/db_backup.err | gzip -9 > "$FILE"; then
  echo "[FAIL] 导出失败：" >&2
  sed -n '1,5p' /tmp/db_backup.err >&2
  rm -f "$FILE"
  exit 1
fi

SIZE=$(du -h "$FILE" | cut -f1)
# 用 gzip -t 验证压缩包完整，避免截断的备份被当成好的
if ! gzip -t "$FILE" 2>/dev/null; then
  echo "[FAIL] 备份文件损坏（gzip -t 不通过）" >&2
  exit 1
fi

# 记一份清单，恢复时能核对
printf '%s\t%s\t%s\n' "$(basename "$FILE")" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$SIZE" >> "${OUT_DIR}/MANIFEST.tsv"

echo "[OK] ${SIZE}，gzip 完整性校验通过"

# 滚动清理：只留最近 KEEP 份
CNT=$(ls -1 "${OUT_DIR}"/*.sql.gz 2>/dev/null | wc -l)
if [ "$CNT" -gt "$KEEP" ]; then
  echo "==> 共 ${CNT} 份，清理到 ${KEEP} 份"
  ls -1t "${OUT_DIR}"/*.sql.gz | tail -n +$((KEEP + 1)) | xargs -r rm -f
fi

echo "==> 现有备份："
ls -1lh "${OUT_DIR}"/*.sql.gz 2>/dev/null | awk '{print "    " $9 "  " $5}'
