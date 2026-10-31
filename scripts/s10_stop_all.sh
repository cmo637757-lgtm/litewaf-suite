#!/usr/bin/env bash
# 停掉 LiteWAF 全部服务（库与 systemd 的引擎实例也一起停，方便干净重来）。
# 用法：sudo bash /mnt/hgfs/share/scripts/s10_stop_all.sh [--keep-db]
set -uo pipefail
KEEP_DB=0
[ "${1:-}" = "--keep-db" ] && KEEP_DB=1
say() { printf '%s\n' "$*"; }

say "==> 停采集器"
pkill -f 'lwaf_collect\.py' 2>/dev/null && say "  已停" || say "  本来就没跑"

say "==> 停后端（18080）"
fuser -k 18080/tcp 2>/dev/null && say "  已停" || say "  本来就没跑"

say "==> 停执行器（18081）"
fuser -k 18081/tcp 2>/dev/null && say "  已停" || say "  本来就没跑"

say "==> 停/卸载静态站（18082）"
bash /mnt/hgfs/share/scripts/console_static.sh stop 2>&1 | tail -2

say "==> 停 WAF 引擎实例（18010）"
systemctl stop litewaf-runtime 2>/dev/null && say "  已停" || say "  没在跑"

say "==> 停 Vite（5173，如果开着）"
fuser -k 5173/tcp 2>/dev/null && say "  已停" || say "  本来就没跑"

if [ "$KEEP_DB" = "0" ]; then
  say "==> 停 MariaDB"
  systemctl stop mariadb 2>/dev/null && say "  已停" || say "  没在跑"
else
  say "==> MariaDB 保持运行（--keep-db）"
fi

echo
say "== 端口自检（应全部无输出） =="
ss -ltn 2>/dev/null | awk 'NR>1{print $4}' | grep -E ':(18010|18080|18081|18082|5173|3306)$' || say "  已全部释放"
