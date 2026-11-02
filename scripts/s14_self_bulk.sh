#!/usr/bin/env bash
# 用离线评估器跑自建千条样本（先 rsync 规则，再跑）
# 用法：bash /mnt/hgfs/share/scripts/s14_self_bulk.sh
set -uo pipefail

SRC=/mnt/hgfs/share/WAF-lite
DST=/opt/litewaf/src/WAF-lite

echo "==> 1/3 同步规则与评估器"
sudo rsync -a --exclude logs --exclude build "$SRC/conf/" "$DST/conf/"
sudo rsync -a --exclude logs --exclude build "$SRC/tools/" "$DST/tools/" 2>/dev/null || true

echo "==> 2/3 确认规则条数"
sudo grep -c '^lwaf_rule' "$DST/conf/litewaf_rules.conf"

echo "==> 3/3 跑自建样本"
cd "$DST"
sudo python3 /mnt/hgfs/share/scripts/s14_bulk_eval2.py \
  --rules "$DST/conf/litewaf_rules.conf" \
  --attack /mnt/hgfs/share/samples/self_attack.tsv \
  --benign /mnt/hgfs/share/samples/self_normal.tsv \
  --out /mnt/hgfs/share/samples/reports/self-1500.json 2>&1 | tail -40
