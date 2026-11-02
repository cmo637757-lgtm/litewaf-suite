#!/usr/bin/env bash
# P1/P2/P3 效果：同步规则 → 自建千条样本 + CRS 公开样本各跑一遍
set -uo pipefail
PW="${KALI_PWD:-kali}"
DST=/opt/litewaf/src/WAF-lite

echo "$PW" | sudo -S rsync -a /mnt/hgfs/share/WAF-lite/conf/litewaf_rules.conf "$DST/conf/litewaf_rules.conf" 2>&1 | grep -v password || true
cd "$DST"

echo "===== 自建千条样本 ====="
echo "$PW" | sudo -S python3 /mnt/hgfs/share/scripts/s14_bulk_eval2.py \
  --rules conf/litewaf_rules.conf \
  --attack /mnt/hgfs/share/samples/self_attack.tsv \
  --benign /mnt/hgfs/share/samples/self_normal.tsv \
  --show 8 2>&1 | grep -vE "password" | tail -22

echo
echo "===== CRS 公开样本 ====="
echo "$PW" | sudo -S python3 /mnt/hgfs/share/scripts/s14_bulk_eval2.py \
  --rules conf/litewaf_rules.conf \
  --attack /mnt/hgfs/share/samples/crs_attack.tsv \
  --benign /mnt/hgfs/share/samples/crs_benign.tsv \
  --show 4 2>&1 | grep -vE "password" | tail -18
