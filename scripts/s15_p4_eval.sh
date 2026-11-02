#!/usr/bin/env bash
# P4 效果：自建千条 + CRS 公开样本，同一份 lwaf_eval 二进制
set -uo pipefail
PW="${KALI_PWD:-kali}"
EVAL=/opt/litewaf/src/WAF-lite/build/lwaf_eval
RULES=/opt/litewaf/src/WAF-lite/conf/litewaf_rules.conf
S=/mnt/hgfs/share/samples

echo "===== 自建千条 ====="
echo "$PW" | sudo -S python3 /mnt/hgfs/share/scripts/s14_bulk_eval2.py \
  --rules "$RULES" \
  --attack "$S/self_attack.tsv" --benign "$S/self_normal.tsv" --show 3 2>&1 | grep -vE "password"

echo
echo "===== CRS 公开样本 ====="
echo "$PW" | sudo -S python3 /mnt/hgfs/share/scripts/s14_bulk_eval2.py \
  --rules "$RULES" \
  --attack "$S/crs_attack.tsv" --benign "$S/crs_benign.tsv" --show 0 2>&1 | grep -vE "password"
