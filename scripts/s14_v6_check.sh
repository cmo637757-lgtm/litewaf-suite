#!/usr/bin/env bash
# v6 规则：同步 → 单测 → 千条样本评估
# 注意：这里所有 sudo 都走 echo <pw> | sudo -S —— 非交互环境下裸 sudo 会卡在密码提示上。
set -uo pipefail
SRC=/mnt/hgfs/share/WAF-lite
DST=/opt/litewaf/src/WAF-lite
PW="${KALI_PWD:-kali}"

echo "==> 1/3 同步"
echo "$PW" | sudo -S rsync -a --exclude logs --exclude build "$SRC/conf/" "$DST/conf/" 2>/dev/null
echo "$PW" | sudo -S grep -c '^lwaf_rule' "$DST/conf/litewaf_rules.conf" 2>/dev/null

echo "==> 2/3 单测"
cd "$DST" && echo "$PW" | sudo -S make test 2>&1 | grep -v '^\[sudo\]' | tail -3

echo "==> 3/3 千条评估"
echo "$PW" | sudo -S python3 /mnt/hgfs/share/scripts/s14_bulk_eval2.py \
  --rules "$DST/conf/litewaf_rules.conf" \
  --attack /mnt/hgfs/share/samples/self_attack.tsv \
  --benign /mnt/hgfs/share/samples/self_normal.tsv \
  --show 12 --out /mnt/hgfs/share/samples/reports/self-v6.json 2>&1 | grep -v '^\[sudo\]' | tail -32
