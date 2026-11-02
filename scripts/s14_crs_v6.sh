#!/usr/bin/env bash
# rules-v6 下重跑 CRS 公开样本（2282 攻击 + 676 正常），与自建千条样本对照
# 注意：非交互下裸 sudo 会卡在密码提示，必须 echo "$PW" | sudo -S
set -uo pipefail
PW="${KALI_PWD:-kali}"
cd /opt/litewaf/src/WAF-lite
echo "$PW" | sudo -S python3 /mnt/hgfs/share/scripts/s14_bulk_eval2.py \
  --rules /opt/litewaf/src/WAF-lite/conf/litewaf_rules.conf \
  --attack /mnt/hgfs/share/samples/crs_attack.tsv \
  --benign /mnt/hgfs/share/samples/crs_benign.tsv \
  --show 6 2>&1 | tail -30
