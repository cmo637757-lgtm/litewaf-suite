#!/usr/bin/env bash
# 同步规则 + 跑 LFI 样本评估（在 Kali 上用 sudo 执行）
set -uo pipefail
rsync -a /mnt/hgfs/share/WAF-lite/conf/ /opt/litewaf/src/WAF-lite/conf/
sed 's/\r$//' /mnt/hgfs/share/scripts/s14_bulk_eval.py > /tmp/be.py
python3 /tmp/be.py /mnt/hgfs/share/samples/raw/lfi.txt attack --param file
