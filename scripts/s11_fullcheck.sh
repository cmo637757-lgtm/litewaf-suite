#!/usr/bin/env bash
# 全项目端到端自检：服务状态 + 15 项一键验收。
# 只读检查，不改数据（采集/告警两个阶段内部会各自清表重灌，属它们的正常行为）。
set -uo pipefail
SHARE=/mnt/hgfs/share

echo "########## A. 服务状态 ##########"
bash "$SHARE/scripts/s10_final_check.sh" 2>&1 | tail -30

echo
echo "########## B. 一键验收（15 项必选 + 1 项引擎 SKIP） ##########"
cp "$SHARE/scripts/s7_accept.sh" /opt/litewaf/s7_accept.sh
chmod +x /opt/litewaf/s7_accept.sh
bash /opt/litewaf/s7_accept.sh --skip-engine 2>&1 | tail -32
