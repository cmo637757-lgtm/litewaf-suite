#!/usr/bin/env bash
# 单独跑引擎的 14 步全量验收（s7 里因端口独占被 SKIP 的那一项）。
# 先停 runtime 实例腾出 18010，跑完再拉起来。
set -uo pipefail
SHARE=/mnt/hgfs/share
SRC=/opt/litewaf/src/WAF-lite

echo "==> 停 runtime 实例（腾 18010）"
systemctl stop litewaf-runtime 2>/dev/null || true
sleep 1

export WORK_DIR=/tmp/lc
export BASIC_PREFIX=/tmp/lc/basic
export VOLUME_PREFIX=/tmp/lc/volume
export RELOAD_PREFIX=/tmp/lc/reload
export SOAK_PREFIX=/tmp/lc/soak
export MULTIWORKER_PREFIX=/tmp/lc/mw
export LEAKY_PREFIX=/tmp/lc/leaky
export NGINX_VERSION=1.24.0
mkdir -p "$WORK_DIR"

cd "$SRC" || exit 3
echo "==> 跑 14 步验收"
bash scripts/run_final_acceptance.sh 2>&1 | tail -26
RC=${PIPESTATUS[0]}

echo
echo "==> 恢复 runtime 实例"
systemctl start litewaf-runtime 2>/dev/null || true
sleep 2
code=$(curl -s -o /dev/null -w '%{http_code}' -A 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0' http://127.0.0.1:18010/)
echo "  runtime 恢复后正常请求 = $code"
echo "==> 14 步退出码 = $RC"
