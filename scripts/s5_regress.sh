#!/usr/bin/env bash
# 回归：改完规则解析器后重跑 14 步全量验收
# 注意：验收脚本要占用 18010/18011/18013，先停 S5 的 runtime 实例
set -uo pipefail

BUILD=/opt/litewaf/build
RT=/opt/litewaf/runtime
SRC=/opt/litewaf/src/WAF-lite
NFX=$BUILD/nginx-check/nginx-1.24.0/objs/nginx

echo "==> 停掉 S5 runtime 实例（让出 18010）"
"$NFX" -p "$RT" -c conf/nginx.conf -s quit 2>/dev/null || true
sleep 2

echo "==> 跑 14 步全量验收"
cd "$SRC"
export WORK_DIR="$BUILD/nginx-check"
export BASIC_PREFIX="$WORK_DIR/runtime"
export VOLUME_PREFIX="$BUILD/volume"
export RELOAD_PREFIX="$BUILD/reload"
export SOAK_PREFIX="$BUILD/soak"
export MULTIWORKER_PREFIX="$BUILD/multiworker"
export LEAKY_PREFIX="$BUILD/leaky"
# 固定用 1.24.0：1.31.1 的 auto/make 对 addon 里的 ../src 文件生成的目标名不对
# （objs/addon/src/lwaf_rule_engine.o 没有规则），见 docs/基线说明.md
export NGINX_VERSION=1.24.0
bash scripts/run_final_acceptance.sh 2>&1 | tail -25

echo
echo "==> 重新拉起 S5 runtime 实例"
"$NFX" -p "$RT" -c conf/nginx.conf
sleep 1
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36'
echo "  正常=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" http://127.0.0.1:18010/index.html) SQLi=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" 'http://127.0.0.1:18010/?id=1%20UNION%20SELECT%20x') marker=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18010/waf-marker)"
