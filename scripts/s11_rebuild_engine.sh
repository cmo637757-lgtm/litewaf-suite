#!/usr/bin/env bash
# 只重编译引擎模块 + 重启 runtime，不碰 runtime 配置和数据。
# 用于规则引擎/模块代码改动后的快速回归（比跑整个 s0_build.sh 安全）。
# 用法：sudo bash /mnt/hgfs/share/scripts/s11_rebuild_engine.sh
set -uo pipefail

SRC=/opt/litewaf/src/WAF-lite
BUILD=/opt/litewaf/build/nginx-check/nginx-1.24.0

echo "==> 1/4 同步模块源码（共享盘 → 编译目录读取的位置）"
rsync -a --delete --exclude .git --exclude logs \
  /mnt/hgfs/share/WAF-lite/ "$SRC/" || { echo "[FAIL] rsync 失败"; exit 1; }

echo "==> 2/4 规则引擎单测"
( cd "$SRC" && rm -rf build && mkdir -p build && make test 2>&1 | tail -3 )

echo "==> 3/4 重编译 nginx（含模块）"
( cd "$BUILD" && make -j4 2>&1 | tail -5 ) || { echo "[FAIL] 编译失败"; exit 1; }

echo "==> 4/4 重启 runtime 并自检"
systemctl restart litewaf-runtime
for i in $(seq 1 20); do
  if curl -s -o /dev/null -m 1 http://127.0.0.1:18010/; then break; fi
  sleep 0.5
done
systemctl is-active litewaf-runtime
# 自检必须用浏览器 UA：curl 默认 UA 里带 "curl"，会被 2001 号「scanner user agent」
# 规则直接 block，看起来像"正常请求被误拦"，其实是规则在正常工作。
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36'
printf '正常请求=%s  ' "$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" http://127.0.0.1:18010/)"
printf 'SQLi=%s\n' "$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" 'http://127.0.0.1:18010/?id=1%20UNION%20SELECT%20password%20FROM%20users')"
echo "完成"
