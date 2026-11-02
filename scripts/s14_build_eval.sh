#!/usr/bin/env bash
# 在 Kali 侧编译离线评估器 lwaf_eval（不依赖 nginx 运行，只依赖 PCRE2）
set -uo pipefail
SRC=/mnt/hgfs/share/WAF-lite
DST=/opt/litewaf/src/WAF-lite

echo "==> 1/3 同步源码"
rsync -a --exclude logs --exclude '*.o' --exclude build --exclude '*.a' "$SRC/" "$DST/"

echo "==> 2/3 编译 lwaf_eval"
cd "$DST"
make build/lwaf_eval 2>&1 | tail -6
ls -l build/lwaf_eval 2>/dev/null || { echo "[FAIL] 编译失败"; exit 1; }

echo "==> 3/3 冒烟：一条 SQLi + 一条正常"
./build/lwaf_eval conf/litewaf_rules.conf "/?id=1%20UNION%20SELECT%201" 2>&1 | head -10
echo "---"
./build/lwaf_eval conf/litewaf_rules.conf "/?page=2&size=20" 2>&1 | head -10
