#!/usr/bin/env bash
# P1/P2：同步源码 → 编译规则引擎 → 跑单测 → 顺手重编 lwaf_eval
# 注意：Makefile 在仓库根目录，必须一起同步，否则 CPPFLAGS 少了 -Isrc/libinjection
set -uo pipefail
PW="${KALI_PWD:-kali}"
SRC=/mnt/hgfs/share/WAF-lite
DST=/opt/litewaf/src/WAF-lite

echo "==> 1/4 同步 src + include + Makefile"
echo "$PW" | sudo -S rsync -a --exclude logs --exclude build "$SRC/src/" "$DST/src/" 2>&1 | grep -v "password" || true
echo "$PW" | sudo -S rsync -a --exclude logs --exclude build "$SRC/include/" "$DST/include/" 2>&1 | grep -v "password" || true
echo "$PW" | sudo -S cp "$SRC/Makefile" "$DST/Makefile" 2>&1 | grep -v "password" || true

echo "==> 2/4 编译单测"
cd "$DST"
echo "$PW" | sudo -S make build/test_rule_engine 2>&1 | tail -12

echo "==> 3/4 跑单测"
echo "$PW" | sudo -S ./build/test_rule_engine 2>&1 | tail -5

echo "==> 4/4 重编 lwaf_eval（评估器）"
echo "$PW" | sudo -S make build/lwaf_eval 2>&1 | tail -4
