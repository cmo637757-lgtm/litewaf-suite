#!/usr/bin/env bash
set -uo pipefail
cd /opt/litewaf/platform/frontend || exit 1
echo "== src 里有没有 doTest =="
grep -c doTest src/views/RulesView.vue || true
echo "== vite 配置里的 outDir / build 段 =="
grep -n -A4 "build:" vite.config.js || echo "（没有 build 段，默认 dist）"
echo "== 现有 dist =="
ls -la dist/index.html
echo "== 重新构建 =="
sudo -u kali ./node_modules/.bin/vite build 2>&1 | tail -3
echo "== 构建后 dist =="
ls -la dist/index.html
echo "== 新产物里有没有 test-input =="
grep -c "test-input" dist/assets/RulesView-*.js || echo "0（说明构建用的是旧源码）"
echo "== dist 里 index.html 引用的入口 =="
grep -o 'index-[A-Za-z0-9_-]*\.js' dist/index.html | head -1
