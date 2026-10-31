#!/usr/bin/env bash
# 前端改完后的标准动作：同步到 Kali → 构建 → 发布到静态目录。
# 用法：sudo bash /mnt/hgfs/share/scripts/s10_frontend.sh
set -euo pipefail

SRC=/mnt/hgfs/share/platform/frontend
DST=/opt/litewaf/platform/frontend
PUB=/opt/litewaf/console

echo "==> 1/3 同步源码"
rsync -a --delete \
  --exclude node_modules --exclude dist --exclude package-lock.json \
  "$SRC/" "$DST/" --chown=kali:kali

echo "==> 2/3 构建（vite build）"
cd "$DST"
sudo -u kali npm run build > /tmp/vite_build.log 2>&1 || { tail -25 /tmp/vite_build.log; exit 1; }
tail -4 /tmp/vite_build.log

echo "==> 3/3 发布到 $PUB"
rm -rf "$PUB"
mkdir -p "$PUB"
cp -r "$DST/dist/." "$PUB/"
chown -R root:root "$PUB"
find "$PUB" -type f | wc -l | sed 's/^/  文件数：/'
ls "$PUB"
