#!/usr/bin/env bash
# 前端改动后重建静态站：rsync → npm run build → 重启 18082。
# 用法：sudo bash /mnt/hgfs/share/scripts/s12_front_rebuild.sh
set -uo pipefail
LW=/opt/litewaf
FE="$LW/platform/frontend"

echo "==> 1/4 同步前端源码"
rsync -a --delete --exclude node_modules --exclude dist --exclude package-lock.json \
  /mnt/hgfs/share/platform/frontend/ "$FE/"
chown -R kali:kali "$FE"

echo "==> 2/4 构建（约 30 秒）"
cd "$FE" || exit 3
BUILD_LOG=$(mktemp /tmp/fe_build.XXXXXX.log)
if ! sudo -u kali npm run build > "$BUILD_LOG" 2>&1; then
    echo "  [FAIL] 构建失败，最后 20 行："
    tail -20 "$BUILD_LOG" | sed 's/^/    /'
    exit 1
fi
grep -E 'dist/assets/(index|Dashboard)[^ ]*\.js' "$BUILD_LOG" | tail -3 | sed 's/^/    /'
du -sh "$FE/dist" | sed 's/^/    dist 体积: /'

echo "==> 3/4 重启静态站 18082"
fuser -k 18082/tcp 2>/dev/null || true
sleep 1
bash /mnt/hgfs/share/scripts/console_static.sh start 2>&1 | tail -3 | sed 's/^/    /'
for i in $(seq 1 15); do
  curl -sf -o /dev/null http://127.0.0.1:18082/ && break
  sleep 1
done

echo "==> 4/4 自检"
echo -n "    静态站 /        = "
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18082/
echo -n "    反代 /api/health = "
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18082/api/health
