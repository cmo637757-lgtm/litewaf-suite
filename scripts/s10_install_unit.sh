#!/usr/bin/env bash
# 安装 LiteWAF 运行时实例的 systemd 守护（R37-02 崩溃恢复）。
# 装完之后 kill -9 nginx 主进程，systemd 会在 RestartSec 内自动拉起，
# 满足「异常终止后 60 秒内恢复」的验收要求。
# 用法：sudo bash /mnt/hgfs/share/scripts/s10_install_unit.sh
set -uo pipefail

NGINX=/opt/litewaf/build/nginx-check/nginx-1.24.0/objs/nginx
PREFIX=/opt/litewaf/runtime
UNIT=/etc/systemd/system/litewaf-runtime.service

if [ ! -x "$NGINX" ]; then
  echo "[FAIL] 找不到 nginx 二进制：$NGINX"
  exit 1
fi

echo "==> 1/4 写 unit（$UNIT）"
cat > "$UNIT" <<EOF
# LiteWAF 运行时实例（监听 127.0.0.1:18010）
# 由 s10_install_unit.sh 生成；改配置请改 $PREFIX/conf/nginx.conf 后 reload
[Unit]
Description=LiteWAF runtime nginx (127.0.0.1:18010)
After=network-online.target mariadb.service
Wants=network-online.target

[Service]
Type=forking
PIDFile=$PREFIX/logs/nginx.pid
ExecStart=$NGINX -p $PREFIX -c conf/nginx.conf
ExecReload=$NGINX -p $PREFIX -c conf/nginx.conf -s reload
ExecStop=/bin/kill -QUIT \$MAINPID
# 崩溃自动拉起：配合 RestartSec=3，kill -9 之后约 3 秒恢复
Restart=always
RestartSec=3
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
EOF

echo "==> 2/4 停掉手工起的实例，交给 systemd 托管"
if [ -f "$PREFIX/logs/nginx.pid" ]; then
  kill -QUIT "$(cat $PREFIX/logs/nginx.pid)" 2>/dev/null || true
  sleep 2
fi
fuser -k 18010/tcp 2>/dev/null || true
sleep 1

echo "==> 3/4 启用并启动"
systemctl daemon-reload
systemctl enable --now litewaf-runtime.service
sleep 2
systemctl is-active litewaf-runtime.service
systemctl --no-pager --lines=0 status litewaf-runtime.service | head -4

echo "==> 4/4 冒烟"
sleep 1
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36'
for u in "/waf-marker" "/" "/?id=1%20UNION%20SELECT%20password%20FROM%20users"; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "http://127.0.0.1:18010$u")
  echo "  $code  $u"
done
