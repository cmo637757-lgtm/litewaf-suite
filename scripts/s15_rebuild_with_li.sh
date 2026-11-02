#!/usr/bin/env bash
# libinjection 进了模块源码列表，必须重新 configure（只 make 不会读新的 addon config）
set -uo pipefail
PW="${KALI_PWD:-kali}"
SRC=/opt/litewaf/src/WAF-lite
BUILD=/opt/litewaf/build/nginx-check/nginx-1.24.0

echo "==> 1/4 同步源码与 addon config"
rsync -a --delete --exclude .git --exclude logs --exclude build "$SRC/../" >/dev/null 2>&1 || true
rsync -a --exclude logs --exclude build /mnt/hgfs/share/WAF-lite/ "$SRC/" || exit 1

echo "==> 2/4 重新 configure（应用新的 addon config）"
cd "$BUILD" || exit 1
./configure --prefix=/usr/local/nginx \
  --with-http_ssl_module \
  --with-http_v2_module \
  --add-module="$SRC/ngx_http_lite_waf_module" >/tmp/ngx_conf.log 2>&1 || {
  tail -12 /tmp/ngx_conf.log; echo "[FAIL] configure"; exit 1; }
echo "    configure ok"

echo "==> 3/4 make -j4"
make -j4 >/tmp/ngx_make.log 2>&1 || { grep -E "error|Error" /tmp/ngx_make.log | head -8; echo "[FAIL] make"; exit 1; }
echo "    make ok"

echo "==> 4/4 装新二进制 + 重启 + 自检"
install -m 755 objs/nginx /usr/local/nginx/sbin/nginx.li
cp objs/nginx /usr/local/nginx/sbin/nginx
cp /mnt/hgfs/share/WAF-lite/conf/litewaf_rules.conf /opt/litewaf/runtime/rules/litewaf_rules.conf
systemctl restart litewaf-runtime
for i in $(seq 1 20); do
  curl -s -o /dev/null -m 1 http://127.0.0.1:18010/ && break
  sleep 0.5
done
systemctl is-active litewaf-runtime
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36'
printf '正常=%s  ' "$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" http://127.0.0.1:18010/)"
printf 'SQLi=%s  ' "$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" 'http://127.0.0.1:18010/?id=1%20UNION%20SELECT%20pwd')"
printf '结构型SQLi=%s  ' "$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" 'http://127.0.0.1:18010/?id=1%20AND%201=1')"
printf 'UA穿越=%s\n' "$(curl -s -o /dev/null -w '%{http_code}' -A 'cat /root/.ssh/id_rsa' http://127.0.0.1:18010/)"
