#!/usr/bin/env bash
# s0_build.sh — S0 基线复现：把 dev_2 源码放到 ext4 上编译，跑通最小拦截验证
# 用法：sudo bash /mnt/hgfs/share/scripts/s0_build.sh
# 说明：编译在 /opt/litewaf/build 下进行，共享盘只作为源码来源（fuse 盘不参与 build）
set -euo pipefail

SHARE_SRC=/mnt/hgfs/share/WAF-lite
SRC=/opt/litewaf/src
BUILD=/opt/litewaf/build
NGINX_VERSION="${NGINX_VERSION:-1.31.1}"

ng() { echo; echo "==> $*"; }
die(){ echo "[FAIL] $*" >&2; exit 1; }

mkdir -p "$SRC" "$BUILD"

# ---------- 1/6 同步源码到 ext4 ----------
ng "1/6 同步源码：$SHARE_SRC → $SRC/WAF-lite"
[[ -d "$SHARE_SRC" ]] || die "看不到 $SHARE_SRC（共享文件夹没挂？先跑 sudo bash /mnt/hgfs/share/scripts/kali_setup.sh）"
rsync -a --delete --exclude '.git/' --exclude 'logs/' "$SHARE_SRC/" "$SRC/WAF-lite/"

# 共享盘上的文本文件可能是 CRLF（Windows 侧 git core.autocrlf=true 检出所致），
# bash 会报 `line N: $'\r': command not found`、`set: pipefail` 这类错。统一转 LF。
# 注意：nginx addon 的 `config` 文件没有扩展名，必须单独列出——
# 它若带 \r，nginx configure 会把 `-I .../include\r` 和 `.../lwaf_rule_engine.c\r` 写进 Makefile，
# 表现为「lwaf_rule_engine.h: No such file」+「No rule to make target 'objs/addon/src/lwaf_rule_engine.o'」。
find "$SRC/WAF-lite" -type f \( -name '*.sh' -o -name '*.py' -o -name '*.c' -o -name '*.h' \
  -o -name '*.conf' -o -name '*.yml' -o -name '*.yaml' -o -name '*.md' -o -name '*.in' \
  -o -name 'Makefile' -o -name 'config' -o -name 'Dockerfile' \) \
  -print0 | xargs -0 -r sed -i 's/\r$//'
echo "    [OK] 行尾已规范化为 LF"

cd "$SRC/WAF-lite"

# ---------- 2/6 规则引擎单测 ----------
ng "2/6 规则引擎单测 make test"
make test

# ---------- 3/6 准备 nginx 源码树（下载 + configure） ----------
export WORK_DIR="$BUILD/nginx-check"
export BASIC_PREFIX="$WORK_DIR/runtime"
export VOLUME_PREFIX="$BUILD/volume"
export RELOAD_PREFIX="$BUILD/reload"
export SOAK_PREFIX="$BUILD/soak"
export MULTIWORKER_PREFIX="$BUILD/multiworker"
export LEAKY_PREFIX="$BUILD/leaky"
export NGINX_VERSION

ng "3/6 prepare_nginx_env.sh（下载 nginx $NGINX_VERSION + configure）"
if ! bash scripts/prepare_nginx_env.sh; then
  die "prepare 失败。若日志是 404 或下载失败，换版本重跑：NGINX_VERSION=1.29.0 bash $0"
fi

# ---------- 4/6 编译 nginx ----------
ng "4/6 编译 nginx（-j4）"
NGINX_SRC_DIR="$WORK_DIR/nginx-$NGINX_VERSION"
mkdir -p "$BUILD"
if ! make -C "$NGINX_SRC_DIR" -j4 >"$BUILD/nginx_build.log" 2>&1; then
  echo "    !! 编译失败，最后 40 行："
  tail -40 "$BUILD/nginx_build.log"
  die "nginx 编译失败，完整日志：$BUILD/nginx_build.log"
fi
echo "    [OK] 编译通过（日志：$BUILD/nginx_build.log）"
[[ -x "$NGINX_SRC_DIR/objs/nginx" ]] || die "nginx 二进制没生成"
echo "    [OK] nginx 二进制：$WORK_DIR/nginx-$NGINX_VERSION/objs/nginx"

# ---------- 5/6 启动最小实例 ----------
ng "5/6 启动实例 :18010"
NGINX_BIN="$WORK_DIR/nginx-$NGINX_VERSION/objs/nginx"
"$NGINX_BIN" -p "$BASIC_PREFIX" -c conf/nginx.conf -s quit >/dev/null 2>&1 || true
sleep 1
"$NGINX_BIN" -p "$BASIC_PREFIX" -c conf/nginx.conf -t
"$NGINX_BIN" -p "$BASIC_PREFIX" -c conf/nginx.conf
sleep 1
ss -lntp 2>/dev/null | grep -q ':18010' && echo "    [OK] 18010 监听中" || die "18010 没起来，看 $BASIC_PREFIX/logs/error.log"

# ---------- 6/6 最小拦截验证 ----------
ng "6/6 最小拦截验证"
# 注意：规则 2001（SCAN）会把 curl/wget/python-requests 的默认 UA 当成扫描器直接拦，
# 所以正常请求与注入测试必须显式带浏览器 UA，否则连正常请求也是 403（假阴性）。
BROWSER_UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36'
code_normal=$(curl -s -o /dev/null -w '%{http_code}' -A "$BROWSER_UA" "http://127.0.0.1:18010/index.html")
code_sqli=$(curl -s -o /dev/null -w '%{http_code}' -A "$BROWSER_UA" "http://127.0.0.1:18010/?id=1%20UNION%20SELECT%20password%20FROM%20users")
code_xss=$(curl -s -o /dev/null -w '%{http_code}' -A "$BROWSER_UA" "http://127.0.0.1:18010/?q=%3Cscript%3Ealert(1)%3C/script%3E")
code_scan=$(curl -s -o /dev/null -w '%{http_code}' -A 'sqlmap/1.7' "http://127.0.0.1:18010/")

echo "    正常请求      : HTTP $code_normal  (期望 200)"
echo "    SQL 注入      : HTTP $code_sqli   (期望 403)"
echo "    XSS           : HTTP $code_xss    (期望 403)"
echo "    扫描器 UA     : HTTP $code_scan   (期望 403)"

AUDIT="$BASIC_PREFIX/logs/waf_audit.log"
if [[ -f "$AUDIT" ]]; then
  echo "    审计日志      : $(wc -l < "$AUDIT") 行 → $AUDIT"
  echo "    最近一条      : $(tail -1 "$AUDIT")"
else
  die "没有审计日志 $AUDIT"
fi

echo
echo "==> S0 完成。实例还在跑（端口 18010），停止："
echo "    $NGINX_BIN -p $BASIC_PREFIX -c conf/nginx.conf -s quit"
echo "==> 下一轮跑全量验收（14 步，约 5 分钟）："
echo "    cd $SRC/WAF-lite && WORK_DIR=$WORK_DIR ... bash scripts/run_final_acceptance.sh"
