#!/usr/bin/env bash
# LiteWAF 综设 · 编译 nginx + lite_waf 模块（Kali 内执行）
# 用法：sudo bash build_nginx.sh
# 可用环境变量覆盖：NGX_VER（默认 1.31.1）、SRC（源码目录）、BUILD（编译目录）
set -eu

NGX_VER="${NGX_VER:-1.31.1}"
SRC="${SRC:-/opt/litewaf/WAF-lite}"
BUILD="${BUILD:-/opt/src}"

[[ ${EUID} -eq 0 ]] || { echo "请用 sudo 运行"; exit 1; }
[[ -f "${SRC}/ngx_http_lite_waf_module/config" ]] || {
  echo "找不到 ${SRC}/ngx_http_lite_waf_module/config"
  echo "先把 WAF-lite 代码放到 /opt/litewaf/WAF-lite（见共享文件夹挂载说明）"
  exit 1
}

mkdir -p "${BUILD}"
cd "${BUILD}"

TARBALL="nginx-${NGX_VER}.tar.gz"
if [[ ! -f "${TARBALL}" ]]; then
  echo "==> 下载 ${TARBALL}"
  curl -fL --retry 3 -o "${TARBALL}" "https://nginx.org/download/${TARBALL}" || {
    echo "!! 下载失败。若是版本号不存在，用 NGX_VER=1.26.2 重跑："
    echo "   sudo NGX_VER=1.26.2 bash build_nginx.sh"
    exit 1
  }
fi

[[ -d "nginx-${NGX_VER}" ]] || tar xf "${TARBALL}"
cd "nginx-${NGX_VER}"

echo "==> configure"
./configure \
  --prefix=/usr/local/nginx \
  --with-http_ssl_module \
  --with-http_v2_module \
  --add-module="${SRC}/ngx_http_lite_waf_module"

echo "==> make -j$(nproc)"
make -j"$(nproc)"

echo "==> install"
make install

echo "==> 版本与模块检查"
/usr/local/nginx/sbin/nginx -V 2>&1 | tr ' ' '\n' | grep -E 'nginx version|add-module' || true
echo
echo "完成。下一步：把 conf/ 里的配置和 litewaf_rules.conf 放到 /usr/local/nginx/conf/，"
echo "然后 /usr/local/nginx/sbin/nginx -t 试语法。"
