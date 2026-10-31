#!/usr/bin/env bash
#
# Prepare a reproducible Nginx source tree and runtime prefixes for LiteWAF-NGX.
#
# The script is intentionally idempotent: local development, Docker, and CI can
# call it before running acceptance tests without caring whether the Nginx tree
# already exists.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="${WORK_DIR:-/private/tmp/litewaf-nginx-check}"
NGINX_VERSION="${NGINX_VERSION:-1.31.1}"
NGINX_URL="${NGINX_URL:-https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz}"
NGINX_SRC="${NGINX_BUILD_DIR:-$WORK_DIR/nginx-$NGINX_VERSION}"
BASIC_PREFIX="${BASIC_PREFIX:-$WORK_DIR/runtime}"
VOLUME_PREFIX="${VOLUME_PREFIX:-/private/tmp/litewaf-nginx-volume}"
RELOAD_PREFIX="${RELOAD_PREFIX:-/private/tmp/litewaf-nginx-reload}"
SOAK_PREFIX="${SOAK_PREFIX:-/private/tmp/litewaf-nginx-soak}"

require_tool() {
    local name="$1"

    if ! command -v "$name" >/dev/null 2>&1; then
        echo "missing required tool: $name" >&2
        exit 1
    fi
}

write_runtime_conf() {
    local prefix="$1"
    local port="$2"
    local dynamic_block="$3"
    local rule_file="$4"
    local worker_processes="${5:-1}"

    mkdir -p "$prefix/conf" "$prefix/logs" "$prefix/html"
    chmod 0777 "$prefix/logs"
    printf 'LiteWAF-NGX test target\n' > "$prefix/html/index.html"

    cat > "$prefix/conf/nginx.conf" <<EOF
worker_processes  $worker_processes;
error_log  logs/error.log notice;
pid        logs/nginx.pid;

events {
    worker_connections  4096;
}

http {
    server {
        listen 127.0.0.1:$port;

        location / {
            lite_waf on;
            lite_waf_trust_proxy off;
            lite_waf_deny_status 403;
            lite_waf_rule_file $rule_file;
            lite_waf_score_threshold SQL 8;
            lite_waf_score_threshold XSS 8;
            lite_waf_score_threshold RFI 8;
            lite_waf_score_threshold TRAVERSAL 8;
            lite_waf_score_threshold EVADE 8;
            lite_waf_score_threshold UPLOAD 8;
            lite_waf_score_threshold SCAN 8;
            lite_waf_score_threshold TOTAL 12;
            lite_waf_dynamic_block $dynamic_block;
            lite_waf_max_requests 20;
            lite_waf_window 10;
            lite_waf_block_duration 60;
            lite_waf_log_path $prefix/logs/waf_audit.log;
            root html;
            index index.html;
            try_files \$uri /index.html;
        }
    }
}
EOF
}

require_tool curl
require_tool make
require_tool tar
require_tool pcre2-config

mkdir -p "$WORK_DIR"

if [ ! -d "$NGINX_SRC" ]; then
    archive="$WORK_DIR/nginx-$NGINX_VERSION.tar.gz"
    echo "Downloading Nginx $NGINX_VERSION to $archive"
    curl -fsSL "$NGINX_URL" -o "$archive"
    tar -xzf "$archive" -C "$WORK_DIR"
fi

if [ ! -f "$NGINX_SRC/objs/Makefile" ]; then
    echo "Configuring Nginx $NGINX_VERSION with LiteWAF-NGX module"
    (
        cd "$NGINX_SRC"
        ./configure \
            --prefix="$WORK_DIR/install" \
            --add-module="$ROOT_DIR/ngx_http_lite_waf_module" \
            --with-cc-opt="$(pcre2-config --cflags)" \
            --with-ld-opt="$(pcre2-config --libs8)"
    )
fi

write_runtime_conf "$BASIC_PREFIX" 18010 "on" "$ROOT_DIR/conf/litewaf_rules.conf" 1
write_runtime_conf "$VOLUME_PREFIX" 18011 "off" "$ROOT_DIR/conf/litewaf_rules.conf" 1
write_runtime_conf "$SOAK_PREFIX" 18013 "off" "$ROOT_DIR/conf/litewaf_rules.conf" 1

mkdir -p "$RELOAD_PREFIX/conf" "$RELOAD_PREFIX/logs" "$RELOAD_PREFIX/html"
chmod 0777 "$RELOAD_PREFIX/logs"
printf 'LiteWAF-NGX reload test target\n' > "$RELOAD_PREFIX/html/index.html"

echo "Prepared LiteWAF-NGX Nginx environment"
echo "NGINX_SRC=$NGINX_SRC"
echo "BASIC_PREFIX=$BASIC_PREFIX"
echo "VOLUME_PREFIX=$VOLUME_PREFIX"
echo "RELOAD_PREFIX=$RELOAD_PREFIX"
echo "SOAK_PREFIX=$SOAK_PREFIX"
