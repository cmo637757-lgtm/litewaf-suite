#!/usr/bin/env bash
#
# Verify that dynamic blocking is shared across Nginx worker processes.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="${WORK_DIR:-/private/tmp/litewaf-nginx-check}"
NGINX_VERSION="${NGINX_VERSION:-1.31.1}"
NGINX_BIN="${NGINX_BIN:-$WORK_DIR/nginx-$NGINX_VERSION/objs/nginx}"
PREFIX="${MULTIWORKER_PREFIX:-/private/tmp/litewaf-nginx-multiworker}"
BASE_URL="${MULTIWORKER_URL:-http://127.0.0.1:18014}"
RESULT_FILE="${RESULT_FILE:-logs/multiworker_results.csv}"
RULE_FILE="${RULE_FILE:-$ROOT_DIR/conf/litewaf_rules.conf}"

stop_nginx() {
    "$NGINX_BIN" -p "$PREFIX" -c conf/nginx.conf -s quit >/dev/null 2>&1 || true
}

run_case() {
    local id="$1"
    local name="$2"
    local sample_type="$3"
    local expected="$4"
    local actual
    local passed

    actual="$(curl -s -o /dev/null -w '%{http_code}' \
        -A "LiteWAF-MultiWorker/1.0" \
        -H "X-Forwarded-For: 198.51.100.77" \
        "$BASE_URL/shared-block")"

    if [ "$actual" = "$expected" ]; then
        passed="yes"
    else
        passed="no"
    fi

    printf '%-8s %-32s expected=%s actual=%s passed=%s\n' \
        "$id" "$name" "$expected" "$actual" "$passed"
    printf '%s,%s,%s,%s,%s,%s\n' \
        "$id" "$name" "$sample_type" "$expected" "$actual" "$passed" \
        >> "$RESULT_FILE"
}

mkdir -p "$PREFIX/conf" "$PREFIX/logs" "$PREFIX/html" logs
chmod 0777 "$PREFIX/logs"
printf 'LiteWAF multi-worker shared block target\n' > "$PREFIX/html/index.html"

cat > "$PREFIX/conf/nginx.conf" <<EOF
worker_processes  4;
error_log  logs/error.log notice;
pid        logs/nginx.pid;

events {
    worker_connections  4096;
    accept_mutex off;
}

http {
    server {
        listen 127.0.0.1:18014;

        location / {
            lite_waf on;
            lite_waf_trust_proxy on;
            lite_waf_deny_status 403;
            lite_waf_rule_file $RULE_FILE;
            lite_waf_score_threshold SQL 8;
            lite_waf_score_threshold XSS 8;
            lite_waf_score_threshold RFI 8;
            lite_waf_score_threshold TRAVERSAL 8;
            lite_waf_score_threshold EVADE 8;
            lite_waf_score_threshold UPLOAD 8;
            lite_waf_score_threshold SCAN 8;
            lite_waf_score_threshold TOTAL 12;
            lite_waf_dynamic_block on;
            lite_waf_max_requests 6;
            lite_waf_window 30;
            lite_waf_block_duration 30;
            lite_waf_log_path $PREFIX/logs/waf_audit.log;
            root html;
            index index.html;
            try_files \$uri /index.html;
        }
    }
}
EOF

printf 'id,name,type,expected_status,actual_status,passed\n' > "$RESULT_FILE"
rm -f "$PREFIX/logs/waf_audit.log"

stop_nginx
"$NGINX_BIN" -p "$PREFIX" -c conf/nginx.conf -t
"$NGINX_BIN" -p "$PREFIX" -c conf/nginx.conf
trap stop_nginx EXIT

echo "LiteWAF-NGX multi-worker shared block test run"
echo "Target: $BASE_URL"
echo "Results: $RESULT_FILE"
echo

for i in $(seq 1 6); do
    run_case "$(printf 'M%03d' "$i")" \
        "$(printf 'shared warmup %02d' "$i")" \
        "normal" \
        "200"
done

for i in $(seq 7 10); do
    run_case "$(printf 'M%03d' "$i")" \
        "$(printf 'shared blocked %02d' "$i")" \
        "attack" \
        "403"
done

echo
echo "CSV results written to $RESULT_FILE"
