#!/usr/bin/env bash
#
# Verify that dynamic blocking uses leaky-bucket behavior, not a fixed window.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="${WORK_DIR:-/private/tmp/litewaf-nginx-check}"
NGINX_VERSION="${NGINX_VERSION:-1.31.1}"
NGINX_BIN="${NGINX_BIN:-$WORK_DIR/nginx-$NGINX_VERSION/objs/nginx}"
PREFIX="${LEAKY_PREFIX:-/private/tmp/litewaf-nginx-leaky}"
BASE_URL="${LEAKY_URL:-http://127.0.0.1:18015}"
RESULT_FILE="${RESULT_FILE:-logs/leaky_bucket_results.csv}"
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
        -A "LiteWAF-LeakyBucket/1.0" \
        -H "X-Forwarded-For: 203.0.113.44" \
        "$BASE_URL/leaky-bucket")"

    if [ "$actual" = "$expected" ]; then
        passed="yes"
    else
        passed="no"
    fi

    printf '%-8s %-34s expected=%s actual=%s passed=%s\n' \
        "$id" "$name" "$expected" "$actual" "$passed"
    printf '%s,%s,%s,%s,%s,%s\n' \
        "$id" "$name" "$sample_type" "$expected" "$actual" "$passed" \
        >> "$RESULT_FILE"
}

mkdir -p "$PREFIX/conf" "$PREFIX/logs" "$PREFIX/html" logs
chmod 0777 "$PREFIX/logs"
printf 'LiteWAF leaky bucket test target\n' > "$PREFIX/html/index.html"

cat > "$PREFIX/conf/nginx.conf" <<EOF
worker_processes  2;
error_log  logs/error.log notice;
pid        logs/nginx.pid;

events {
    worker_connections  4096;
}

http {
    server {
        listen 127.0.0.1:18015;

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
            lite_waf_max_requests 4;
            lite_waf_window 4;
            lite_waf_block_duration 20;
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

echo "LiteWAF-NGX leaky-bucket dynamic block test run"
echo "Target: $BASE_URL"
echo "Results: $RESULT_FILE"
echo

for i in $(seq 1 4); do
    run_case "$(printf 'L%03d' "$i")" \
        "$(printf 'fill bucket %02d' "$i")" \
        "normal" \
        "200"
done

echo "Waiting 3 seconds so the leaky bucket can drain..."
sleep 3

for i in $(seq 5 7); do
    run_case "$(printf 'L%03d' "$i")" \
        "$(printf 'after leak pass %02d' "$i")" \
        "normal" \
        "200"
done

run_case "L008" "overflow after leak" "attack" "403"

echo
echo "CSV results written to $RESULT_FILE"
