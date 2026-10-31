#!/usr/bin/env bash
#
# Verify that `lite_waf_rule_file` is parsed again after `nginx -s reload`.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="${WORK_DIR:-/private/tmp/litewaf-nginx-check}"
NGINX_VERSION="${NGINX_VERSION:-1.31.1}"
NGINX_BIN="${NGINX_BIN:-$WORK_DIR/nginx-$NGINX_VERSION/objs/nginx}"
PREFIX="${RELOAD_PREFIX:-/private/tmp/litewaf-nginx-reload}"
PORT="${RELOAD_PORT:-18012}"
BASE_URL="${BASE_URL:-http://127.0.0.1:$PORT}"
RESULT_FILE="${RESULT_FILE:-logs/reload_results.csv}"
RULE_FILE="$PREFIX/conf/reload_rules.conf"
CONF_FILE="$PREFIX/conf/nginx.conf"
PROBE_PATH="/reload-check?marker=litewafreloadprobe"

stop_nginx() {
    "$NGINX_BIN" -p "$PREFIX" -c conf/nginx.conf -s quit >/dev/null 2>&1 || true
}

write_conf() {
    mkdir -p "$PREFIX/conf" "$PREFIX/logs" "$PREFIX/html"
    chmod 0777 "$PREFIX/logs"
    printf 'LiteWAF-NGX reload test target\n' > "$PREFIX/html/index.html"

    cat > "$CONF_FILE" <<EOF
worker_processes  1;
error_log  logs/error.log notice;
pid        logs/nginx.pid;

events {
    worker_connections  1024;
}

http {
    server {
        listen 127.0.0.1:$PORT;

        location / {
            lite_waf on;
            lite_waf_trust_proxy off;
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
            lite_waf_dynamic_block off;
            lite_waf_log_path $PREFIX/logs/waf_audit.log;
            root html;
            index index.html;
            try_files \$uri /index.html;
        }
    }
}
EOF
}

http_status() {
    curl -sS -A 'LiteWAF-Reload/1.0' -o /dev/null -w '%{http_code}' "$BASE_URL$PROBE_PATH"
}

record_case() {
    local id="$1"
    local name="$2"
    local sample_type="$3"
    local expected="$4"
    local actual="$5"
    local passed="no"

    if [ "$expected" = "$actual" ]; then
        passed="yes"
    fi
    printf '%s,%s,%s,%s,%s,%s\n' "$id" "$name" "$sample_type" "$expected" "$actual" "$passed" >> "$RESULT_FILE"
    if [ "$passed" != "yes" ]; then
        echo "reload test failed: $id expected=$expected actual=$actual" >&2
        return 1
    fi
}

mkdir -p "$(dirname "$RESULT_FILE")"
printf 'id,name,type,expected_status,actual_status,passed\n' > "$RESULT_FILE"

cp "$ROOT_DIR/conf/litewaf_rules.conf" "$RULE_FILE"
write_conf
stop_nginx
trap stop_nginx EXIT

"$NGINX_BIN" -p "$PREFIX" -c conf/nginx.conf -t
"$NGINX_BIN" -p "$PREFIX" -c conf/nginx.conf
sleep 1

record_case "RL001" "probe before marker rule" "normal" "200" "$(http_status)"

cat >> "$RULE_FILE" <<'EOF'
lwaf_rule id=9001 name="reload marker rule" type=str pattern="litewafreloadprobe" zones=ARGS score=SQL:8 action=score
EOF

"$NGINX_BIN" -p "$PREFIX" -c conf/nginx.conf -t
"$NGINX_BIN" -p "$PREFIX" -c conf/nginx.conf -s reload
sleep 1
record_case "RL002" "probe after marker rule reload" "attack" "403" "$(http_status)"

cp "$ROOT_DIR/conf/litewaf_rules.conf" "$RULE_FILE"
"$NGINX_BIN" -p "$PREFIX" -c conf/nginx.conf -t
"$NGINX_BIN" -p "$PREFIX" -c conf/nginx.conf -s reload
sleep 1
record_case "RL003" "probe after marker rule removal reload" "normal" "200" "$(http_status)"

echo "LiteWAF-NGX reload test: 3/3 passed"
echo "Results: $RESULT_FILE"
