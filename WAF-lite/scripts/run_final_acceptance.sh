#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="${WORK_DIR:-/private/tmp/litewaf-nginx-check}"
NGINX_VERSION="${NGINX_VERSION:-1.31.1}"
NGINX_BIN="${NGINX_BIN:-$WORK_DIR/nginx-$NGINX_VERSION/objs/nginx}"
NGINX_BUILD_DIR="${NGINX_BUILD_DIR:-$WORK_DIR/nginx-$NGINX_VERSION}"
BASIC_PREFIX="${BASIC_PREFIX:-$WORK_DIR/runtime}"
VOLUME_PREFIX="${VOLUME_PREFIX:-/private/tmp/litewaf-nginx-volume}"
RELOAD_PREFIX="${RELOAD_PREFIX:-/private/tmp/litewaf-nginx-reload}"
SOAK_PREFIX="${SOAK_PREFIX:-/private/tmp/litewaf-nginx-soak}"
MULTIWORKER_PREFIX="${MULTIWORKER_PREFIX:-/private/tmp/litewaf-nginx-multiworker}"
LEAKY_PREFIX="${LEAKY_PREFIX:-/private/tmp/litewaf-nginx-leaky}"
BASIC_CONF="${BASIC_CONF:-conf/nginx.conf}"
VOLUME_CONF="${VOLUME_CONF:-conf/nginx.conf}"
SOAK_CONF="${SOAK_CONF:-conf/nginx.conf}"
BASIC_URL="${BASIC_URL:-http://127.0.0.1:18010}"
VOLUME_URL="${VOLUME_URL:-http://127.0.0.1:18011}"
SOAK_URL="${SOAK_URL:-http://127.0.0.1:18013}"
SOAK_DURATION="${SOAK_DURATION:-30}"
SOAK_CONCURRENCY="${SOAK_CONCURRENCY:-12}"
SOAK_TARGET_RPS="${SOAK_TARGET_RPS:-80}"

stop_nginx() {
    local prefix="$1"
    local conf="$2"

    "$NGINX_BIN" -p "$prefix" -c "$conf" -s quit >/dev/null 2>&1 || true
}

require_tool() {
    local name="$1"

    if ! command -v "$name" >/dev/null 2>&1; then
        echo "missing required tool: $name" >&2
        exit 1
    fi
}

parse_json_lines() {
    local path="$1"
    local label="$2"
    local minimum="${3:-0}"

    python3 - "$path" "$label" "$minimum" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
label = sys.argv[2]
minimum = int(sys.argv[3])
count = 0
if path.exists():
    for line in path.read_text().splitlines():
        if line.strip():
            json.loads(line)
            count += 1
print(f"{label}_json_lines: {count}")
if count < minimum:
    print(f"{label}_json_lines below expected minimum: {count} < {minimum}", file=sys.stderr)
    raise SystemExit(1)
PY
}

echo "LiteWAF-NGX final acceptance"
echo "ROOT_DIR=$ROOT_DIR"
echo "NGINX_BIN=$NGINX_BIN"
echo

require_tool bash
require_tool curl
require_tool python3
require_tool ab

cd "$ROOT_DIR"

echo "[1/14] Prepare Nginx environment"
bash scripts/prepare_nginx_env.sh

echo "[2/14] Rule engine unit test"
make test

echo "[3/14] Nginx module build"
make -C "$NGINX_BUILD_DIR" -j2

echo "[4/14] Prepare runtime directories"
mkdir -p "$BASIC_PREFIX/logs" "$VOLUME_PREFIX/logs" "$VOLUME_PREFIX/html" "$SOAK_PREFIX/logs" "$MULTIWORKER_PREFIX/logs" "$LEAKY_PREFIX/logs"
chmod 0777 "$BASIC_PREFIX/logs" "$VOLUME_PREFIX/logs" "$SOAK_PREFIX/logs" "$MULTIWORKER_PREFIX/logs" "$LEAKY_PREFIX/logs"
printf 'LiteWAF volume test target\n' > "$VOLUME_PREFIX/html/index.html"
rm -f logs/test_results.csv logs/volume_results.csv logs/reload_results.csv logs/post_body_results.csv logs/multiworker_results.csv logs/leaky_bucket_results.csv
rm -f logs/soak_results.csv logs/soak_summary.json
rm -rf logs/load
rm -f "$BASIC_PREFIX/logs/waf_audit.log" "$VOLUME_PREFIX/logs/waf_audit.log" "$SOAK_PREFIX/logs/waf_audit.log" "$MULTIWORKER_PREFIX/logs/waf_audit.log" "$LEAKY_PREFIX/logs/waf_audit.log"

echo "[5/14] nginx -t"
"$NGINX_BIN" -p "$BASIC_PREFIX" -c "$BASIC_CONF" -t
"$NGINX_BIN" -p "$VOLUME_PREFIX" -c "$VOLUME_CONF" -t
"$NGINX_BIN" -p "$SOAK_PREFIX" -c "$SOAK_CONF" -t

echo "[6/14] Basic endpoint regression"
stop_nginx "$BASIC_PREFIX" "$BASIC_CONF"
"$NGINX_BIN" -p "$BASIC_PREFIX" -c "$BASIC_CONF"
trap 'stop_nginx "$BASIC_PREFIX" "$BASIC_CONF"; stop_nginx "$VOLUME_PREFIX" "$VOLUME_CONF"; stop_nginx "$SOAK_PREFIX" "$SOAK_CONF"; "$NGINX_BIN" -p "$MULTIWORKER_PREFIX" -c conf/nginx.conf -s quit >/dev/null 2>&1 || true; "$NGINX_BIN" -p "$LEAKY_PREFIX" -c conf/nginx.conf -s quit >/dev/null 2>&1 || true' EXIT
BASE_URL="$BASIC_URL" bash scripts/run_waf_tests.sh
python3 scripts/calc_metrics.py logs/test_results.csv
parse_json_lines "$BASIC_PREFIX/logs/waf_audit.log" "basic" 25
stop_nginx "$BASIC_PREFIX" "$BASIC_CONF"
sleep 1

echo "[7/14] Rule reload regression"
bash scripts/run_waf_reload_tests.sh
python3 scripts/calc_metrics.py logs/reload_results.csv

echo "[8/14] Volume regression"
stop_nginx "$VOLUME_PREFIX" "$VOLUME_CONF"
"$NGINX_BIN" -p "$VOLUME_PREFIX" -c "$VOLUME_CONF"
python3 scripts/run_waf_volume_tests.py \
    --base-url "$VOLUME_URL" \
    --repeat 10 \
    --output logs/volume_results.csv
python3 scripts/calc_metrics.py logs/volume_results.csv

echo "[9/14] Real POST body regression"
BASE_URL="$VOLUME_URL" RESULT_FILE=logs/post_body_results.csv bash scripts/run_waf_post_body_tests.sh
python3 scripts/calc_metrics.py logs/post_body_results.csv

echo "[10/14] Multi-worker shared dynamic block regression"
MULTIWORKER_PREFIX="$MULTIWORKER_PREFIX" bash scripts/run_waf_multiworker_tests.sh
python3 scripts/calc_metrics.py logs/multiworker_results.csv

echo "[11/14] Leaky-bucket dynamic block regression"
LEAKY_PREFIX="$LEAKY_PREFIX" bash scripts/run_waf_leaky_bucket_tests.sh
python3 scripts/calc_metrics.py logs/leaky_bucket_results.csv

echo "[12/14] ApacheBench load tests"
BASE_URL="$VOLUME_URL" \
REQUESTS=5000 \
CONCURRENCY=50 \
ATTACK_REQUESTS=1000 \
ATTACK_CONCURRENCY=20 \
bash scripts/run_waf_load_tests.sh

echo "[13/14] Sustained mixed traffic test"
stop_nginx "$SOAK_PREFIX" "$SOAK_CONF"
"$NGINX_BIN" -p "$SOAK_PREFIX" -c "$SOAK_CONF"
python3 scripts/run_waf_soak_tests.py \
    --base-url "$SOAK_URL" \
    --duration "$SOAK_DURATION" \
    --concurrency "$SOAK_CONCURRENCY" \
    --target-rps "$SOAK_TARGET_RPS" \
    --output logs/soak_results.csv \
    --summary logs/soak_summary.json

echo "[14/14] JSON audit validation and summary"
parse_json_lines "$VOLUME_PREFIX/logs/waf_audit.log" "volume" 1000
parse_json_lines "$MULTIWORKER_PREFIX/logs/waf_audit.log" "multiworker" 4
parse_json_lines "$LEAKY_PREFIX/logs/waf_audit.log" "leaky" 1
parse_json_lines "$SOAK_PREFIX/logs/waf_audit.log" "soak" 1

python3 - <<'PY'
import csv
import json
from pathlib import Path

for path in [Path("logs/test_results.csv"), Path("logs/reload_results.csv"), Path("logs/volume_results.csv"), Path("logs/post_body_results.csv"), Path("logs/multiworker_results.csv"), Path("logs/leaky_bucket_results.csv"), Path("logs/soak_results.csv")]:
    with path.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    failed = [row for row in rows if row.get("passed") != "yes"]
    print(f"{path}: total={len(rows)} failed={len(failed)}")
    if failed:
        raise SystemExit(f"{path} has failed rows: {failed[:3]}")

for path in [Path("logs/load/ab_normal.txt"), Path("logs/load/ab_attack.txt")]:
    print(path)
    text = path.read_text(errors="ignore")
    for line in text.splitlines():
        if (
            "Complete requests" in line
            or "Failed requests" in line
            or "Non-2xx responses" in line
            or "Requests per second" in line
            or "Time per request" in line
        ):
            print("  " + line)

print(Path("logs/soak_summary.json"))
print(json.dumps(json.loads(Path("logs/soak_summary.json").read_text()), indent=2))
PY

echo
echo "FINAL ACCEPTANCE PASSED"
