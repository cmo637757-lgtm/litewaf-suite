#!/usr/bin/env bash

set -u

BASE_URL="${BASE_URL:-http://127.0.0.1:18011}"
RESULT_DIR="${RESULT_DIR:-logs/load}"
REQUESTS="${REQUESTS:-5000}"
CONCURRENCY="${CONCURRENCY:-50}"
ATTACK_REQUESTS="${ATTACK_REQUESTS:-1000}"
ATTACK_CONCURRENCY="${ATTACK_CONCURRENCY:-20}"

mkdir -p "$RESULT_DIR"

if ! command -v ab >/dev/null 2>&1; then
    echo "ApacheBench (ab) is not installed. Install httpd via brew or provide another load tool." >&2
    exit 1
fi

echo "LiteWAF-NGX load test"
echo "Target: $BASE_URL"
echo "Result dir: $RESULT_DIR"
echo

echo "Normal traffic benchmark: $REQUESTS requests, concurrency $CONCURRENCY"
ab -n "$REQUESTS" -c "$CONCURRENCY" "$BASE_URL/" > "$RESULT_DIR/ab_normal.txt"

echo "Rule-hit benchmark: $ATTACK_REQUESTS requests, concurrency $ATTACK_CONCURRENCY"
ab -n "$ATTACK_REQUESTS" -c "$ATTACK_CONCURRENCY" \
    "$BASE_URL/search?q=1%27%20OR%20%271%27=%271" > "$RESULT_DIR/ab_attack.txt"

echo
echo "Load test reports:"
echo "  $RESULT_DIR/ab_normal.txt"
echo "  $RESULT_DIR/ab_attack.txt"
