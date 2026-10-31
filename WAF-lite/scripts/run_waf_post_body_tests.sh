#!/usr/bin/env bash
#
# Verify that LiteWAF inspects the real Nginx request body instead of only
# URL, query string, header, or cookie fields.

set -u

BASE_URL="${BASE_URL:-http://127.0.0.1:18011}"
RESULT_FILE="${RESULT_FILE:-logs/post_body_results.csv}"

mkdir -p logs
printf 'id,name,type,expected_status,actual_status,passed\n' > "$RESULT_FILE"

echo "LiteWAF-NGX POST body test run"
echo "Target: $BASE_URL"
echo "Results: $RESULT_FILE"
echo

run_post_case() {
    local id="$1"
    local name="$2"
    local sample_type="$3"
    local expected="$4"
    local body="$5"
    local content_type="${6:-application/x-www-form-urlencoded}"
    local actual
    local passed

    actual="$(curl -s -o /dev/null -w '%{http_code}' \
        -A "LiteWAF-PostBody/1.0" \
        -X POST \
        -H "Content-Type: $content_type" \
        --data "$body" \
        "$BASE_URL/post-check")"

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

run_post_case "P001" "benign form body" "normal" "405" "msg=hello-world&qty=1"
run_post_case "P002" "sql body tautology" "attack" "403" "user=admin&pass=x%27+OR+%271%27%3D%271"
run_post_case "P003" "sql body union select" "attack" "403" "id=1+UNION+SELECT+user,password+FROM+users"
run_post_case "P004" "xss body script" "attack" "403" "comment=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
run_post_case "P005" "traversal body path" "attack" "403" "file=..%2F..%2Fetc%2Fpasswd"
run_post_case "P006" "rfi body url" "attack" "403" "next=http%3A%2F%2Fevil.example%2Fshell.txt"
run_post_case "P007" "json benign body" "normal" "405" '{"name":"alice","role":"reader"}' "application/json"
run_post_case "P008" "json sql body" "attack" "403" '{"id":"1 UNION SELECT password FROM users"}' "application/json"

echo
echo "CSV results written to $RESULT_FILE"
