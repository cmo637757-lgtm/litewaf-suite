#!/usr/bin/env bash

set -u

BASE_URL="${BASE_URL:-http://localhost:8010}"
RESULT_FILE="logs/test_results.csv"

mkdir -p logs
printf 'id,name,type,expected_status,actual_status,passed\n' > "$RESULT_FILE"

echo "LiteWAF-NGX test run"
echo "Target: $BASE_URL"
echo "Results: $RESULT_FILE"
echo

run_case() {
    local id="$1"
    local name="$2"
    local sample_type="$3"
    local expected="$4"
    local path="$5"
    local user_agent="${6:-LiteWAF-Test/1.0}"
    local path_mode="${7:-normal}"
    local actual
    local passed

    if [ "$path_mode" = "path_as_is" ]; then
        actual="$(curl --path-as-is -s -o /dev/null -w '%{http_code}' -A "$user_agent" "$BASE_URL$path")"
    else
        actual="$(curl -s -o /dev/null -w '%{http_code}' -A "$user_agent" "$BASE_URL$path")"
    fi

    if [ "$actual" = "$expected" ]; then
        passed="yes"
    else
        passed="no"
    fi

    printf '%-8s %-32s expected=%s actual=%s passed=%s\n' "$id" "$name" "$expected" "$actual" "$passed"
    printf '%s,%s,%s,%s,%s,%s\n' "$id" "$name" "$sample_type" "$expected" "$actual" "$passed" >> "$RESULT_FILE"
}

echo "Attack sample checks: 20 rule-driven requests"
run_case "A001" "sql tautology" "attack" "403" "/search?q=1%27%20OR%20%271%27=%271"
run_case "A002" "sql union select" "attack" "403" "/item?id=1%20UNION%20SELECT%20user,password%20FROM%20users"
run_case "A003" "sql comment bypass" "attack" "403" "/login?user=admin%27%20OR%201=1--"
run_case "A004" "sql drop table" "attack" "403" "/api/order?id=1%3Bdrop%20table%20orders"
run_case "A005" "sql hex literal" "attack" "403" "/api/item?id=0xdeadbeef%20UNION%20SELECT"
run_case "A006" "rfi http scheme" "attack" "403" "/redirect?next=http%3A%2F%2Fevil.example%2Fshell.txt"
run_case "A007" "rfi php wrapper" "attack" "403" "/view?file=php%3A%2F%2Ffilter%2Fresource%3Dindex.php"
run_case "A008" "unix traversal" "attack" "403" "/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd" "LiteWAF-Test/1.0" "path_as_is"
run_case "A009" "windows cmd shell" "attack" "403" "/download?file=..%5C..%5Cwindows%5Csystem32%5Ccmd.exe"
run_case "A010" "powershell probe" "attack" "403" "/run?bin=powershell.exe"
run_case "A011" "xss script tag" "attack" "403" "/comment?msg=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
run_case "A012" "xss javascript uri" "attack" "403" "/redirect?next=javascript%3Aalert(1)"
run_case "A013" "xss event handler" "attack" "403" "/profile?name=%3Cimg%20src=x%20onerror=alert(1)%3E"
run_case "A014" "xss svg onload" "attack" "403" "/search?q=%3Csvg%20onload=alert(1)%3E"
run_case "A015" "encoded evasion" "attack" "403" "/search?q=%25u003c%26%23x3c"
run_case "A016" "dangerous upload ext" "attack" "403" "/upload?file=shell.php"
run_case "A017" "nikto user agent" "attack" "403" "/" "Nikto/2.5.0"
run_case "A018" "sqlmap user agent" "attack" "403" "/" "sqlmap/1.8"
run_case "A019" "python requests ua" "attack" "403" "/" "python-requests/2.31"
run_case "A020" "wget user agent" "attack" "403" "/" "Wget/1.21"

echo
echo "Waiting 11 seconds before normal samples to avoid dynamic blocking cross-talk..."
sleep 11

echo "Normal sample checks: 20 benign requests"
run_case "N001" "homepage" "normal" "200" "/"
run_case "N002" "index html" "normal" "200" "/index.html"
run_case "N003" "about page" "normal" "200" "/about"
run_case "N004" "contact page" "normal" "200" "/contact"
run_case "N005" "login page" "normal" "200" "/login"
run_case "N006" "search nginx" "normal" "200" "/search?q=nginx"
run_case "N007" "numeric product id" "normal" "200" "/product?id=1001"
run_case "N008" "api status" "normal" "200" "/api/status"
run_case "N009" "css asset" "normal" "200" "/assets/app.css"
run_case "N010" "js asset" "normal" "200" "/assets/app.js"
run_case "N011" "image asset" "normal" "200" "/images/logo.png"
run_case "N012" "text document" "normal" "200" "/docs/readme.txt"
run_case "N013" "profile alice" "normal" "200" "/profile?name=alice"
run_case "N014" "simple comment" "normal" "200" "/comment?msg=hello-world"
run_case "N015" "cart item" "normal" "200" "/cart?item=book&qty=1"
run_case "N016" "manual download" "normal" "200" "/download?file=manual.pdf"
run_case "N017" "health check" "normal" "200" "/health"
run_case "N018" "pagination" "normal" "200" "/api/users?page=1&size=10"
run_case "N019" "friendly url" "normal" "200" "/news/2026/course-design"
run_case "N020" "safe upload name" "normal" "200" "/upload?file=avatar.png"

echo
echo "Waiting 11 seconds before dynamic blocking test to let the leaky bucket drain..."
sleep 11

echo "Dynamic blocking check: 25 requests to /login"
for i in $(seq 1 25); do
    id="$(printf 'D%03d' "$i")"
    name="$(printf 'dynamic login %02d' "$i")"

    if [ "$i" -le 20 ]; then
        run_case "$id" "$name" "normal" "200" "/login"
    else
        run_case "$id" "$name" "attack" "403" "/login"
    fi
done

echo
echo "CSV results written to $RESULT_FILE"
