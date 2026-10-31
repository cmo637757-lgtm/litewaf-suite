#!/usr/bin/env bash
# S3 鉴权验收：未登录 401 / viewer 只读 / viewer 写 403 / 口令错 401 / 登出后旧 token 失效
set -u
BASE=http://127.0.0.1:18080
J='Content-Type: application/json'

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

echo "--- 1. 未认证访问统计（期望 401）---"
echo -n "实际: "; code "$BASE/api/stats/summary"; echo

echo "--- 2. admin 登录 ---"
LOGIN=$(curl -s -X POST "$BASE/api/auth/login" -H "$J" \
    -d '{"username":"admin","password":"LiteWaf@2026"}')
echo "$LOGIN" | head -c 200; echo
TOKEN=$(echo "$LOGIN" | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')

echo "--- 3. 带 token 访问统计（期望 200）---"
echo -n "实际: "; code "$BASE/api/stats/summary?from=1789862400000&to=1789862460000" \
    -H "Authorization: Bearer $TOKEN"; echo

echo "--- 4. viewer 登录 ---"
VLOGIN=$(curl -s -X POST "$BASE/api/auth/login" -H "$J" \
    -d '{"username":"viewer","password":"Viewer@2026"}')
echo "$VLOGIN" | head -c 160; echo
VTOKEN=$(echo "$VLOGIN" | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')

echo "--- 5. viewer 读事件（期望 200）---"
echo -n "实际: "; code "$BASE/api/events?page_size=1" -H "Authorization: Bearer $VTOKEN"; echo

echo "--- 6. viewer 写操作（期望 403）---"
echo -n "实际: "; code -X POST "$BASE/api/rules" -H "Authorization: Bearer $VTOKEN" \
    -H "$J" -d '{}'; echo

echo "--- 7. 错误口令（期望 401）---"
echo -n "实际: "; code -X POST "$BASE/api/auth/login" -H "$J" \
    -d '{"username":"admin","password":"wrong-password"}'; echo

echo "--- 8. admin 登出后旧 token（期望先 200 后 401）---"
echo -n "logout: "; code -X POST "$BASE/api/auth/logout" -H "Authorization: Bearer $TOKEN"; echo
echo -n "旧 token: "; code "$BASE/api/stats/summary" -H "Authorization: Bearer $TOKEN"; echo

echo "--- 9. health ---"
curl -s "$BASE/api/health"; echo
