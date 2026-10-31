#!/usr/bin/env bash
# 登录失败限流验收：同一账号连续 5 次失败 → 锁定 15 分钟（第 6 次起 429）
set -u
BASE=http://127.0.0.1:18080
J='Content-Type: application/json'

echo "--- 连续 6 次错误口令（期望 401×5 后 429）---"
for i in $(seq 1 6); do
    printf '第 %d 次: ' "$i"
    curl -s -o /dev/null -w '%{http_code}\n' -X POST "$BASE/api/auth/login" \
        -H "$J" -d '{"username":"rateprobe","password":"definitely-wrong"}'
done

echo "--- 换一个账号不受影响（期望 200）---"
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$BASE/api/auth/login" \
    -H "$J" -d '{"username":"viewer","password":"Viewer@2026"}'
