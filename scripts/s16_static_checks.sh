#!/usr/bin/env bash
# 三项请求级检查的逐项验证：防盗链 / 机器人 / CSRF
# 判定口径：403 = 被 WAF 拦；其余（200/405）= 放行到后端。
# 后端是 `root html` + `try_files $uri /index.html`，所以不存在的静态文件也回 200，
# 不能拿 404 当「放行」的标志，这里统一按 200/405 判。
set -uo pipefail
BASE=http://127.0.0.1:18010
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36'
pass=0; fail=0

chk() { # chk 名称 期望码 实际码 说明
  if [ "$2" = "$3" ]; then
    printf '  [PASS] %-26s %s%s\n' "$1" "$3" "$4"; pass=$((pass+1))
  else
    printf '  [FAIL] %-26s %s（期望 %s）%s\n' "$1" "$3" "$2" "$4"; fail=$((fail+1))
  fi
}
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

echo "==> 1/3 防盗链：只对静态扩展名，需外站 Referer"
chk "外站引用 .css"     403 "$(code -A "$UA" -H 'Referer: http://evil.com/x.html' "$BASE/style.css")" ""
chk "同站引用 .css"     200 "$(code -A "$UA" -H 'Referer: http://127.0.0.1:18010/index.html' "$BASE/style.css")" ""
chk "白名单域引用"      200 "$(code -A "$UA" -H 'Referer: https://app.example.com/x' "$BASE/logo.png")" ""
chk "无 Referer 直连"   200 "$(code -A "$UA" "$BASE/logo.png")" ""
chk "HTML 页面不拦"     200 "$(code -A "$UA" -H 'Referer: http://evil.com/' "$BASE/")" ""

echo "==> 2/3 机器人监测：只拦明确扫描器，不拦 curl"
chk "sqlmap UA"         403 "$(code -A 'sqlmap/1.7.2#stable (https://sqlmap.org)' "$BASE/")" ""
chk "nuclei UA"         403 "$(code -A 'Nuclei - Open-source project (github.com/projectdiscovery/nuclei)' "$BASE/")" ""
chk "nikto UA"          403 "$(code -A 'Mozilla/5.00 (Nikto/2.1.6) (Evasions:None)' "$BASE/")" ""
chk "浏览器 UA"         200 "$(code -A "$UA" "$BASE/")" ""
chk "中性脚本 UA"       200 "$(code -A "MyApp/1.0" "$BASE/")" "（只拦扫描器，不拦普通脚本；curl 默认 UA 会被既有规则 2001 拦，属预期）"

echo "==> 3/3 CSRF：只对非安全方法，比 Origin/Referer"
chk "POST 异站 Origin"  403 "$(code -A "$UA" -X POST -H 'Origin: http://evil.com' "$BASE/api/x")" ""
chk "POST 同站 Origin"  405 "$(code -A "$UA" -X POST -H 'Origin: http://127.0.0.1:18010' "$BASE/api/x")" "（放行；静态站不支持 POST 才 405）"
chk "POST 无 Origin"    405 "$(code -A "$UA" -X POST "$BASE/api/x")" "（放行；curl/服务端调用）"
chk "POST 带 XSRF 头"   405 "$(code -A "$UA" -X POST -H 'Origin: http://evil.com' -H 'X-Requested-With: XMLHttpRequest' "$BASE/api/x")" ""
chk "GET 异站 Referer"  200 "$(code -A "$UA" -H 'Referer: http://evil.com/' "$BASE/")" "（安全方法不管来源）"

echo
echo "==> 审计日志里的拦截原因统计"
echo kali | sudo -S tail -n 60 /opt/litewaf/runtime/logs/waf_audit.log \
  | grep -oE '"reason":"(hotlink|bot_ua|bot_ua_empty|csrf_origin|csrf_referer)"' \
  | sort | uniq -c || true

echo
echo "通过 $pass 项，失败 $fail 项"
[ "$fail" -eq 0 ]
