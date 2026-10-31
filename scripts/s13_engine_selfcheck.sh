#!/usr/bin/env bash
# 引擎侧自检：正常请求应 200、SQLi/XSS 应 403。默认先重启实例清空 CC 封禁状态。
# 用法：sudo bash /mnt/hgfs/share/scripts/s13_engine_selfcheck.sh [--no-restart]
set -uo pipefail

if [ "${1:-}" != "--no-restart" ]; then
    systemctl restart litewaf-runtime
    for i in $(seq 1 20); do
        if curl -s -o /dev/null http://127.0.0.1:18010/ 2>/dev/null; then break; fi
        sleep 0.3
    done
fi

UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36'
probe() {
    local label="$1" url="$2"
    local code
    code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "$url")
    printf '  %-14s %s  %s\n' "$label" "$code" "$url"
}
probe "正常"        'http://127.0.0.1:18010/'
probe "SQLi"        'http://127.0.0.1:18010/?id=1%20UNION%20SELECT%201'
probe "SQLi盲注"    'http://127.0.0.1:18010/?id=1%20AND%201=1'
probe "XSS"         'http://127.0.0.1:18010/?q=%3Cscript%3Ealert(1)%3C/script%3E'
probe "穿越"        'http://127.0.0.1:18010/../../etc/passwd'
