#!/usr/bin/env bash
# 把三项请求级检查写进 runtime 配置（幂等），然后 reload
# 注意：conf 是 root:root 644，kali 可读不可写 —— 所以先在 /tmp 生成，再 sudo cp
set -uo pipefail
PW="${KALI_PWD:-kali}"
CONF=/opt/litewaf/runtime/conf/nginx.conf
NGINX=/opt/litewaf/build/nginx-check/nginx-1.24.0/objs/nginx

python3 - "$CONF" <<'PY'
import io, sys
p = sys.argv[1]
s = io.open(p, encoding="utf-8", newline="").read()
block = """            lite_waf_hotlink on;
            lite_waf_hotlink_refers example.com;
            lite_waf_bot_protection on;
            lite_waf_csrf_protection on;
"""
if "lite_waf_hotlink" in s:
    print("  配置已存在，跳过")
else:
    anchor = "            lite_waf_max_body_bytes 8192;\n"
    if anchor not in s:
        anchor = "            lite_waf_log_path /opt/litewaf/runtime/logs/waf_audit.log;\n"
    s = s.replace(anchor, anchor + block, 1)
    print("  已生成新配置")
io.open("/tmp/nginx.conf.new", "w", encoding="utf-8", newline="").write(s)
PY
echo "$PW" | sudo -S cp /tmp/nginx.conf.new "$CONF"

echo "==> nginx -t"
echo "$PW" | sudo -S "$NGINX" -p /opt/litewaf/runtime -c conf/nginx.conf -t 2>&1 | tail -2
echo "==> reload"
echo "$PW" | sudo -S "$NGINX" -p /opt/litewaf/runtime -c conf/nginx.conf -s reload 2>&1 | tail -2
sleep 1
echo "==> 探针"
curl -s -o /dev/null -w "  marker=%{http_code}\n" http://127.0.0.1:18010/waf-marker
curl -s -o /dev/null -w "  normal=%{http_code}\n" -A "Mozilla/5.0 (X11; Linux x86_64)" http://127.0.0.1:18010/
