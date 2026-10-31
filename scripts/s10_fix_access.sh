#!/usr/bin/env bash
# 一次性修复：把 runtime 实例的 access_log 从 nginx 默认 combined 换成 JSONL，
# 并清掉按旧格式记下的 636 条 ingest_errors（那些是格式不匹配，不是真错误）。
# 用法：sudo bash /mnt/hgfs/share/scripts/s10_fix_access.sh
set -uo pipefail

CONF=/opt/litewaf/runtime/conf/nginx.conf
LOGS=/opt/litewaf/runtime/logs
RULES=/opt/litewaf/runtime/rules/litewaf_rules.conf

echo "==> 1/6 备份并改写 access_log 配置"
cp "$CONF" "$CONF.bak-combined"
python3 - "$CONF" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
if "log_format lwaf_access" in s:
    print("[SKIP] 已经是 JSON 格式")
    sys.exit(0)
block = '''    log_format lwaf_access escape=json
        '{"time":$msec,"client_ip":"$remote_addr","method":"$request_method",'
        '"uri":"$request_uri","status":$status,'
        '"body_bytes_sent":$body_bytes_sent,"request_time":$request_time}';
    access_log logs/access.log lwaf_access;
'''
s2, n = re.subn(r"[ \t]*access_log\s+logs/access\.log;\n", block, s, count=1)
if n != 1:
    print("[FAIL] 没找到 access_log 行"); sys.exit(1)
open(p, "w", encoding="utf-8").write(s2)
print("[OK] nginx.conf 已改成 JSON 访问日志")
PY
sed -n '9,16p' "$CONF"

echo "==> 2/6 nginx -t 校验"
/opt/litewaf/build/nginx-check/nginx-1.24.0/objs/nginx -p /opt/litewaf/runtime -c conf/nginx.conf -t 2>&1 | tail -3

echo "==> 3/6 停实例、清空旧格式日志、重启"
kill -QUIT "$(cat $LOGS/nginx.pid)" 2>/dev/null || true
sleep 2
: > "$LOGS/access.log"
/opt/litewaf/build/nginx-check/nginx-1.24.0/objs/nginx -p /opt/litewaf/runtime -c conf/nginx.conf
sleep 1
pgrep -fa 'nginx: master' | head -2

echo "==> 4/6 清掉旧格式造成的错误行 + 重置 access 游标"
python3 - "$RULES" <<'PY'
import pymysql, sys
rules, = sys.argv[1:]
conn = pymysql.connect(host="127.0.0.1", user="litewaf", password="LiteWaf@2026",
                       database="litewaf", charset="utf8mb4", autocommit=True,
                       ssl_disabled=True)
with conn.cursor() as cur:
    cur.execute("DELETE FROM ingest_errors WHERE reason LIKE 'JSONDecodeError%'")
    print(f"[OK] 删除旧格式错误行 {cur.rowcount} 条")
    cur.execute("DELETE FROM ingest_cursors WHERE source_id=(SELECT id FROM ingest_sources WHERE name='nginx_access')")
    print(f"[OK] 重置 nginx_access 游标 {cur.rowcount} 条")
conn.close()
PY

echo "==> 5/6 打 3 条真实请求（1 正常 + 2 攻击）"
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36'
for u in "/" "/?id=1%20UNION%20SELECT%20password%20FROM%20users" "/?q=%3Cscript%3Ealert(1)%3C/script%3E"; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "http://127.0.0.1:18010$u")
  echo "  $code  $u"
done
sleep 1
echo "--- access.log 最后 2 行 ---"
tail -2 "$LOGS/access.log"

echo "==> 6/6 采集器跑一轮，看是否入库"
cd /opt/litewaf/platform/collector
sudo -u kali python3 lwaf_collect.py --config config.ini --once 2>&1 | tail -4
python3 - <<'PY'
import pymysql
conn = pymysql.connect(host="127.0.0.1", user="litewaf", password="LiteWaf@2026",
                       database="litewaf", charset="utf8mb4", ssl_disabled=True)
with conn.cursor() as cur:
    cur.execute("SELECT COUNT(*) FROM requests")
    req = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM ingest_errors")
    err = cur.fetchone()[0]
    cur.execute("SELECT event_time_ms, client_ip, uri, status FROM requests ORDER BY id DESC LIMIT 3")
    rows = cur.fetchall()
print(f"[OK] requests={req} ingest_errors={err}")
for r in rows:
    print("   ", r)
conn.close()
PY
