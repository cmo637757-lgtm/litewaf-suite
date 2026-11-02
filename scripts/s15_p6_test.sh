#!/usr/bin/env bash
# P6 验收：站内信渠道
# 场景：把规则 2 的 channel 改成 inapp，造一段流量触发告警，验证
#       ① 站内消息落表且未读数正确 ② 投递记录仍记一条（inapp://local / sent）
#       ③ 标记已读幂等 ④ 全部已读生效
set -uo pipefail
PW="${KALI_PWD:-kali}"
BASE=http://127.0.0.1:18080
TOKEN=$(curl -s -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"LiteWaf@2026"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
AUTH="Authorization: Bearer $TOKEN"
pass=0; fail=0
ok()   { echo "  PASS $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL $1（实际：$2）"; fail=$((fail+1)); }

echo "==> 1/5 规则 2 改成 channel=inapp"
code=$(curl -s -o /tmp/p6_rule.json -w '%{http_code}' -X POST "$BASE/api/alert-rules/2" -H "$AUTH" \
  -H 'Content-Type: application/json' \
  -d '{"threshold":5,"window_s":60,"suppress_s":120,"ratio":2.0,"severity":"yellow","channel":"inapp","webhook_url":"http://127.0.0.1:18099/hook","enabled":true}')
[ "$code" = "200" ] && ok "改规则返回 200" || bad "改规则返回 200" "$code"
ch=$(curl -s "$BASE/api/alert-rules" -H "$AUTH" | python3 -c 'import sys,json;print([r["channel"] for r in json.load(sys.stdin) if r["id"]==2][0])')
[ "$ch" = "inapp" ] && ok "规则 2 的渠道已是 inapp" || bad "规则 2 的渠道已是 inapp" "$ch"

echo "==> 2/5 造 12 条当前窗口事件"
python3 - <<'PY'
import time, subprocess
now = int(time.time() * 1000)
vals = ",".join(
    f"({now - (12 - j) * 700},'10.88.0.8','GET','/im{j}','CC','CC','score_threshold',0,0,'deny',403,300,1)"
    for j in range(12)
)
sql = ("INSERT INTO waf_events (event_time_ms, client_ip, method, uri, category, category_display, "
       "reason, rule_id, total_score, action, status, cost_us, source_id) VALUES " + vals + ";\n"
       "UPDATE alert_consumer_cursor SET last_event_id = (SELECT MIN(id) - 1 FROM waf_events "
       "WHERE client_ip='10.88.0.8') WHERE id = 1;")
subprocess.run(["python3", "/mnt/hgfs/share/scripts/db_query.py"], input=sql, text=True, check=True)
print("   inserted 12 events")
PY
echo "==> 3/5 等消费器（6 秒）"
sleep 6

echo "==> 4/5 查站内消息与投递记录"
curl -s "$BASE/api/messages?limit=5" -H "$AUTH" > /tmp/p6_msg.json
n=$(python3 -c 'import json;d=json.load(open("/tmp/p6_msg.json"));print(len(d))')
[ "$n" -ge 1 ] && ok "站内消息落表（$n 条）" || bad "站内消息落表" "$n"
first=$(python3 -c 'import json;d=json.load(open("/tmp/p6_msg.json"));print(d[0]["title"] if d else "")')
echo "    最新一条：$first"
uc=$(curl -s "$BASE/api/messages/unread-count" -H "$AUTH" | python3 -c 'import sys,json;print(json.load(sys.stdin)["count"])')
[ "$uc" -ge 1 ] && ok "未读数 > 0（$uc）" || bad "未读数 > 0" "$uc"
mid=$(python3 -c 'import json;d=json.load(open("/tmp/p6_msg.json"));print(d[0]["id"])')
dl=$(python3 /mnt/hgfs/share/scripts/db_query.py <<<"SELECT url, status FROM alert_deliveries ORDER BY id DESC LIMIT 1;" | tail -2 | head -1)
echo "    最新投递记录：$dl"
case "$dl" in *inapp://local*sent*) ok "投递记录写的是 inapp://local / sent" ;; *) bad "投递记录写的是 inapp://local / sent" "$dl" ;; esac

echo "==> 5/5 标记已读"
r1=$(curl -s -X POST "$BASE/api/messages/$mid/read" -H "$AUTH" | python3 -c 'import sys,json;print(json.load(sys.stdin)["updated"])')
[ "$r1" = "1" ] && ok "首次标记已读 updated=1" || bad "首次标记已读 updated=1" "$r1"
r2=$(curl -s -X POST "$BASE/api/messages/$mid/read" -H "$AUTH" | python3 -c 'import sys,json;print(json.load(sys.stdin)["updated"])')
[ "$r2" = "0" ] && ok "重复标记幂等 updated=0" || bad "重复标记幂等 updated=0" "$r2"
ra=$(curl -s -X POST "$BASE/api/messages/read-all" -H "$AUTH" | python3 -c 'import sys,json;print(json.load(sys.stdin)["updated"])')
uc2=$(curl -s "$BASE/api/messages/unread-count" -H "$AUTH" | python3 -c 'import sys,json;print(json.load(sys.stdin)["count"])')
[ "$uc2" = "0" ] && ok "全部已读后未读数=0（本次清了 $ra 条）" || bad "全部已读后未读数=0" "$uc2"

echo
echo "结果：$((pass+fail)) 项，失败 $fail 项"
[ "$fail" -eq 0 ]
