#!/usr/bin/env bash
# S5 执行器冒烟：启动 engine-exec，检查 /status、/check、/publish、/rollback
# 用法（Kali）：sudo bash /mnt/hgfs/share/scripts/s5_engine_smoke.sh
set -uo pipefail

RT=/opt/litewaf/runtime
ENG=/opt/litewaf/engine/engine_exec.py
LOG=/opt/litewaf/engine.log
PORT=18081

ng() { echo -e "\n==> $*"; }

ng "1/7 重启执行器"
fuser -k ${PORT}/tcp 2>/dev/null || true
sleep 1
setsid /usr/bin/python3 "$ENG" > "$LOG" 2>&1 < /dev/null &
sleep 2
tail -2 "$LOG"

TOKEN=$(cat "$RT/engine.token")
AUTH="X-Engine-Token: $TOKEN"

ng "2/7 令牌鉴权：无令牌应 401"
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:${PORT}/status)
echo "无令牌=$code（期望 401）"

ng "3/7 /status"
curl -s -H "$AUTH" http://127.0.0.1:${PORT}/status \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print("nginx_alive=%s current=%s previous=%s marker=%s normal=%s sqli=%s versions=%d" % (d["nginx_alive"], d["current"], d["previous"] or "-", d["marker"], d["normal"], d["sqli"], len(d["versions"])))'

ng "4/7 /check 合法规则（应 ok=true）"
curl -s -H "$AUTH" -H 'Content-Type: application/json' -X POST \
  -d @- http://127.0.0.1:${PORT}/check <<'JSON' | head -c 400
{"text":"rule 1000 SQL str \"union select\" score 8\nrule 2001 SCAN ua rx \"sqlmap\" block\n","name":"smoke-good"}
JSON

ng "5/7 /check 非法规则（应 ok=false，且报错带行号）"
curl -s -H "$AUTH" -H 'Content-Type: application/json' -X POST \
  -d @- http://127.0.0.1:${PORT}/check <<'JSON' | head -c 600
{"text":"rule 1000 SQL str \"union select\n","name":"smoke-bad"}
JSON

ng "6/7 /publish 合法候选"
CID=$(curl -s -H "$AUTH" -H 'Content-Type: application/json' -X POST \
  -d @- http://127.0.0.1:${PORT}/check <<'JSON' | python3 -c 'import json,sys; print(json.load(sys.stdin)["candidate_id"] or "")'
{"text":"rule 1000 SQL str \"union select\" score 8\nrule 1001 SQL str \"information_schema\" score 8\nrule 1300 XSS str \"<script\" score 8\nrule 2001 SCAN ua rx \"sqlmap\" block\n","name":"smoke-publish"}
JSON
)
echo "candidate=$CID"
curl -s -H "$AUTH" -H 'Content-Type: application/json' -X POST \
  -d "{\"candidate_id\":\"$CID\"}" http://127.0.0.1:${PORT}/publish | head -c 500

ng "7/7 /rollback"
curl -s -H "$AUTH" -H 'Content-Type: application/json' -X POST \
  -d '{}' http://127.0.0.1:${PORT}/rollback | head -c 400

echo
echo "==> 完成。日志：$LOG"
