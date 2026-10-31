#!/usr/bin/env python3
"""S5 平台侧接口自检：登录 → 读规则 → 校验 → 发布 → 回退 → 权限。"""
import json
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:18080"
results = []


def http(path, method="GET", body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {}
    if data:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.load(e)
        except Exception:
            return e.code, {}


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    print("%s %-42s %s" % ("PASS" if cond else "FAIL", name, detail))


# 1. 未登录读规则 → 401
code, _ = http("/api/rules")
check("未登录读 /api/rules 返回 401", code == 401, code)

# 2. admin 登录
code, body = http("/api/auth/login", "POST", {"username": "admin", "password": "LiteWaf@2026"})
admin_tok = body.get("token", "")
check("admin 登录", code == 200 and admin_tok, code)

# 3. viewer 登录
code, body = http("/api/auth/login", "POST", {"username": "viewer", "password": "Viewer@2026"})
viewer_tok = body.get("token", "")
check("viewer 登录", code == 200 and viewer_tok, code)

# 4. 读当前规则
code, cur = http("/api/rules", token=admin_tok)
text = cur.get("text", "")
cc = cur.get("cc", {})
check("读当前规则", code == 200 and len(text) > 100, "bytes=%d cc=%s" % (len(text), cc))

# 5. 状态
code, st = http("/api/engine/status", token=admin_tok)
check("读引擎状态", code == 200 and st.get("nginx_alive") is True,
      "current=%s previous=%s marker=%s normal=%s sqli=%s" % (
          st.get("current"), st.get("previous"), st.get("marker"),
          st.get("normal"), st.get("sqli")))

# 6. viewer 不能 check（POST 需 ADMIN）
code, _ = http("/api/rules/check", "POST", {"rules": text, "name": "viewer-try"}, token=viewer_tok)
check("viewer 发起 check 被 403", code == 403, code)

# 7. admin check 正常
code, r = http("/api/rules/check", "POST", {"rules": text, "cc": cc, "name": "自检原样"}, token=admin_tok)
cid = r.get("candidate_id")
check("admin check 通过并拿到 candidate_id", code == 200 and r.get("ok") and cid, cid)

# 8. 坏规则被拒
bad = text + '\nlwaf_rule id=3001 name="bad" type=str pattern="x" zones=ARGS score=SQL:8\n'
code, r2 = http("/api/rules/check", "POST", {"rules": bad, "cc": cc, "name": "坏规则"}, token=admin_tok)
check("坏规则被拒 + 给出错误位置", code == 200 and not r2.get("ok") and r2.get("line_no"),
      r2.get("line_no") or r2.get("error"))

# 9. CC 越界被拒
code, r3 = http("/api/rules/check", "POST",
                {"rules": text, "cc": {"max_requests": 9999, "window": 10, "block_duration": 60}},
                token=admin_tok)
check("CC 越界被拒", code == 200 and not r3.get("ok"), r3.get("error"))

# 10. 发布
code, p = http("/api/rules/publish", "POST", {"candidate_id": cid}, token=admin_tok)
ver = p.get("version", "")
check("发布成功且有 operation_id", code == 200 and p.get("ok") and p.get("operation_id"),
      "version=%s op=%s" % (ver, p.get("operation_id")))

# 11. 发布后行为不变
code, st2 = http("/api/engine/status", token=admin_tok)
check("发布后 正常200/SQLi403", st2.get("normal") == 200 and st2.get("sqli") == 403,
      "normal=%s sqli=%s" % (st2.get("normal"), st2.get("sqli")))

# 12. 回退
code, rb = http("/api/rules/rollback", "POST", {}, token=admin_tok)
check("回退成功", code == 200 and rb.get("ok"), "version=%s" % rb.get("version"))

# 13. 审计表有记录（用应用账号直连，不依赖 sudo）
try:
    import pymysql
    conn = pymysql.connect(host="127.0.0.1", user="litewaf", password="LiteWaf@2026",
                           database="litewaf", ssl_disabled=True, charset="utf8mb4")
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*), GROUP_CONCAT(DISTINCT action) FROM operations")
        cnt, acts = cur.fetchone()
    conn.close()
    check("operations 审计有记录", cnt is not None and cnt >= 3,
          "共 %s 条，动作=%s" % (cnt, acts))
except Exception as e:                                    # noqa: BLE001
    check("operations 审计有记录", False, "查询失败：%s" % e)

print()
bad_n = sum(1 for _, ok, _ in results if not ok)
print("结果：%d 项，失败 %d 项" % (len(results), bad_n))
raise SystemExit(1 if bad_n else 0)
