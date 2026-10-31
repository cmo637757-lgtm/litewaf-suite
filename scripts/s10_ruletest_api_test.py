#!/usr/bin/env python3
"""规则试打沙箱接口自检（S10-5）。

用法：python3 s10_ruletest_api_test.py
注意：每次试打都会真实打一发到 18010，会计入 CC 漏桶，别连打太多次。
"""
import json
import sys
import urllib.request
import urllib.error

BASE = "http://127.0.0.1:18080"
results = []


def check(name, ok, detail=""):
    results.append((name, ok))
    print(("  PASS  " if ok else "  FAIL  ") + name + (("  → " + detail) if detail else ""))


def request(method, path, body=None, token=None):
    req = urllib.request.Request(BASE + path,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw or "{}")
        except json.JSONDecodeError:
            return e.code, {"raw": raw}
    except urllib.error.URLError as e:
        return 0, {"error": str(e)}


def main():
    print("=== 规则试打沙箱接口自检 ===")

    code, _ = request("POST", "/api/rules/test", {"uri": "/?id=1"})
    check("未登录 401", code == 401, f"code={code}")

    code, tok = request("POST", "/api/auth/login", {"username": "admin", "password": "LiteWaf@2026"})
    token = tok.get("token")
    check("admin 登录", code == 200 and bool(token))

    # 1) 正常 URL：应当放行
    code, r = request("POST", "/api/rules/test", {"uri": "/p1"}, token=token)
    check("正常 URI 返回 200", code == 200, f"code={code}")
    check("正常 URI 未被拦截", r.get("blocked") is False, f"status={r.get('status')}")

    # 2) SQLi：应当拦截并给出规则名
    code, r = request("POST", "/api/rules/test",
                      {"uri": "/?id=1%20UNION%20SELECT%20password%20FROM%20users"}, token=token)
    check("SQLi 被拦截", r.get("status") == 403 and r.get("blocked") is True,
          f"status={r.get('status')}")
    check("能读到命中规则名", bool(r.get("rule_name")), f"rule_name={r.get('rule_name')}")
    check("能读到类别 SQLi", r.get("category_display") == "SQLi", f"cat={r.get('category_display')}")
    check("有得分", isinstance(r.get("score"), int), f"score={r.get('score')}")

    # 3) XSS
    code, r = request("POST", "/api/rules/test",
                      {"uri": "/?q=%3Cscript%3Ealert(1)%3C/script%3E"}, token=token)
    check("XSS 被拦截", r.get("status") == 403, f"status={r.get('status')}")

    # 4) 参数校验
    code, r = request("POST", "/api/rules/test", {"uri": "no-slash"}, token=token)
    check("uri 不带 / → 400", code == 400, f"code={code}")
    code, r = request("POST", "/api/rules/test", {"uri": ""}, token=token)
    check("uri 为空 → 400", code == 400, f"code={code}")

    # 5) viewer 能不能试打（试打是只读探测，允许 VIEWER）
    code, vt = request("POST", "/api/auth/login", {"username": "viewer", "password": "Viewer@2026"})
    vtoken = vt.get("token")
    if vtoken:
        code, r = request("POST", "/api/rules/test", {"uri": "/p1"}, token=vtoken)
        check("viewer 可以试打", code == 200, f"code={code}")

    passed = sum(1 for _, ok in results if ok)
    print(f"\n结果：{passed}/{len(results)} 通过，失败 {len(results) - passed} 项")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
