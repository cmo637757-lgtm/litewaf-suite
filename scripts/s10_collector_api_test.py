#!/usr/bin/env python3
"""采集器健康状态接口自检（S10-3）。

用法：python3 s10_collector_api_test.py [--base http://127.0.0.1:18080]

检查项：
  1. 未登录访问 /api/collector/status → 401
  2. admin 登录 → 200
  3. alive=true 且 age_ms 在 20 秒内（心跳新鲜）
  4. sources 有两个来源，带 offset/size
  5. 字段齐全（rounds / ingested_total / errors_total / hint）
"""
import json
import sys
import time
import urllib.request
import urllib.error

BASE = "http://127.0.0.1:18080"
ADMIN = ("admin", "LiteWaf@2026")

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("  PASS  " if ok else "  FAIL  ") + name + (("  → " + detail) if detail else ""))


def request(method, path, body=None, token=None):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
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
    print("=== 采集器健康状态接口自检 ===")

    code, _ = request("GET", "/api/collector/status")
    check("未登录访问返回 401", code == 401, f"code={code}")

    code, body = request("POST", "/api/auth/login",
                         {"username": ADMIN[0], "password": ADMIN[1]})
    token = body.get("token")
    check("admin 登录成功", code == 200 and bool(token), f"code={code}")

    code, st = request("GET", "/api/collector/status", token=token)
    check("状态接口 200", code == 200, f"code={code}")

    alive = st.get("alive")
    age = st.get("age_ms", -1)
    check("采集器 alive=true", alive is True, f"alive={alive} hint={st.get('hint')}")
    check("心跳在 20 秒内", 0 <= age <= 20000, f"age_ms={age}")

    sources = st.get("sources") or []
    check("来源数量 2", len(sources) == 2, f"count={len(sources)}")
    names = sorted(s.get("name", "") for s in sources)
    check("来源名称正确", names == ["nginx_access", "waf_reject"], str(names))
    ok_fields = all("offset" in s and "size" in s and "lag_bytes" in s for s in sources)
    check("每个来源带 offset/size/lag", ok_fields,
          str([(s.get("name"), s.get("offset"), s.get("size")) for s in sources]))

    need = ["rounds", "ingested_total", "errors_total", "last_error", "hint", "ts"]
    missing = [k for k in need if k not in st]
    check("响应字段齐全", not missing, str(missing) if missing else "ok")

    # 采集器在跑的话，等两轮心跳再读一次，rounds 应该涨（证明不是一具尸体的旧文件）
    time.sleep(2.5)
    code, st2 = request("GET", "/api/collector/status", token=token)
    grew = st2.get("rounds", 0) > st.get("rounds", 0)
    check("两秒内心跳轮数在增长", grew,
          f"{st.get('rounds')} → {st2.get('rounds')}（采集器没在跑时这条会 FAIL）")

    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print(f"\n结果：{passed}/{total} 通过，失败 {total - passed} 项")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
