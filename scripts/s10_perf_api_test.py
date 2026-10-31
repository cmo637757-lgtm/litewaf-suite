#!/usr/bin/env python3
"""性能与数据源状态接口自检（S10-4）。

用法：python3 s10_perf_api_test.py
"""
import json
import sys
import time
import urllib.request
import urllib.error

BASE = "http://127.0.0.1:18080"
results = []


def check(name, ok, detail=""):
    results.append((name, ok))
    print(("  PASS  " if ok else "  FAIL  ") + name + (("  → " + detail) if detail else ""))


def request(method, path, body=None, token=None):
    req = urllib.request.Request(BASE + path,
                                 data=json.dumps(body).encode() if body else None,
                                 method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, {}
    except urllib.error.URLError:
        return 0, {}


def main():
    print("=== 性能与数据源状态接口自检 ===")

    code, _ = request("GET", "/api/perf/summary")
    check("未登录 401", code == 401, f"code={code}")

    code, tok = request("POST", "/api/auth/login", {"username": "admin", "password": "LiteWaf@2026"})
    token = tok.get("token")
    check("admin 登录", code == 200 and bool(token))

    # 先打几次接口，让环形缓冲里有样本
    for _ in range(3):
        request("GET", "/api/stats/recent?limit=3", token=token)
        time.sleep(0.05)

    code, s = request("GET", "/api/perf/summary", token=token)
    check("状态接口 200", code == 200, f"code={code}")

    api = s.get("api") or {}
    check("api 字段齐全", all(k in api for k in ("count", "p50_ms", "p95_ms", "max_ms")), str(list(api)))
    check("api 样本数 > 0", api.get("count", 0) > 0, f"count={api.get('count')}")
    check("p95 >= p50", api.get("p95_ms", 0) >= api.get("p50_ms", 0),
          f"p50={api.get('p50_ms')} p95={api.get('p95_ms')}")
    check("接口 P95 在 1 秒内（本机应当很快）", api.get("p95_ms", 9999) < 1000, f"p95={api.get('p95_ms')}ms")

    col = s.get("collector") or {}
    check("采集器 alive", col.get("alive") is True, str(col.get("hint")))

    files = s.get("files") or []
    check("三个日志文件都在列表里", len(files) == 3, str([f.get("path") for f in files]))
    access = [f for f in files if f.get("path", "").endswith("access.log")]
    check("access.log 存在且非空", bool(access) and access[0].get("exists") and access[0].get("size_bytes", 0) > 0,
          str(access[0]) if access else "missing")

    tables = {t.get("name"): t.get("rows") for t in (s.get("tables") or [])}
    check("表行数齐全", set(tables) == {"requests", "waf_events", "ingest_errors", "false_positive_marks"},
          str(tables))
    check("requests 有数据", tables.get("requests", 0) > 0, f"requests={tables.get('requests')}")

    passed = sum(1 for _, ok in results if ok)
    print(f"\n结果：{passed}/{len(results)} 通过，失败 {len(results) - passed} 项")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
