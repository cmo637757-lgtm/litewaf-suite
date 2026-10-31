#!/usr/bin/env python3
"""评估报告接口自检（R34-11 展示侧）。用法：python3 s8_eval_api_test.py"""
import json
import sys
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:18080"
PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("  [PASS] " if cond else "  [FAIL] ") + name + (f"  {extra}" if extra else ""))


def get(path, token=None):
    req = urllib.request.Request(BASE + path)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read() or "{}")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"raw": body}


def main():
    req = urllib.request.Request(BASE + "/api/auth/login",
                                 data=json.dumps({"username": "admin", "password": "LiteWaf@2026"}).encode(),
                                 method="POST")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=20) as r:
        admin = json.loads(r.read())["token"]

    st, lst = get("/api/evaluations", admin)
    check("列表 200", st == 200, f"HTTP {st}")
    check("至少一次跑分", isinstance(lst, list) and len(lst) > 0, f"{len(lst) if isinstance(lst, list) else '?'} 条")
    if not lst:
        return 1
    first = lst[0]
    for k in ("run_id", "tp", "fn", "fp", "tn", "fnr", "fpr", "accuracy", "cc_first_block"):
        check(f"列表含 {k}", k in first)

    rid = first["run_id"]
    st, det = get(f"/api/evaluations/{rid}", admin)
    check("详情 200", st == 200, f"HTTP {st}")
    check("详情有 by_category", "by_category" in det)
    check("详情有 misses", "misses" in det)
    check("详情有 samples_sha256", "samples_sha256" in det)

    st, _ = get("/api/evaluations/20200101-000000", admin)
    check("不存在的跑次 404", st == 404, f"HTTP {st}")
    st, _ = get("/api/evaluations/..%2F..%2Fetc", admin)
    check("路径穿越被拒", st in (400, 404), f"HTTP {st}")

    st, _ = get("/api/evaluations")
    check("未登录 401", st == 401, f"HTTP {st}")

    print()
    print(f"结果：{len(PASS)} 项通过，{len(FAIL)} 项失败")
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
