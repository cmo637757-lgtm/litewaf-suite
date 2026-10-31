#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""给演示准备几条人工复核记录（幂等，重复跑不会重复插入）。

用法：python3 s8_seed_marks.py [--clear]
  默认给 F20 的 1 号事件标「确认误报」、2 号标「驳回」；
  --clear 则把所有标记清空。
"""
import json
import sys
import urllib.request

BASE = "http://127.0.0.1:18080"


def call(method, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def main():
    st, body = call("POST", "/api/auth/login", {"username": "admin", "password": "LiteWaf@2026"})
    if st != 200:
        print("登录失败", st, body)
        return 2
    token = body["token"]

    if "--clear" in sys.argv:
        for eid in range(1, 200):
            call("DELETE", f"/api/events/{eid}/mark", token=token)
        print("已清空全部标记")
        return 0

    plan = [
        (1, "confirmed", "分页参数 page=1 被 union select 规则误伤，属正常业务"),
        (2, "rejected", "确实是注入尝试，规则命中正确"),
    ]
    for eid, decision, remark in plan:
        st, body = call("POST", f"/api/events/{eid}/mark", {"decision": decision, "remark": remark}, token=token)
        print(f"事件 {eid} → {decision}: HTTP {st}")

    st, m = call("GET", "/api/fp/metrics?from=1789862400000&to=1789862460000", token=token)
    print("F20 指标：", json.dumps(m, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
