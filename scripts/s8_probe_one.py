#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""逐条试打：把指定的 URI 真打一遍运行中的 WAF，读回命中规则。

用途：评估里漏报的样本，要判断是「规则没覆盖」还是「请求根本没到 ARGS」，
      只有看命中明细才知道往哪儿补。
用法（Kali 内）：
  python3 s8_probe_one.py "/?id=1; SELECT * FROM users" "/?q=eval(alert(1))"
"""
import json
import sys
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:18080"


def call(path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data,
                                 method="POST" if data else "GET")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


def main():
    uris = sys.argv[1:]
    st, body = call("/api/auth/login", {"username": "admin", "password": "LiteWaf@2026"})
    token = body.get("token")
    if not token:
        raise SystemExit("登录失败：%s" % body)
    for uri in uris:
        st, r = call("/api/rules/test", {"uri": uri}, token)
        hits = r.get("matches") or []
        desc = ", ".join("%s(%s)" % (h.get("rule_id"), h.get("category")) for h in hits) or "无命中"
        print("%-60s -> HTTP %s  score=%-3s  %s" % (uri, r.get("status"), r.get("score"), desc))


if __name__ == "__main__":
    main()
