#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""临时探针：打印告警接口的原始返回，排查 500/404。"""
import json
import sys
import urllib.error
import urllib.request

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
BASE = "http://127.0.0.1:18080"


def http(path, method="GET", body=None, token=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


code, body = http("/api/auth/login", "POST", {"username": "admin", "password": "LiteWaf@2026"})
tok = json.loads(body)["token"]
for p in ("/api/alerts", "/api/alerts/state", "/api/alert-rules"):
    c, b = http(p, token=tok)
    print(p, "->", c, b[:500])
