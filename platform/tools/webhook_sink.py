#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
本地 Webhook 接收器（告警验收用）。

告警模块按卡片 R35-04 只允许一个本地 HTTP 渠道。真接 IM 机器人要外网、要 token，
验收时用这个极简接收器：收到 POST 就把 JSON 原文追加到文件，然后回 200。

用法：
    python3 webhook_sink.py              # 默认 18099 端口，写 /tmp/webhook_received.jsonl
    python3 webhook_sink.py --port 18099 --out /opt/litewaf/runtime/logs/webhook.jsonl

--code 可以让它故意返回非 2xx，用来验证「投递失败 → 页面上可见 → 可重试」这条链路。
"""

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CODE = 200
OUT = "/tmp/webhook_received.jsonl"


class Handler(BaseHTTPRequestHandler):
    # 静默默认日志（每来一条就打一行太吵，验收时只看文件）
    def log_message(self, fmt, *args):      # noqa: A003
        pass

    def do_POST(self):                      # noqa: N802 —— BaseHTTPRequestHandler 规定的名字
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        try:
            payload = json.loads(raw)       # 顺便校验是不是合法 JSON
        except json.JSONDecodeError:
            payload = {"_raw": raw}

        record = {"path": self.path, "code": CODE, "payload": payload}
        with open(OUT, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

        self.send_response(CODE)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"ok": CODE < 300}, ensure_ascii=False).encode())

    def do_GET(self):                       # noqa: N802
        # 方便用 curl 看一眼收了几条
        n = 0
        if os.path.exists(OUT):
            with open(OUT, encoding="utf-8") as f:
                n = sum(1 for _ in f)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"received": n, "out": OUT, "code": CODE}).encode())


def main():
    global CODE, OUT
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18099)
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--code", type=int, default=200, help="固定返回的 HTTP 状态码，用于测失败重试")
    args = ap.parse_args()

    OUT = args.out
    CODE = args.code
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    if not os.path.exists(OUT):
        open(OUT, "w", encoding="utf-8").close()

    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print("webhook sink listening on http://127.0.0.1:%d  -> %s  code=%d"
          % (args.port, OUT, CODE), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("bye", flush=True)
        sys.exit(0)


if __name__ == "__main__":
    main()
