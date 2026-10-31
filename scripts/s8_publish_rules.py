#!/usr/bin/env python3
"""
把新的规则集通过「检查 → 发布」正式流程推上去（rules-v2）。

为什么不直接 cp 到 /opt/litewaf/runtime/rules/：
   线上规则文件由执行器管理，还要配套 nginx.conf 与版本目录，
   直接覆盖会让「当前版本 / 上一版本 / 回退」对不上账。
   所以这里走平台的 check → publish 接口，和网页上点按钮是同一条路径。

用法（在 Kali 上）：
    python3 /mnt/hgfs/share/scripts/s8_publish_rules.py
    python3 /mnt/hgfs/share/scripts/s8_publish_rules.py --dry   # 只检查不发布
"""
import argparse
import json
import sys
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:18080"
RULES_FILE = "/mnt/hgfs/share/WAF-lite/conf/litewaf_rules.conf"
CC = {"max_requests": 20, "window": 10, "block_duration": 60}


def call(path, body=None, token=None, method=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data,
                                 method=method or ("POST" if data else "GET"))
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            txt = r.read().decode()
            return r.status, (json.loads(txt) if txt else {})
    except urllib.error.HTTPError as e:
        txt = e.read().decode()
        try:
            return e.code, json.loads(txt)
        except Exception:
            return e.code, {"raw": txt}


def login():
    st, body = call("/api/auth/login", {"username": "admin", "password": "LiteWaf@2026"})
    if st != 200:
        sys.exit(f"登录失败 {st}: {body}")
    return body["token"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry", action="store_true", help="只做检查，不发布")
    args = ap.parse_args()

    rules = open(RULES_FILE, encoding="utf-8").read()
    print(f"规则文件 {RULES_FILE}：{len(rules)} 字节，{rules.count('lwaf_rule ')} 条规则")

    token = login()
    st, chk = call("/api/rules/check", {"rules": rules, "cc": CC}, token)
    print(f"检查 → HTTP {st}  {chk}")
    if st != 200 or not chk.get("ok"):
        sys.exit(1)

    candidate = chk.get("candidate_id")
    print(f"候选 {candidate}（规则字符数 {chk.get('rules_chars', '?')}，"
          f"nginx -t 通过）")

    if args.dry:
        print("--dry：到此为止，没有发布")
        return

    st, pub = call("/api/rules/publish", {"candidate_id": candidate}, token)
    print(f"发布 → HTTP {st}  {pub}")
    if st != 200 or not pub.get("ok"):
        sys.exit(1)
    print(f"当前版本 v{pub.get('version')}，上一版本 v{pub.get('previous')}，"
          f"operation {pub.get('operation_id')}")


if __name__ == "__main__":
    main()
