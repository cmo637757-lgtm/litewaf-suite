#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 OWASP CRS 的规则文件里抽出可以直接复用的 @rx 正则。

CRS 规则是 ModSecurity 的 SecRule 语法，大部分依赖事务变量（TX）、链式规则、
运算符文件（@pmFromFile）或者像 @detectSQLi 这样的内置库，没法直接搬。
但其中相当一部分就是「一个正则匹配请求内容」，跟我们的 lwaf_rule 语义一致。

换算规则：
- 变量 → 我们的 zones（ARGS,BODY,COOKIE,URL）
- t:urlDecodeUni 我们引擎对 args/body/cookie 本身就解码后再匹配，等价
- 分数 → 按 CRS severity 给（CRITICAL 8 / ERROR 7 / WARNING 6）

自动排除：
- 正则里带双引号（会截断我们 pattern="..." 的写法）
- 正则里带 %{ （CRS 事务变量插值）
- @pm / @pmFromFile / @detectSQLi / @detectXSS（不是正则）
- 带 chain 的规则（语义是多条一起才算）

用法：python scripts/s14_crs2rules.py --conf 942 941 930
输出：samples/crs_rules_candidates.json
"""
import argparse
import json
import os
import re
import sys
import zipfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ZIP = os.path.join(ROOT, "samples", "raw", "coreruleset-main.zip")

FILES = {
    "942": "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
    "941": "REQUEST-941-APPLICATION-ATTACK-XSS.conf",
    "930": "REQUEST-930-APPLICATION-ATTACK-LFI.conf",
    "931": "REQUEST-931-APPLICATION-ATTACK-RFI.conf",
    "934": "REQUEST-934-APPLICATION-ATTACK-GENERIC.conf",
}

# CRS 规则 id 前缀 → 我们引擎的分数类别
CATEGORY = {"942": "SQL", "941": "XSS", "930": "TRAVERSAL", "931": "RFI", "934": "SQL"}


def parse_conf(text):
    """按行扫 SecRule，取出 (id, msg, severity, regex)。

    CRS 的写法是「SecRule 变量 "@rx 正则" \\ 换行 续行参数」，
    正则可能很长，所以用行尾最后一个引号做边界（贪婪），
    由调用方再按内容过滤掉不合适的。
    """
    out = []
    lines = text.splitlines()
    rx_line = re.compile(r'^\s*SecRule\s+(?P<vars>\S+)\s+"@(?P<op>rx|pm|pmFromFile|detectSQLi|detectXSS|contains)\s+(?P<rest>.*)"\s*\\?\s*$')
    other = re.compile(r'^\s*SecRule\s+(?P<vars>\S+)\s+"@(?P<op>\w+)\s*(?P<rest>[^"]*)"')
    i = 0
    while i < len(lines):
        line = lines[i]
        m = rx_line.match(line) or other.match(line)
        if not m:
            i += 1
            continue
        # 参数在后面几行里，收集到下一个 SecRule 或连续两个空行为止
        params, j = [], i + 1
        while j < len(lines) and not lines[j].lstrip().startswith("SecRule") and j < i + 25:
            params.append(lines[j])
            if lines[j].rstrip().endswith('"'):
                break
            j += 1
        blob = "\n".join(params)
        rid = re.search(r"id:(\d+)", blob)
        msg = re.search(r"msg:'([^']*)'", blob)
        sev = re.search(r"severity:'(\w+)'", blob)
        if rid:
            out.append({
                "id": rid.group(1),
                "msg": msg.group(1) if msg else "",
                "severity": sev.group(1) if sev else "",
                "op": "@" + m.group("op"),
                "regex": m.group("rest"),
                "vars": m.group("vars"),
                "chain": "chain" in blob,
            })
        i = j + 1
    return out


def score_of(sev):
    return {"CRITICAL": 8, "ERROR": 7, "WARNING": 6}.get(sev, 6)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--conf", nargs="*", default=["942", "941", "930"])
    ap.add_argument("--out", default=os.path.join(ROOT, "samples", "crs_rules_candidates.json"))
    args = ap.parse_args()

    z = zipfile.ZipFile(ZIP)
    candidates, skipped = [], {"not_rx": 0, "quotes": 0, "tx_var": 0, "chain": 0, "empty": 0}
    for key in args.conf:
        fname = FILES.get(key)
        if not fname:
            continue
        text = z.read("coreruleset-main/rules/" + fname).decode("utf-8", "replace")
        for rule in parse_conf(text):
            if rule["op"] != "@rx":
                skipped["not_rx"] += 1
                continue
            rx = rule["regex"]
            if not rx:
                skipped["empty"] += 1
                continue
            if '"' in rx:
                skipped["quotes"] += 1
                continue
            if "%{" in rx:
                skipped["tx_var"] += 1
                continue
            if rule["chain"]:
                skipped["chain"] += 1
                continue
            candidates.append({
                "crs_id": rule["id"],
                "name": rule["msg"][:60] or f"crs {rule['id']}",
                "regex": rx,
                "category": CATEGORY[key],
                "score": score_of(rule["severity"]),
                "source": key,
            })

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"candidates": candidates, "skipped": skipped}, f,
                  ensure_ascii=False, indent=2)
    by_src = {}
    for c in candidates:
        by_src[c["source"]] = by_src.get(c["source"], 0) + 1
    print(json.dumps({"candidates": len(candidates), "by_source": by_src,
                      "skipped": skipped}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    sys.exit(main())
