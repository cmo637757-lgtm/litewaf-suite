#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 CRS 候选正则转成 lwaf_rule，并按「正常样本零误报」自动筛选。

思路：CRS 的正则质量高但精确度参差，逐条丢进我们的引擎、只用 676 条正常
样本试一遍，凡是会误拦正常请求的一律不要。剩下的再合并进主规则文件，
整体评估一次看增益。

用法（在 Kali 上，先跑过 s14_crs2rules.py 生成候选）：
    python3 s14_promote_crs.py --out /mnt/hgfs/share/WAF-lite/conf/litewaf_rules.d/crs-extra.conf
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile

EVAL = "/opt/litewaf/src/WAF-lite/build/lwaf_eval"
CAND = "/mnt/hgfs/share/samples/crs_rules_candidates.json"
BENIGN = "/mnt/hgfs/share/samples/crs_benign.tsv"
BASE_RULES = "/mnt/hgfs/share/WAF-lite/conf/litewaf_rules.conf"


def escape_for_rule(regex):
    """规则文件里反斜杠要被引擎吃掉一层，所以这里全部双写。"""
    return regex.replace("\\", "\\\\")


def rule_line(idx, cand):
    rid = 9000 + idx
    name = (cand["name"] or "crs rule").replace('"', "'")[:56]
    cat = cand["category"]
    score = max(6, min(8, int(cand["score"])))
    return (f'lwaf_rule id={rid} name="{name}" type=rx '
            f'pattern="{escape_for_rule(cand["regex"])}" '
            f'zones=URL,ARGS,BODY,COOKIE score={cat}:{score} action=score')


def load_tsv(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        head = f.readline().rstrip("\n").split("\t")
        for line in f:
            vals = line.rstrip("\n").split("\t")
            if len(vals) < len(head):
                vals += [""] * (len(head) - len(vals))
            rows.append(dict(zip(head, vals)))
    return rows


def run(rules, row):
    args = [EVAL, rules, row["path"] or "/", row["query"] or "",
            row["ua"] or "", row["cookie"] or "", row["body"] or "",
            row.get("headers", "") or ""]
    p = subprocess.run(args, capture_output=True, timeout=10)
    return p.returncode == 2


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/mnt/hgfs/share/WAF-lite/conf/litewaf_rules.d/crs-extra.conf")
    ap.add_argument("--limit", type=int, default=0, help="只测前 N 条候选（调试用）")
    args = ap.parse_args()

    cands = json.load(open(CAND, encoding="utf-8"))["candidates"]
    if args.limit:
        cands = cands[: args.limit]
    benign = load_tsv(BENIGN)
    print(f"候选 {len(cands)} 条，正常样本 {len(benign)} 条")

    kept, dropped = [], []
    tmpdir = tempfile.mkdtemp(prefix="crsrule-")
    for idx, cand in enumerate(cands):
        line = rule_line(idx, cand)
        path = os.path.join(tmpdir, f"r{idx}.conf")
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(line + "\n")
        # 先确认规则本身能编译（坏正则会加载失败）
        ok = subprocess.run([EVAL, path, "/", "", "", "", "", ""],
                            capture_output=True).returncode in (0, 2)
        if not ok:
            dropped.append({**cand, "why": "regex compile failed"})
            continue
        fp = 0
        for row in benign:
            if run(path, row):
                fp += 1
                if fp > 2:  # 已经够脏了，不用数完
                    break
        if fp == 0:
            kept.append({"idx": idx, "line": line, **cand})
        else:
            dropped.append({**cand, "why": f"{fp}+ 正常样本误拦"})

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        f.write("# 由 s14_promote_crs.py 从 OWASP CRS 正则自动生成并筛选（正常样本零误报）\n")
        for k in kept:
            f.write(k["line"] + "\n")

    print(f"保留 {len(kept)} 条 → {args.out}；丢弃 {len(dropped)} 条")
    for d in dropped[:10]:
        print(f"  丢弃 {d['crs_id']} {d['name'][:40]} — {d['why']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
