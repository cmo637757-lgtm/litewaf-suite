#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用离线评估器批量跑 CRS 样本（攻击 + 正常），出检出率/误报率。

为什么不用 HTTP：几千条样本打真实实例，几十分钟，还会被 CC 封禁干扰。
lwaf_eval 直接调引擎，一条一个进程约 2ms，两千多条十秒内跑完。

用法（在 Kali 上）：
    python3 s14_bulk_eval2.py --rules /opt/litewaf/src/WAF-lite/conf/litewaf_rules.conf \
        --attack /mnt/hgfs/share/samples/crs_attack.tsv \
        --benign /mnt/hgfs/share/samples/crs_benign.tsv \
        --out /mnt/hgfs/share/samples/reports/crs-baseline.json

退出码：0 正常（不管检出多少），1 参数/环境问题。
"""
import argparse
import collections
import csv
import json
import os
import subprocess
import sys
import time

EVAL = "/opt/litewaf/src/WAF-lite/build/lwaf_eval"


def run_one(rules, path, query, ua, cookie, body, headers=""):
    """跑一条样本，返回 (blocked, reason, matches)。"""
    args = [EVAL, rules, path or "/", query or "", ua or "", cookie or "",
            body or "", headers or ""]
    try:
        p = subprocess.run(args, capture_output=True, timeout=10)
    except Exception as exc:  # noqa: BLE001
        return False, f"error:{exc}", []
    blocked = p.returncode == 2
    reason = ""
    matches = []
    text = (p.stdout or b"").decode("utf-8", "replace")
    for line in text.splitlines():
        s = line.strip()
        if s.startswith('"reason"'):
            reason = s.split(":", 1)[1].strip().strip(",").strip('"')
        elif s.startswith('"matches"'):
            chunk = s.split(":", 1)[1].strip().rstrip("]}").strip()
            for item in chunk.split("}, {"):
                if '"rule_id"' in item:
                    rid = item.split('"rule_id":')[1].split(",")[0]
                    matches.append(rid)
    if p.returncode not in (0, 2):
        reason = "crash:" + (p.stderr or b"").decode("utf-8", "replace")[:120]
    return blocked, reason, matches


def load_tsv(path):
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default="/opt/litewaf/src/WAF-lite/conf/litewaf_rules.conf")
    ap.add_argument("--attack", default="/mnt/hgfs/share/samples/crs_attack.tsv")
    ap.add_argument("--benign", default="/mnt/hgfs/share/samples/crs_benign.tsv")
    ap.add_argument("--out", default="")
    ap.add_argument("--show", type=int, default=15, help="漏报/误报清单各显示多少条")
    args = ap.parse_args()

    if not os.path.exists(EVAL):
        print(f"[FAIL] 找不到评估器 {EVAL}（先跑 s14_build_eval.sh）")
        return 1

    report = {"rules": args.rules, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    t0 = time.time()

    # ---- 攻击样本：该拦没拦 = 漏报 ----
    attacks = load_tsv(args.attack)
    per_cat = collections.defaultdict(lambda: {"n": 0, "hit": 0, "miss": []})
    for row in attacks:
        blocked, reason, matches = run_one(args.rules, row["path"], row["query"],
                                           row["ua"], row["cookie"], row["body"],
                                           row.get("headers", ""))
        cat = row["category"]
        per_cat[cat]["n"] += 1
        if blocked:
            per_cat[cat]["hit"] += 1
        else:
            per_cat[cat]["miss"].append({
                "method": row["method"], "path": row["path"], "query": row["query"][:200],
                "body": row["body"][:200], "ua": row["ua"][:60],
                "headers": (row.get("headers") or "")[:160],
            })
    total_n = sum(v["n"] for v in per_cat.values())
    total_hit = sum(v["hit"] for v in per_cat.values())
    report["attack"] = {
        "total": total_n, "blocked": total_hit,
        "detection_rate": round(total_hit / total_n * 100, 2) if total_n else 0.0,
        "by_category": {k: {"n": v["n"], "hit": v["hit"],
                            "rate": round(v["hit"] / v["n"] * 100, 2) if v["n"] else 0.0}
                        for k, v in sorted(per_cat.items())},
    }

    # ---- 正常样本：不该拦却拦了 = 误报 ----
    benign = load_tsv(args.benign)
    fp = []
    for row in benign:
        blocked, reason, matches = run_one(args.rules, row["path"], row["query"],
                                           row["ua"], row["cookie"], row["body"],
                                           row.get("headers", ""))
        if blocked:
            fp.append({
                "category": row["category"], "method": row["method"],
                "path": row["path"], "query": row["query"][:200],
                "body": row["body"][:200], "reason": reason, "rules": matches,
            })
    report["benign"] = {
        "total": len(benign), "false_positive": len(fp),
        "fpr": round(len(fp) / len(benign) * 100, 2) if benign else 0.0,
    }
    report["elapsed_sec"] = round(time.time() - t0, 1)

    if args.out:
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        # 漏报/误报明细单独存，方便逐条看
        with open(args.out.replace(".json", "-miss.json"), "w", encoding="utf-8") as f:
            json.dump({k: v["miss"] for k, v in per_cat.items()}, f, ensure_ascii=False, indent=2)
        with open(args.out.replace(".json", "-fp.json"), "w", encoding="utf-8") as f:
            json.dump(fp, f, ensure_ascii=False, indent=2)

    print(f"== 攻击 {total_n} 条：拦截 {total_hit}（{report['attack']['detection_rate']}%）")
    for k, v in report["attack"]["by_category"].items():
        print(f"   {k:<10} {v['hit']:>4}/{v['n']:<5} {v['rate']:>6}%")
    print(f"== 正常 {len(benign)} 条：误拦 {len(fp)}（{report['benign']['fpr']}%）")
    print(f"== 耗时 {report['elapsed_sec']} 秒")

    if per_cat:
        shown = 0
        for cat, v in sorted(per_cat.items()):
            if not v["miss"]:
                continue
            print(f"\n-- {cat} 漏报样例（共 {len(v['miss'])}）")
            for m in v["miss"][:args.show]:
                print(f"   {m['method']} {m['path']} |q={m['query']}| |b={m['body']}|")
                shown += 1
        if shown == 0:
            print("\n-- 无漏报")
    if fp:
        print(f"\n-- 误拦样例（共 {len(fp)}）")
        for m in fp[:args.show]:
            print(f"   [{m['category']}] {m['method']} {m['path']} |q={m['query']}| |b={m['body']}| <- {m['rules']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
