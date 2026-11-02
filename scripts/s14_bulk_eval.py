#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线批量评估：拿公开样本集打现有规则，统计检出/漏报/误报。

用法（在 Kali 上跑）：
    python3 s14_bulk_eval.py <样本文件> <attack|benign> [--param file] [--limit N]

样本文件：一行一条 payload（URL 里的参数值或完整路径）。
结果：打印统计 + 漏报名单，并写 JSON 到 /mnt/hgfs/share/samples/reports/
"""
import json
import os
import subprocess
import sys
import time
import collections

EVAL = "/opt/litewaf/src/WAF-lite/build/lwaf_eval"
RULES = "/opt/litewaf/src/WAF-lite/conf/litewaf_rules.conf"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
OUT_DIR = "/mnt/hgfs/share/samples/reports"


def run_eval(url, args="", ua=UA):
    """跑一次评估，返回 (是否拦截, 原始 stdout)。"""
    try:
        p = subprocess.run([EVAL, RULES, url, args, ua],
                           capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired:
        return False, '{"blocked": false, "timeout": true}'
    return p.returncode == 2, p.stdout


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    path, label = sys.argv[1], sys.argv[2]
    param = "file"
    limit = 0
    args = sys.argv[3:]
    for i, a in enumerate(args):
        if a == "--param" and i + 1 < len(args):
            param = args[i + 1]
        if a == "--limit" and i + 1 < len(args):
            limit = int(args[i + 1])

    with open(path, encoding="utf-8", errors="replace") as f:
        payloads = [ln.rstrip("\n").rstrip("\r") for ln in f if ln.strip()]
    if limit:
        payloads = payloads[:limit]

    t0 = time.time()
    blocked_n = 0
    missed = []
    for i, pl in enumerate(payloads):
        # lwaf_eval 把 argv[2] 当 path、argv[3] 当 query，所以要分开传；
        # 真实 LFI 就是 ?file=../../etc/passwd 这种形态。
        url = "/lfi"
        qs = "%s=%s" % (param, pl.replace(" ", "%20"))
        hit, _ = run_eval(url, qs)
        if hit:
            blocked_n += 1
        else:
            missed.append(pl[:160])
        if (i + 1) % 200 == 0:
            print("  ... %d/%d  已拦 %d" % (i + 1, len(payloads), blocked_n))

    n = len(payloads)
    elapsed = time.time() - t0
    if label == "attack":
        tp, fn, fp, tn = blocked_n, n - blocked_n, 0, 0
    else:
        tp, fn, fp, tn = 0, 0, blocked_n, n - blocked_n

    print()
    print("=" * 56)
    print("样本: %s  类别: %s  条数: %d" % (os.path.basename(path), label, n))
    print("拦截 %d / 放行 %d   耗时 %.1fs (%.1f 条/秒)"
          % (blocked_n, n - blocked_n, elapsed, n / elapsed if elapsed else 0))
    if label == "attack":
        print("检出率 %.2f%%   漏报 %d 条" % (100.0 * blocked_n / n, n - blocked_n))
        if missed:
            print("\n漏报前 40 条:")
            for m in missed[:40]:
                print("  - " + m)
    else:
        print("误拦率 %.2f%%   误拦 %d 条" % (100.0 * blocked_n / n, blocked_n))
        if missed:
            print("\n被误拦的样本前 40 条:")
            for m in missed[:40]:
                print("  - " + m)
    print("=" * 56)

    os.makedirs(OUT_DIR, exist_ok=True)
    name = os.path.splitext(os.path.basename(path))[0]
    rep = {
        "sample_file": os.path.basename(path),
        "label": label,
        "total": n,
        "blocked": blocked_n,
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "elapsed_s": round(elapsed, 1),
        "missed": missed,
    }
    out = os.path.join(OUT_DIR, "%s-%s.json" % (name, label))
    with open(out, "w", encoding="utf-8") as f:
        json.dump(rep, f, ensure_ascii=False, indent=2)
    print("报告: " + out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
