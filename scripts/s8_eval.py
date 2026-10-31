#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
R34-11 带标签样本评估：拿冻结样本打真实 WAF，算出 TP/FN/FP/TN。

为什么必须打真实实例而不是"看规则像不像"：
  卡片要求「真实样本 + 真实源站 + 真实日志联合验收」。规则写得再像，
  实际是否 403 只有打过去才知道——而且 reload 之后行为可能变。

口径（卡片 R34-11）：
  TP = 攻击样本被拦（403）
  FN = 攻击样本没被拦（200）          → 漏报
  FP = 正常样本被拦（403）            → 误报
  TN = 正常样本没被拦（200）
  error = 连接失败/超时，单独计数，绝对不充进 TN
  FNR = FN / (TP + FN)   FPR = FP / (FP + TN)

CC 场景单独跑：同一来源在窗口内连打，看第 C+1 次是否 403。

用法：
  python3 s8_eval.py                      # 打 127.0.0.1:18010
  python3 s8_eval.py --base http://127.0.0.1:18010 --gap 0.7
  python3 s8_eval.py --cc-only            # 只跑 CC 场景
"""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_BASE = "http://127.0.0.1:18010"
# 放 /opt/litewaf/evaluations 而不是 runtime 下面：runtime 属主是 root（nginx 要写日志），
# 往它里面写报告得 sudo，没必要。evaluations 由 kali 拥有，脚本直接写。
OUT_ROOT = "/opt/litewaf/evaluations"

# ---------------------------------------------------------------- 冻结样本
# 这些字符串就是"带标签样本集"，改动它必须重跑并把 hash 记进报告，
# 否则前后两次报告不可比（卡片 AC03 要求逐条可复现）。

SQLI = [
    "/?id=1' OR '1'='1",
    "/?id=1 UNION SELECT username,password FROM users",
    "/?id=1 AND 1=1",
    "/?id=1 AND 1=2",
    "/?id=1; DROP TABLE users--",
    "/?id=1' AND SLEEP(5)--",
    "/?id=1 UNION/**/SELECT/**/1,2,3",
    "/?id=1 or 1=1",
    "/?id=1' or 'x'='x",
    "/?id=1 AND EXTRACTVALUE(1,CONCAT(0x7e,version()))",
    "/?id=1 AND (SELECT COUNT(*) FROM information_schema.tables)>0",
    "/?id=1 ORDER BY 100",
    "/?id=1 GROUP BY 1 HAVING 1=1",
    "/?id=1' WAITFOR DELAY '0:0:5'--",
    "/?id=1 INTO OUTFILE '/tmp/x'",
    "/?id=1 UNION ALL SELECT NULL,NULL,NULL--",
    "/?id=1' AND '1'='1' --",
    "/?id=1;SELECT pg_sleep(5)",
    "/?id=1 AND BENCHMARK(10000000,MD5(1))",
    "/?id=1 /*!50000UNION*/ SELECT 1",
    "/?id=1 AND/**/1=1",
    "/?id=1 UNION%0aSELECT 1,2,3",
    "/?id=1 UNION%09SELECT 1,2",
    "/?id=1 un/**/ion sel/**/ect 1",
    "/?id=1%27%20OR%20%271%27=%271",
    "/?id=1%2527%20OR%201%3D1",
    "/?id=1 UnIoN SeLeCt NULL",
    "/?id=1 OR 0x31=0x31",
    "/?id=1 OR TRUE",
    "/?id=1 AND 1 LIKE 1",
    "/?id=1 AND 1=1%23",
    "/?id=1; SELECT * FROM users",
    "/?id=1 AND @@version LIKE 0x38000000",
    "/?id=1 AND (SELECT 1 FROM sys.tables)",
    "/?id=1 OR CHAR(65)=CHAR(65)",
    "/?id=1 AND 1>0",
    "/?id=1 OR \"1\"=\"1\"",
    "/?id=1 AND SLEEP(5)=0",
    "/?id=1 AND UPDATEXML(1,CONCAT(1,0x7e),1)",
    "/?id=1 order by 1,2,3,4,5,6,7,8,9,10",
    "/?id=1 group by 1 having 1>0",
    "/?id=1; DROP TABLE t--",
    "/?id=1 AND MID(@@version,1,1)='5'",
    "/?id=1 AND SUBSTRING((SELECT database()),1,1)>0",
    "/?id=1 AND load_file('/etc/passwd')",
    "/?id=1 /*!50000AND*/ 1=1",
    "/?id=1%0aAND%201=1",
    "/?id=1 AND (SELECT 1 FROM users WHERE 1=1)",
    "/?id=1' OR 'a'='a",
    "/?id=1 AND EXISTS(SELECT 1 FROM information_schema.tables)",
]

XSS = [
    "/?q=<script>alert(1)</script>",
    "/?q=<img src=x onerror=alert(1)>",
    "/?q=<svg/onload=alert(1)>",
    "/?q=javascript:alert(1)",
    "/?q=<iframe src=javascript:alert(1)>",
    "/?q=<body onload=alert(1)>",
    "/?q=<a href=javascript:alert(1)>click</a>",
    "/?q=%3Cscript%3Ealert(1)%3C/script%3E",
    "/?q=<script>document.cookie</script>",
    "/?q=<img src=\"x\" onerror=\"alert(document.domain)\">",
    "/?q=<details open ontoggle=alert(1)>",
    "/?q=<input autofocus onfocus=alert(1)>",
    "/?q=<video><source onerror=alert(1)>",
    "/?q=<object data=javascript:alert(1)>",
    "/?q=<embed src=javascript:alert(1)>",
    "/?q=<form action=javascript:alert(1)><input type=submit>",
    "/?q=<style>@import 'javascript:alert(1)'</style>",
    "/?q=</script><script>alert(1)</script>",
    "/?q=<math><mtext><script>alert(1)</script></mtext></math>",
    "/?q=<script src=//evil.example/x.js></script>",
    "/?q=<svg onload=alert(1)>",
    "/?q=<math href=javascript:alert(1)>x</math>",
    "/?q=<iframe srcdoc=<script>alert(1)</script>>",
    "/?q=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "/?q=<template><script>alert(1)</script></template>",
    "/?q=<base href=javascript:alert(1)//>",
    "/?q=<div style=background:url(javascript:alert(1))>",
    "/?q=<style>@import url(//evil.example/x.css)</style>",
    "/?q=<object data=data:text/html,<script>alert(1)</script>>",
    "/?q=<svg><script>alert(1)</script></svg>",
    "/?q=<SCRIPT>alert(1)</SCRIPT>",
    "/?q=<img src=x onerror=alert&#40;1&#41;>",
    "/?q=document.cookie",
    "/?q=javascript:alert(document.domain)",
    "/?q=<marquee onstart=alert(1)>",
    "/?q=<video poster=javascript:alert(1)>",
    "/?q=<form><button formaction=javascript:alert(1)>X</button>",
    "/?q=<input type=image src=javascript:alert(1)>",
    "/?q=<link rel=stylesheet href=javascript:alert(1)>",
    "/?q=<meta http-equiv=refresh content=0;url=javascript:alert(1)>",
    "/?q=<body background=javascript:alert(1)>",
    "/?q=<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    "/?q=eval(alert(1))",
    "/?q=%3Csvg%20onload%3Dalert%281%29%3E",
    "/?q=<xss style=x:expression(alert(1))>",
    "/?q=<noscript><p title=</noscript><img src=x onerror=alert(1)>>",
    "/?q=<a href=javascript:alert(1)>click</a>",
    "/?q=<details open ontoggle=alert(1)>",
    "/?q=<svg/onload=alert(1)>",
    "/?q=<object data=javascript:alert(1)>",
]

NORMAL = [
    "/", "/index.html", "/about", "/products", "/products/42", "/search?q=nginx",
    "/search?q=%E9%98%B2%E7%81%AB%E5%A2%99", "/api/v1/products?page=1&size=20",
    "/api/v1/products?page=2&size=20", "/login", "/static/app.css", "/static/app.js",
    "/img/logo.png", "/favicon.ico", "/sitemap.xml", "/robots.txt", "/blog/2026/09/hello",
    "/blog/2026/09/hello?ref=home", "/user/42/profile", "/user/42/profile?tab=orders",
    "/?q=hello+world", "/?q=union+street", "/?q=select+a+plan", "/?q=alert+me+later",
    "/?q=script+kiddie", "/?q=1+or+2+equals+3", "/?id=42", "/?id=abc",
    "/?order=asc&sort=price", "/cart?items=3", "/checkout", "/order/20260920",
    "/api/v1/health", "/metrics", "/admin/login", "/admin/dashboard",
    "/?file=report.pdf", "/download?id=9", "/feedback?score=5",
    "/?lang=zh-CN", "/?utm_source=newsletter&utm_medium=email",
    "/?q=how+to+select+a+product",
    "/?q=shipped+from+china",
    "/?q=where+is+my+order",
    "/?q=table+for+two",
    "/?q=union+jack+station",
    "/?q=rock+and+roll",
    "/?q=drop+table+of+contents",
    "/?q=update+your+profile",
    "/?q=insert+coin+to+continue",
    "/?q=delete+my+account",
    "/?q=order+your+meal",
    "/?q=group+discount+plan",
    "/?q=having+fun",
    "/?q=or+maybe+not",
    "/?q=1%3C2",
    "/?q=a%3Cb",
    "/?q=5%3E3",
    "/?q=if(x%3C10,y,z)",
    "/?q=%3C3",
    "/?q=well--done",
    "/?q=5*3=15",
    "/?q=100%25+discount",
    "/?q=%E4%B8%AD%E6%96%87%E6%90%9C%E7%B4%A2",
    "/?q=emoji+%F0%9F%98%80",
    "/?q=a||b",
    "/?a=1&&b=2",
    "/?q=height%3C=2m",
    "/?q=price%3E100",
    "/?q=user%40example.com",
    "/?q=2026-10-22",
    "/?q=12:30:00",
    "/?q=50%25+off",
    "/?q=1+%2B+2",
    "/?q=a%26b",
    "/?q=%22quoted+text%22",
    "/?q=it%27s+fine",
    "/?q=/path/to/file.txt",
    "/docs/../about",
    "/?id=1000000",
    "/?q=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "/?q=%E9%98%B2%E7%81%AB%E5%A2%99%E8%A7%84%E5%88%99",
    "/?sort=asc&order=price",
    "/?q=price+order",
    "/?q=select+options",
    "/?q=from+the+top",
    "/?q=where+to+buy",
    "/?q=table+reservation",
    "/?q=union+members",
    "/?q=script+writing",
    "/?q=alert+notification",
    "/?q=cookie+policy",
    "/?q=eval+results",
    "/?q=document+library",
    "/?q=innerHTML+tutorial",
    "/?q=if+you+select+all",
    "/?q=update+pending",
    "/?q=drop+by+office",
    "/?q=insert+card",
    "/?q=delete+key",
    "/feedback?name=alice&message=great+site",
]


def request(base, path, timeout=8):
    """
    发一条请求，返回 HTTP 状态码；连接层失败返回 None（记为 error，绝不充 TN）。

    两个坑：
    1. UA 必须伪装成浏览器——规则集里的 2001（扫描器特征）会拦 python-urllib/curl/wget，
       不设 UA 的话 40 条正常样本会被当成扫描器全部 403，评估结果直接失真；
    2. payload 里有空格、单引号、尖括号，直接拼进 URL 会被 urllib 判为 InvalidURL
       并当成连接失败（于是全算 error），必须先 quote。WAF 侧会先做 URL 解码再匹配，
       所以编码过的 payload 检测能力等价。
    """
    safe = "/?=&%+;:@!$'()*,~"  # 保留 payload 里的单引号和分号，只转义空格与 <> 之类
    url = base + urllib.parse.quote(path, safe=safe).replace(" ", "%20")
    req = urllib.request.Request(url)
    req.add_header("User-Agent",
                   "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
    req.add_header("Accept", "text/html,application/xhtml+xml")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None


def classify(base, samples, gap, kind):
    """逐条打，返回 [(path, status, verdict)]；verdict ∈ tp/fn/fp/tn/error。"""
    out = []
    for p in samples:
        st = request(base, p)
        if st is None:
            v = "error"
        elif kind == "attack":
            v = "tp" if st == 403 else "fn"
        else:
            v = "fp" if st == 403 else "tn"
        out.append((p, st, v))
        time.sleep(gap)  # 放慢是为了不触发 CC 漏桶，把 CC 单独当一个场景测
    return out


def cc_scenario(base, max_requests, window_s):
    """
    CC 场景：同一来源快速连打 max_requests+6 次，期望在容量耗尽后开始 403。

    这里的算盘要算清楚，不然会误判成「CC 不工作」：
      漏桶每来一个请求 +1，同时按 C/W 的速率排水。间隔 gap 秒时，
      每个请求的**净贡献**是 1 - gap*(C/W)。
      要让前 C 次放行、第 C+1 次开始拦，净贡献必须接近 1，也就是 gap 要远小于 W/C。
      按 20/10 算：gap=0.05s → 每次净贡献 0.9，25 次累计 22.5 > 21，够封；
      之前用 window/(max+6)=0.38s，每次净贡献只有 0.24，25 次才 6，永远封不了。
    """
    cw = max_requests / window_s if window_s else 1.0
    gap = min(0.05, 0.5 / cw)  # 保证每请求净贡献 >= 0.5
    total = max_requests + 6
    statuses = []
    for _ in range(total):
        statuses.append(request(base, "/?cc=" + str(len(statuses))))
        time.sleep(gap)
    first_block = next((i + 1 for i, s in enumerate(statuses) if s == 403), None)
    # 允许比理论值晚几次：排水会让实际触发点后移，但必须落在 (C, C+8] 内
    ok = first_block is not None and max_requests < first_block <= max_requests + 8
    return {
        "max_requests": max_requests,
        "window_s": window_s,
        "gap_s": round(gap, 3),
        "sent": total,
        "statuses": statuses,
        "first_block_at": first_block,
        "expected_first_block": max_requests + 1,
        "ok": ok,
    }


def metrics(tp, fn, fp, tn):
    fnr = fn / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    acc = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    return {
        "fnr": round(fnr, 4),
        "fpr": round(fpr, 4),
        "accuracy": round(acc, 4),
        "precision": round(precision, 4),
        "recall": round(tp / (tp + fn), 4) if (tp + fn) else 0.0,
    }


def main():
    args = sys.argv[1:]
    base = DEFAULT_BASE
    gap = 0.7
    cc_only = "--cc-only" in args
    if "--base" in args:
        base = args[args.index("--base") + 1]
    if "--gap" in args:
        gap = float(args[args.index("--gap") + 1])

    print(f"== R34-11 带标签样本评估 ==")
    print(f"目标 {base}   样本间隔 {gap}s")

    # 先确认实例活着，否则所有条目都会是 error，白跑
    health = request(base + "/waf-marker" if False else base, "/")
    if health is None:
        print(f"  [FATAL] {base} 连不上，先确认 runtime 实例在跑")
        return 2

    report = {
        "run_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "target": base,
        "gap_s": gap,
        "samples": {
            "attack_sqli": len(SQLI),
            "attack_xss": len(XSS),
            "normal": len(NORMAL),
        },
    }

    if not cc_only:
        sqli = classify(base, SQLI, gap, "attack")
        xss = classify(base, XSS, gap, "attack")
        normal = classify(base, NORMAL, gap, "normal")

        def count(rows, v):
            return sum(1 for _, _, x in rows if x == v)

        tp = count(sqli, "tp") + count(xss, "tp")
        fn = count(sqli, "fn") + count(xss, "fn")
        fp = count(normal, "fp")
        tn = count(normal, "tn")
        err = count(sqli, "error") + count(xss, "error") + count(normal, "error")

        m = metrics(tp, fn, fp, tn)
        report.update({
            "confusion": {"tp": tp, "fn": fn, "fp": fp, "tn": tn, "error": err},
            "metrics": m,
            "by_category": {
                "SQLi": {"tp": count(sqli, "tp"), "fn": count(sqli, "fn")},
                "XSS": {"tp": count(xss, "tp"), "fn": count(xss, "fn")},
            },
            "misses": [{"path": p, "status": s} for p, s, v in (sqli + xss) if v == "fn"],
            "false_positives": [{"path": p, "status": s} for p, s, v in normal if v == "fp"],
            "errors": [{"path": p, "status": s} for p, s, v in (sqli + xss + normal) if v == "error"],
        })

        print(f"\n  TP={tp}  FN={fn}  FP={fp}  TN={tn}  error={err}")
        print(f"  漏报率 FNR = {m['fnr']:.2%}   误报率 FPR = {m['fpr']:.2%}")
        print(f"  准确率 = {m['accuracy']:.2%}   精确率 = {m['precision']:.2%}   召回率 = {m['recall']:.2%}")
        print(f"  SQLi 检出 {report['by_category']['SQLi']['tp']}/{len(SQLI)}"
              f"   XSS 检出 {report['by_category']['XSS']['tp']}/{len(XSS)}"
              f"   正常误拦 {fp}/{len(NORMAL)}")
        if report["misses"]:
            print("  漏报明细：")
            for x in report["misses"][:10]:
                print(f"    - {x['path']} → {x['status']}")
        if report["false_positives"]:
            print("  误报明细：")
            for x in report["false_positives"][:10]:
                print(f"    - {x['path']} → {x['status']}")

    # CC 单独场景（会把这台来源 IP 短暂封掉，所以放最后）
    cc = cc_scenario(base, 20, 10)
    report["cc"] = cc
    print(f"\n  CC：第 {cc['first_block_at']} 次开始 403（期望第 {cc['expected_first_block']} 次），"
          f"{'OK' if cc['ok'] else '不符合预期'}")

    run_id = time.strftime("%Y%m%d-%H%M%S")
    out_dir = os.path.join(OUT_ROOT, run_id)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "report.json")
    import hashlib
    report["samples_sha256"] = hashlib.sha256(
        (json.dumps({"sqli": SQLI, "xss": XSS, "normal": NORMAL}, ensure_ascii=False)
         ).encode()).hexdigest()
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"\n  报告已写入 {out_path}")

    ok = (report.get("confusion", {}).get("fp", 0) == 0
          and report.get("by_category", {}).get("SQLi", {}).get("fn", 0) == 0
          and report.get("by_category", {}).get("XSS", {}).get("fn", 0) == 0)
    return 0 if (cc["ok"] and ok) else 1


if __name__ == "__main__":
    sys.exit(main())
