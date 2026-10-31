#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gen_fixture.py —— 冻结验收数据集生成器（S1 交付物）

为什么要它：需求卡片第七章规定所有看板/采集/告警的验收必须跑固定数据集，
数字对不上就是缺陷。数据集一旦冻结，任何人任何时候重跑都应得到同一份字节。

三套数据：
  F20  20 条访问 + 5 条 WAF 拒绝，覆盖首页 KPI/趋势/分类/Top 的固定口径
  A5   5 条同 IP SQLi 事件，覆盖阈值/固定时间桶/抑制/合并计数
  R    带标签样本集，正常 40 + SQLi 20 + XSS 20 + CC 20，覆盖误拦率/漏报率评估

用法：
    python tools/gen_fixture.py            # 生成到仓库 fixtures/
    python tools/gen_fixture.py --out D:/x # 指定输出目录

生成后 fixtures/MANIFEST.json 记录每个文件的 sha256，验收报告里引用它。
"""

import argparse
import datetime as dt
import hashlib
import json
import pathlib

# ---------------------------------------------------------------- 时间基准
# 需求卡片固定 F20 窗口为 UTC 2026-09-20T00:00:00Z 起 60 秒，闭开区间 [start, end)
F20_START = dt.datetime(2026, 9, 20, 0, 0, 0, tzinfo=dt.timezone.utc)
A5_START = dt.datetime(2026, 9, 20, 1, 0, 0, tzinfo=dt.timezone.utc)

# WAF 审计日志的 14 个字段（顺序固定，与 ngx_http_lite_waf_module.c 输出一致）
WAF_FIELDS = [
    "time", "client_ip", "method", "uri", "reason", "rule_id", "rule_name",
    "zone", "category", "score", "total_score", "action", "status", "cost_us",
]


def epoch_ms(t: dt.datetime) -> int:
    """把 UTC datetime 转成 epoch 毫秒（日志与 event_time 统一用这个）"""
    return int(t.timestamp() * 1000)


def waf_event(t, ip, uri, reason, rule_id, rule_name, zone, category,
              score, total_score, action, status, cost_us, method="GET"):
    """构造一条 14 字段 WAF 审计事件（JSON Lines 一行）"""
    return {
        "time": epoch_ms(t),
        "client_ip": ip,
        "method": method,
        "uri": uri,
        "reason": reason,
        "rule_id": rule_id,
        "rule_name": rule_name,
        "zone": zone,
        "category": category,
        "score": score,
        "total_score": total_score,
        "action": action,
        "status": status,
        "cost_us": cost_us,
    }


# ---------------------------------------------------------------- F20 数据集
def build_f20():
    """F20：20 条访问（含 1 条源站 403）+ 5 条 WAF 拒绝。

    期望值（需求卡片 7.1）：
      N=20  B=5  ratio=25%  窗口 QPS=0.3333
      分类 SQLi=3 XSS=1 CC=1
      Top IP .10=3 / .20=1 / .30=1
      body_bytes 合计 20000，request_time P50=100ms P95=190ms
      拒绝处理耗时 均值 300us / P95=500us
    """
    access, reject = [], []

    # 20 条访问：i 秒时第 i+1 条，request_time = i/100 秒，body 1000 字节
    # IP 轮转 .10 x5 / .20 x5 / .30 x5 / .40 x5
    for i in range(20):
        ip = f"10.0.0.{10 + (i // 5) * 10}"
        # 响应体：源站 403 那条（a19）用 1000 字节的自定义错误页，保证合计仍是 20000
        status = 403 if i == 19 else 200
        access.append({
            "time": epoch_ms(F20_START + dt.timedelta(seconds=i)),
            "client_ip": ip,
            "method": "GET",
            "uri": f"/p{i}",
            "status": status,
            "body_bytes_sent": 1000,
            "request_time": i / 100,
        })

    # 5 条拒绝：3 SQLi(.10) + 1 XSS(.20) + 1 漏桶 CC(.30)
    # e01..e03 是 SQL 规则命中（最后一条累计 total_score 超阈值才能 403，这里直接记最终态）
    reject.append(waf_event(F20_START + dt.timedelta(seconds=1), "10.0.0.10", "/p1",
                            "score_threshold", 1000, "sql keywords", "ARGS",
                            "SQL", 4, 12, "deny", 403, 100))
    reject.append(waf_event(F20_START + dt.timedelta(seconds=2), "10.0.0.10", "/p2",
                            "score_threshold", 1005, "union select", "ARGS",
                            "SQL", 8, 12, "deny", 403, 200))
    reject.append(waf_event(F20_START + dt.timedelta(seconds=3), "10.0.0.10", "/p3",
                            "score_threshold", 1005, "union select", "ARGS",
                            "SQL", 8, 12, "deny", 403, 300))
    reject.append(waf_event(F20_START + dt.timedelta(seconds=4), "10.0.0.20", "/p4",
                            "score_threshold", 1300, "xss tags", "ARGS",
                            "XSS", 8, 12, "deny", 403, 400))
    # 漏桶：category 为空、reason=dynamic_block、rule_id=0；采集适配层据此映射为 CC
    reject.append(waf_event(F20_START + dt.timedelta(seconds=5), "10.0.0.30", "/p5",
                            "dynamic_block", 0, "", "", "", 0, 0, "deny", 403, 500))

    expected = {
        "window": {
            "start_ms": epoch_ms(F20_START),
            "end_ms": epoch_ms(F20_START + dt.timedelta(seconds=60)),
        },
        "kpi": {"N": 20, "B": 5, "ratio": 0.25, "qps": 0.3333},
        "category": {"SQLi": 3, "XSS": 1, "CC": 1},
        "top_ip": {"10.0.0.10": 3, "10.0.0.20": 1, "10.0.0.30": 1},
        "body_bytes_sum": 20000,
        "request_time_ms": {"p50": 100, "p95": 190},
        "reject_cost_us": {"mean": 300, "p95": 500},
        "notes": "a19 是源站 403，不进 WAF 拒绝列表，但计入 N 与 body_bytes",
    }
    return access, reject, expected


# ---------------------------------------------------------------- A5 数据集
def build_a5():
    """A5：同 IP 第 10/20/30/40/50 秒各一条 SQLi，阈值 3、窗口 60、抑制 300。

    期望（卡片 7.3）：trigger_count=3（30/40/50 秒各触发一次候选）
                      event_count=5（关联事件去重计数）
                      delivery_count=1（首触发发一次，后续被抑制）
    """
    ip = "10.0.0.77"
    events = []
    for sec in (10, 20, 30, 40, 50):
        events.append(waf_event(A5_START + dt.timedelta(seconds=sec), ip, f"/a{sec}",
                                "score_threshold", 1000, "sql keywords", "ARGS",
                                "SQL", 6, 12, "deny", 403, 120))

    expected = {
        "rule": {"window_s": 60, "threshold": 3, "suppress_s": 300},
        "trigger_count": 3,
        "event_count": 5,
        "delivery_count": 1,
        "first_trigger_s": 30,
        "notes": "第 3 条落在 30 秒首次触发，40/50 秒因抑制窗口内不再分发（delivery 仍是 1）",
    }
    return events, expected


# ---------------------------------------------------------------- R 标签集
# 正常请求 40 条：不同路径/UA/参数，必须全部放行（FP 目标 0）
BENIGN = [
    ("/", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"),
    ("/index.html", "Mozilla/5.0 (X11; Linux x86_64) Chrome/127.0"),
    ("/product?id=1", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"),
    ("/search?q=hello+world", "Mozilla/5.0 (Windows NT 10.0) Firefox/128.0"),
    ("/login", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"),
    ("/static/app.css", "Mozilla/5.0 (Windows NT 10.0) Chrome/127.0"),
    ("/static/app.js", "Mozilla/5.0 (Linux; Android 14) Chrome/127.0"),
    ("/api/items?page=2", "Mozilla/5.0 (Windows NT 10.0) Edge/127.0"),
    ("/docs/readme.md", "Mozilla/5.0 (X11; Ubuntu) Firefox/128.0"),
    ("/about", "Mozilla/5.0 (Windows NT 10.0) Chrome/127.0"),
    ("/contact", "Mozilla/5.0 (iPhone) Safari/604.1"),
    ("/news/2026/09", "Mozilla/5.0 (Windows NT 10.0) Chrome/127.0"),
    ("/user/profile", "Mozilla/5.0 (iPad) Safari/604.1"),
    ("/cart?step=2", "Mozilla/5.0 (Windows NT 10.0) Chrome/127.0"),
    ("/order/10086", "Mozilla/5.0 (Linux) Firefox/128.0"),
    ("/files/report.pdf", "Mozilla/5.0 (Windows NT 10.0) Chrome/127.0"),
    ("/img/logo.png", "Mozilla/5.0 (Windows NT 10.0) Edge/127.0"),
    ("/api/health", "Mozilla/5.0 (Windows NT 10.0) Chrome/127.0"),
    ("/reset?email=a@b.com", "Mozilla/5.0 (Windows NT 10.0) Chrome/127.0"),
    ("/tag/security", "Mozilla/5.0 (Windows NT 10.0) Chrome/127.0"),
    ("/tag/nginx", "Mozilla/5.0 (Windows NT 10.0) Chrome/127.0"),
    ("/post/42", "Mozilla/5.0 (Windows NT 10.0) Chrome/127.0"),
    ("/post/42/comments", "Mozilla/5.0 (Windows NT 10.0) Chrome/127.0"),
    ("/api/v1/list?limit=10&offset=0", "Mozilla/5.0 (Windows NT 10.0) Chrome/127.0"),
    ("/api/v1/list?sort=time&order=desc", "Mozilla/5.0 (Windows NT 10.0) Chrome/127.0"),
    ("/download?file=report.csv", "Mozilla/5.0 (Windows NT 10.0) Chrome/127.0"),
    ("/faq#install", "Mozilla/5.0 (Windows NT 10.0) Chrome/127.0"),
    ("/pricing", "Mozilla/5.0 (Macintosh) Chrome/127.0"),
    ("/blog/nginx-waf", "Mozilla/5.0 (Windows NT 10.0) Chrome/127.0"),
    ("/help?topic=rule", "Mozilla/5.0 (Windows NT 10.0) Chrome/127.0"),
    ("/archive?year=2026&month=09", "Mozilla/5.0 (Windows NT 10.0) Chrome/127.0"),
    ("/feed.xml", "Mozilla/5.0 (Windows NT 10.0) Chrome/127.0"),
    ("/robots.txt", "Googlebot/2.1 (+http://www.google.com/bot.html)"),
    ("/sitemap.xml", "Mozilla/5.0 (compatible; bingbot/2.0)"),
    ("/api/status?verbose=1", "Mozilla/5.0 (Windows NT 10.0) Chrome/127.0"),
    ("/team", "Mozilla/5.0 (Windows NT 10.0) Chrome/127.0"),
    ("/legal/privacy", "Mozilla/5.0 (Windows NT 10.0) Chrome/127.0"),
    ("/signup?plan=pro", "Mozilla/5.0 (Windows NT 10.0) Chrome/127.0"),
    ("/user/10086/avatar", "Mozilla/5.0 (Windows NT 10.0) Chrome/127.0"),
    ("/metrics", "Mozilla/5.0 (Windows NT 10.0) Chrome/127.0"),
]

# SQLi 20 条：覆盖规则 1000-1006（关键字/union/布尔/时间盲注/报错/文件/元数据）
SQLI = [
    "/?id=1'+OR+'1'='1",
    "/?id=1 UNION SELECT password FROM users",
    "/?id=1;SELECT * FROM users",
    "/?id=1 AND SLEEP(5)",
    "/?id=1 AND benchmark(1000000,MD5(1))",
    "/?id=-1 UNION ALL SELECT NULL--",
    "/?id=1'+AND+(SELECT+COUNT(*)+FROM+users)>0--",
    "/?id=1' AND extractvalue(1,concat(0x7e,database()))--",
    "/?id=1 AND updatexml(1,concat(0x7e),1)",
    "/?id=1 AND load_file('/etc/passwd')",
    "/?id=1 INTO OUTFILE '/tmp/x.txt'",
    "/?id=1' AND ascii(substr(database(),1,1))>100--",
    "/?id=1 UNION SELECT table_name FROM information_schema.tables",
    "/?id=1 ORDER BY 100--",
    "/?id=1' HAVING 1=1--",
    "/?id=1 OR 'x'='x",
    "/?id=1;DROP TABLE users--",
    "/?id=1 AND 1=(SELECT 1 FROM users LIMIT 1)",
    "/?id=1 WAITFOR DELAY '0:0:5'--",
    "/?id=1 UNION SELECT 1,2,3,4,5--",
]

# XSS 20 条：覆盖规则 1300-1303（script 标签/事件属性/javascript 伪协议/编码绕过）
XSS = [
    "/?q=<script>alert(1)</script>",
    "/?q=<img src=x onerror=alert(1)>",
    "/?q=javascript:alert(1)",
    "/?q=<svg/onload=alert(1)>",
    "/?q=<iframe src=javascript:alert(1)>",
    "/?q=<body onload=alert(1)>",
    "/?q=<a href=\"javascript:alert(1)\">x</a>",
    "/?q=\"><script>alert(1)</script>",
    "/?q=<div onclick=alert(1)>x</div>",
    "/?q=<input autofocus onfocus=alert(1)>",
    "/?q=<details open ontoggle=alert(1)>",
    "/?q=<marquee onstart=alert(1)>",
    "/?q=<video><source onerror=alert(1)>",
    "/?q=<object data=javascript:alert(1)>",
    "/?q=<embed src=javascript:alert(1)>",
    "/?q=<form action=javascript:alert(1)>",
    "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "/?q=<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
    "/?q=document.cookie",
    "/?q=<img src=1 onerror=eval(atob('YWxlcnQoMSk='))>",
]


def build_r():
    """R：带标签样本集（JSON 数组），字段 request 供 HTTP 回归脚本逐条发送"""
    r = []

    for i, (uri, ua) in enumerate(BENIGN):
        r.append({"id": f"b{i:02d}", "label": "benign", "category": "none",
                  "expect_status": 200, "request": {"uri": uri, "ua": ua}})

    for i, uri in enumerate(SQLI):
        r.append({"id": f"s{i:02d}", "label": "attack", "category": "SQLi",
                  "expect_status": 403,
                  "request": {"uri": uri, "ua": "Mozilla/5.0 (Windows NT 10.0) Chrome/127.0"}})

    for i, uri in enumerate(XSS):
        r.append({"id": f"x{i:02d}", "label": "attack", "category": "XSS",
                  "expect_status": 403,
                  "request": {"uri": uri, "ua": "Mozilla/5.0 (Windows NT 10.0) Chrome/127.0"}})

    # CC：同一 IP 连发 20 条普通请求，须先预热 C 次（默认 C=20）才能让这 20 条落进封禁态
    cc_ip = "10.0.0.99"
    cc = []
    for i in range(20):
        cc.append({
            "id": f"c{i:02d}", "label": "attack", "category": "CC",
            "expect_status": 403, "src_ip": cc_ip,
            "request": {"uri": f"/p{i}", "ua": "Mozilla/5.0 (Windows NT 10.0) Chrome/127.0"},
        })

    expected = {
        "core": {"benign": 40, "SQLi": 20, "XSS": 20, "CC": 20},
        "targets": {"FP": 0, "FP_total": 40, "SQLi_TP": 20, "XSS_TP": 20,
                    "FNR_max": 0.0, "FPR_max": 0.0},
        "cc_warmup": {"src_ip": cc_ip, "count": 20,
                      "note": "先发 20 条普通请求把漏桶打满，随后这 20 条须全部 403"},
    }
    return {"benign": r[:40], "attack": r[40:] + cc}, expected


# ---------------------------------------------------------------- 落盘与清单
def dump_jsonl(path: pathlib.Path, rows):
    """JSON Lines：一行一条，末尾带换行，UTF-8 无 BOM（PowerShell 写会带 BOM，必须用 Python）"""
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def dump_json(path: pathlib.Path, obj):
    with path.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write("\n")


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description="生成并冻结 F20/A5/R 验收数据集")
    ap.add_argument("--out", default="fixtures", help="输出目录（默认仓库下 fixtures/）")
    args = ap.parse_args()

    root = pathlib.Path(args.out).resolve()
    (root / "f20").mkdir(parents=True, exist_ok=True)
    (root / "a5").mkdir(parents=True, exist_ok=True)
    (root / "r").mkdir(parents=True, exist_ok=True)

    # F20
    access, reject, exp_f20 = build_f20()
    dump_jsonl(root / "f20" / "access.log", access)
    dump_jsonl(root / "f20" / "reject.log", reject)
    dump_json(root / "f20" / "expected.json", exp_f20)

    # A5
    events, exp_a5 = build_a5()
    dump_jsonl(root / "a5" / "events.log", events)
    dump_json(root / "a5" / "expected.json", exp_a5)

    # R
    labels, exp_r = build_r()
    dump_json(root / "r" / "labels.json", labels)
    dump_json(root / "r" / "expected.json", exp_r)

    # 清单：任何人拿到 fixtures 都能核对没被改过
    files = sorted(p for p in root.rglob("*") if p.is_file())
    manifest = {
        "generated_by": "tools/gen_fixture.py",
        "frozen_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "files": {str(p.relative_to(root)).replace("\\", "/"): {
            "sha256": sha256(p), "bytes": p.stat().st_size} for p in files},
    }
    dump_json(root / "MANIFEST.json", manifest)

    print(f"输出目录: {root}")
    for name, meta in manifest["files"].items():
        print(f"  {name:24s} {meta['bytes']:7d} B  {meta['sha256'][:16]}…")
    print(f"共 {len(manifest['files'])} 个文件")


if __name__ == "__main__":
    main()
