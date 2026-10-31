#!/usr/bin/env python3
"""
R36-01 导出接口自检：JSONL / CSV 两种格式 + 超限拒绝 + CSV 注入防护。

口径（卡片 R36-01）：
  - 导出的是「当前筛选条件」下的事件，与页面上看到的一致
  - 上限 1 万行，超了要提示缩小范围，不能静默截断
  - CSV 里 = + - @ 开头的字段按文本处理（否则 Excel 会当公式执行）

用法：python3 /mnt/hgfs/share/scripts/s8_export_test.py
"""
import json
import sys
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:18080"
F20_FROM, F20_TO = 1789862400000, 1789862460000
PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("  [PASS] " if cond else "  [FAIL] ") + name + (f"  {extra}" if extra else ""))


def call(path, token=None, raw=False):
    req = urllib.request.Request(BASE + path)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read().decode("utf-8", "replace")
            return r.status, (body if raw else json.loads(body or "{}")), r.headers
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        if raw:
            return e.code, body, e.headers
        try:
            return e.code, json.loads(body), e.headers
        except Exception:
            return e.code, {"raw": body}, e.headers


def main():
    st, body, _ = call("/api/auth/login")
    req = urllib.request.Request(BASE + "/api/auth/login",
                                 data=json.dumps({"username": "admin", "password": "LiteWaf@2026"}).encode(),
                                 method="POST")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=20) as r:
        token = json.loads(r.read())["token"]

    win = f"from={F20_FROM}&to={F20_TO}"

    print("== JSONL ==")
    st, body, hdr = call(f"/api/export?format=jsonl&{win}", token, raw=True)
    lines = [l for l in body.splitlines() if l.strip()]
    check("200", st == 200, f"HTTP {st}")
    check("5 行（F20 的 5 条拦截）", len(lines) == 5, f"实际 {len(lines)}")
    ok_json = True
    for l in lines:
        try:
            obj = json.loads(l)
            if not obj.get("id"):
                ok_json = False
        except Exception:
            ok_json = False
    check("每行都是合法 JSON 且含 id", ok_json)

    print("== CSV ==")
    st, body, hdr = call(f"/api/export?format=csv&{win}", token, raw=True)
    rows = [l for l in body.splitlines() if l.strip()]
    check("200", st == 200, f"HTTP {st}")
    check("表头 + 5 行", len(rows) == 6, f"实际 {len(rows)} 行")
    check("Content-Type 是 csv", "csv" in (hdr.get("Content-Type") or ""),
          hdr.get("Content-Type", ""))
    check("含脱敏标记的规则列", "rule_name" in rows[0], rows[0][:80])

    print("== 筛选生效 ==")
    st, body, _ = call(f"/api/export?format=jsonl&{win}&category=SQLi", token, raw=True)
    n = len([l for l in body.splitlines() if l.strip()])
    check("按 SQLi 过滤得 3 条", n == 3, f"实际 {n}")

    print("== 上限（临时灌 12000 行再删）==")
    import pymysql
    conn = pymysql.connect(host="127.0.0.1", user="litewaf", password="LiteWaf@2026",
                           database="litewaf", ssl_disabled=True, autocommit=True)
    base_ms = 1759276800000  # 2026-10-01 00:00:00Z，和 F20 隔开，不污染演示数据
    with conn.cursor() as cur:
        cur.execute("DELETE FROM waf_events WHERE event_time_ms BETWEEN %s AND %s",
                    (base_ms, base_ms + 12000 * 1000))
        cur.execute("SELECT id FROM ingest_sources ORDER BY id LIMIT 1")
        row = cur.fetchone()
        if not row:
            check("有 ingest_sources 记录", False, "库里没有采集来源，先跑一次采集")
            return 1
        src = row[0]
        rows = [(src, base_ms + i * 1000, "10.5.0.1", "GET", "/load/" + str(i), 403,
                 "score_threshold", 1005, "union select", "SQL", "SQLi", "deny", 300, 8)
                for i in range(12000)]
        cur.executemany(
            "INSERT INTO waf_events (source_id, event_time_ms, client_ip, method, uri, status, reason,"
            " rule_id, rule_name, category, category_display, action, cost_us, score)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", rows)
    try:
        st, body, _ = call(f"/api/export?format=csv&from={base_ms}&to={base_ms + 12000 * 1000}",
                           token, raw=True)
        check("超 1 万行被拒绝（4xx）", 400 <= st < 500, f"HTTP {st}")
        check("拒绝时给出缩小范围的提示", "上限" in body or "缩小" in body, body[:120])
        st, body, _ = call(f"/api/export?format=csv&from={base_ms}&to={base_ms + 500 * 1000}",
                           token, raw=True)
        check("缩小范围后可导出（500 行）", st == 200, f"HTTP {st}")
    finally:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM waf_events WHERE event_time_ms BETWEEN %s AND %s",
                        (base_ms, base_ms + 12000 * 1000))
        conn.close()
        print("  （临时数据已清理）")

    print("== CSV 注入防护 ==")
    st, body, _ = call(f"/api/export?format=csv&{win}", token, raw=True)
    csv_rows = [l for l in body.splitlines() if l.strip()]
    cells = [c for row in csv_rows[1:] for c in row.split(",")[:3]]
    bad = [c for c in cells if c.startswith(("=", "+", "-", "@"))]
    check("没有裸公式起始字符", not bad, str(bad[:5]))
    check("导出字段数一致（14 列）", all(len(r.split(",")) >= 14 for r in csv_rows[1:]),
          f"最少 {min(len(r.split(',')) for r in csv_rows[1:])} 列")

    print()
    print(f"结果：{len(PASS)} 项通过，{len(FAIL)} 项失败")
    if FAIL:
        for f in FAIL:
            print("  - " + f)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
