#!/usr/bin/env python3
"""
平台接口自检（对应需求卡片 S3/S4 验收项）。

用法：
    python3 api_check.py [BASE_URL]      # 默认 http://127.0.0.1:18080

前提：库里已灌入 F20 固定数据集（fixtures/f20），5 条拦截事件。

输出：逐项 PASS/FAIL 表；任一失败退出码非 0。
"""
import json
import sys
import urllib.error
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:18080"
F20_FROM = 1789862400000
F20_TO = 1789862460000

results = []


def call(path, token=None, method="GET", payload=None):
    """发一个请求，返回 (状态码, 解析后的 JSON 或 None)"""
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            body = r.read().decode("utf-8")
            return r.status, (json.loads(body) if body.strip().startswith(("{", "[")) else body)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, body


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("  PASS  " if ok else "  FAIL  ") + name + (("  → " + detail) if detail else ""))


def main():
    print("== 1. 未认证 ==")
    st, _ = call("/api/stats/summary")
    check("未认证访问统计返回 401", st == 401, "实际 %s" % st)

    print("== 2. 登录 ==")
    st, body = call("/api/auth/login", method="POST",
                    payload={"username": "admin", "password": "LiteWaf@2026"})
    check("admin 登录 200", st == 200, "实际 %s" % st)
    token = (body or {}).get("token")
    check("返回 token", bool(token))
    if not token:
        return finish()

    st, _ = call("/api/auth/login", method="POST",
                 payload={"username": "admin", "password": "wrong"})
    check("错误口令返回 401", st == 401, "实际 %s" % st)

    print("== 3. F20 统计口径 ==")
    st, s = call("/api/stats/summary?from=%d&to=%d" % (F20_FROM, F20_TO), token)
    check("summary 200", st == 200, "实际 %s" % st)
    if st == 200:
        kpi, lat = s["kpi"], s["latency"]
        check("N=20", kpi["n"] == 20, str(kpi["n"]))
        check("B=5", kpi["b"] == 5, str(kpi["b"]))
        check("ratio=0.25", kpi["ratio"] == 0.25, str(kpi["ratio"]))
        check("qps=0.3333", kpi["qps"] == 0.3333, str(kpi["qps"]))
        check("P50=100", lat["request_p50_ms"] == 100.0, str(lat["request_p50_ms"]))
        check("P95=190", lat["request_p95_ms"] == 190.0, str(lat["request_p95_ms"]))
        check("拒绝耗时均值 300μs", lat["reject_cost_mean_us"] == 300.0, str(lat["reject_cost_mean_us"]))
        check("拒绝耗时 P95 500μs", lat["reject_cost_p95_us"] == 500.0, str(lat["reject_cost_p95_us"]))
        cats = {c["key"]: c["count"] for c in s["categories"]}
        check("分类 SQLi=3 / XSS=1 / CC=1",
              cats.get("SQLi") == 3 and cats.get("XSS") == 1 and cats.get("CC") == 1, str(cats))
        ips = {c["key"]: c["count"] for c in s["top_ips"]}
        check("Top IP 10.0.0.10=3", ips.get("10.0.0.10") == 3, str(ips))

    print("== 4. 趋势与最近事件 ==")
    st, t = call("/api/stats/trend?from=%d&to=%d&bucket_s=10" % (F20_FROM, F20_TO), token)
    check("trend 200", st == 200, "实际 %s" % st)
    if st == 200:
        points = t["points"]
        total_n = sum(p["n"] for p in points)
        total_b = sum(p["b"] for p in points)
        # F20 是 20 条 1 秒间隔的访问，跨 20 秒；10 秒一个桶正好 2 个，每桶 10 条
        check("trend 覆盖 2 个 10 秒桶", len(points) == 2, "实际 %d 个" % len(points))
        check("trend 每桶访问数均匀", all(p["n"] == 10 for p in points), str([p["n"] for p in points]))
        check("trend 访问总数 20", total_n == 20, str(total_n))
        check("trend 拦截总数 5", total_b == 5, str(total_b))

    # 越界参数应返回 400 而不是 500
    st, _ = call("/api/stats/trend?bucket_s=1", token)
    check("bucket_s 越界返回 400", st == 400, "实际 %s" % st)

    st, r = call("/api/stats/recent?limit=8", token)
    check("recent 200", st == 200, "实际 %s" % st)
    if st == 200:
        # recent 是「全局最近 N 条」，不随窗口变；库里多于 8 条时返回 8 条才对。
        # 早先写死 ==5 只在 F20 独占库时成立，加了真实流量后就成了假失败。
        check("recent 返回 1–8 条且含 rule_name",
              1 <= len(r["items"]) <= 8 and all("rule_name" in x for x in r["items"]),
              "实际 %d 条" % len(r["items"]))

    print("== 5. 事件接口 ==")
    st, e = call("/api/events?from=%d&to=%d&page_size=2&page=1" % (F20_FROM, F20_TO), token)
    check("事件列表 200", st == 200, "实际 %s" % st)
    if st == 200:
        check("total=5、本页 2 条", e["total"] == 5 and len(e["items"]) == 2,
              "total=%s items=%d" % (e["total"], len(e["items"])))
        check("返回体含 items/total/page/page_size/as_of",
              all(k in e for k in ("items", "total", "page", "page_size", "as_of")))
    st, e2 = call("/api/events?ip=10.0.0.10", token)
    check("按 IP 过滤得 3 条", st == 200 and e2["total"] == 3,
          "状态 %s total=%s" % (st, (e2 or {}).get("total")))
    st, _ = call("/api/events/999999", token)
    check("不存在的事件 404", st == 404, "实际 %s" % st)
    st, inj = call("/api/events?uri=%3Cscript%3E", token)
    check("URI 脚本标签只作文本（查不到、不报错）", st == 200 and inj["total"] == 0)

    print("== 6. 权限 ==")
    st, v = call("/api/auth/login", method="POST",
                 payload={"username": "viewer", "password": "Viewer@2026"})
    vtoken = (v or {}).get("token")
    check("viewer 登录 200", st == 200)
    st, _ = call("/api/events?page_size=1", vtoken)
    check("viewer 读事件 200", st == 200, "实际 %s" % st)
    st, _ = call("/api/rules", vtoken, method="POST", payload={})
    check("viewer 写接口 403", st == 403, "实际 %s" % st)

    finish()


def finish():
    print("\n== 汇总 ==")
    total = len(results)
    passed = sum(1 for _, ok, _ in results if ok)
    print("%d/%d 通过" % (passed, total))
    if passed != total:
        print("失败项：")
        for name, ok, detail in results:
            if not ok:
                print("  - %s（%s）" % (name, detail))
        sys.exit(1)


if __name__ == "__main__":
    main()
