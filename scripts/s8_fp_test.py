#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
R34-10 误报标记与调优闭环的接口测试。

跑法：python3 s8_fp_test.py
前置：后端在 18080、库里有 F20（5 条拦截事件，id 1..5）

覆盖卡片 AC：
  * 三个指标分开算，不能混口径
  * 重复标记同一事件只覆盖判定（不新增行）
  * 事件不存在 → 404；decision 非法 → 400
  * viewer 能读不能写；未登录 401
  * 撤销标记后指标回落
"""
import json
import sys
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:18080"
F20_FROM, F20_TO = 1789862400000, 1789862460000

RESULTS = []


def call(method, path, body=None, token=None, expect=None):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read().decode("utf-8")
            payload = json.loads(raw) if raw else None
            return r.status, payload
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8")
        try:
            payload = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            payload = raw
        return e.code, payload


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print(("  PASS  " if cond else "  FAIL  ") + name + ("  " + str(detail) if detail and not cond else ""))


def login(user, pwd):
    st, body = call("POST", "/api/auth/login", {"username": user, "password": pwd})
    if st != 200:
        print(f"登录失败 {user}: {st} {body}")
        sys.exit(2)
    return body["token"]


def metrics(token, frm=None, to=None):
    q = f"/api/fp/metrics?from={frm}&to={to}" if frm else "/api/fp/metrics"
    st, m = call("GET", q, token=token)
    return st, m


def main():
    print("== R34-10 误报标记测试 ==")

    st, _ = call("GET", "/api/fp/metrics")
    check("未登录读指标 → 401", st == 401, f"得到 {st}")

    admin = login("admin", "LiteWaf@2026")
    viewer = login("viewer", "Viewer@2026")

    # 先清掉上一次跑留下的标记：这个用例断言的是「从零开始」的计数，
    # 不清的话第二次跑就会看到 confirmed=1，前面几条断言全部假失败。
    import pymysql
    conn = pymysql.connect(host="127.0.0.1", user="litewaf", password="LiteWaf@2026",
                           database="litewaf", ssl_disabled=True, autocommit=True)
    with conn.cursor() as cur:
        cur.execute("DELETE FROM false_positive_marks WHERE event_id IN "
                    "(SELECT id FROM waf_events WHERE event_time_ms BETWEEN %s AND %s)",
                    (F20_FROM, F20_TO))
    conn.close()
    print("  （已清空 F20 窗口的历史标记）")

    st, m = metrics(admin, F20_FROM, F20_TO)
    check("F20 窗口全部拦截数=5", st == 200 and m["total"] == 5, f"{st} {m}")
    check("初始无复核：confirmed=0 且覆盖率=0", m["confirmed"] == 0 and m["coverage_ratio"] == 0)

    # 卡片 R34-10 AC02 的场景：5 拒绝中 1 确认 2 驳回 2 未复核
    st, mk = call("POST", "/api/events/1/mark", {"decision": "confirmed", "remark": "这是正常搜索参数"}, token=admin)
    check("标记事件 1 为确认误报", st == 200 and mk["decision"] == "confirmed", f"{st} {mk}")
    check("标记记录了操作人", mk.get("operator") == "admin", mk.get("operator"))

    st, m = metrics(admin, F20_FROM, F20_TO)
    check("confirmed=1", m["confirmed"] == 1, m)
    # 1/5 = 20%
    check("已确认误拦占全部拦截=20%", abs(m["confirmed_ratio"] - 0.2) < 1e-6, m["confirmed_ratio"])
    # 1/1 = 100%
    check("已复核误拦占比=100%（只复核了这 1 条）", abs(m["reviewed_fp_ratio"] - 1.0) < 1e-6, m["reviewed_fp_ratio"])

    st, _ = call("POST", "/api/events/2/mark", {"decision": "rejected", "remark": "真 union 注入"}, token=admin)
    st2, _ = call("POST", "/api/events/3/mark", {"decision": "rejected"}, token=admin)
    check("再标记两条驳回", st == 200 and st2 == 200)

    st, m = metrics(admin, F20_FROM, F20_TO)
    check("confirmed=1 rejected=2", m["confirmed"] == 1 and m["rejected"] == 2, m)
    check("复核覆盖率=60%", abs(m["coverage_ratio"] - 0.6) < 1e-6, m["coverage_ratio"])
    check("已复核误拦占比=33.33%", abs(m["reviewed_fp_ratio"] - 0.3333) < 0.001, m["reviewed_fp_ratio"])
    check("未复核=2", m["unreviewed"] == 2, m["unreviewed"])

    # 重复标记：同一事件改判，不应新增行
    st, mk = call("POST", "/api/events/1/mark", {"decision": "rejected", "remark": "复查后确认是真攻击"}, token=admin)
    check("重复标记覆盖判定", st == 200 and mk["decision"] == "rejected", f"{st} {mk}")
    st, m = metrics(admin, F20_FROM, F20_TO)
    check("改判后 confirmed=0 rejected=3", m["confirmed"] == 0 and m["rejected"] == 3, m)
    check("改判后已复核误拦占比=0", m["reviewed_fp_ratio"] == 0, m["reviewed_fp_ratio"])
    check("确认比例=0（分母仍是 5）", m["confirmed_ratio"] == 0 and m["total"] == 5)

    st, body = call("POST", "/api/events/999999/mark", {"decision": "confirmed"}, token=admin)
    check("不存在的事件 → 404", st == 404, f"{st} {body}")

    st, body = call("POST", "/api/events/1/mark", {"decision": "maybe"}, token=admin)
    check("decision 非法 → 400", st == 400, f"{st} {body}")

    st, body = call("POST", "/api/events/1/mark", {"decision": "confirmed"}, token=viewer)
    check("viewer 写标记 → 403", st == 403, f"{st}")

    st, body = call("GET", "/api/fp/metrics", token=viewer)
    check("viewer 读指标 → 200", st == 200, f"{st}")

    st, mk = call("GET", "/api/events/2/mark", token=viewer)
    check("读单条标记 → 200 且 decision=rejected", st == 200 and mk["decision"] == "rejected", f"{st} {mk}")

    st, page = call("GET", "/api/fp/marks?page=1&page_size=10", token=admin)
    check("标记列表 total=3", st == 200 and page["total"] == 3, f"{st} {page.get('total')}")

    st, page = call("GET", "/api/fp/marks?decision=confirmed", token=admin)
    check("按结论过滤 confirmed=0", st == 200 and page["total"] == 0, f"{st} {page.get('total')}")

    # 撤销，指标回落
    st, _ = call("DELETE", "/api/events/3/mark", token=admin)
    check("撤销标记 → 204", st == 204, f"{st}")
    st, m = metrics(admin, F20_FROM, F20_TO)
    check("撤销后复核覆盖率=40%", abs(m["coverage_ratio"] - 0.4) < 1e-6, m["coverage_ratio"])

    st, body = call("DELETE", "/api/events/3/mark", token=viewer)
    check("viewer 撤销标记 → 403", st == 403, f"{st}")

    # 清理：把测试留下的标记删掉，保证可重复跑
    for eid in (1, 2, 3):
        call("DELETE", f"/api/events/{eid}/mark", token=admin)
    st, m = metrics(admin, F20_FROM, F20_TO)
    check("清理后回到未复核状态", m["confirmed"] == 0 and m["rejected"] == 0, m)

    passed = sum(1 for _, ok, _ in RESULTS if ok)
    total = len(RESULTS)
    print(f"\n{passed}/{total} 通过")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
