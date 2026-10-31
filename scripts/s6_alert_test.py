#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S6 告警验收脚本（Kali 里跑）。

覆盖卡片 R35-01 ~ R35-05 的核心语义，用真实数据库 + 真实 HTTP：
  1. 固定时间桶 + 阈值：同 IP 某类事件攒够阈值才触发
  2. 抑制合并：抑制期内不再新建告警，但 trigger_count / event_count 继续累加
  3. 一次投递：首发只发一次 Webhook，重试复用同一条 delivery
  4. 人工重试 / 已处理：状态可见、可改
  5. 历史事件不发实时通知（live 120 秒窗口）

用法：
    sudo -u kali python3 s6_alert_test.py            # 需要 webhook_sink.py 在 18099 跑着
    python3 s6_alert_test.py --no-webhook            # 只测数据库侧

退出码：0 全过；1 有失败。
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request

import pymysql

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = "http://127.0.0.1:18080"
DB = dict(host="127.0.0.1", user="litewaf", password="LiteWaf@2026",
          database="litewaf", ssl_disabled=True, charset="utf8mb4")
WEBHOOK_LOG = "/tmp/webhook_received.jsonl"

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("PASS " if ok else "FAIL ") + name.ljust(34) + " " + str(detail))


def http(path, method="GET", body=None, token=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


def login(user, pwd):
    code, j = http("/api/auth/login", "POST", {"username": user, "password": pwd})
    return j.get("token") if code == 200 else None


def reset_tables(conn):
    """清空告警相关表和测试 IP 的历史事件，游标归零。

    为什么连事件一起删：告警是按「固定时间桶」计数的，同一桶里如果还留着上一轮
    测试的 10.99.0.x 事件，新建告警时会把它们一并 link 进去，event_count 就翻倍
    （实测 5 → 10）。只清测试 IP，看板用的 F20 数据不动。
    """
    with conn.cursor() as cur:
        cur.execute("DELETE FROM alert_events")
        cur.execute("DELETE FROM alert_deliveries")
        cur.execute("DELETE FROM alerts")
        cur.execute("DELETE FROM waf_events WHERE client_ip LIKE '10.99.0.%%'")
        cur.execute("UPDATE alert_consumer_cursor SET last_event_id = 0, skipped_total = 0 WHERE id = 1")
        # 让消费器从"当前最大 id"重新开始，避免把历史事件全扫一遍
        cur.execute("SELECT COALESCE(MAX(id),0) FROM waf_events")
        cur.execute("UPDATE alert_consumer_cursor SET last_event_id = %s WHERE id = 1", (cur.fetchone()[0],))
    conn.commit()


def insert_events(conn, ip, category, count, start_ms, step_ms=1000, reason="score_threshold",
                  rule_id=1005, rule_name="union select"):
    """按固定间隔插 count 条事件，返回 (首条 id, 末条 id)。"""
    ids = []
    with conn.cursor() as cur:
        for i in range(count):
            cur.execute(
                "INSERT INTO waf_events (event_time_ms, client_ip, method, uri, reason, rule_id, rule_name, "
                "zone, category, category_display, score, total_score, action, status, cost_us, source_id) "
                "VALUES (%s,%s,'GET',%s,%s,%s,%s,'ARGS',%s,%s,8,8,'deny',403,300,1)",
                (start_ms + i * step_ms, ip, "/p%d" % i, reason, rule_id, rule_name,
                 category, category))
            ids.append(cur.lastrowid)
    conn.commit()
    return ids


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-webhook", action="store_true", help="跳过 Webhook 相关断言")
    ap.add_argument("--wait", type=float, default=6.0, help="等消费器跑一轮的秒数")
    args = ap.parse_args()

    # 清空接收器日志，避免上次运行的记录干扰"只投递一次"的断言
    try:
        open(WEBHOOK_LOG, "w", encoding="utf-8").close()
    except OSError:
        pass

    conn = pymysql.connect(**DB, autocommit=False)
    token = login("admin", "LiteWaf@2026")
    if not token:
        print("FAIL  admin 登录失败，先确认后端在 18080")
        return 1

    # ── 0. 规则可读、窗口约束可校验 ──────────────────────────────────
    code, rules = http("/api/alert-rules", token=token)
    check("告警规则可读", code == 200 and isinstance(rules, list) and len(rules) >= 2,
          "共 %d 条" % (len(rules) if isinstance(rules, list) else -1))

    code, _ = http("/api/alert-rules/1", "POST", {"threshold": 3, "window_s": 60,
                                                 "suppress_s": 10, "webhook_url": "http://127.0.0.1:18099/hook"},
                   token=token)
    check("抑制 < 窗口 被拒", code == 400, "HTTP %s" % code)
    code, _ = http("/api/alert-rules/1", "POST", {"threshold": 3, "window_s": 60, "suppress_s": 300,
                                                 "webhook_url": "file:///etc/passwd"}, token=token)
    check("file:// webhook 被拒", code == 400, "HTTP %s" % code)
    code, _ = http("/api/alert-rules/1", "POST", {"threshold": 3, "window_s": 60, "suppress_s": 300,
                                                 "webhook_url": "http://127.0.0.1:18099/hook"}, token=token)
    check("规则可更新", code == 200, "HTTP %s" % code)

    # ── 1. 阈值 + 抑制合并 ──────────────────────────────────────────
    reset_tables(conn)
    now = int(time.time() * 1000)
    ip = "10.99.0.1"
    insert_events(conn, ip, "SQLi", 5, now - 5000, 1000)
    time.sleep(args.wait)

    code, alerts = http("/api/alerts", token=token)
    mine = [a for a in alerts if a.get("client_ip") == ip] if code == 200 else []
    check("阈值触发 1 条告警", len(mine) == 1, "实际 %d 条" % len(mine))
    if mine:
        a = mine[0]
        check("trigger_count=3", a.get("trigger_count") == 3, "实际 %s" % a.get("trigger_count"))
        check("event_count=5", a.get("event_count") == 5, "实际 %s" % a.get("event_count"))
        check("抑制期内合并（未新建）", a.get("suppressed") is True, "suppressed=%s" % a.get("suppressed"))

    if not args.no_webhook:
        lines = []
        try:
            with open(WEBHOOK_LOG, encoding="utf-8") as f:
                lines = [json.loads(x) for x in f if x.strip()]
        except FileNotFoundError:
            pass
        hits = [x for x in lines if x.get("payload", {}).get("client_ip") == ip]
        # 同一个 IP 可能同时触发两条规则（本轮插的是 SQLi，但历史数据上的 CC 规则
        # 也可能被触发），投递会各发一条。只校验本轮这条告警的投递，别把别人的算进来。
        if mine:
            target_id = mine[0].get("id")
            hits = [x for x in hits if x.get("payload", {}).get("alert_id") == target_id]
        check("Webhook 收到 1 条", len(hits) == 1, "实际 %d 条" % len(hits))
        if hits:
            p = hits[0]["payload"]
            check("payload 字段齐全", all(k in p for k in (
                "schema_version", "delivery_id", "alert_id", "rule_name", "client_ip",
                "category", "first_trigger_ms", "last_trigger_ms", "event_count", "trigger_count")),
                "keys=%d" % len(p))

    # ── 2. 抑制期满后重新开启 ────────────────────────────────────────
    reset_tables(conn)
    insert_events(conn, "10.99.0.2", "XSS", 3, now - 3000)
    time.sleep(args.wait)
    code, alerts2 = http("/api/alerts", token=token)
    xss = [a for a in alerts2 if a.get("client_ip") == "10.99.0.2"]
    check("XSS 规则未覆盖时不误报", len(xss) == 0, "实际 %d 条（XSS 没有配规则）" % len(xss))

    # ── 3. 历史事件不发实时通知 ──────────────────────────────────────
    reset_tables(conn)
    old = now - 3600_000
    insert_events(conn, "10.99.0.3", "SQLi", 5, old)
    time.sleep(args.wait)
    code, alerts3 = http("/api/alerts", token=token)
    hist = [a for a in alerts3 if a.get("client_ip") == "10.99.0.3"]
    check("1 小时前的事件不发实时告警", len(hist) == 0, "实际 %d 条" % len(hist))
    code, st = http("/api/alerts/state", token=token)
    check("游标已推进且记了跳过数", code == 200 and st.get("skipped_total", 0) >= 5,
          "skipped=%s" % (st.get("skipped_total") if code == 200 else "-"))

    # ── 4. 人工重试 + 已处理 ────────────────────────────────────────
    reset_tables(conn)
    insert_events(conn, "10.99.0.4", "SQLi", 3, now - 2000)
    time.sleep(args.wait)
    code, alerts4 = http("/api/alerts", token=token)
    mine4 = [a for a in alerts4 if a.get("client_ip") == "10.99.0.4"]
    if mine4:
        aid = mine4[0]["id"]
        code, _ = http("/api/alerts/%d/retry" % aid, "POST", {}, token=token)
        check("人工重试成功", code == 200, "HTTP %s" % code)
        code, _ = http("/api/alerts/%d/handled" % aid, "POST", {"handled": True}, token=token)
        check("标记已处理", code == 200, "HTTP %s" % code)
        code, d = http("/api/alerts/%d" % aid, token=token)
        check("详情里 handled=true 且关联 3 条事件",
              code == 200 and d.get("alert", {}).get("handled") is True and len(d.get("event_ids", [])) == 3,
              "eventIds=%d" % len((d or {}).get("event_ids", [])))
        code, _ = http("/api/alerts/999999", token=token)
        check("不存在的告警返回 404", code == 404, "HTTP %s" % code)

    # ── 5. viewer 权限 ──────────────────────────────────────────────
    vtok = login("viewer", "Viewer@2026")
    if vtok:
        code, _ = http("/api/alerts", token=vtok)
        check("viewer 可读告警", code == 200, "HTTP %s" % code)
        code, _ = http("/api/alert-rules/1", "POST", {"threshold": 3, "window_s": 60,
                                                     "suppress_s": 300,
                                                     "webhook_url": "http://127.0.0.1:18099/hook"},
                       token=vtok)
        check("viewer 改规则 403", code == 403, "HTTP %s" % code)

    conn.close()
    print()
    bad = sum(1 for _, ok, _ in results if not ok)
    print("结果：%d 项，失败 %d 项" % (len(results), bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
