#!/usr/bin/env python3
"""
F20 固定数据集校验（S2 / R33-07 的验收锚点）。

做的事：
  1. 清空采集相关表，把 fixtures/f20 复制到采集器读取的固定目录
  2. 跑一遍采集器（--once）
  3. 断言数据库里的数字与卡片第七节完全一致：20 条访问、5 条拦截、SQLi 3 / XSS 1 / CC 1
  4. 再跑一遍采集器，断言行数不变（游标 + 去重键生效，不会重复入库）

为什么单独写：F20 是整条链路唯一"冻结"的数据集，界面、接口、图表、告警都用它对齐，
任何一个环节改了口径，这里会第一个报警。

用法：python3 platform/collector/verify_f20.py
退出码：0 通过 / 1 不通过
"""
import atexit
import configparser
import json
import os
import shutil
import subprocess
import sys
import time

import pymysql

HERE = os.path.dirname(os.path.abspath(__file__))
SHARE = os.environ.get("LITEWAF_SHARE", "/mnt/hgfs/share")
FIXTURE_SRC = os.path.join(SHARE, "WAF-lite", "fixtures", "f20")
FIXTURE_DST = "/opt/litewaf/platform/fixtures/f20"
CONFIG = os.path.join(HERE, "config.fixture.ini")
COLLECTOR = os.path.join(HERE, "lwaf_collect.py")


def load_db():
    cfg = configparser.ConfigParser()
    cfg.read(CONFIG, encoding="utf-8")
    return {
        "host": cfg.get("db", "host"),
        "port": cfg.getint("db", "port"),
        "user": cfg.get("db", "user"),
        "password": cfg.get("db", "password"),
        "database": cfg.get("db", "database"),
        "charset": "utf8mb4",
        "autocommit": True,
        "ssl_disabled": True,  # MariaDB 11.8 默认要 TLS，本机走 socket 直连
    }


def run_collector():
    r = subprocess.run([sys.executable, COLLECTOR, "--config", CONFIG, "--once"],
                       capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        raise SystemExit("采集器执行失败：\n%s\n%s" % (r.stdout[-800:], r.stderr[-800:]))
    return r.stdout


def main():
    fails = []

    # 0) 常驻采集器会一边盯 runtime/logs 一边往 requests/waf_events 里塞新行，
    #    而本校验要断言"只有 20 条"。所以被 s7_accept.sh 调用时（PAUSE_COLLECTOR=1）
    #    先把常驻采集器 SIGSTOP 挂起，测完再 SIGCONT 放回去——不杀进程，游标不丢。
    paused = False
    if os.environ.get("LITEWAF_PAUSE_COLLECTOR") == "1":
        r = subprocess.run(["pkill", "-STOP", "-f", "lwaf_collect.py"],
                           capture_output=True, text=True)
        paused = r.returncode == 0
        # 无论后面断言怎么退出，都必须把采集器放回去，否则线上就"停更"了
        atexit.register(lambda: subprocess.run(
            ["pkill", "-CONT", "-f", "lwaf_collect.py"], capture_output=True))
        time.sleep(0.3)

    # 1) 准备固定目录：采集器只认 /opt/litewaf/platform/fixtures/f20
    os.makedirs(FIXTURE_DST, exist_ok=True)
    for name in ("access.log", "reject.log"):
        shutil.copyfile(os.path.join(FIXTURE_SRC, name), os.path.join(FIXTURE_DST, name))

    db = load_db()
    conn = pymysql.connect(**db)
    cur = conn.cursor()
    # 清干净，避免上一次残留影响计数
    for t in ("requests", "waf_events", "ingest_errors", "ingest_cursors"):
        cur.execute("TRUNCATE TABLE %s" % t)
    conn.commit()

    # 2) 第一遍采集
    run_collector()

    # 3) 断言
    cur.execute("SELECT COUNT(*) FROM requests")
    n = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM waf_events")
    b = cur.fetchone()[0]
    cur.execute("SELECT category_display, COUNT(*) FROM waf_events GROUP BY category_display")
    by_cat = dict(cur.fetchall())
    cur.execute("SELECT COALESCE(SUM(body_bytes_sent),0) FROM requests")
    body = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM ingest_errors")
    errs = cur.fetchone()[0]

    def expect(name, got, want):
        if got != want:
            fails.append("%s: 期望 %s，实际 %s" % (name, want, got))

    expect("访问记录数", n, 20)
    expect("拦截事件数", b, 5)
    expect("SQLi 条数", by_cat.get("SQLi", 0), 3)
    expect("XSS 条数", by_cat.get("XSS", 0), 1)
    expect("CC 条数", by_cat.get("CC", 0), 1)
    expect("响应体合计", int(body), 20000)
    expect("解析错误行数", errs, 0)

    # 4) 再采一遍：游标已到文件末尾，不应新增任何行
    run_collector()
    cur.execute("SELECT COUNT(*) FROM requests")
    n2 = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM waf_events")
    b2 = cur.fetchone()[0]
    expect("二次采集后访问记录数（幂等）", n2, 20)
    expect("二次采集后拦截事件数（幂等）", b2, 5)

    if fails:
        print("F20 FAIL")
        for f in fails:
            print("  - " + f)
        cur.close()
        conn.close()
        if paused:
            subprocess.run(["pkill", "-CONT", "-f", "lwaf_collect.py"])
        return 1

    print("F20 PASS  n=20 b=5 ratio=25.0% SQLi=3 XSS=1 CC=1 body=20000 幂等重跑 20/5")
    cur.close()
    conn.close()
    if paused:
        subprocess.run(["pkill", "-CONT", "-f", "lwaf_collect.py"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
