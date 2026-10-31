#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 fp_marks.sql 应用到 litewaf 库。"""
import sys
sys.path.insert(0, "/mnt/hgfs/share/scripts")
from db_query import CONF  # noqa: E402

import pymysql  # noqa: E402

SQL = open("/mnt/hgfs/share/platform/backend/src/main/resources/sql/fp_marks.sql", encoding="utf-8").read()

# 先剥掉整行注释再按 ; 切段：否则第一段是"-- 注释\nCREATE TABLE ..."，
# 开头就是 -- 会把整段（含建表语句）一起误过滤掉。
BODY = "\n".join(ln for ln in SQL.splitlines() if not ln.strip().startswith("--"))

conn = pymysql.connect(**CONF)
try:
    with conn.cursor() as cur:
        for stmt in [s.strip() for s in BODY.split(";") if s.strip()]:
            cur.execute(stmt)
    conn.commit()
    print("OK: false_positive_marks 已就绪")
finally:
    conn.close()
