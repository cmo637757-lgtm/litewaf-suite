#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LiteWAF 数据库小工具（只读 + 执行 SQL）

为什么要这个：
  Kali 里的 `mariadb` 命令行客户端在 ssh / sudo -S 组合下参数和引号很容易被 shell 吃掉，
  换成 Python + pymysql 就绕开了所有引号地狱（本项目其他脚本也统一走 pymysql）。

用法：
  python3 db_query.py "show tables"
  python3 db_query.py "select count(*) from waf_events"
  echo "show tables" | python3 db_query.py
  python3 db_query.py --file /path/to/x.sql     # 整段 SQL（多条用 ; 分隔）

注意：
  MariaDB 11.8 的 pymysql 连接要显式 ssl_disabled=True，否则握手报
  TLSV1_ALERT_INTERNAL_ERROR（见 docs 里的踩坑记录）。
"""
import sys

import pymysql

CONF = dict(
    host="127.0.0.1",
    port=3306,
    user="litewaf",
    password="LiteWaf@2026",
    database="litewaf",
    charset="utf8mb4",
    ssl_disabled=True,
    autocommit=True,
)


def run(conn, sql: str) -> None:
    """执行一段可能含多条语句的 SQL，SELECT 类的打印表格，其余打印影响行数。"""
    statements = [s.strip() for s in sql.split(";") if s.strip()]
    with conn.cursor() as cur:
        for stmt in statements:
            cur.execute(stmt)
            if cur.description:
                cols = [d[0] for d in cur.description]
                rows = cur.fetchall()
                print("\t".join(cols))
                for row in rows:
                    print("\t".join("" if v is None else str(v) for v in row))
                print(f"-- {len(rows)} row(s)")
            else:
                print(f"-- ok, affected={cur.rowcount}")


def main() -> int:
    args = sys.argv[1:]
    if not args:
        sql = sys.stdin.read()
    elif args[0] == "--file":
        with open(args[1], encoding="utf-8") as f:
            sql = f.read()
    else:
        sql = " ".join(args)
    if not sql.strip():
        print("用法：db_query.py \"<sql>\" 或 db_query.py --file <path>", file=sys.stderr)
        return 2
    conn = pymysql.connect(**CONF)
    try:
        run(conn, sql)
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
