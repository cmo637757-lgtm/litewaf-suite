#!/usr/bin/env python3
"""
生成两个初始账号的 BCrypt 哈希（只算一次，把结果写进 schema-users.sql）。

为什么不在应用启动时用明文口令建库：验收要求「源码无明文固定口令」，
库里和代码里都只出现哈希；初始口令另外交给部署者。
"""
import bcrypt

for name, pw in (("admin", "LiteWaf@2026"), ("viewer", "Viewer@2026")):
    h = bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=10)).decode()
    print("%s\t%s" % (name, h))
