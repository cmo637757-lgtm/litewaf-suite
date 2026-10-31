#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 s8_eval.py 的冻结样本从 80 条扩到 200 条（v3 对抗样本集）。

为什么单独用脚本改而不是手写：
  Windows 侧直接编辑会把文件写成 CRLF，Kali 里 bash 跑 python 时 shebang 和
  多行字符串都可能出问题；这里统一用 newline='\\n' 写回，保住 LF。

扩样本的逻辑（对应 2026-10-22 的决定）：
  SQLi 20→50：补注释拆词、换行/制表分隔、编码、非标准恒真、堆叠查询；
  XSS  20→50：补非 script 载体（svg/math/iframe/base）、data URI、CSS/DOM 汇点；
  正常 40→100：专门塞「含 SQL 关键字/尖括号/注释但确实是正常业务」的请求，
              用来压误报率——只有误报没涨，检出提升才算真提升。
"""
import io
import re

PATH = r"D:\网安综设\scripts\s8_eval.py"

SQLI_ADD = [
    # ---- v3 对抗变体：注释拆词 / 换行制表分隔 / 编码 / 非标准恒真 / 堆叠 ----
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

XSS_ADD = [
    # ---- v3 对抗变体：非 script 载体 / data URI / CSS 与 DOM 汇点 ----
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

NORMAL_ADD = [
    # ---- v3 误报压力样本：含关键字/尖括号/注释，但都是正常业务参数 ----
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
    "/?q=" + "x" * 200,
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
    # 一个干净的 body 请求：正常 POST 表单（不带任何危险字符）
    "/feedback?name=alice&message=great+site",
]


def render(items):
    return "\n".join('    "%s",' % s.replace('"', '\\"') for s in items)


def main():
    with io.open(PATH, "r", encoding="utf-8") as f:
        src = f.read()

    def insert_after(anchor, items, label):
        nonlocal src
        if anchor not in src:
            raise SystemExit("锚点没找到：" + label)
        head = src.index(anchor) + len(anchor)
        # 锚点行本身以 ",\n" 结尾，新条目直接接在它后面、列表闭合的 "]" 之前
        tail = src[head:]
        close = tail.index("\n]")
        new = "\n" + render(items)
        src = src[:head] + new + tail[close:]
        print("  %s +%d" % (label, len(items)))

    insert_after('    "/?id=1 /*!50000UNION*/ SELECT 1",', SQLI_ADD, "SQLI")
    insert_after('    "/?q=<script src=//evil.example/x.js></script>",', XSS_ADD, "XSS")
    insert_after('    "/?lang=zh-CN", "/?utm_source=newsletter&utm_medium=email",',
                 NORMAL_ADD, "NORMAL")

    with io.open(PATH, "w", encoding="utf-8", newline="\n") as f:
        f.write(src)

    # 自检：数一下每个列表的条目
    for name in ("SQLI", "XSS", "NORMAL"):
        m = re.search(r"^%s = \[(.*?)^\]" % name, src, re.S | re.M)
        print("%s 现在 %d 条" % (name, m.group(1).count('",')))


if __name__ == "__main__":
    main()
