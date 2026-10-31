#!/usr/bin/env python3
"""
生成性能测试用的大日志文件（纯 access 行，M4 格式，非 JSON）。

用途：验收卡片 10.1 的公共门槛——10 万行数据下首页聚合 P95 ≤ 2 秒、
检索 P95 ≤ 3 秒。数据全是正常请求（status=200），不产生 waf_events。

用法：
    python3 gen_big.py /tmp/lwaf_big/access.log 120000

参数：
    第 1 个：输出文件路径（默认 /tmp/lwaf_big/access.log）
    第 2 个：行数（默认 120000）

固定起点 1789862400000 = 2026-09-20T00:00:00Z，行间隔 100ms，
因此 12 万行覆盖约 3.3 小时，方便按窗口切片查询。
"""
import os
import sys

out = sys.argv[1] if len(sys.argv) > 1 else "/tmp/lwaf_big/access.log"
lines = int(sys.argv[2]) if len(sys.argv) > 2 else 120000
base = 1789862400000
step_ms = 100

os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "w", encoding="utf-8", newline="\n") as f:
    for i in range(lines):
        f.write(
            '{"time":%d,"remote_addr":"10.1.0.%d","method":"GET",'
            '"uri":"/p%d","status":200,"body_bytes_sent":1000}\n'
            % (base + i * step_ms, (i % 250) + 1, i % 50)
        )

print("生成完成：%s（%d 行）" % (out, lines))
