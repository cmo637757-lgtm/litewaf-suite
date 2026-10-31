#!/usr/bin/env bash
# S3 统计接口性能测试：10 万行数据下的响应时间
# 验收口径：卡片 10.1 —— 首页聚合 P95 ≤ 2 秒
set -u

URL=http://127.0.0.1:18080/api/stats/summary
FROM=1789862400000
TO=1789866000000

echo "--- 首查结果（N 应为 36000：1 小时窗口 / 100ms 一条）---"
curl -s "$URL?from=$FROM&to=$TO" | head -c 400
echo
echo "--- 20 次计时 ---"
for i in $(seq 1 20); do
    curl -s -o /dev/null -w '%{time_total}\n' "$URL?from=$FROM&to=$TO"
done | sort -n | awk '{a[NR]=$1} END{printf "n=%d min=%.3fs p50=%.3fs p95=%.3fs max=%.3fs\n", NR, a[1], a[int(NR/2)], a[int(NR*0.95)], a[NR]}'

echo "--- 连续 5 次，看缓存热了之后的稳定值 ---"
for i in $(seq 1 5); do
    curl -s -o /dev/null -w '%{time_total}\n' "$URL?from=$FROM&to=$TO"
done
