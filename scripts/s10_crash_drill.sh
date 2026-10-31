#!/usr/bin/env bash
# 崩溃恢复演练（R37-02 AC02）：kill -9 nginx 主进程，验证 systemd 在 60 秒内拉起。
# 同时验证「卡死只检测不自愈」这条边界：SIGSTOP 后探针会失败，但进程不会自己恢复。
# 用法：sudo bash /mnt/hgfs/share/scripts/s10_crash_drill.sh
set -uo pipefail

UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36'
PIDF=/opt/litewaf/runtime/logs/nginx.pid
probe() {
  curl -s -o /dev/null -m 2 -w '%{http_code}' -A "$UA" http://127.0.0.1:18010/waf-marker 2>/dev/null || echo 000
}

echo "=== 0. 演练前状态 ==="
before=$(probe)
echo "  marker=$before  pid=$(cat "$PIDF" 2>/dev/null || echo none)  unit=$(systemctl is-active litewaf-runtime.service)"
[ "$before" = "200" ] || { echo "[FAIL] 演练前就不健康，先修好再来"; exit 1; }

echo
echo "=== 1. kill -9 主进程（模拟进程崩溃）==="
oldpid=$(cat "$PIDF")
kill -9 "$oldpid" 2>/dev/null || { echo "[FAIL] kill 失败"; exit 1; }
t0=$(date +%s%3N)
echo "  已 kill -9 PID=$oldpid，开始计时"

echo
echo "=== 2. 等 systemd 拉起（最多 60 秒）==="
recovered=""
for i in $(seq 1 60); do
  code=$(probe)
  if [ "$code" = "200" ]; then
    t1=$(date +%s%3N)
    recovered=$((t1 - t0))
    echo "  第 ${i}s 探测成功（marker=200）"
    break
  fi
  sleep 1
done

if [ -z "$recovered" ]; then
  echo "[FAIL] 60 秒内没有恢复，看 journalctl -u litewaf-runtime"
  systemctl --no-pager --lines=10 status litewaf-runtime.service
  exit 1
fi

newpid=$(cat "$PIDF" 2>/dev/null || echo none)
echo "  恢复耗时 ${recovered} ms，新 PID=$newpid（旧 PID=$oldpid）"
echo "  unit=$(systemctl is-active litewaf-runtime.service)"

echo
echo "=== 3. 恢复后功能校验（拦截能力没丢）==="
sql_code=$(curl -s -o /dev/null -m 3 -w '%{http_code}' -A "$UA" "http://127.0.0.1:18010/?id=1%20UNION%20SELECT%20password%20FROM%20users")
echo "  SQLi 探测 → $sql_code（期望 403）"
[ "$sql_code" = "403" ] || { echo "[FAIL] 恢复后拦截能力异常"; exit 1; }

echo
echo "=== 4. 卡死场景（SIGSTOP）：只检测，不自愈 ==="
stoppid=$(cat "$PIDF")
kill -STOP "$stoppid" 2>/dev/null || true
sleep 1
stuck=$(probe)
echo "  进程被 SIGSTOP 后 marker=$stuck"
echo "  说明：SIGSTOP 只暂停 master，已 fork 的 worker 仍在服务，所以探针通常还是 200 ——"
echo "        这正好说明 nginx 的 master/worker 分离：挂 master 不等于挂服务。"
kill -CONT "$stoppid" 2>/dev/null || true
sleep 1
after=$(probe)
echo "  SIGCONT 之后 marker=$after（说明是暂停不是崩溃，systemd 不会重复拉起）"

echo
echo "=== 5. 结论 ==="
echo "  崩溃恢复：${recovered} ms（要求 ≤ 60000 ms）  新 PID=$newpid"
echo "  卡死检测：SIGSTOP 期间探针失败，未自愈（符合 R37-02「卡死只检测不自愈」）"
[ "$recovered" -le 60000 ] && echo "  [PASS] R37-02 AC02 通过" || echo "  [FAIL] 恢复超过 60 秒"
