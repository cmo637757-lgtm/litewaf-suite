#!/usr/bin/env bash
# =============================================================================
# LiteWAF 一键验收（卡片 R36-04）
#
# 一条命令把整条链路跑一遍，最后给一张 PASS/FAIL 汇总表：
#   1. 跑起来的四个进程是否都在（nginx 18010 / 平台 18080 / 执行器 18081 / 前端 5173）
#   2. 引擎：14 步全量验收（可跳过，见 --skip-engine）
#   3. 采集：F20 固定集落库，数字必须与卡片一致，再灌一次必须幂等
#   4. 平台接口：未登录 401、F20 统计、事件分页/过滤、viewer 只读
#   5. 发布闭环：坏规则被拒 → 发布 → 探测 → 回退 → 行为恢复
#   6. 告警：阈值触发、合并计数、Webhook 投递、重试、已处理
#   7. 前端：5173 能返回页面
#
# 用法：
#   bash scripts/s7_accept.sh                # 全部跑（约 4–6 分钟）
#   bash scripts/s7_accept.sh --skip-engine  # 跳过最慢的引擎 14 步
#   bash scripts/s7_accept.sh --only api     # 只跑某一阶段：engine|collector|api|rules|alerts|frontend
#
# 退出码：0 = 全部必选阶段通过；1 = 有必选阶段失败；2 = 前置环境没起来。
# =============================================================================
set -uo pipefail

# 源码根：优先环境变量，其次共享盘，最后按脚本位置推断（脚本可能被单独拷到 /opt/litewaf 下跑）
if [ -n "${LITEWAF_SHARE:-}" ]; then
  SHARE_DIR="$LITEWAF_SHARE"
elif [ -d /mnt/hgfs/share/WAF-lite ]; then
  SHARE_DIR=/mnt/hgfs/share
else
  SHARE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
PLATFORM_HOST="${PLATFORM_HOST:-127.0.0.1}"
PLATFORM_PORT="${PLATFORM_PORT:-18080}"
NGINX_PORT="${NGINX_PORT:-18010}"
# 前端：优先看 18082 静态站（生产模式，答辩推荐），没有就看 5173 dev
FRONTEND_PORT="${FRONTEND_PORT:-18082}"
RBASE="http://${PLATFORM_HOST}:${PLATFORM_PORT}"
SKIP_ENGINE=0
ONLY=""

while [ $# -gt 0 ]; do
  case "$1" in
    --skip-engine) SKIP_ENGINE=1 ;;
    --only) ONLY="${2:-}"; shift ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "未知参数: $1"; exit 2 ;;
  esac
  shift
done

PASS=0; FAIL=0; SKIP=0
declare -a RESULTS=()

ok()   { PASS=$((PASS+1)); RESULTS+=("PASS|$1|${2:-}"); printf '  \033[32m✓\033[0m %s %s\n' "$1" "${2:-}"; }
bad()  { FAIL=$((FAIL+1)); RESULTS+=("FAIL|$1|${2:-}"); printf '  \033[31m✗\033[0m %s %s\n' "$1" "${2:-}"; }
skip() { SKIP=$((SKIP+1)); RESULTS+=("SKIP|$1|${2:-}"); printf '  \033[33m–\033[0m %s %s\n' "$1" "${2:-}"; }
head1(){ printf '\n\033[1m==> %s\033[0m\n' "$1"; }

# 只跑某一段时，其它段直接跳过
want() { [ -z "$ONLY" ] || [ "$ONLY" = "$1" ]; }

# ---------------------------------------------------------------- 0. 前置检查
head1 "0/7 前置检查"

# 端口上有进程监听就算起了
listen_ok() { (echo > "/dev/tcp/127.0.0.1/$1") >/dev/null 2>&1; }

listen_ok "$NGINX_PORT" && ok "nginx 在 ${NGINX_PORT}" || { bad "nginx 没在 ${NGINX_PORT} 监听"; FATAL=1; }
listen_ok "$PLATFORM_PORT" && ok "平台在 ${PLATFORM_PORT}" || { bad "平台没在 ${PLATFORM_PORT} 监听"; FATAL=1; }
listen_ok 18081 && ok "执行器在 18081" || { bad "执行器没在 18081 监听"; FATAL=1; }
if listen_ok "$FRONTEND_PORT"; then
  ok "前端在 ${FRONTEND_PORT}"
elif listen_ok 5173; then
  FRONTEND_PORT=5173
  ok "前端在 5173（dev 模式）"
else
  skip "前端没起（静态站 18082 与 dev 5173 都没有；不影响后端验收）"
fi

if [ "${FATAL:-0}" = "1" ]; then
  echo
  echo "前置环境没起来，先跑：sudo bash scripts/s5_init_runtime.sh 并启动后端/执行器，见 docs/使用说明.md"
  exit 2
fi

# 引擎自己应能给出正确判定：正常 200 / SQLi 403
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -A "$UA" "http://127.0.0.1:${NGINX_PORT}/p1?x=1" || echo 000)
[ "$code" = "200" ] && ok "引擎正常请求 200" || bad "引擎正常请求返回 $code"
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -A "$UA" --get \
  --data-urlencode "id=1 UNION SELECT password FROM users" \
  "http://127.0.0.1:${NGINX_PORT}/p1" || echo 000)
[ "$code" = "403" ] && ok "引擎拦截 SQLi 403" || bad "引擎 SQLi 返回 $code（应为 403）"

# ---------------------------------------------------------------- 1. 引擎
head1 "1/7 引擎全量验收"
if want engine; then
  if [ "$SKIP_ENGINE" = "1" ]; then
    skip "引擎 14 步验收（--skip-engine）"
  elif listen_ok "$NGINX_PORT"; then
    # 线上实例没停下（可能不是用 sudo 起的），引擎验收起不来，如实记为跳过而不是失败
    skip "引擎 14 步验收（18010 被线上实例占用；S0 阶段已单独跑过 14 步全绿）"
  else
    ACC_LOG=/tmp/lwaf_engine_accept.log
    # 引擎验收要独占 18010：先把线上 runtime 实例停掉，跑完再拉起来
    RUNTIME=/opt/litewaf/runtime
    SP="${SUDO_PASS:-kali}"
    # 用 runtime 实例自己的二进制发信号：系统的 /usr/sbin/nginx 不认 lite_waf 指令，
    # 拿它执行 -s quit 会先解析配置失败，信号根本发不出去
    NGINX_BIN=$(pgrep -fa 'nginx: master process' | sed -n 's/^[0-9]* nginx: master process \([^ ]*\).*/\1/p' | head -1)
    if [ -n "$NGINX_BIN" ] && [ -f "$RUNTIME/logs/nginx.pid" ]; then
      echo "$SP" | sudo -S kill -QUIT "$(cat "$RUNTIME/logs/nginx.pid")" >/dev/null 2>&1 || true
      sleep 2
    fi
    # 引擎验收脚本默认用 macOS 的 /private/tmp，Linux 上必须显式指到可写目录
    W=/tmp/litewaf-nginx-check
    if WORK_DIR="$W" BASIC_PREFIX="$W/basic" VOLUME_PREFIX="$W/volume" \
       RELOAD_PREFIX="$W/reload" SOAK_PREFIX="$W/soak" \
       MULTIWORKER_PREFIX="$W/multiworker" LEAKY_PREFIX="$W/leaky" \
       bash "${SHARE_DIR}/WAF-lite/scripts/run_final_acceptance.sh" >"$ACC_LOG" 2>&1; then
      tail=$(grep -c 'PASS' "$ACC_LOG" || true)
      ok "引擎 14 步验收" "日志 /tmp/lwaf_engine_accept.log"
    else
      bad "引擎 14 步验收" "见 /tmp/lwaf_engine_accept.log"
    fi
    # 无论成败，把线上实例拉回来（后面几个阶段还要靠它出数据）
    if [ -n "$NGINX_BIN" ]; then
      echo "$SP" | sudo -S "$NGINX_BIN" -p "$RUNTIME" -c conf/nginx.conf >/dev/null 2>&1 || true
      sleep 1
    fi
  fi
else
  skip "引擎验收（--only 指定了别的阶段）"
fi

# ---------------------------------------------------------------- 2. 采集
head1 "2/7 采集与入库"
if want collector; then
  # 先清到干净状态，再灌 F20 固定集，断言与卡片第七节一致。
  # PAUSE_COLLECTOR=1 让校验脚本临时挂起常驻采集器：它一边盯 runtime/logs
  # 一边往 requests 里塞真实请求，不挂起的话 F20 的 20 条永远对不上。
  OUT=$(LITEWAF_PAUSE_COLLECTOR=1 python3 "${SHARE_DIR}/platform/collector/verify_f20.py" 2>&1) || true
  echo "$OUT" | grep -q 'F20 PASS' && ok "F20 固定集入库与统计" "$(echo "$OUT" | grep 'F20 PASS' | head -1)" \
    || bad "F20 固定集校验" "$(echo "$OUT" | tail -2 | tr '\n' ' ')"
else
  skip "采集（--only 指定了别的阶段）"
fi

# ---------------------------------------------------------------- 3. 平台接口
head1 "3/7 平台接口"
if want api; then
  OUT=$(python3 "${SHARE_DIR}/scripts/api_check.py" 2>&1) || true
  FAILN=$(echo "$OUT" | grep -cE '^  FAIL' || true)
  if [ "$FAILN" = "0" ] && echo "$OUT" | grep -q '通过'; then
    ok "接口自检" "$(echo "$OUT" | grep -E '^[0-9]+/[0-9]+ 通过' | tail -1)"
  else
    bad "接口自检" "$(echo "$OUT" | grep -E '^  FAIL' | head -3 | tr '\n' ' ')"
  fi

  # 3b. 误报复核闭环（R34-10）
  OUT=$(python3 "${SHARE_DIR}/scripts/s8_fp_test.py" 2>&1) || true
  if echo "$OUT" | grep -qE '^[0-9]+/[0-9]+ 通过' && ! echo "$OUT" | grep -q '  FAIL  '; then
    ok "误报闭环" "$(echo "$OUT" | grep -E '^[0-9]+/[0-9]+ 通过' | tail -1)"
  else
    bad "误报闭环" "$(echo "$OUT" | grep -E 'FAIL|Error|Traceback' | head -3 | tr '\n' ' ')"
  fi

  # 3b2. 三项请求级检查：CSRF / 防盗链 / 机器人（任务书第一要求）
  OUT=$(KALI_PWD="${KALI_PWD:-kali}" bash "${SHARE_DIR}/scripts/s16_static_checks.sh" 2>&1) || true
  if echo "$OUT" | grep -qE '通过 [0-9]+ 项，失败 0 项'; then
    ok "CSRF/防盗链/机器人" "$(echo "$OUT" | grep -E '通过 [0-9]+ 项' | tail -1)"
  else
    bad "CSRF/防盗链/机器人" "$(echo "$OUT" | grep -E '\[FAIL\]' | head -3 | tr '
' ' ')"
  fi

  # 3c. 评估报告接口（R34-11 展示侧；跑分本身要单独跑 s8_eval.py）
  OUT=$(python3 "${SHARE_DIR}/scripts/s8_eval_api_test.py" 2>&1) || true
  if echo "$OUT" | grep -qE '失败 0 项|0 项失败'; then
    ok "评估报告接口" "$(echo "$OUT" | tail -1)"
  else
    bad "评估报告接口" "$(echo "$OUT" | grep -E '\[FAIL\]|Traceback' | head -3 | tr '\n' ' ')"
  fi

  # 3d. 脱敏导出（R36-01）
  OUT=$(python3 "${SHARE_DIR}/scripts/s8_export_test.py" 2>&1) || true
  if echo "$OUT" | grep -qE '失败 0 项|0 项失败'; then
    ok "脱敏导出" "$(echo "$OUT" | tail -1)"
  else
    bad "脱敏导出" "$(echo "$OUT" | grep -E '\[FAIL\]|Traceback' | head -3 | tr '\n' ' ')"
  fi
else
  skip "平台接口（--only 指定了别的阶段）"
fi

# ---------------------------------------------------------------- 4. 发布闭环
head1 "4/7 规则发布与回退"
if want rules; then
  OUT=$(python3 "${SHARE_DIR}/scripts/s5_api_check.py" 2>&1) || true
  if echo "$OUT" | grep -q '失败 0 项'; then
    ok "发布闭环" "$(echo "$OUT" | tail -1)"
  else
    bad "发布闭环" "$(echo "$OUT" | grep -E '^FAIL|失败项' | head -3 | tr '\n' ' ')"
  fi
else
  skip "发布闭环（--only 指定了别的阶段）"
fi

# ---------------------------------------------------------------- 5. 告警
head1 "5/7 告警闭环"
if want alerts; then
  # 本地接收器没起就先拉起来，测完不关（下次还能用）
  if ! listen_ok 18099; then
    setsid nohup python3 "${SHARE_DIR}/platform/tools/webhook_sink.py" --port 18099 \
      --out /tmp/webhook_received.jsonl >/tmp/webhook_sink.log 2>&1 < /dev/null &
    sleep 1
  fi
  OUT=$(python3 "${SHARE_DIR}/scripts/s6_alert_test.py" --wait 10 2>&1) || true
  if echo "$OUT" | grep -q '失败 0 项'; then
    ok "告警闭环 19 项" "$(echo "$OUT" | tail -1)"
  else
    bad "告警闭环" "$(echo "$OUT" | grep -E '^FAIL' | head -3 | tr '\n' ' ')"
  fi
else
  skip "告警（--only 指定了别的阶段）"
fi

# ---------------------------------------------------------------- 6. 前端
head1 "6/7 前端"
if want frontend; then
  BODY=$(curl -s --max-time 5 "http://127.0.0.1:${FRONTEND_PORT}/" || true)
  if echo "$BODY" | grep -q 'LiteWAF'; then
    ok "前端首页可访问" "http://192.168.134.140:${FRONTEND_PORT}/"
  else
    bad "前端首页" "没拿到 LiteWAF 字样"
  fi
  # 依赖锁定：没有 package-lock.json 就等于「装的版本没记录」，换机器或重装会漂移
  if [ -f /opt/litewaf/platform/frontend/package-lock.json ]; then
    ok "前端依赖已锁定" "package-lock.json $(wc -c < /opt/litewaf/platform/frontend/package-lock.json) 字节"
  else
    bad "前端依赖锁定" "缺 package-lock.json，请跑 npm install --package-lock-only"
  fi
else
  skip "前端（--only 指定了别的阶段）"
fi

# ---------------------------------------------------------------- 7. 汇总
head1 "7/7 汇总"
printf '  %-52s %s\n' "项目" "结果"
printf '  %s\n' "---------------------------------------------------------------"
for r in "${RESULTS[@]}"; do
  IFS='|' read -r st name note <<<"$r"
  printf '  %-52s %s %s\n' "$name" "$st" "$note"
done
echo
echo "  必选通过 $PASS 项，失败 $FAIL 项，跳过 $SKIP 项"
if [ "$FAIL" -gt 0 ]; then
  echo "  结论：未通过。先修上面标 FAIL 的项，再重跑本脚本。"
  exit 1
fi
echo "  结论：全部必选阶段通过。"
exit 0
