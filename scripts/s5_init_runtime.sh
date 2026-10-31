#!/usr/bin/env bash
# s5_init_runtime.sh — 建「可发布」的运行时目录，并启动受管 nginx 实例
#
# 为什么要单独一套 runtime：
#   S0 起的实例把 rule_file 指向源码目录 /opt/litewaf/src/WAF-lite/conf/…，
#   那是"开发目录"，不能当线上配置改。发布必须改一个独立位置，才能做版本与回退。
#
# 目录结构：
#   /opt/litewaf/runtime/
#     conf/nginx.conf            主配置（rule_file 指向下面的 current 文件）
#     rules/litewaf_rules.conf   当前生效规则（发布时整体替换）
#     versions/<id>/…            每个版本的规则副本 + manifest.json
#     candidates/<id>.conf       待发布候选（check 通过但还没 publish）
#     current  previous          两个指针文件，内容为版本 id
#     logs/                      access / error / waf_audit
#
# 用法：sudo bash /mnt/hgfs/share/scripts/s5_init_runtime.sh
set -euo pipefail

RT=/opt/litewaf/runtime
NGINX_BIN=/opt/litewaf/build/nginx-check/nginx-1.24.0/objs/nginx
SRC_RULES=/opt/litewaf/src/WAF-lite/conf/litewaf_rules.conf
PORT=18010

ng() { echo; echo "==> $*"; }
die() { echo "[FAIL] $*" >&2; exit 1; }

[[ -x "$NGINX_BIN" ]] || die "找不到 nginx 二进制 $NGINX_BIN（先跑 s0_build.sh）"
[[ -f "$SRC_RULES" ]] || die "找不到源码规则文件 $SRC_RULES"

ng "1/5 建目录"
mkdir -p "$RT"/{conf,rules,versions,candidates,logs}
# nginx 以 root 起主进程、nobody 跑 worker，temp 目录要 everyone 可写
chmod 755 "$RT"
chmod 777 "$RT"/{logs,client_body_temp,proxy_temp,fastcgi_temp,uwsgi_temp,scgi_temp} 2>/dev/null || true

# 源站页面：nginx.conf 里 root 是相对 prefix 的 html 目录，缺了会 500
mkdir -p "$RT/html"
if [[ ! -f "$RT/html/index.html" ]]; then
  cp -r /opt/litewaf/build/nginx-check/runtime/html/. "$RT/html/" 2>/dev/null || true
  [[ -f "$RT/html/index.html" ]] || printf '<!doctype html><meta charset=utf-8><h1>LiteWAF 受保护站点</h1>\n' > "$RT/html/index.html"
fi
chmod -R a+r "$RT/html"

ng "2/5 生成主配置（rule_file 指向 runtime/rules）"
cat > "$RT/conf/nginx.conf" <<EOF
# LiteWAF 运行时主配置（由 s5_init_runtime.sh 生成，不要手改）
# 与 S0 实例的区别只有两处：更长的 error_log 级别、rule_file 指向可发布的 runtime 目录
worker_processes  1;
error_log  logs/error.log notice;
pid        logs/nginx.pid;

events {
    worker_connections  4096;
}

http {
    # 访问日志必须是 JSONL：采集器 parse_access() 按字段名解析，nginx 默认的
    # combined 格式一行都进不了库（S5 初期踩过：636 行全进 ingest_errors）。
    # $msec 是「秒.毫秒」浮点，采集器按数量级自动换算成毫秒。
    log_format lwaf_access escape=json
        '{"time":$msec,"client_ip":"$remote_addr","method":"$request_method",'
        '"uri":"$request_uri","status":$status,'
        '"body_bytes_sent":$body_bytes_sent,"request_time":$request_time}';
    access_log logs/access.log lwaf_access;

    server {
        listen 127.0.0.1:$PORT;

        # 内部探针：发布后用它确认「新规则真的被 worker 加载了」。
        # 该路径不受规则影响、也不计入 CC，只回一段固定文本。
        location = /waf-marker {
            access_log off;
            default_type text/plain;
            return 200 "litewaf-ok\n";
        }

        location / {
            lite_waf on;
            lite_waf_trust_proxy off;
            lite_waf_deny_status 403;
            lite_waf_rule_file $RT/rules/litewaf_rules.conf;
            lite_waf_score_threshold SQL 8;
            lite_waf_score_threshold XSS 8;
            lite_waf_score_threshold RFI 8;
            lite_waf_score_threshold TRAVERSAL 8;
            lite_waf_score_threshold EVADE 8;
            lite_waf_score_threshold UPLOAD 8;
            lite_waf_score_threshold SCAN 8;
            lite_waf_score_threshold TOTAL 12;
            lite_waf_dynamic_block on;
            lite_waf_max_requests 20;
            lite_waf_window 10;
            lite_waf_block_duration 60;
            lite_waf_log_path $RT/logs/waf_audit.log;
            root html;
            index index.html;
            try_files \$uri /index.html;
        }
    }
}
EOF
echo "    [OK] $RT/conf/nginx.conf"

ng "3/5 建立初始版本 v1"
if [[ ! -f "$RT/current" ]]; then
  mkdir -p "$RT/versions/v1"
  cp "$SRC_RULES" "$RT/versions/v1/litewaf_rules.conf"
  HASH=$(sha256sum "$RT/versions/v1/litewaf_rules.conf" | cut -d' ' -f1)
  cat > "$RT/versions/v1/manifest.json" <<EOF
{
  "version": "v1",
  "kind": "bootstrap",
  "hash": "$HASH",
  "created_at": "$(date -Iseconds)",
  "created_by": "s5_init_runtime.sh",
  "note": "从源码 conf/litewaf_rules.conf 建立基线"
}
EOF
  cp "$RT/versions/v1/litewaf_rules.conf" "$RT/rules/litewaf_rules.conf"
  echo v1 > "$RT/current"
  echo v1 > "$RT/previous"
  echo "    [OK] v1 已建立 hash=$HASH"
else
  echo "    [SKIP] 已有 current=$(cat "$RT/current")"
fi

ng "4/5 启动 nginx（prefix=$RT）"
"$NGINX_BIN" -p "$RT" -c conf/nginx.conf -t
"$NGINX_BIN" -p "$RT" -c conf/nginx.conf -s quit >/dev/null 2>&1 || true
sleep 1
"$NGINX_BIN" -p "$RT" -c conf/nginx.conf
sleep 1
ss -lntp 2>/dev/null | grep -q ":$PORT" || die ":$PORT 没起来，看 $RT/logs/error.log"

ng "5/5 冒烟：正常 200 / SQLi 403 / 探针 200"
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36'
normal=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "http://127.0.0.1:$PORT/index.html")
sqli=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "http://127.0.0.1:$PORT/?id=1%20UNION%20SELECT%20password%20FROM%20users")
marker=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/waf-marker")
echo "    正常=$normal（期望 200） SQLi=$sqli（期望 403） marker=$marker（期望 200）"
[[ "$normal" == "200" && "$sqli" == "403" && "$marker" == "200" ]] || die "冒烟失败"

echo
echo "==> runtime 就绪：$RT（端口 $PORT）"
echo "    停止：sudo $NGINX_BIN -p $RT -c conf/nginx.conf -s quit"
