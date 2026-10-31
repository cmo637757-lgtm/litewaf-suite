# LiteWAF-NGX 产品测试操作手册

更新时间：2026-07-01

本文档用于把 `05_产品测试说明_LiteWAF-NGX.docx` 中的测试体系落实为可执行步骤。测试要求来自 `01_产品总体设计文档_LiteWAF-NGX.docx` 与 `02_产品设计文档_LiteWAF-NGX.docx`：攻击样本应被拦截，正常样本应放行，动态封禁应在阈值后生效，日志应可审计，指标应能计算 TP/TN/FP/FN、检出率、误报率和准确率。

## 1. 测试目标

- 验证 `lite_waf on` 后模块能够在 Nginx `ACCESS_PHASE` 生效。
- 验证 SQLi、RFI、目录穿越、XSS、编码绕过、危险上传扩展名、扫描器 User-Agent 能返回 403。
- 验证 20 条正常样本能返回 200。
- 验证默认漏桶动态封禁策略：桶容量为 20，请求积压超过容量后 `/login` 返回 403，桶会按 `lite_waf_window` 配置逐步泄漏恢复。
- 验证 `logs/test_results.csv` 可用于指标统计。
- 验证 `waf_audit.log` 为合法 JSON Lines，并包含规则、分类、分值、状态码等字段。

## 2. 测试平台

当前已验证平台：

| 项目 | 值 |
| --- | --- |
| 操作系统 | Darwin arm64，内核 25.2.0 |
| Nginx | nginx/1.31.1 |
| Nginx 模块 | `ngx_http_lite_waf_module`，通过 `--add-module` 静态编译 |
| 编译器 | clang 21.0.0 |
| PCRE2 | `/Volumes/MSD/opt/homebrew/opt/pcre2` |
| Docker | Docker 29.5.3，已通过 `docker compose build` 与容器最终验收 |
| 测试工具 | bash、curl、python3 |

课程 Linux 环境可复用同一流程，需将 Nginx 源码路径、PCRE2 路径、监听端口和日志路径替换为实际路径。

## 3. 测试准备

1. 确认分支与工作区。

```bash
git switch dev
git status --short --branch
```

2. 确认关键文件存在。

```bash
test -f conf/litewaf_rules.conf
test -f scripts/run_waf_tests.sh
test -f scripts/calc_metrics.py
test -f ngx_http_lite_waf_module/ngx_http_lite_waf_module.c
```

3. 确认本地工具。

```bash
curl --version
python3 --version
docker --version
```

4. 确认规则集数量。

```bash
rg '^lwaf_rule ' conf/litewaf_rules.conf
```

预期：至少覆盖 SQL、RFI、Traversal、XSS、Evade、Upload、Scanner 等类别。

## 4. 单元测试

执行：

```bash
make test
```

预期输出包含：

```text
PASS: 21 rules loaded; B rule engine matched and scored sample traffic
```

失败处理：

- 若规则加载失败，检查 `conf/litewaf_rules.conf` 语法。
- 若 PCRE2 编译失败，检查正则转义和 PCRE2 开发库路径。
- 若样本未命中，检查对应规则的 `zones`、`score`、`action` 和阈值。

## 5. Nginx 模块构建与配置校验

本机临时 Nginx 源码树路径：

```text
/private/tmp/litewaf-nginx-check/nginx-1.31.1
```

模块构建：

```bash
cd /private/tmp/litewaf-nginx-check/nginx-1.31.1
make -j2
```

配置校验：

```bash
/private/tmp/litewaf-nginx-check/nginx-1.31.1/objs/nginx \
  -p /private/tmp/litewaf-nginx-check/runtime \
  -c conf/nginx.conf \
  -t
```

预期输出：

```text
syntax is ok
test is successful
```

如果需要重建 Nginx，可参考以下配置参数：

```bash
./configure \
  --prefix=/private/tmp/litewaf-nginx-check/install \
  --add-module=/Users/logib/Documents/Codex/WAF_lite/ngx_http_lite_waf_module \
  --with-cc-opt="-I/Volumes/MSD/opt/homebrew/opt/pcre2/include" \
  --with-ld-opt="-L/Volumes/MSD/opt/homebrew/opt/pcre2/lib"
make -j2
```

## 6. 启停临时 Nginx

启动：

```bash
/private/tmp/litewaf-nginx-check/nginx-1.31.1/objs/nginx \
  -p /private/tmp/litewaf-nginx-check/runtime \
  -c conf/nginx.conf
```

停止：

```bash
/private/tmp/litewaf-nginx-check/nginx-1.31.1/objs/nginx \
  -p /private/tmp/litewaf-nginx-check/runtime \
  -c conf/nginx.conf \
  -s quit
```

建议每次跑动态封禁测试前重启 Nginx，避免共享计数状态影响结果。

## 7. 端到端回归测试

执行：

```bash
BASE_URL=http://127.0.0.1:18010 bash scripts/run_waf_tests.sh
```

脚本输出文件：

```text
logs/test_results.csv
```

当前脚本共 65 条记录：

| 分组 | 数量 | 样本类型 | 预期 |
| --- | ---: | --- | --- |
| A001-A020 | 20 | 规则攻击样本 | 403 |
| N001-N020 | 20 | 正常样本 | 200 |
| D001-D020 | 20 | 动态封禁前正常请求 | 200 |
| D021-D025 | 5 | 动态封禁后攻击样本 | 403 |

脚本在攻击样本、正常样本、动态封禁样本之间分别等待 11 秒，让默认漏桶状态充分泄漏，避免前一组请求污染后一组结果。

## 8. 接近生产强度的批量回归与压测

为提高测试强度，当前项目新增独立压测配置与脚本。该配置监听 `18011`，关闭动态封禁，目的是在不被限流逻辑干扰的情况下测试规则检测吞吐、日志写入和正常流量放行能力。动态封禁仍由第 7 节的专项脚本验证。

新增文件：

```text
conf/nginx_litewaf_volume_test.conf
scripts/run_final_acceptance.sh
scripts/run_waf_volume_tests.py
scripts/run_waf_load_tests.sh
```

推荐最终验收入口：

```bash
bash scripts/run_final_acceptance.sh
```

该脚本会自动完成工具检查、Nginx 环境准备、单元测试、Nginx 编译、运行目录准备、`nginx -t`、基础回归、规则 reload 回归、批量回归、真实 POST BODY 回归、4 worker 共享动态封禁回归、ApacheBench 压测、长稳混合流量、JSON Lines 硬性解析和结果汇总。

### 8.0 自动准备 Nginx 环境

执行：

```bash
bash scripts/prepare_nginx_env.sh
```

该脚本会在 `/private/tmp` 下准备 Nginx 1.31.1 源码树、基础回归运行目录、容量回归运行目录、reload 测试运行目录和 soak 测试运行目录，并生成带绝对规则路径和绝对审计日志路径的临时配置。Linux 容器中 Nginx worker 会降权运行，脚本会同步放开临时 `logs/` 目录写权限，保证 JSON Lines 审计日志可写。

### 8.1 规则 reload 自动化测试

执行：

```bash
bash scripts/run_waf_reload_tests.sh
python3 scripts/calc_metrics.py logs/reload_results.csv
```

该脚本监听 `18012`，先确认探针请求放行，再向临时规则文件追加 `litewafreloadprobe` 规则并执行 `nginx -s reload`，确认探针被 403 阻断；随后还原规则文件再次 reload，确认探针恢复 200。当前实测 3/3 通过，TP=1、TN=2、FP=0、FN=0。

### 8.2 准备压测运行目录

```bash
mkdir -p /private/tmp/litewaf-nginx-volume/logs /private/tmp/litewaf-nginx-volume/html
printf 'LiteWAF volume test target\n' > /private/tmp/litewaf-nginx-volume/html/index.html
```

### 8.3 校验并启动压测 Nginx

```bash
/private/tmp/litewaf-nginx-check/nginx-1.31.1/objs/nginx \
  -p /private/tmp/litewaf-nginx-volume \
  -c /Users/logib/Documents/Codex/WAF_lite/conf/nginx_litewaf_volume_test.conf \
  -t

/private/tmp/litewaf-nginx-check/nginx-1.31.1/objs/nginx \
  -p /private/tmp/litewaf-nginx-volume \
  -c /Users/logib/Documents/Codex/WAF_lite/conf/nginx_litewaf_volume_test.conf
```

### 8.4 批量安全样本回归

执行：

```bash
python3 scripts/run_waf_volume_tests.py \
  --base-url http://127.0.0.1:18011 \
  --repeat 10 \
  --output logs/volume_results.csv
```

当前实测：

```text
LiteWAF-NGX volume test: 400/400 passed
```

指标：

```bash
python3 scripts/calc_metrics.py logs/volume_results.csv
```

当前实测结果：

```text
TP: 200
TN: 200
FP: 0
FN: 0
detection_rate: 100.00%
false_positive_rate: 0.00%
accuracy: 100.00%
```

### 8.5 ApacheBench 并发压测

工具检查：

```bash
ab -V
```

当前本机已安装 `/Volumes/MSD/opt/homebrew/bin/ab`，无需 brew 安装。若课程环境缺少该工具，可安装 Apache HTTP Server 工具集：

```bash
export https_proxy=http://127.0.0.1:7897 http_proxy=http://127.0.0.1:7897 all_proxy=socks5://127.0.0.1:7897
brew install httpd
```

执行：

```bash
BASE_URL=http://127.0.0.1:18011 \
REQUESTS=5000 \
CONCURRENCY=50 \
ATTACK_REQUESTS=1000 \
ATTACK_CONCURRENCY=20 \
bash scripts/run_waf_load_tests.sh
```

输出：

```text
logs/load/ab_normal.txt
logs/load/ab_attack.txt
```

当前实测摘要：

| 场景 | 请求数 | 并发 | 失败数 | 结果摘要 |
| --- | ---: | ---: | ---: | --- |
| 正常流量 `/` | 5000 | 50 | 0 | 约 43644 req/s，平均请求耗时 1.146 ms |
| 规则命中 SQLi | 1000 | 20 | 0 | 1000 个非 2xx 阻断，约 35312 req/s，平均请求耗时 0.566 ms |

### 8.6 真实 POST BODY 回归

执行：

```bash
BASE_URL=http://127.0.0.1:18011 \
RESULT_FILE=logs/post_body_results.csv \
bash scripts/run_waf_post_body_tests.sh

python3 scripts/calc_metrics.py logs/post_body_results.csv
```

该测试在关闭动态封禁的 18011 配置上执行，避免限流状态影响 BODY 规则判断。脚本发送表单与 JSON 两类 POST 请求，其中正常请求预期由 Nginx 静态模块返回 405，攻击请求应在 ACCESS_PHASE 被 LiteWAF 提前拦截为 403。

当前实测：8/8 通过，TP=6、TN=2、FP=0、FN=0，覆盖 SQLi、XSS、Traversal、RFI 和 benign form/json body。

### 8.7 多 worker 共享动态封禁回归

执行：

```bash
bash scripts/run_waf_multiworker_tests.sh
python3 scripts/calc_metrics.py logs/multiworker_results.csv
```

该脚本临时生成 `worker_processes 4`、`lite_waf_trust_proxy on`、`lite_waf_max_requests 6` 的 Nginx 配置，使用同一个 `X-Forwarded-For` 客户端 IP 连续访问。前 6 次应返回 200，第 7 至第 10 次应跨 worker 共享计数并返回 403。

当前实测：10/10 通过，TP=4、TN=6、FP=0、FN=0；`/private/tmp/litewaf-nginx-multiworker/logs/waf_audit.log` 中 4 行动态封禁日志均可解析。

### 8.8 漏桶算法回归

执行：

```bash
bash scripts/run_waf_leaky_bucket_tests.sh
python3 scripts/calc_metrics.py logs/leaky_bucket_results.csv
```

该脚本使用 `lite_waf_max_requests 4`、`lite_waf_window 4` 的临时配置。测试先快速发送 4 次请求填满桶，再等待 3 秒让桶泄漏，然后继续发送 3 次请求并期望全部放行，最后再发送 1 次请求触发 403。若实现仍是固定窗口，等待 3 秒后的请求仍会因为同一窗口累计数超限而失败；因此该用例可以区分漏桶与固定窗口。

当前实测：8/8 通过，说明动态封禁使用漏桶而非固定窗口。

### 8.9 长稳混合流量测试

执行：

```bash
SOAK_DURATION=30 \
SOAK_CONCURRENCY=12 \
SOAK_TARGET_RPS=80 \
bash scripts/run_final_acceptance.sh
```

也可单独执行：

```bash
python3 scripts/run_waf_soak_tests.py \
  --base-url http://127.0.0.1:18013 \
  --duration 30 \
  --concurrency 12 \
  --target-rps 80 \
  --output logs/soak_results.csv \
  --summary logs/soak_summary.json
```

当前最终验收实测：30 秒内发送 2400 条混合请求，其中攻击 822 条、正常 1578 条，失败数 0，平均速率约 79.98 req/s。生产化演示或长稳观察时，可将 `SOAK_DURATION` 提升到 1800 秒或更长，并保留同一输出结构。

### 8.10 压测日志检查

```bash
python3 - <<'PY'
import json
from pathlib import Path

path = Path('/private/tmp/litewaf-nginx-volume/logs/waf_audit.log')
count = 0
for line in path.read_text().splitlines():
    if line.strip():
        json.loads(line)
        count += 1
print('volume_json_lines:', count)
PY
```

当前实测：

```text
volume_json_lines: 1212
multiworker_json_lines: 4
leaky_json_lines: 1
soak_json_lines: 822
```

最终验收脚本应以如下输出结束：

```text
FINAL ACCEPTANCE PASSED
```

### 8.11 Docker/CI 自动化复现

Docker 镜像构建：

```bash
export https_proxy=http://127.0.0.1:7897 http_proxy=http://127.0.0.1:7897 all_proxy=socks5://127.0.0.1:7897
docker compose build
```

容器内最终验收：

```bash
docker compose run --rm litewaf-acceptance
```

当前实测：容器内完成 Nginx 编译、基础 65 条、reload 3 条、批量 400 条、POST BODY 8 条、多 worker 10 条、ApacheBench 6000 次、混合流量 2400 条、JSON Lines 日志硬性校验，输出 `FINAL ACCEPTANCE PASSED`。

CI 文件位于 `.github/workflows/ci.yml`，会在 `dev`、`dev_2`、`taska`、`taskb`、`member-c-json-log` 分支 push 或 pull request 时安装依赖并运行 `bash scripts/run_final_acceptance.sh`。

### 8.12 停止压测 Nginx

```bash
/private/tmp/litewaf-nginx-check/nginx-1.31.1/objs/nginx \
  -p /private/tmp/litewaf-nginx-volume \
  -c /Users/logib/Documents/Codex/WAF_lite/conf/nginx_litewaf_volume_test.conf \
  -s quit
```

## 9. 测试数据

### 9.1 攻击样本

| 编号 | 名称 | 请求或条件 | 预期 |
| --- | --- | --- | --- |
| A001 | SQL tautology | `/search?q=1%27%20OR%20%271%27=%271` | 403 |
| A002 | SQL UNION | `/item?id=1%20UNION%20SELECT%20user,password%20FROM%20users` | 403 |
| A003 | SQL comment bypass | `/login?user=admin%27%20OR%201=1--` | 403 |
| A004 | SQL drop table | `/api/order?id=1%3Bdrop%20table%20orders` | 403 |
| A005 | SQL hex literal | `/api/item?id=0xdeadbeef%20UNION%20SELECT` | 403 |
| A006 | RFI HTTP scheme | `/redirect?next=http%3A%2F%2Fevil.example%2Fshell.txt` | 403 |
| A007 | RFI PHP wrapper | `/view?file=php%3A%2F%2Ffilter%2Fresource%3Dindex.php` | 403 |
| A008 | Unix traversal | `/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd` | 403 |
| A009 | Windows cmd shell | `/download?file=..%5C..%5Cwindows%5Csystem32%5Ccmd.exe` | 403 |
| A010 | PowerShell probe | `/run?bin=powershell.exe` | 403 |
| A011 | XSS script tag | `/comment?msg=%3Cscript%3Ealert(1)%3C%2Fscript%3E` | 403 |
| A012 | XSS JavaScript URI | `/redirect?next=javascript%3Aalert(1)` | 403 |
| A013 | XSS event handler | `/profile?name=%3Cimg%20src=x%20onerror=alert(1)%3E` | 403 |
| A014 | XSS SVG onload | `/search?q=%3Csvg%20onload=alert(1)%3E` | 403 |
| A015 | Encoded evasion | `/search?q=%25u003c%26%23x3c` | 403 |
| A016 | Dangerous upload extension | `/upload?file=shell.php` | 403 |
| A017 | Nikto UA | `/` with `Nikto/2.5.0` | 403 |
| A018 | sqlmap UA | `/` with `sqlmap/1.8` | 403 |
| A019 | python-requests UA | `/` with `python-requests/2.31` | 403 |
| A020 | Wget UA | `/` with `Wget/1.21` | 403 |

### 9.2 正常样本

| 编号 | 名称 | 请求 | 预期 |
| --- | --- | --- | --- |
| N001 | Homepage | `/` | 200 |
| N002 | Index HTML | `/index.html` | 200 |
| N003 | About page | `/about` | 200 |
| N004 | Contact page | `/contact` | 200 |
| N005 | Login page | `/login` | 200 |
| N006 | Search nginx | `/search?q=nginx` | 200 |
| N007 | Numeric product ID | `/product?id=1001` | 200 |
| N008 | API status | `/api/status` | 200 |
| N009 | CSS asset | `/assets/app.css` | 200 |
| N010 | JS asset | `/assets/app.js` | 200 |
| N011 | Image asset | `/images/logo.png` | 200 |
| N012 | Text document | `/docs/readme.txt` | 200 |
| N013 | Profile alice | `/profile?name=alice` | 200 |
| N014 | Simple comment | `/comment?msg=hello-world` | 200 |
| N015 | Cart item | `/cart?item=book&qty=1` | 200 |
| N016 | Manual download | `/download?file=manual.pdf` | 200 |
| N017 | Health check | `/health` | 200 |
| N018 | Pagination | `/api/users?page=1&size=10` | 200 |
| N019 | Friendly URL | `/news/2026/course-design` | 200 |
| N020 | Safe upload name | `/upload?file=avatar.png` | 200 |

### 9.3 动态封禁样本

| 编号 | 请求 | 预期 | 说明 |
| --- | --- | --- | --- |
| D001-D020 | `/login` | 200 | 同一 IP 在 10 秒窗口内前 20 次放行。 |
| D021-D025 | `/login` | 403 | 第 21 次开始进入动态封禁。 |

## 10. 指标统计

执行：

```bash
python3 scripts/calc_metrics.py logs/test_results.csv
```

当前实测结果：

```text
TP: 25
TN: 40
FP: 0
FN: 0
detection_rate: 100.00%
false_positive_rate: 0.00%
accuracy: 100.00%
```

指标口径：

- TP：攻击样本被拦截。
- TN：正常样本被放行。
- FP：正常样本被拦截，即误报。
- FN：攻击样本被放行，即漏报。
- 检出率：`TP / (TP + FN)`。
- 误报率：`FP / (FP + TN)`。
- 准确率：`(TP + TN) / (TP + TN + FP + FN)`。

## 11. JSON 日志检查

临时 Nginx 日志路径：

```text
/private/tmp/litewaf-nginx-check/runtime/logs/waf_audit.log
```

执行 JSON Lines 解析检查：

```bash
python3 - <<'PY'
import json
from pathlib import Path

path = Path('/private/tmp/litewaf-nginx-check/runtime/logs/waf_audit.log')
count = 0
for line in path.read_text().splitlines():
    if line.strip():
        json.loads(line)
        count += 1
print('json_lines:', count)
PY
```

当前实测结果：

```text
basic_json_lines: 25
```

抽查最近 5 条日志：

```bash
tail -n 5 /private/tmp/litewaf-nginx-check/runtime/logs/waf_audit.log
```

每条日志至少应包含：

- `time`
- `client_ip`
- `method`
- `uri`
- `reason`
- `rule_id`
- `rule_name`
- `zone`
- `category`
- `score`
- `total_score`
- `action`
- `status`
- `cost_us`

## 12. 验收标准

| 验收项 | 通过标准 |
| --- | --- |
| 单元测试 | `make test` 返回 0，并出现 PASS。 |
| 配置测试 | `nginx -t` 返回 successful。 |
| 样本数量 | 至少 20 条攻击样本和 20 条正常样本参与统计。 |
| 攻击拦截 | A001-A020、D021-D025 均返回 403。 |
| 正常放行 | N001-N020、D001-D020 均返回 200。 |
| 指标 | 输出 TP/TN/FP/FN、检出率、误报率、准确率。 |
| 日志 | 拦截事件写入 JSON Lines，且可被标准 JSON 解析。 |
| 批量回归 | 400 条批量样本全部通过，TP=200、TN=200、FP=0、FN=0。 |
| 并发压测 | ApacheBench 正常流量 5000 请求并发 50 无失败；攻击命中 1000 请求并发 20 无失败且均被阻断。 |
| 工程资料 | README、配置、规则、测试脚本、测试说明、操作手册齐全。 |

## 13. 常见问题

### 13.1 目录穿越返回 400 而不是 403

原因：某些 Nginx 版本会在 WAF 前拒绝直接形态的 `/../../etc/passwd`。

处理：使用当前脚本中的编码查询参数样本：

```text
/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

并保留 `curl --path-as-is`。

### 13.2 动态封禁提前触发

原因：共享动态封禁表中的 IP 计数未清空，或测试窗口之间没有等待 10 秒以上。

处理：

```bash
/private/tmp/litewaf-nginx-check/nginx-1.31.1/objs/nginx \
  -p /private/tmp/litewaf-nginx-check/runtime \
  -c conf/nginx.conf \
  -s quit
sleep 2
/private/tmp/litewaf-nginx-check/nginx-1.31.1/objs/nginx \
  -p /private/tmp/litewaf-nginx-check/runtime \
  -c conf/nginx.conf
```

### 13.3 某条攻击样本没有返回 403

排查顺序：

1. 检查 `conf/litewaf_rules.conf` 是否包含对应类别规则。
2. 检查样本是否落入规则的 `zones`。
3. 检查分类阈值是否被配置得过高。
4. 检查请求是否被 Nginx 核心提前处理，没有进入 WAF。
5. 检查 `waf_audit.log` 中是否记录命中细节。

### 13.4 JSON 日志解析失败

排查顺序：

1. 确认日志文件没有被手工拼接其他非 JSON 文本。
2. 确认当前代码包含 `lwaf_json_escape()`。
3. 重新运行端到端脚本生成干净日志。

## 14. 测试结束清理

停止临时 Nginx：

```bash
/private/tmp/litewaf-nginx-check/nginx-1.31.1/objs/nginx \
  -p /private/tmp/litewaf-nginx-check/runtime \
  -c conf/nginx.conf \
  -s quit
```

保留以下结果用于报告：

- `logs/test_results.csv`
- `python3 scripts/calc_metrics.py logs/test_results.csv` 的输出
- `/private/tmp/litewaf-nginx-check/runtime/logs/waf_audit.log` 的部分样例
- `nginx -t` 成功输出
- `make test` 成功输出
