# LiteWAF-NGX 1 分钟演示视频脚本

要求：无字幕，录屏为主，必要时配旁白；总时长约 60 秒。画面重点展示“配置可见、攻击被拦、正常放行、动态封禁、日志与指标可追溯”。

## 一、当前完善与测试增强建议

### 1. 当前目标完成度

当前项目已经达到课程设计 MVP 的完整闭环：

- A/B/C 模块已整合到 `dev` 分支。
- 支持 Nginx ACCESS_PHASE 接入、黑白名单、XFF、规则引擎、真实 POST BODY 检测、异常评分、shared memory 动态封禁、JSON Lines 审计日志。
- 规则覆盖 SQLi、RFI、目录穿越、XSS、编码绕过、危险上传扩展名和扫描器 User-Agent。
- 文档已覆盖 01/02/03/04/05/06/07/08，以及 Markdown 操作手册、测试用例说明和文档汇总。
- `scripts/run_final_acceptance.sh` 已通过最终验收；基础端到端 65 条样本、reload 3 条样本、批量回归 400 条样本、POST BODY 8 条样本、多 worker 10 条样本、ApacheBench 6000 次并发请求、30 秒混合流量 2400 条请求均通过。

### 2. 可进一步完善内容

| 优先级 | 建议 | 价值 |
| --- | --- | --- |
| 中 | 扩展 Docker/CI 平台矩阵 | 当前已支持 Docker/compose 与 GitHub Actions，可继续覆盖 Linux/amd64、更多 Nginx 版本和长周期任务。 |
| 中 | 日志轮转与异步/缓冲写入 | 降低高并发下同步写日志对延迟的影响。 |
| 中 | 增加共享封禁表观测接口 | 便于演示和运维查看当前 IP 计数、封禁到期时间和淘汰状态。 |
| 低 | 增加规则白名单和学习模式 | 支持误报调优和演示“观察模式”。 |
| 低 | 增加可视化报告生成 | 将 CSV 和 JSON 日志转成 HTML/PDF 报告，便于答辩展示。 |

### 3. 可继续增强的测试内容

| 类型 | 建议 | 说明 |
| --- | --- | --- |
| 兼容性测试 | Docker Linux/arm64 与 Linux/amd64 双环境测试 | 当前已通过 Docker Linux/arm64；可继续扩展 amd64。 |
| 长稳测试 | 30 分钟以上持续压测 | 当前已加入 30 秒混合流量基线；长周期用于观察内存、日志增长和 Nginx 稳定性。 |
| 混合流量测试 | 正常与攻击并发混合发送 | 已通过 `run_waf_soak_tests.py` 覆盖，可继续提升时长和 RPS。 |
| 多 worker 测试 | `worker_processes > 1` | 已通过 4 worker 共享动态封禁回归，可继续扩展更高 worker 数和更长窗口。 |
| 规则变更测试 | reload 后规则新增、删除、错误配置 | 已覆盖新增/删除 reload；可继续补错误配置和高频 reload。 |
| 边界输入测试 | 超长 URI、超长 Cookie、特殊控制字符 | 验证截断、安全转义和日志稳定性。 |

## 二、演示前准备

建议先打开三个终端窗口：

1. 左侧终端：项目目录，用于展示配置、规则和运行测试。
2. 右侧终端：显示 Nginx 审计日志。
3. 下方或切换窗口：显示指标统计输出。

录制前先完成一次环境准备和完整验收。该步骤不建议放入 1 分钟正式录屏，因为耗时较长：

```bash
cd /Users/logib/Documents/Codex/WAF_lite
make test
bash scripts/run_final_acceptance.sh
```

正式录制前重置演示用 Nginx。该命令会停止 18010 的临时演示实例并重新启动，目的是清空动态封禁计数，保证第 21 次请求稳定返回 403：

```bash
/private/tmp/litewaf-nginx-check/nginx-1.31.1/objs/nginx \
  -p /private/tmp/litewaf-nginx-check/runtime \
  -c conf/nginx.conf \
  -s stop >/dev/null 2>&1 || true

sleep 1

/private/tmp/litewaf-nginx-check/nginx-1.31.1/objs/nginx \
  -p /private/tmp/litewaf-nginx-check/runtime \
  -c conf/nginx.conf
```

演示结束停止：

```bash
/private/tmp/litewaf-nginx-check/nginx-1.31.1/objs/nginx \
  -p /private/tmp/litewaf-nginx-check/runtime \
  -c conf/nginx.conf \
  -s quit
```

## 三、60 秒镜头脚本

| 时间 | 画面 | 操作 | 旁白要点 |
| --- | --- | --- | --- |
| 0-5 秒 | 项目目录与 README/文档列表 | 快速展示 `ls`、`docs/`、`conf/`、`scripts/`，扫过 01-08 文档 | “这是 LiteWAF-NGX，一个基于 Nginx 模块的轻量级 Web 应用防火墙。” |
| 5-12 秒 | Nginx 配置片段 | 打开 `conf/nginx_litewaf_volume_test.conf` 或临时 `nginx.conf`，突出 `lite_waf on`、规则文件、动态封禁、日志路径 | “模块挂载在 Nginx 访问阶段，规则、阈值、动态封禁和日志路径都可配置。” |
| 12-20 秒 | 规则文件 | 展示 `conf/litewaf_rules.conf` 中 SQL、XSS、Traversal、Scanner 规则 | “规则引擎支持字符串和 PCRE2 正则，按 SQL、XSS、目录穿越等类别评分。” |
| 20-28 秒 | 正常请求 | 执行正常请求短命令，显示 `正常请求 HTTP 200` | “正常业务请求会被放行。” |
| 28-38 秒 | 攻击与 POST BODY | 执行 SQLi curl 和 POST JSON body curl，显示 403 | “SQL 注入既可以在查询参数中被识别，也可以在真实 POST BODY 中被识别。” |
| 38-47 秒 | 动态封禁 | 执行 21 次短循环，展示第 21 次 `/login` 返回 403 | “同一 IP 高频访问会触发共享动态封禁，多 worker 下也使用同一份计数状态。” |
| 47-54 秒 | 审计日志 | `tail -n 3 waf_audit.log`，显示 JSON Lines | “每次拦截都会写入 JSON 审计日志，包含 IP、URI、规则、分值、原因和状态码。” |
| 54-60 秒 | 最终验收 | 展示 `run_final_acceptance.sh` 末尾 `FINAL ACCEPTANCE PASSED` 或 06/07 文档结果 | “当前基础回归、POST BODY、multi-worker、reload、并发压测和混合流量均通过，检测率 100%，误报率 0%。” |

## 四、可直接使用的录屏命令顺序

以下命令已在本机 `dev_2` 分支验证可运行。正式录制时建议逐段复制执行，不要临时手打。

### 0. 进入目录并重置演示 Nginx

```bash
cd /Users/logib/Documents/Codex/WAF_lite

/private/tmp/litewaf-nginx-check/nginx-1.31.1/objs/nginx \
  -p /private/tmp/litewaf-nginx-check/runtime \
  -c conf/nginx.conf \
  -s stop >/dev/null 2>&1 || true

sleep 1

/private/tmp/litewaf-nginx-check/nginx-1.31.1/objs/nginx \
  -p /private/tmp/litewaf-nginx-check/runtime \
  -c conf/nginx.conf
```

预期：无错误输出；若端口曾被占用，重置后 `18010` 应可访问。

### 1. 展示配置

```bash
sed -n '13,32p' /private/tmp/litewaf-nginx-check/runtime/conf/nginx.conf
```

预期：出现 `lite_waf on`、`lite_waf_rule_file`、`lite_waf_dynamic_block on`、`lite_waf_log_path` 等配置。

### 2. 展示规则

```bash
sed -n '12,40p' conf/litewaf_rules.conf
```

预期：出现 SQL、RFI、Traversal、XSS、Evade、Upload 和 Scanner 规则。

### 3. 正常请求

```bash
curl -s -o /dev/null -w '正常请求 HTTP %{http_code}\n' \
  -A 'LiteWAF-Demo/1.0' \
  http://127.0.0.1:18010/
```

预期输出：

```text
正常请求 HTTP 200
```

### 4. SQL 注入请求

```bash
curl -s -o /dev/null -w 'SQLi 请求 HTTP %{http_code}\n' \
  -A 'LiteWAF-Demo/1.0' \
  'http://127.0.0.1:18010/search?q=1%27%20OR%20%271%27=%271'
```

预期输出：

```text
SQLi 请求 HTTP 403
```

### 5. 真实 POST BODY 检测

```bash
curl -s -o /dev/null -w 'POST BODY 请求 HTTP %{http_code}\n' \
  -A 'LiteWAF-Demo/1.0' \
  -X POST \
  -H 'Content-Type: application/json' \
  --data '{"id":"1 UNION SELECT password FROM users"}' \
  http://127.0.0.1:18010/post-check
```

预期输出：

```text
POST BODY 请求 HTTP 403
```

### 6. 动态封禁短演示

前面几个请求也会进入同一 IP 的漏桶。为了让画面稳定展示“前 20 次 200、第 21 次 403”，动态封禁演示前先重置一次演示 Nginx：

```bash
/private/tmp/litewaf-nginx-check/nginx-1.31.1/objs/nginx \
  -p /private/tmp/litewaf-nginx-check/runtime \
  -c conf/nginx.conf \
  -s stop >/dev/null 2>&1 || true

sleep 1

/private/tmp/litewaf-nginx-check/nginx-1.31.1/objs/nginx \
  -p /private/tmp/litewaf-nginx-check/runtime \
  -c conf/nginx.conf

for i in $(seq 1 21); do
  code=$(curl -s -o /dev/null -w '%{http_code}' \
    -A 'LiteWAF-Demo/1.0' \
    http://127.0.0.1:18010/login)
  printf '%02d %s\n' "$i" "$code"
done | tail -n 5
```

预期输出最后一行是 `21 403`：

```text
17 200
18 200
19 200
20 200
21 403
```

### 7. 指标展示

```bash
python3 scripts/calc_metrics.py logs/post_body_results.csv
python3 scripts/calc_metrics.py logs/multiworker_results.csv
```

预期重点：

```text
detection_rate: 100.00%
false_positive_rate: 0.00%
accuracy: 100.00%
```

### 8. 日志审计

```bash
tail -n 5 /private/tmp/litewaf-nginx-check/runtime/logs/waf_audit.log
```

预期：出现 `score_threshold`、`BODY`、`dynamic_block`、`status":403` 等字段。

### 9. 最终验收结果展示

1 分钟录屏中不建议重新运行完整验收，建议展示已生成的验收截图或待打印总结报告附录：

```bash
ls 待打印/运行截图
```

如现场时间充足，也可执行完整验收：

```bash
bash scripts/run_final_acceptance.sh
```

## 五、拍摄建议

- 不加字幕时，终端字体要调大，建议 18-22 pt。
- 每个命令提前准备好，录制时直接回车，避免打字占用时间。
- 画面只保留一个主终端，减少干扰。
- 攻击请求画面重点停留在 `SQLi 请求 HTTP 403` 和 `POST BODY 请求 HTTP 403`。
- 指标画面重点停留在 `detection_rate: 100.00%`、`false_positive_rate: 0.00%` 和 `FINAL ACCEPTANCE PASSED`。
- 若动态封禁短演示提前返回 403，说明当前 Nginx 计数状态未清空；重新执行“0. 进入目录并重置演示 Nginx”后再录制即可。
