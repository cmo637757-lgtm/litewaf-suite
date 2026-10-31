# LiteWAF-NGX 06_测试用例说明

更新时间：2026-07-01

## 0. 文档介绍

### 0.1 文档目的

本文档综合参考《18组 测试用例报告文档.docx》和《附录D 测试用例报告文档.docx》的组织方式，面向 LiteWAF-NGX 给出可复用的测试用例说明。文档重点覆盖接口路径、功能、安全健壮性、动态封禁、日志审计和性能压测。

### 0.2 文档范围

本文档覆盖当前 `dev` 分支已实现能力：

- Nginx 模块接入与配置解析
- IP/CIDR 黑白名单与 X-Forwarded-For 取源地址
- B 规则引擎的 URL、ARGS、BODY、HEADERS、COOKIE、USER_AGENT、FILE_EXT 检测
- SQLi、RFI、目录穿越、XSS、编码绕过、危险上传扩展名、扫描器 User-Agent 规则
- 基于 Nginx shared memory 的漏桶动态封禁，多 worker 共享计数
- JSON Lines 审计日志
- TP/TN/FP/FN 指标统计
- 真实 POST BODY、批量回归、规则 reload、多 worker、长稳混合流量与 ApacheBench 并发压测
- Docker/CI 自动化验收

管理端 UI 属于后续增强项，不纳入当前验收口径。POST BODY 检测、多 worker 共享动态封禁、规则 reload 行为、Docker 容器复现和 CI 自动化已纳入当前验收。

### 0.3 读者对象

- 项目开发人员
- 测试人员
- 课程验收与答辩评审人员
- 后续维护者

### 0.4 术语与缩写

| 术语 | 解释 |
| --- | --- |
| WAF | Web Application Firewall，Web 应用防火墙。 |
| ACCESS_PHASE | Nginx HTTP 请求处理阶段之一，适合执行访问控制和拦截。 |
| TP | 攻击样本被拦截。 |
| TN | 正常样本被放行。 |
| FP | 正常样本被拦截，即误报。 |
| FN | 攻击样本被放行，即漏报。 |
| JSON Lines | 每行一个独立 JSON 对象的日志格式。 |
| 动态封禁 | 按客户端 IP 在固定时间窗口内统计请求次数，超过阈值后短期封禁。 |

## 1. 接口与路径测试用例

### 1.1 被测试对象

被测试对象为 `ngx_http_lite_waf_module` 的请求处理链路，入口为 Nginx `ACCESS_PHASE` handler。核心路径如下：

1. 读取 location 配置。
2. 获取客户端 IP。
3. 白名单优先放行。
4. 黑名单命中拦截。
5. 动态封禁检查。
6. 如请求包含 body，则通过 Nginx 请求体回调读取真实 body。
7. 构造规则引擎请求上下文。
8. 执行规则匹配、评分和阻断决策。
9. 写入 JSON Lines 审计日志。

### 1.2 测试范围与目的

- 覆盖模块开关、IP 来源、名单优先级、动态封禁、规则检测、阈值判定、日志写入。
- 覆盖正常路径、攻击路径、边界路径和高频路径。
- 保证 HTTP 状态码符合预期：正常样本 200，攻击或封禁样本 403。

### 1.3 测试环境与辅助工具

| 项目 | 内容 |
| --- | --- |
| 操作系统 | Darwin arm64，内核 25.2.0 |
| Nginx | nginx/1.31.1 |
| 编译方式 | `--add-module=/Users/logib/Documents/Codex/WAF_lite/ngx_http_lite_waf_module` |
| 规则文件 | `conf/litewaf_rules.conf` |
| 测试脚本 | `scripts/run_waf_tests.sh`、`scripts/run_waf_post_body_tests.sh`、`scripts/run_waf_multiworker_tests.sh`、`scripts/run_waf_reload_tests.sh`、`scripts/run_waf_volume_tests.py`、`scripts/run_waf_soak_tests.py` |
| 指标脚本 | `scripts/calc_metrics.py` |
| 压测工具 | ApacheBench `ab` |
| Docker | Docker 29.5.3，已通过 compose 构建与容器验收 |

### 1.4 测试驱动程序设计

| 驱动程序 | 作用 | 输出 |
| --- | --- | --- |
| `make test` | 独立验证 B 规则引擎。 | 控制台 PASS/失败信息 |
| `scripts/run_waf_tests.sh` | 65 条基础端到端样本。 | `logs/test_results.csv` |
| `scripts/run_waf_post_body_tests.sh` | 真实 POST 表单与 JSON body 检测。 | `logs/post_body_results.csv` |
| `scripts/run_waf_multiworker_tests.sh` | 4 worker 共享动态封禁检测。 | `logs/multiworker_results.csv` |
| `scripts/run_waf_reload_tests.sh` | 规则新增、reload 生效、规则移除回退。 | `logs/reload_results.csv` |
| `scripts/run_waf_volume_tests.py` | 400 条批量功能/安全样本。 | `logs/volume_results.csv` |
| `scripts/run_waf_load_tests.sh` | ApacheBench 正常与规则命中压测。 | `logs/load/ab_normal.txt`、`logs/load/ab_attack.txt` |
| `scripts/run_waf_soak_tests.py` | 正常与攻击并发混合的持续流量。 | `logs/soak_results.csv`、`logs/soak_summary.json` |
| `scripts/run_final_acceptance.sh` | 一键最终验收，串联准备、基础回归、reload、批量回归、压测、soak 和日志解析。 | `FINAL ACCEPTANCE PASSED` |
| Python JSON 检查片段 | 验证审计日志可解析。 | JSON 行数和异常位置 |

## 2. 功能测试用例

### 2.1 等价类划分

| 功能域 | 有效等价类 | 无效/攻击等价类 | 验收点 |
| --- | --- | --- | --- |
| 普通路径 | `/`、`/index.html`、`/about` | 无 | 返回 200 |
| 查询参数 | `q=nginx`、`id=1001` | SQLi、RFI、XSS、Traversal payload | 正常 200，攻击 403 |
| POST body | benign form/json | SQLi、RFI、XSS、Traversal payload | 正常不被 WAF 拦截，攻击 403 |
| User-Agent | `LiteWAF-Test/1.0` | Nikto、sqlmap、python-requests、Wget | 扫描器 UA 403 |
| 文件名参数 | `avatar.png`、`manual.pdf` | `shell.php`、`.jsp` 等危险扩展 | 正常 200，危险 403 |
| 高频访问 | 漏桶容量内 `/login` | 超过漏桶容量后的 `/login` | 容量内 200，溢出后 403 |

### 2.2 基础端到端用例

| 用例组 | 数量 | 输入 | 预期 |
| --- | ---: | --- | --- |
| A001-A020 | 20 | SQLi、RFI、Traversal、XSS、Evade、Upload、Scanner | 403 |
| N001-N020 | 20 | 首页、静态资源、普通查询、健康检查、安全文件名 | 200 |
| D001-D020 | 20 | 同一 IP 连续访问 `/login` 前 20 次 | 200 |
| D021-D025 | 5 | 同一 IP 连续访问 `/login` 第 21-25 次 | 403 |

当前实测：65/65 通过，TP=25、TN=40、FP=0、FN=0。

### 2.3 批量回归用例

批量回归将 20 条攻击模板与 20 条正常模板重复 10 轮，共 400 条请求。动态封禁在该配置中关闭，以避免限流状态污染规则检测结果。

| 用例组 | 数量 | 配置 | 预期 |
| --- | ---: | --- | --- |
| VA0101-VA1020 | 200 | 攻击模板重复 10 轮 | 全部 403 |
| VN0101-VN1020 | 200 | 正常模板重复 10 轮 | 全部 200 |

当前实测：400/400 通过，TP=200、TN=200、FP=0、FN=0。

### 2.4 规则 reload 用例

| 用例 | 输入 | 操作 | 预期 |
| --- | --- | --- | --- |
| RL001 | `/reload-check?marker=litewafreloadprobe` | 使用默认规则启动 | 200 |
| RL002 | 同一探针 | 追加临时规则并执行 `nginx -s reload` | 403 |
| RL003 | 同一探针 | 还原规则并再次 reload | 200 |

当前实测：3/3 通过，TP=1、TN=2、FP=0、FN=0。

### 2.5 真实 POST BODY 用例

| 用例组 | 数量 | 输入 | 预期 |
| --- | ---: | --- | --- |
| P001/P007 | 2 | benign form body、benign JSON body | 不被 WAF 拦截；当前静态后端返回 405 |
| P002-P006/P008 | 6 | SQLi、XSS、Traversal、RFI POST body | 403 |

当前实测：8/8 通过，TP=6、TN=2、FP=0、FN=0。

### 2.6 多 worker 共享动态封禁用例

| 用例组 | 数量 | 配置 | 预期 |
| --- | ---: | --- | --- |
| M001-M006 | 6 | `worker_processes 4`，同一 `X-Forwarded-For` IP 前 6 次请求 | 200 |
| M007-M010 | 4 | 同一 IP 第 7-10 次请求 | 403 |

当前实测：10/10 通过，TP=4、TN=6、FP=0、FN=0。

### 2.7 漏桶泄漏恢复用例

| 用例组 | 数量 | 配置 | 预期 |
| --- | ---: | --- | --- |
| L001-L004 | 4 | `lite_waf_max_requests 4`、`lite_waf_window 4`，快速填满桶 | 200 |
| L005-L007 | 3 | 等待 3 秒泄漏后继续请求 | 200 |
| L008 | 1 | 泄漏后再次快速溢出 | 403 |

当前实测：8/8 通过，验证当前动态封禁为漏桶行为，而非固定窗口行为。

## 3. 安全与健壮性测试用例

| 编号 | 类别 | 输入条件 | 预期结果 |
| --- | --- | --- | --- |
| R001 | URL 编码 | `%2e%2e%2f%2e%2e%2fetc%2fpasswd` | 解码后命中 Traversal，返回 403 |
| R002 | 反斜杠路径 | `..%5C..%5Cwindows%5Csystem32%5Ccmd.exe` | 命中 Windows shell 特征，返回 403 |
| R003 | 控制字符日志风险 | URI、规则名等字符串经 JSON 转义写入日志 | 日志可被标准 JSON 解析 |
| R004 | 漏桶容量边界 | 桶容量内请求不封禁，溢出请求封禁 | 容量内 200，溢出后 403 |
| R005 | Nginx 核心提前拒绝 | 避免使用直连 `/../../etc/passwd` 作为稳定断言 | 使用编码查询参数替代 |
| R006 | 规则载荷保持 | 批量脚本不追加破坏 payload 语义的查询后缀 | `shell.php` 仍位于被检测值末尾 |

## 4. 性能与负载测试用例

### 4.1 测试工具

本机已安装 ApacheBench：

```text
/Volumes/MSD/opt/homebrew/bin/ab
```

若课程环境缺失，可在代理环境下使用 brew 安装：

```bash
export https_proxy=http://127.0.0.1:7897 http_proxy=http://127.0.0.1:7897 all_proxy=socks5://127.0.0.1:7897
brew install httpd
```

### 4.2 压测用例

| 编号 | 场景 | 请求数 | 并发 | 预期 |
| --- | --- | ---: | ---: | --- |
| P001 | 正常流量 `/` | 5000 | 50 | Failed requests = 0 |
| P002 | SQLi 规则命中 | 1000 | 20 | Failed requests = 0，Non-2xx responses = 1000 |
| P003 | 正常/攻击混合流量 | 2400 | 12 | 30 秒持续发送，失败数 = 0 |
| P004 | POST BODY 回归 | 8 | 串行 | 8/8 通过 |
| P005 | 多 worker 共享封禁 | 10 | 4 worker | 10/10 通过 |

当前实测结果：

| 场景 | Requests/sec | 平均请求耗时 | 失败数 |
| --- | ---: | ---: | ---: |
| 正常流量 | 43644.11 req/s | 1.146 ms | 0 |
| SQLi 命中 | 35311.98 req/s | 0.566 ms | 0 |
| 混合流量 | 约 79.98 req/s | P95 约 2.9-5.0 ms | 0 |

## 5. 日志审计测试用例

| 编号 | 场景 | 检查内容 | 预期 |
| --- | --- | --- | --- |
| L001 | 黑名单/规则/动态封禁拦截 | `reason`、`status`、`action` | 字段存在且语义正确 |
| L002 | 规则命中 | `rule_id`、`rule_name`、`zone`、`category`、`score` | 能解释拦截原因 |
| L003 | JSON 转义 | URI、规则名中含引号、反斜杠、控制字符 | 日志仍为合法 JSON |
| L004 | 批量压测日志 | `/private/tmp/litewaf-nginx-volume/logs/waf_audit.log` | 1212 行均可解析 |
| L005 | 多 worker 日志 | `/private/tmp/litewaf-nginx-multiworker/logs/waf_audit.log` | 4 行均可解析 |
| L006 | 混合流量日志 | `/private/tmp/litewaf-nginx-soak/logs/waf_audit.log` | 822 行均可解析 |

## 6. Docker/CI 自动化测试用例

| 编号 | 场景 | 操作 | 预期 |
| --- | --- | --- | --- |
| C001 | Docker 镜像构建 | `docker compose build` | 成功构建 Debian + Nginx + LiteWAF 镜像 |
| C002 | 容器最终验收 | `docker compose run --rm litewaf-acceptance` | 输出 `FINAL ACCEPTANCE PASSED` |
| C003 | GitHub Actions | push 或 pull request 触发 `.github/workflows/ci.yml` | 安装依赖并执行最终验收 |

## 7. 路径测试检查表

| 检查项 | 当前结论 |
| --- | --- |
| 数据类型问题 | 未发现。IP、分值、状态码均使用明确整数类型或 Nginx 类型。 |
| 变量初始化问题 | 未发现。location 配置创建阶段使用未设置值，merge 阶段给默认值。 |
| 逻辑判断问题 | 白名单优先、黑名单次之、动态封禁先于规则引擎，POST body 回调后继续规则检测，顺序符合设计。 |
| 循环问题 | 规则遍历、CIDR 遍历、动态表遍历均有边界。 |
| 内存问题 | 规则引擎独立测试通过；请求上下文使用请求池或固定缓冲区。 |
| 文件 I/O 问题 | 规则文件配置期加载，日志文件追加写入，路径可配置。 |
| 错误处理问题 | 规则加载失败会导致 `nginx -t` 失败；日志打开失败记录 Nginx error log。 |

## 8. 验收结论

当前测试体系已经从基础 65 条端到端样本扩展到 reload 3 条、400 条批量回归样本、8 条真实 POST BODY 样本、10 条多 worker 共享封禁样本、6000 次 ApacheBench 并发压测请求和 2400 条长稳混合流量，并通过 `scripts/run_final_acceptance.sh` 串联为一键最终验收流程。Docker 容器验收也已通过，现有结果满足 01/02 设计文档提出的功能验收、日志验收、指标验收和工程验收要求，可作为后续提交前回归基线。
