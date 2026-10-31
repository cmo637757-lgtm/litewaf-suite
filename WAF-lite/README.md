# LiteWAF-NGX

LiteWAF-NGX 是基于 Nginx HTTP 模块的轻量级 Web 应用防火墙（电子科技大学「进阶式挑战性综合项目 III」课题）。
模块挂载在 `NGX_HTTP_ACCESS_PHASE`，在请求进入后端应用前完成 IP/CIDR 访问控制、X-Forwarded-For 真实 IP 提取、
外部规则匹配与异常评分、基于漏桶的 CC 自动封禁，并输出 14 字段 JSON Lines 审计日志。

## 当前状态

| 项 | 状态 |
|---|---|
| 代码基线 | 分支 `dev_2`，HEAD `055f8d4` + S1 口径对齐（见 `docs/基线说明.md`） |
| 引擎 | 已完成：18 条规则、7 个正则区域、漏桶动态封禁、POST BODY、reload 继承共享内存 |
| 编译 | Kali 2026.3 + nginx **1.24.0** 源码编译通过（需 `libcrypt-dev`） |
| 验收 | 14 步全量脚本 `FINAL ACCEPTANCE PASSED`（65 基础用例、400 体积、POST、4 worker、漏桶、soak 全绿） |
| 冻结数据 | `fixtures/`：F20 / A5 / R 三套数据集 + `MANIFEST.json`（sha256） |
| 平台侧 | 规划中：采集器 → 后端 → 看板 → 发布闭环 → 告警（见 `../LiteWAF-综设-实施计划书.md`） |

## 目录结构

```text
conf/                         规则文件（litewaf_rules.conf，rules-v1）
docs/                         基线说明 / 需求 / 测试 / 报告材料
fixtures/                     冻结验收数据集（F20、A5、R）+ MANIFEST
include/                      规则引擎公共头文件
ngx_http_lite_waf_module/     Nginx HTTP 模块（handler、日志、漏桶）
scripts/                      构建、验收、压测、指标脚本
src/                          独立 C 规则引擎
tests/                        规则引擎单元测试
tools/                        eval 工具、文档生成、数据集生成
```

## 快速开始（Kali 虚拟机）

一次性的系统准备（apt 源、ForceIPv4、依赖、共享文件夹、MariaDB）：

```bash
sudo bash /mnt/hgfs/share/scripts/kali_setup.sh
```

编译 + 最小验证（正常 200、SQLi/XSS/扫描器 UA 均 403）：

```bash
cd /mnt/hgfs/share
sudo NGINX_VERSION=1.24.0 bash scripts/s0_build.sh
```

全量 14 步验收：

```bash
cd /opt/litewaf/src/WAF-lite
sudo env WORK_DIR=/opt/litewaf/build/nginx-check NGINX_VERSION=1.24.0 \
  BASIC_PREFIX=/opt/litewaf/build/nginx-check/runtime \
  VOLUME_PREFIX=/opt/litewaf/build/volume RELOAD_PREFIX=/opt/litewaf/build/reload \
  SOAK_PREFIX=/opt/litewaf/build/soak MULTIWORKER_PREFIX=/opt/litewaf/build/multiworker \
  LEAKY_PREFIX=/opt/litewaf/build/leaky bash scripts/run_final_acceptance.sh
```

> 注意：裸 `curl` 会被规则 2001（扫描器 UA）拦截。测正常请求必须带浏览器 UA。

## 规则引擎独立测试

```bash
make test                                                    # 21 条规则加载 + B 引擎打分
make build/lwaf_eval
build/lwaf_eval conf/litewaf_rules.conf /api 'query=hello' 'Mozilla/5.0'
build/lwaf_eval conf/litewaf_rules.conf /api 'query=1%20UNION%20SELECT' 'Mozilla/5.0'
```

## 冻结验收数据集

```bash
python tools/gen_fixture.py            # 生成 fixtures/ 与 MANIFEST.json
```

- `f20/`：20 条访问 + 5 条拒绝，期望 N=20 / B=5 / ratio=25% / QPS=0.3333，分类 SQLi3+XSS1+CC1
- `a5/`：同 IP 5 条 SQLi（10/20/30/40/50 秒），期望 trigger=3 / event=5 / delivery=1
- `r/`：正常 40 + SQLi 20 + XSS 20 + CC 20 的带标签样本，供误拦率/漏报率评估

## Nginx 配置示例

```nginx
location / {
    lite_waf on;
    lite_waf_trust_proxy off;
    lite_waf_deny_status 403;

    lite_waf_whitelist 127.0.0.1/32;
    lite_waf_blacklist 10.10.10.10/32;

    lite_waf_rule_file conf/litewaf_rules.conf;
    lite_waf_score_threshold SQL 8;
    lite_waf_score_threshold XSS 8;
    lite_waf_score_threshold TOTAL 12;

    lite_waf_dynamic_block on;
    lite_waf_max_requests 20;      # 漏桶容量 C：前 C 次放行，第 C+1 次起封禁
    lite_waf_window 10;            # 排空时间 W：每秒泄漏 C/W
    lite_waf_block_duration 60;    # 封禁时长 D
    lite_waf_log_path logs/waf_audit.log;

    root html;
    index index.html index.htm;
}
```

## 规则语法

```conf
lwaf_rule id=1000 name="sql keywords" type=rx pattern="\\b(select|union)\\b" zones=URL,ARGS score=SQL:4 action=score
```

必填 `id`、`name`、`type`、`pattern`、`zones`、`score`、`action`。区域支持 `URL`、`ARGS`、`BODY`、
`HEADERS`、`COOKIE`、`USER_AGENT`、`FILE_EXT`。`action` 支持 `score`（累计超阈值才拦）与 `block`（命中即拦）。

## 审计日志格式

```json
{"time":1789862401000,"client_ip":"10.0.0.10","method":"GET","uri":"/p1","reason":"score_threshold",
 "rule_id":1000,"rule_name":"sql keywords","zone":"ARGS","category":"SQL","score":4,"total_score":12,
 "action":"deny","status":403,"cost_us":100}
```

`time` 为 UTC 毫秒；`cost_us` 是从进入 handler 到日志写完的耗时（含异步 BODY 等待）；
`reason=dynamic_block` 的条目由适配层映射为 CC，源文件不改写。

## 测试入口

```bash
BASE_URL=http://127.0.0.1:18010 bash scripts/run_waf_tests.sh
python scripts/calc_metrics.py logs/test_results.csv
```

更多细节见 `docs/基线说明.md`。
