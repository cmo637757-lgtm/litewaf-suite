# 成员 C 开发需求说明

项目名称：LiteWAF-NGX：基于 Nginx 的轻量级 Web 应用防火墙

## 1. 成员 C 负责范围

成员 C 负责项目中的运行期治理、日志审计、测试验证和报告整理部分。

具体包括：

1. 动态封禁模块
2. JSON 审计日志
3. curl / Nikto / DVWA 测试
4. 指标统计
5. 报告和答辩材料整理

成员 C 不负责从零实现整个 Nginx 模块，也不负责重写规则引擎。成员 C 的代码应接入成员 A/B 已有的模块骨架、配置结构体、客户端 IP 获取函数、规则匹配结果和评分结果。

---

## 2. 动态封禁模块要求

动态封禁最终实现采用漏桶算法。

默认参数：

* 时间窗口：10 秒
* 最大请求数：20 次
* 封禁时间：60 秒
* 封禁返回码：403

基本逻辑：

1. 按客户端 IP 记录访问状态。
2. 如果某个 IP 在 10 秒内请求超过 20 次，则封禁 60 秒。
3. 封禁期间，该 IP 的请求直接返回 403。
4. 封禁时间到期后自动恢复。
5. 如果超过统计窗口，则重置该 IP 的计数器。

最终实现使用 Nginx shared memory 保存 IP 漏桶状态，支持多 worker 共享计数。

建议数据结构：

```c
typedef struct {
    ngx_str_t ip;
    time_t first_seen;
    ngx_uint_t req_count;
    time_t block_expire;
} lwaf_ip_stat_t;
```

建议函数：

```c
ngx_int_t lwaf_dynamic_check_and_update(
    ngx_http_request_t *r,
    lwaf_loc_conf_t *conf,
    ngx_str_t client_ip
);
```

建议接入位置：

```text
lite_waf off 检查之后
client_ip 获取之后
白名单检查之后
黑名单检查之后
规则引擎执行之前
```

---

## 3. JSON 审计日志要求

每次拦截请求都应写入一行 JSON 日志。

日志路径：

```text
logs/waf_audit.log
```

日志格式采用 JSON Lines，即每次拦截写入一行 JSON 对象。

每条日志至少包含以下字段：

* time
* client_ip
* method
* uri
* reason
* rule_id
* rule_name
* zone
* category
* score
* total_score
* action
* status
* cost_us

动态封禁时：

```json
{
  "reason": "dynamic_block",
  "action": "deny",
  "status": 403
}
```

黑名单拦截时：

```json
{
  "reason": "blacklist",
  "action": "deny",
  "status": 403
}
```

规则直接拦截时：

```json
{
  "reason": "rule_block",
  "action": "deny",
  "status": 403
}
```

评分阈值拦截时：

```json
{
  "reason": "score_threshold",
  "action": "deny",
  "status": 403
}
```

建议函数：

```c
ngx_int_t lwaf_log_write(
    ngx_http_request_t *r,
    lwaf_loc_conf_t *conf,
    lwaf_log_event_t *event
);
```

---

## 4. 测试脚本要求

需要提供测试脚本：

```text
scripts/run_waf_tests.sh
```

测试脚本应支持配置目标地址，默认地址为：

```text
http://localhost:8010
```

测试内容至少包括：

1. 正常请求，应返回 200。
2. SQL 注入请求，应返回 403。
3. XSS 请求，应返回 403。
4. 目录穿越请求，应返回 403。
5. 扫描器 User-Agent 请求，应返回 403。
6. 连续访问 `/login` 25 次，第 21 次或之后应返回 403。

---

## 5. 指标统计脚本要求

需要提供统计脚本：

```text
scripts/calc_metrics.py
```

统计脚本用于计算：

* TP：攻击样本被拦截
* TN：正常样本被放行
* FP：正常样本被拦截
* FN：攻击样本被放行
* 检出率
* 误报率
* 准确率

计算公式：

```text
检出率 = TP / (TP + FN)
误报率 = FP / (FP + TN)
准确率 = (TP + TN) / (TP + TN + FP + FN)
```

---

## 6. 测试用例文档要求

需要提供测试用例文档：

```text
docs/member_c_test_cases.md
```

内容要求：

1. 至少 20 条攻击样本。
2. 至少 20 条正常样本。
3. 每条样本需要包含：

   * 编号
   * 请求路径或请求条件
   * 样本类型
   * 预期状态码
   * 测试目的

---

## 7. 实现原则

1. 不重写整个项目。
2. 不重构成员 A/B 的核心代码。
3. 不改变规则文件语法。
4. 不改变已有 Nginx 模块整体结构。
5. 动态封禁、日志、测试脚本应以最小改动接入现有项目。
6. 每次代码改动后，需要能够通过：

```bash
nginx -t
```

7. 每次功能完成后，需要使用 curl 进行回归测试。
8. 每完成一个小功能，都应进行一次 Git 提交。

---

## 8. 成员 C 阶段性交付物

成员 C 最终应提交：

```text
动态封禁模块代码
JSON 审计日志代码
scripts/run_waf_tests.sh
scripts/calc_metrics.py
docs/member_c_test_cases.md
logs/waf_audit.log 示例
README 中的成员 C 使用说明
测试截图
指标统计结果
答辩说明材料
```

---

## 9. 当前阶段限制

当前其他成员尚未完成成员 A/B 的模块骨架和规则引擎，因此成员 C 当前阶段先完成：

1. 成员 C 需求文档。
2. 测试脚本框架。
3. 测试用例表。
4. 指标统计脚本。

暂时不要实现 Nginx C 模块中的动态封禁和日志接入代码。
