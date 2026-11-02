# LiteWAF 可视化平台 · 综合项目 III 实施计划书

> 版本 v2.3（2026-10-24 修订：v2.0 对抗样本复测；v2.1 引擎按命中次数计分 + 请求体硬上限；v2.2 三项运维强化——日志轮转与数据保留、密钥/口令环境变量外置、SSE 实时推送；**v2.3 引擎代码评审后的 6 处性能与正确性改动（CC 槽位回收、毫秒级漏水、日志 fd 复用、match_data 复用、提前退出），14 步验收 PASSED、吞吐 +48%~+63%、soak P95 −55%**；**v2.4 用 OWASP CRS 公开样本（2282 攻击 + 676 正常）压测规则并升级到 rules-v5（74 条），修掉 5 个真实误报、201 条回归回到 TP99/FN1/FP0**；v1.1 以 `dev_2` 为唯一基线；v1.2 补四份课件 `1/3/6/7` 参考对照；v1.3 按 Kali 2026.3 重建后更新 §3.5 环境、数据库统一 MariaDB；v1.4 记录 S0 实测通过；v1.5 记录 S2 采集器与 S3 后端完成，并修正分位数公式；v1.6 记录 S4 前端完成与截图证据；v1.7 记录 S5 发布闭环、S6 告警、S7 一键验收全部完成，并附使用说明与工作报告；v1.8 补做 R34-10 误报闭环、R34-11 带标签评估、R36-01 脱敏导出，规则集升 rules-v2，ECharts 升 6.1；v1.9 补 S9 运维六件套（备份/静态站/采集器健康/性能页/规则试打/崩溃演练），一键验收扩到 15 项全绿，S8 缓冲段封闭；**v2.0 把评估样本从 80 条扩到 201 条对抗样本，规则集升 rules-v3（38 条），记录三次复测暴露的引擎机制限制**）｜ 依据：课程任务书（李美蓉）、《NEW_WAF 完整需求卡片 V2 可裁剪实施版》、`WAF-lite@dev_2` 实测、Windows 宿主 + Kali 2026.3 实测环境

---

## 0. 一句话结论

**引擎侧已经做完了，工作量全在"平台化"。**

`dev_2` 分支不是骨架，是一套**可运行、可验收、已通过 Docker 与 CI 验证**的完整 WAF：Nginx 模块 1296 行、规则引擎 909 行、21 条规则、漏桶共享内存多 worker 封禁、真实 POST/JSON Body 检测、JSONL 审计日志、8 个测试脚本、Dockerfile + docker-compose + GitHub Actions、8 份 docx 产品文档。

因此本项目真正要写的，只剩任务书第（2）（3）（4）条：**日志采集入库、后端 API、可视化仪表盘、配置发布闭环、告警**。按本计划裁剪后 **P0 全做 + 3 张 P1**，单人约 **36 人日（9–10 周）**，三人小组 **5–6 周**。

唯一硬前置**已解决**：Windows 侧没有 Linux（WSL 未安装、MinGW 缺 pcre2），改用 **VMware + Kali 2026.3** 承担编译与运行验证（§3.5）。

**当前状态（2026-10-22 下午）**：计划内的 S0–S7 全部落地并实测通过，另补做三张 P0（误报闭环、带标签评估、脱敏导出）与六项运维能力（S9），一条命令 **15 项必选全 PASS**。剩余未做项见 §9 第 14 条与 `docs/工作报告.md` 第十节。

---

## 1. 现状盘点

### 1.1 材料

| 材料 | 状态 |
|---|---|
| 任务书 PDF（4 页） | 已解析：优/良/中/差四级标准；四个必做模块：规则处理引擎、日志收集、日志分析、数据展示 |
| 需求卡片 V2（1156 行） | 已解析：35 张卡，P0 23 / P1 6 / P2 6；固定验收数据集 F20 / A5 / R 集 |
| 课件 `1 阶段引导与系统思维` | 参考：综设 I 攻 / II 防 / III 管；给出答辩"六问"与本周任务（基线指标：准确率/误报率/漏报率/响应时间/CPU 内存/QPS；功能模块图、用例图、角色权限矩阵）——已并入 §5.9 自检 |
| 课件 `3 前后端分离与接口设计` | 参考：RESTful 规范（路径用名词复数、`limit/offset` 分页、状态码 200/201/400/401/403/500、错误体 `{"error": "..."}`）——S3 的接口按此口径，并交付数据字典 + 接口文档 |
| 课件 `6 日志采集` | 参考：集中式日志五要素（收集/传输/存储/分析/告警）、ELK/EFK 与倒排索引；自研采集的取舍见 §5.9 注 |
| 课件 `7 规则加载&动态更新` | 参考：四种规则加载方案（reload / inotify·轮询 / 共享内存 + 文件·HTTP·Unix socket·信号 / Redis 广播）与版本回滚问题——S5 取舍见 §5 注 |

### 1.2 代码基线：`dev_2`（已检出）

> 仓库：`https://github.com/Llogib/WAF-lite`，当前工作区已切到本地分支 `dev_2`（跟踪 `origin/dev_2`，HEAD `055f8d4 replace dynamic block with leaky bucket`）

| 模块 | 文件 | 规模 | 状态 |
|---|---|---|---|
| Nginx 模块 | `ngx_http_lite_waf_module/ngx_http_lite_waf_module.c` | 1296 行 | 挂载 `NGX_HTTP_ACCESS_PHASE`，13 条指令，shared dict 漏桶 |
| 规则引擎 | `src/lwaf_rule_engine.c` + `include/lwaf_rule_engine.h` | 909 + 227 行 | PCRE2 正则、7 个检测区域、分类计分、阈值决策 |
| 规则集 | `conf/litewaf_rules.conf` | `dev_2` 自带 21 条 MVP 规则（现在是 **74 条 rules-v5**，见 S1/S8/v2.0/v2.4） | SQLi / XSS / RFI / 目录穿越 / 编码绕过 / 危险上传 / 扫描器 UA |
| 测试 | `tests/test_rule_engine.c`、`scripts/run_*.sh`（8 个） | 151 + 1000 余行 | 单测、65 条端到端、reload、POST body、多 worker、漏桶、400 条批量、ab 压测、soak |
| 工具 | `tools/lwaf_eval.c`、`calc_metrics.py`、`prepare_nginx_env.sh`、`build_product_docs.py` | 111 / 48 / 120 / 724 行 | 手工评估、TP/TN/FP/FN 统计、幂等环境准备、文档生成 |
| 容器/CI | `Dockerfile`、`docker-compose.yml`、`.github/workflows/ci.yml` | Debian bookworm + nginx 1.31.1 + ubuntu-24.04 | **已跑通**：docker compose build 成功、容器内 65 条全过 |
| 文档 | `01_…08_*.docx`（8 份）+ `docs/*.md`（5 份） | — | 总体设计/设计/实现/功能/测试/用例/项目报告/文档汇总**已有初稿** |

**文档记录的实测结论（开发机为 macOS aarch64）**：

- 基础端到端 65 条：TP=25、TN=40、FP=0、FN=0
- reload 回归 3/3：TP=1、TN=2、FP=0、FN=0
- 批量回归 400 条：TP=200、TN=200、FP=0、FN=0
- 真实 POST/JSON Body 8/8：TP=6、TN=2、FP=0、FN=0
- 4 worker 共享封禁 10/10、漏桶 8/8
- ab 正常流量 5000 请求并发 50 无失败；30 秒混合流量 2400 条（攻击 822 / 正常 1578）全过
- 审计日志全部可被 Python `json` 解析（25 / 1212 / 822 行等）

**缺口（平台化工作）**：没有采集器、没有数据库、没有后端 API、没有前端、没有降警、没有配置发布/回退、没有权限与操作审计。也就是需求卡片 R33-07 之后的全部内容。

### 1.3 本机环境（实测）

| 项 | 实测 | 影响 |
|---|---|---|
| 宿主系统 / CPU / 内存 | Win11 build 26200 / 16 逻辑核 / 16 GB（可用约 4.2 GB） | VM 给 6 GB，够 nginx + MariaDB + JVM |
| 磁盘 | C 26.8G 空闲，D 76.8G，E 53.4G | VM 放 D 盘（约 17G 系统 + 源码/构建） |
| Linux 运行时 | **VMware Workstation 17.5.2 + Kali 2026.3**（4 vCPU / 6 GB / NAT） | 编译与运行全在 VM 内（§3.5） |
| WSL | 未安装（**已不再需要**） | 由方案 D 取代 |
| Docker | 未安装 | `dev_2` 的 Dockerfile 可在 VM 内用；本项目不做容器化 |
| 宿主编译器 | MinGW gcc 14.2.0，**无 MSVC、无 pcre2** | 不参与编译 |
| VM 编译器 | gcc 15.2 + PCRE2（版本以 `kali_setup.sh` 自检为准） | 规则引擎单测与 nginx 编译在 VM 内完成 |
| Python | 宿主 3.14.0（PyMuPDF/pypdf/pdfplumber）；VM 3.14.x | 采集器/验收脚本首选 |
| Node | 24（`D:\code\node.exe`），npm 可达 | 前端可做 |
| Java | VM 内 OpenJDK 25 + Maven 3.9.12 | Spring Boot 构建在 VM 内完成 |
| 数据库 | **MariaDB（VM 内，仅监听 127.0.0.1:3306）**，库 `litewaf` | 卡片默认 MySQL，MariaDB 协议兼容 |
| 浏览器 | Edge 155 + Chrome 155 | 截图验收 |
| 外网 | github / npm 可达（git 用 `-c http.sslBackend=openssl`）；VM 内 apt 强制 IPv4 | 依赖下载 OK |
| SSIBAL 项目 | **本机不存在** | 卡片"复用 SSIBAL 前端"作废，Vue 从零建 |

---

## 2. 目标架构

```
攻击流量
   │
   ▼┌────────────── Kali 2026.3（VMware，NAT）──────────────┐
    │ nginx + lite_waf（dev_2 原样，:18010 起）              │
    │   └─► JSONL 审计日志 /opt/litewaf/logs/*.log          │
    │            │ 每 1s tail + 游标 + 去重                   │
    │   ┌────────▼────────┐      ┌──────────────────────┐   │
    │   │ 采集器 (Python)  │──写──►│ MariaDB 127.0.0.1     │   │
    │   └─────────────────┘      │ requests / waf_events │   │
    │   ┌─────────────────┐      │ ingest_* / versions   │   │
    │   │ 后端 Spring Boot │◄─读──│ alerts / operations   │   │
    │   │ /api/stats|config│      └──────────────────────┘   │
    │   │ /api/audit|health│                                 │
    │   └───────┬─────────┘      ┌──────────────────────┐   │
    │   ┌───────▼─────────┐      │ 执行器 engine-exec    │   │
    │   │ 告警 worker      │      │ check/publish/        │   │
    │   │ 阈值/抑制/webhook│      │ rollback/status       │   │
    │   └─────────────────┘      └──────────────────────┘   │
    └───────────────┬───────────────────────────────────────┘
                    │ 同一 VM 内 localhost:8080 / :18010
     ┌──────────────▼──────────────┐
     │ 浏览器（VM 内或 Windows）      │
     │ Vue3+Vite+ECharts            │
     │ 仪表盘 / 事件 / 配置 / 告警    │
     └─────────────────────────────┘
```

**五条不可砍边界**（卡片要求）：真实 WAF 拦截、唯一持久采集、网页改配置经真实 check 与回退、服务端权限与输出安全、真实样本/源站/日志联合验收。

**最终端口分配（实测）**：

| 端口 | 进程 | 说明 |
|---|---|---|
| 18010 | nginx + lite_waf | 被保护站点，**systemd 守护**（误杀 4 秒拉起） |
| 18080 | 平台后端（Spring Boot） | REST API + `/health` |
| 18081 | 执行器（Python） | 只绑 127.0.0.1，`X-Engine-Token` 鉴权，四个动作白名单 |
| 18082 | 控制台静态站（nginx） | 生产模式页面，反代 `/api` 到 18080 |
| 5173 | Vite dev server | 开发模式，改代码即时生效 |
| 3306 | MariaDB | 只绑 127.0.0.1 |

**接口口径（对齐课件 3）**：资源路径用名词复数（`/api/events`、`/api/stats/summary`、`/api/configs`），分页统一 `?limit=&offset=&sortby=&order=`；成功 200/201，参数错 400、未登录 401、无权限 403、服务端 500，4xx/5xx 返回 `{"error": "..."}`。S3 同步交付数据字典 + 接口文档（每接口：URL、方法、参数、返回示例、状态码）。

---

## 3. 环境方案（已定：VMware + Kali）

> **决策点 D1 已定（2026-10-21）**：采用**方案 D：VMware Workstation 17.5.2 + Kali Linux 2026.3**（4 vCPU / 6 GB / NAT 192.168.134.0/24）。下面 3.2–3.4 的 WSL / CI / 纯 Windows 为备选记录，实施细节见 3.5。

### 3.1 为什么必须 Linux

`dev_2` 的 Makefile 依赖 `pcre2-config`，本机 MinGW 没有 pcre2；nginx Windows 版不支持第三方模块；模块用了 `ngx_slab` 共享内存与 reload，只能在真实 nginx 里验证。**没有 Linux，就只能交"中等"档。**

### 3.2 方案 A：WSL2 + Ubuntu 24.04（推荐，约 30–40 分钟 + 一次重启）

```powershell
# 管理员 PowerShell
wsl --install -d Ubuntu-24.04
# 重启后设置用户名密码，然后迁到 D 盘
wsl --export Ubuntu-24.04 D:\wsl\ubuntu.tar
wsl --unregister Ubuntu-24.04
wsl --import Ubuntu-24.04 D:\wsl\Ubuntu-24.04 D:\wsl\ubuntu.tar
```

```bash
# WSL 内
sudo apt update && sudo apt install -y build-essential libpcre2-dev libssl-dev zlib1g-dev \
  python3-venv curl apache2-utils openjdk-21-jdk maven
cd /mnt/d/网安综设/WAF-lite
export WORK_DIR=/tmp/litewaf-nginx-check BASIC_PREFIX=/tmp/litewaf-nginx-check/runtime
export VOLUME_PREFIX=/tmp/litewaf-nginx-volume RELOAD_PREFIX=/tmp/litewaf-nginx-reload SOAK_PREFIX=/tmp/litewaf-nginx-soak
bash scripts/run_final_acceptance.sh
```

**干净卸载**：`wsl --unregister Ubuntu-24.04`，不装 Windows 服务、不改系统 PATH、不写注册表自启。这是对主人"只影响项目目录"底线最合规的路径。

### 3.3 方案 B：GitHub Actions 跑验收 + 本机只做平台（零系统改动）

`dev_2` 的 CI 已配置 `ubuntu-24.04` 全量验收。私有仓库免费额度 2000 分钟/月，一次验收约 3–5 分钟，跑 100 次都够。代价：**改 C 代码要 push 才能验证**，迭代慢；本机仍然跑不了 nginx，平台联调性差。适合只改平台层、C 层不动的情况。

### 3.4 方案 C：纯 Windows（不推荐）

只能前端 + Java 后端 + 用 `dev_2` 的 macOS/Linux 既有验收报告交差。nginx 集成本机无法复现 → 答辩被问"现场跑一遍"会翻车。

> **决策点 D1（旧）**：A（装 WSL）还是 B（靠 CI）？—— 已由方案 D 取代。

### 3.5 方案 D（已选定）：VMware + Kali

| 项 | 内容 |
|---|---|
| 宿主 | Windows 11 26200，VMware Workstation 17.5.2；VM 放在 D 盘独立目录（旧 `D:\kali-linux` 已废弃，2026-10-21 因磁盘坏块重建） |
| 客户机 | Kali Linux **2026.3**（rolling），4 vCPU / 6 GB / 79 GB |
| 网络 | NAT：VMnet8 `192.168.134.1/24`，guest 由 DHCP 分配（本次实测 `192.168.134.140`，登录后 `ip -4 -o addr show scope global` 确认），网关/DNS `192.168.134.2` |
| 代码通道 | 共享文件夹 `share` → `D:\网安综设`，guest 挂载 `/mnt/hgfs/share`；`scripts/kali_setup.sh` 一次写好 `fuse.conf` + `fstab` 永久挂载 |
| 已装依赖 | build-essential、PCRE2 10.48、gcc 16.2.0、make 4.4.1、OpenJDK 25.0.5-ea、Maven 3.9.12、Python 3.14.7、SQLite 3.53.4、**MariaDB 11.8.9**（active，仅监听 127.0.0.1:3306）、sshd（22） |
| 工作目录 | `/opt/litewaf/{src,engine,platform,data,logs,runtime}` |
| 编译隔离 | 源码从共享盘 rsync 到 `/opt/litewaf/src` 再编译（fuse 盘不参与 build，避免权限/时间戳问题） |
| 数据库 | 卡片默认 MySQL；本方案用 Kali 源内 `mariadb-server`（MySQL 协议兼容），库 `litewaf`、用户 `litewaf@127.0.0.1`、密码 `LiteWaf@2026`，仅监听本机 |
| 角色 | 编译/运行/验收都在 VM 内；Windows 侧只编辑源码与文档，共享盘做通道 |

**踩坑记录**（已在环境搭建中实证）：
- 旧 Kali 2026.2 VM 的虚拟磁盘出现物理坏块（`critical medium error` 扇区 72716208、`fsck` 未跑过、`vmware-vdiskmanager -R` 判定不可修复），导致系统头文件读取报 `输入/输出错误`。教训：**VM 磁盘异常时不要逐个文件修**，直接换新镜像重建；日常用 `sudo poweroff` 关机（点「关闭虚拟机电源」会损坏 journal）。
- 共享文件夹重启后不自动挂载 → `fuse.conf` 开 `user_allow_other` + `fstab` 写 `.host:/ /mnt/hgfs fuse.vmhgfs-fuse allow_other,defaults 0 0`，一次配好永久生效（`kali_setup.sh` 已自动写）。
- apt 解析到 IPv6 导致 `connect (101) 网络不可达` → 写 `/etc/apt/apt.conf.d/99force-ipv4` 强制 IPv4。
- Kali 源 JDK 版本随 rolling 变化：按 `openjdk-25 → 21 → 17 → default` 自适应（2026.3 落在 OpenJDK 25，Spring Boot 3.x 可跑）。
- Kali 2026.3 默认启用 systemd-timesyncd，与 chrony 抢时间源 → 先 `disable --now systemd-timesyncd` 再启用 chrony（`kali_setup.sh` 已处理）。
- 4 GB 内存跑 Maven 构建偏紧 → VM 调 6 GB；MariaDB `innodb_buffer_pool_size=256M`、JVM `-Xmx768m`。
- 宿主 16 GB，当前可用约 2.3 GB → VM 不建议设 8 GB，会和 Windows 抢内存。

---

## 4. 范围裁剪

### 4.1 原则

1. 引擎侧已经完成且已验证 → **不重写、只对齐口径**（R32-01 只剩字段与语义改名）。
2. 评分驱动：只做能提升"规则覆盖 / 监控预警 / 可视化交互"的项。
3. D4 卡片全砍：R32-02、R34-05、R34-08、R34-12。
4. 单机单实例：不做多站点、容器集群、公网告警通道。
5. 数据库：卡片默认 MySQL → **MariaDB 11.x（VM 内 `127.0.0.1:3306`）**，MySQL 协议兼容，口径（≤10 万行直接 SQL 分组、同查询缓存 5 秒）不变。

### 4.2 卡片裁剪表

| 卡片 | 名称 | 取舍 | 理由 |
|---|---|---|---|
| R32-01 | 基础 WAF 接入与三类真实防护 | **做**（已基本完成） | 只需补 `event_id/category/rule_id` 与 `cost_us`→"拦截处理耗时" |
| R32-02 | 编码/高级检测 | **不做** | D4，6–10 人日 |
| R33-01 | 首页仪表盘 | **做** | 评分核心 |
| R33-02 | 实时监控（SSE） | **降级**：10 秒轮询 | SSE 需 worker→master IPC |
| R33-03 | 事件详情与误报入口 | **做** | 误报率依赖它 |
| R33-04 | 检索 / Top 分析 | **做** | 交互性 |
| R33-05 | 周/月报 | **做**（P1 后置） | 便宜 |
| R33-06 | 性能与数据源状态 | **做**（P1） | 健康页复用 |
| R33-07 | 唯一日志采集 | **做**（最核心） | 平台地基 |
| R34-01 | 控制台与内部接口 | **做** | — |
| R34-02 | 规则表单/分类启停/预览 | **做** | 交互性 |
| R34-03 | 多版本列表与差异 | **降级**：只留版本列表 | — |
| R34-04 | 测试/演示目录隔离 | **并入环境脚本** | 独立价值低 |
| R34-05 | 灰度实验 | **不做** | D4 |
| R34-06 | 权限与平台自身安全 | **做** | 评分点 |
| R34-07 | 操作审计 | **做** | 评分点 |
| R34-08 | 多站点 | **不做** | 单机单站点 |
| R34-09 | CC 配置与自动拦截 | **做** | 任务书明确要求 |
| R34-10 | 误报标记/复核/调优 | **做** | "漏报误报少" |
| R34-11 | 标签样本评估与回归 | **做** | 验收证据 |
| R34-12 | 字段级豁免/学习模式 | **不做** | D4 |
| R34-13 | 关联 ID/脱敏摘要 | **不做** | D3 |
| R35-01~05 | 告警消费/阈值/合并抑制/本地 webhook/记录重试 | **全做** | 任务书"监控预警"，每张 0.5–1 人日 |
| R36-01 | 筛选与脱敏导出 | **做** | — |
| R36-02 | 统一 JSON 指标 | **降级** | 并入验收脚本 |
| R36-03 | 统一配置检查命令 | **做** | 发布闭环前置 |
| R36-04 | 一键核心验收 | **做** | 答辩演示 |
| R37-01 | 单机部署与固定执行器 | **做** | — |
| R37-02 | 健康与崩溃恢复 | **做** | — |
| R37-03 | 配置包导入导出 | **不做** | — |
| R37-04 | 检查后发布与回退 | **做** | 任务书"策略管理"核心 |

**统计**：做 P0 23 张 + P1 3 张；砍 P2 6 张；降级 3 张（R33-02、R34-03、R34-04）。

**实际落地情况（2026-10-22）**：上表「做」的项**全部完成**（含 P0 23 张里的边界项）；R33-06 性能与数据源页在 S9 完成；R33-05 周月报仍未做。另有 6 项计划外的运维能力（备份、静态站、采集器健康、规则试打、崩溃演练、数据自洽脚本）一并落地，见 S9。

### 4.3 九类攻击只承诺三类

卡片第五章已定：**SQLi / XSS / CC 三类真实检测**，其余显示"未支持"不填 0。`dev_2` 的实际能力还多三样（目录穿越、危险上传扩展、扫描器 UA），答辩时按"已支持清单"如实列出即可。

**实测口径（rules-v5，74 条）**：201 条对抗样本（SQLi 50 / XSS 50 / 正常 100 + CC 场景）→ SQLi 49/50、XSS 50/50、正常请求 0/101 误拦、CC 第 23 次 403，准确率 99.50%、精确率 100%、召回率 99.00%（剩下 1 条漏报是 `OR CHAR(65)=CHAR(65)` 函数型盲注）。**另用 OWASP CRS 公开样本（2282 攻击 + 676 正常）做外部校验：全体检出 28.3%、三族（SQLi/XSS/穿越）36.0% / 61.7% / 32.8%、误拦 8.14%**（RCE/PHP 注入不覆盖，占样本 49%，见 §7 局限）。**4 条漏报都是"裸 SQL 语句"**（`; SELECT * FROM`、`OR CHAR(65)=CHAR(65)`、`AND SUBSTRING(...)>0`、`AND (SELECT 1 FROM ...)`），根因是引擎按规则计分、不按命中次数——1000 号关键字规则命中 `select` 与 `from` 两次仍只算 4 分，够不到阈值 8。这条限制在 §7 已知限制里写明。九类里的「文件上传」只按后缀判（不做 multipart 结构解析）、「远程脚本执行」只认 RFI 特征，「CSRF / 防盗链」不在支持范围。

---

## 5. 分阶段路线（每阶段一条命令能验收）

### S0 基线复现（✅ 已完成 2026-10-22，2 小时内）

| 项 | 内容 |
|---|---|
| 交付物 | Kali 2026.3 VM（`scripts/kali_setup.sh` 一次备好依赖 + 共享盘挂载 + MariaDB）；`/opt/litewaf/build/nginx-check` 下 nginx 源码树；`scripts/s0_build.sh`（rsync → `make test` → nginx 编译 → 起 18010 → 四条 curl 验证） |
| **验收** | ① 新 VM 从零到 `s0_build.sh` 全绿 ≤40 分钟；② 65 条 TP=25/TN=40/FP=0/FN=0；③ 4 worker 封禁 10/10、漏桶 8/8 复现；④ 审计日志可被 `json` 解析 |
| 注意 | `prepare_nginx_env.sh` 默认 `/private/tmp`（mac 习惯），Linux 必须显式导出 `WORK_DIR` 等变量（`s0_build.sh` 已导出）；nginx 下载 404 时 `NGINX_VERSION=1.29.0 sudo -E bash ...` 重跑 |

**实测结果（2026-10-22，`NGINX_VERSION=1.24.0`）**：`make test` PASS（21 条规则）；`s0_build.sh` 四条 curl = 200 / 403 / 403 / 403；`run_final_acceptance.sh` 14 步 **FINAL ACCEPTANCE PASSED**——基础 65/65、reload 3/3、volume 400/400、POST BODY 8/8、4-worker 10/10、漏桶 8/8、soak 2400/2400（攻击 822、正常 1578、RPS 79.98、P95 2119 µs）、ab 正常 5000 请求 0 失败（17691 RPS）/攻击 1000 全 403；JSON 行数 1212/4/1/822 全部可解析。

**踩坑两条（已写进脚本，后续别再踩）**：
1. **`ngx_http_lite_waf_module/config` 必须是 LF**——这个文件没有扩展名，`s0_build.sh` 的 CRLF 规范化最初漏了它，导致 configure 把 `-I .../include\r` 与 `.../lwaf_rule_engine.c\r` 写进 Makefile，报「`lwaf_rule_engine.h` 找不到」+「`No rule to make target 'objs/addon/src/lwaf_rule_engine.o'`」。已修：`s0_build.sh` 的 `find` 加 `-name 'config' -o -name 'Dockerfile'`；Windows 侧共享盘也要修（`Set-Content -Encoding ascii` 会把中文路径写成 `????`，必须用 `utf8`）。改完 config 要 `rm -rf .../nginx-$VER` 重新 configure，旧 `objs/Makefile` 会缓存坏路径。
2. **规则 2001（SCAN）会把 `curl` 默认 UA 当扫描器拦**——裸 `curl` 测正常请求也是 403，看着像误拦。`s0_build.sh` 的四个测试已统一带浏览器 UA（`Mozilla/5.0 ... Chrome/120`），只有扫描器那条用 `sqlmap/1.7`。
3. nginx 1.24.0 在 Kali 上要先 `apt install libcrypt-dev`（缺 `crypt.h`），1.31.1 没这个问题（但 1.31.1 的 `auto/make` 对 addon 子目录规则处理不同，优先用 1.24.0）。

### S1 口径对齐（✅ 已完成 2026-10-22）

| 项 | 内容 |
|---|---|
| 改动 | ① 审计日志 `time` 由秒级字符串改为 **UTC 毫秒整数**；② `cost_us` 注释明确为「拦截处理耗时」（含异步 BODY 等待）；③ `conf/litewaf_rules.conf` 全量重写加中文逐条注释并冻结为 **rules-v1**；④ `ngx_http_lite_waf_module/config` 与 `.dockerignore` 的 CRLF 改 LF；⑤ 新增 `tools/gen_fixture.py` 生成冻结数据集 |
| **验收（实测）** | ① `make test` PASS（21 条规则）；② `s0_build.sh` 四条 = 200/403/403/403，日志样例 `"time":1792599126563` 为毫秒；③ 14 步验收复跑 **FINAL ACCEPTANCE PASSED**（soak P95 从 2119 µs 降到 989 µs）；④ `fixtures/` 生成 7 个文件 + `MANIFEST.json`（sha256），F20 校验：access 20 行 / body 合计 20000 / 1 条源站 403，reject 5 行 / cost 均值 300 µs / 字段 14 个 |
| 不动 | 规则引擎与匹配逻辑（已验证，改它等于重测 8 个脚本）；`category` 值不改写 |

**两处判断修正**（对照卡片原话）：
1. **不加 `event_id`**：需求卡片第 111 行写「`reason=dynamic_block` 在适配层映射显示类 CC，`blacklist` 归访问控制，SQL 归 SQLi，原字段原值另存，不改写源文件」——日志只保留引擎原值，`event_id` 由入库时数据库自增主键生成，不需要 WAF 端产生。
2. **`category` 映射放适配层**：源日志仍是 `SQL/XSS/SCAN/...`，看板与事件页展示时映射成 `SQLi/XSS/CC`，避免引擎与展示口径耦合。

**交付记录**：`docs/基线说明.md` 记录基线 HEAD、S1 四个改动文件、rules-v1 hash（`6242ec7a8369fbcfe09b939ad77d168460fee95d2e718a016845101740518820`，6239 字节）、日志 14 字段、已验证数据、5 条「复现别再踩」的坑。

### S2 采集与入库（✅ 已完成 2026-10-22）

| 项 | 内容 |
|---|---|
| 交付物 | `platform/collector/`：`schema.sql`（5 张表）、`lwaf_collect.py`（约 430 行，Python 3 + `python3-pymysql`）、`config.ini` / `config.fixture.ini`、`lwaf-collector.service`、`selftest_10w.sh`、`README.md` |
| 机制 | 1 秒轮询；单批 ≤500 行；去重键 `source+file_identity(dev:ino)+generation+offset`；游标与数据行同事务推进；失败退避 1/2/5/10/30；rename+create 轮转；坏行进 `ingest_errors`；UTC 毫秒；磁盘 85%/95% |
| **验收（实测）** | ① F20 灌入：`requests=20`、`waf_events=5`、`errors=0`，`category_display` 正好 SQLi 3 / XSS 1 / CC 1，`body_bytes` 合计 20000；② 重跑幂等 0 行；③ 追加 2 行 → 22，`mv` 轮转后新文件从 0 读、旧游标停在 2869；④ **10 万行 5 秒采完（201 批）**；⑤ 常驻模式跑 3 秒 `kill -9`（当时已入库 107000），重启续采 13000 行补齐到 **120000 且无重复**，游标 `byte_offset = inode_size = 16263850` |

**新踩的坑**：
1. **MariaDB 11.8 客户端默认走 TLS**，本机 socket 连接报 `TLS/SSL error: tlsv1 alert internal error`，所有 `mariadb` 命令都要加 `--skip-ssl`。
2. `--once` 最初只跑「一轮」= 最多 500 行，看起来像漏采；已改成**循环到本轮 0 行为止**（初始导入与积压追平都靠它）。
3. `sudo -S mariadb < file` 的密码会被 `< file` 抢走 stdin，必须 `sudo bash -c 'mariadb ... < file'`。

### S3 后端与权限（7–9 天，R34-01/06/07 + R33 数据接口）— ✅ 已完成（2026-10-22）

| 项 | 内容 |
|---|---|
| 交付物 | Spring Boot **3.5.6**（VM 内 JDK 25，Maven 3.9，仅 web/jdbc/security/validation + mariadb-java-client + jjwt）；**不用 JPA**，口径直接写 SQL；`/api/stats/summary`、`/api/events`、`/api/events/{id}`、`/api/auth/{login,logout,me}`、`/api/health`；`users` 表 + BCrypt + Bearer JWT（30 分钟，HS384） |
| 锁死口径 | N=访问数、B=拒绝事件、ratio=B/N、QPS=窗口 N/秒数、P50/P95 **最近秩 `k=ceil(p×(n+1))`**、空值返回 null（前端显示"—"） |
| **验收（实测）** | ① F20 返回 **N=20、B=5、ratio=0.25、QPS=0.3333、P50=100、P95=190** 逐字段一致 ✅；② 拒绝耗时均值 300μs / P95 500μs ✅；③ viewer `POST /api/rules` 得 **403** ✅；④ 未登录 **401**、错误口令 401、连续 5 次失败后 **429**、登出后旧 token 401 ✅；⑤ 排序字段白名单 + 全参数化查询，`uri=1' OR '1'='1` 只当文本 ✅；⑥ 10 万行下首页聚合 **P95=53ms**（门槛 2 秒）✅ |
| 关键修正 | 卡片写的 `ceil(p×n)` 在 n=20 时 P50 落第 10 个（90ms）、P95 落第 19 个（180ms），与 F20 固定的 100/190 对不上；改为 `ceil(p×(n+1))` 后 P50=第 11、P95=第 20，完全吻合。已在 `StatsService.nearestRank` 写明理由 |
| 登录安全 | 不区分「用户不存在 / 口令错」统一 401（防账号探测）；同账号 5 次失败锁 15 分钟（内存计数，单机可接受） |
| 代码位置 | `platform/backend/`（约 900 行 Java，全中文注释）；账号初始化 `sql/users.sql` |

### S4 前端仪表盘（7–9 天，R33-01/03/04）✅ 已完成 2026-10-22

| 项 | 内容 |
|---|---|
| 交付物 | `platform/frontend/`：Vue 3.5 + Vite 7 + Pinia 3 + Router 4 + **ECharts 6.1**，手写 CSS 不引 UI 框架（约 2600 行，全中文注释）。页面（最终 7 个）：登录、总览、事件列表、事件详情、规则与 CC、告警、误报与调优、评估报告、性能与数据源 |
| 已完成范围 | ① 总览：4 张 KPI（请求数 / 拦截数 / 拦截占比 / 窗口平均 QPS）+ 访问拦截双轴趋势（**阶梯线**，按窗口自适应桶大小）+ 攻击类型分布（横向条形带数值，不只靠颜色）+ 响应耗时 4 卡（P50/P95、拦截处理耗时均值/P95）+ Top 攻击 IP / Top 被攻击 URI + 最近拦截事件表；② 事件列表：时间窗口 / IP / 类型 / URI 过滤、页码分页、列排序（time/ip/cost 白名单）；③ 事件详情：14 字段 + 同 IP 24 小时关联事件（CC 无规则名的显示「日志未记录」）；④ 登录态存 localStorage、Bearer 走头（无 CSRF 面）、401 自动踢回登录页 |
| 实测 | 切「演示数据（F20 固定集）」后页面显示 **20 / 5 / 25.0% / 0.3333 / 100ms / 190ms / 300μs / 500μs**，分类 SQLi 3、CC 1、XSS 1，Top IP 10.0.0.10=3，与 `/api/stats/summary` 完全一致；事件 5 条、分页 1/1；详情页同 IP 关联 2 条；接口自检 `scripts/api_check.py` **32/32 通过** |
| 截图 | `artifacts/` 下 6 张：`final-1366-dashboard.png`、`s4-dashboard-1366x1500.png`、`dash-1920-padded2.png`、`s4-events-1366.png`、`s4-event-detail-1366.png`、`dash-f20-1366-padded.png` |
| 前端坑 | ① Kali 无 node，apt 装包被 mirrorbrain 重定向到 DNS 挂掉的镜像 → 换清华源后拉到 Node 24.21 / npm 12.2；② npm 12 默认拦截 esbuild 的 postinstall，必须 `npm install-scripts approve esbuild` 再 rebuild，否则 vite 起不来；③ 后端只返回「有数据的桶」，曲线会连成斜线误导，前端按 `[from, to)` 补齐零值桶并用 `step: 'end'`；④ 改完源码必须 rsync 到 `/opt/litewaf/platform/frontend` 才被 Vite 看到（共享盘不是同一份） |
| 未做（后续阶段） | 周报/月报下载（R33-05，P1）、SSE 实时流（已降级为 10 秒轮询）。规则与 CC、告警、误报、评估、性能页在 S5–S9 已补齐，侧栏不再有灰显项 |
| 验收 | ① 1366×768 与 1920×1080 两档截图无溢出、无横向滚动（1920 下 KPI 一行 4 个，1366 下自动 2×2）；② 首页数字与接口一致（见上）；③ 断网/令牌失效显示错误态不白屏；④ 检索走索引，10 万行 20 次查询 P95 ≤ 3 秒（后端已测 53ms） |

### S5 配置发布闭环（7–9 天，R34-02/09/10/11 + R36-03 + R37-04）✅ 已完成 2026-10-22

| 项 | 内容 |
|---|---|
| 交付物 | 规则编辑页（表单 + 分类启停 + 样本预览）；`config_versions` 表；执行器 `engine-exec`（127.0.0.1、独立 token、只收 `check/publish/rollback/status`、不拼 shell） |
| 流程 | 编辑 → `check`（临时配置 + `nginx -t`）→ 通过才 `publish`（备份 + 原子替换 + reload）→ 失败自动 `rollback` |
| 取舍（对课件 7） | 选课件的**方案 1+2**：改配置 + `nginx -s reload`，外面套 `nginx -t` 预检和 `config_versions` 回滚。不选方案 3/4（共享内存热更、Redis 广播）——要改 C 模块、改动面大、验收证据难留；留作时间富余时的扩展项，且必须先过 S8 |
| **验收** | ① 坏配置（少分号）被 check 拦下、线上不受影响；② 正确配置发布后 5 秒内生效（阈值改动使样本结论翻转）；③ rollback 回到上一版 hash；④ 执行器收非法动作返回 400；⑤ 每次发布在 `operations` 留审计 |
| **实测** | 坏规则在第 82 行被精确拒绝（带文件与行号）；发布生成 v11，探测 marker=200 / 正常=200 / SQLi=403 三项通过；回退回到 v9；`operations` 记录 check/publish/rollback；`scripts/s5_api_check.py` 13/13 |

> 实现细节：`platform/executor/engine_exec.py` 只绑 127.0.0.1:18081，校验 `X-Executor-Token`，动作白名单四选一，参数以数组传给内部函数（不经过 shell）；规则文本先写 `candidates/`，`nginx -t` 用 `-p` 指向临时 prefix，发布时同目录原子 rename + `nginx -s reload` + 三次新连接探测，任一步失败自动回退上一版。

### S6 告警（4–6 天，R35-01~05）✅ 已完成 2026-10-22

| 项 | 内容 |
|---|---|
| 交付物 | 告警 worker（增量消费 + 断点）；`alert_rules`（固定时间桶）；抑制/合并；本地 webhook 接收器 `tools/webhook_sink.py`（127.0.0.1:9001 落文件）；`alerts/deliveries` 表 |
| **验收** | ① 回放 A5（10/20/30/40/50 秒各 1 事件、阈值 3、抑制 300 秒）→ `trigger=3 / event=5 / delivery=1`；② 抑制窗口内不新增 delivery；③ 接收器停掉后重试恢复、**不重复投递**（delivery_id 幂等）；④ 告警延迟 ≤70 秒 |
| **实测** | A5 场景 → `trigger_count=3 / event_count=5 / delivery_count=1`；Webhook 收到 1 条且 10 字段齐全；1 小时前事件只计 `skipped`；`scripts/s6_alert_test.py` 19/19 |
| 不做 | 邮件/公网通道、严格一次投递承诺 |

> 修过的两个坑：① 桶内计数上界要用「本条事件时间」而不是「桶结束时间」，否则批量补数会把后续事件算进前面的候选，`trigger_count` 被放大（5 而不是 3）；② 首次触发要把桶内已有事件全部补进关联表，否则 `event_count` 只从触发那条算起（3 而不是 5）。另外 `@Scheduled` 默认单线程，Webhook 重试（最长 5 秒）会把消费卡住，已配 2 线程调度池。

### S7 验收工具与文档（5–7 天，R36-01/04 + R37-01/02）✅ 已完成 2026-10-22

| 项 | 内容 |
|---|---|
| 交付物 | `accept.sh`（隔离实例 → 灌固定数据 → 逐项断言 → `report.json` + PASS/FAIL 表）；`/health` 四态；崩溃恢复演练；更新 8 份 docx（`tools/build_product_docs.py` 可直接改生成源） |
| **验收** | ① 干净环境一条命令 ≤10 分钟出 JSON 汇总；② kill 采集器/告警 worker 后重启数据补齐；③ 健康页故障注入四态变红；④ 验收记录按卡片模板（卡 ID/范围/配置 hash/测试集 hash/证据/结论）留档 |
| **实测** | `scripts/s7_accept.sh` 覆盖 7 个阶段（进程 → 引擎 200/403 → F20 落库幂等 → 接口 32 项 + 误报 28 项 + 评估接口 18 项 + 导出 13 项 → 发布闭环 13 项 → 告警 19 项 → 前端）：**15 项必选全绿 + 1 项跳过**。跳过的是「引擎 14 步验收」——它要独占 127.0.0.1:18010，运行态下被线上实例占着（系统的 `/usr/sbin/nginx -s quit` 不认 `lite_waf` 指令发不出信号），脚本如实记为 SKIP 并给出原因；该 14 步在 S0 阶段已单独跑通过（`FINAL ACCEPTANCE PASSED`，日志与实测数据见 S0 段）。`--skip-engine` 约 90 秒，全量约 5 分钟；任一必选失败退出码非 0 |

### S8 缓冲（5–8 天）✅ 已完成 2026-10-22

两轮全量验收、不同分辨率、冷启动、演示脚本、报告更新（含偏离说明：MariaDB 替代 MySQL、SSE→轮询、九类只承诺三类）。

| 项 | 内容 |
|---|---|
| **实测** | 一键验收 `--skip-engine` 两轮均 15 项全绿；1366×768 / 1920×1080 两档截图（`artifacts/` 23 张）；ECharts 升 6.1 后 `npm audit` 0 漏洞、richText tooltip 回归正常；`docs/使用说明.md`、`docs/工作报告.md` 定稿 |

### S9 运维六件套（答辩加分项，2–3 天）✅ 已完成 2026-10-22

原本是可选项，做下来发现这些"让系统看起来是活的"的东西，比再加一个功能页更能支撑现场演示。

| # | 项 | 交付物 | 实测 |
|---|---|---|---|
| 1 | 数据库备份/恢复 | `scripts/db_backup.sh`、`db_restore.sh`（自动保留 7 份，恢复前先安全备份） | 备份 2 秒；`--list` 可列历史 |
| 2 | 控制台静态托管 | `scripts/console_static.sh` + `nginx-static.conf`（18082，纯静态 + 反代 `/api`） | 首页/SPA 路由/接口全 200；不依赖 Node |
| 3 | 采集器健康 | `collector_status.json`（每轮刷新）+ `GET /api/collector` + 首页徽标 | 12/12 接口自检；rounds/ingested/errors/双路 lag 可见 |
| 4 | 性能与数据源页 | `ApiTimingInterceptor` + `GET /api/perf` + `/perf` 页 | 12/12；接口 P50/P95/最慢一次（最近 200 次） |
| 5 | 规则试打沙箱 | `POST /api/rules/test` + 规则页下方输入框 | 12/12；打 UNION SELECT 回「403 · sql keywords(1000) · SQLi · 4 分」，3 ms |
| 6 | 崩溃恢复演练 | `litewaf-runtime.service`（systemd）+ `scripts/s10_crash_drill.sh` | kill -9 后 **4.1 秒**自动拉起，页面重新出数 |

> 这一轮修掉两个**真实数据 bug**：① 审计日志 `$msec` 是秒级小数，解析后未乘 1000 落到 1970 年，导致「最近 24 小时」窗口请求数恒为 0；② `access.log` 清空过而 `waf_audit.log` 保留历史，两表不同步让「拦截占比」显示 7900%。已补 `scripts/s10_reset_data.sh` 一条命令恢复自洽，并写进使用说明的演示前检查项。

---

### 5.9 对照任务书与教师清单的自检（参考课件 1）

答辩前按课件 1 的"六问"逐条自答，答案位置即证据位置：

| 教师六问 | 本计划对应 | 证据 |
|---|---|---|
| ① 现在能拦哪些类型、每类多少条 payload | §4.3：只承诺 SQLi / XSS / RFI / 目录穿越 / 编码绕过 / 危险上传 / 扫描器 UA；规则集 **74 条（rules-v5）**，其中 SQLi 31 条、XSS 26 条、穿越 9 条，另含从 OWASP CRS 筛选移植的 28 条 | 201 条对抗样本：SQLi 49/50、XSS 50/50、正常误拦 0/101（`s8_eval.py`）；CRS 外部样本 2282 条检出 28.3%、误拦 8.14% |
| ② 某次拦截怎么找到日志、要多久 | S2 入库（`requests` + `waf_events`）+ S4 事件详情按 `event_id` 直达 | 页面「事件详情」按 id 打开；`/api/events/{id}` 实测单条查询 |
| ③ 今天拦了多少、哪类最多、来源哪 | S4 首页 + `/api/stats/*` | 页面数字与 SQL 直算一致（F20：20/5/25%/0.3333） |
| ④ 新加一条规则要多久 | S5：表单 → `check` → `publish`，探测三连通过即生效 | S5 13/13；规则页「规则试打」可先验证会不会误伤 |
| ⑤ 规则谁能改、谁改的 | R34-06 权限（ADMIN / VIEWER）+ `operations` 审计 | viewer 写操作 403、未认证 401、连续 5 次错口令 429；`operations` 记录 check/publish/rollback |
| ⑥ 流量打满怎么自动限流、怎么通知 | 引擎漏桶（`dev_2` 原样，容量/窗口/封禁可配）+ S6 固定桶阈值告警 + 本地 Webhook | CC 场景第 22 次 403（`s8_eval.py`）；A5 → trigger=3/event=5/delivery=1 |

**基线指标**（课件 1 要求）：准确率 100% / 漏报率 0% / 误报率 0%（80 条冻结样本，`s8_eval.py` 产出）/ 平均响应时间 P50 100ms、P95 190ms（F20）/ 拦截处理耗时均值 300µs / QPS 0.3333（F20 窗口）、soak 79.98 RPS / 引擎内存与 CPU 见 `docs/工作报告.md`。全部写进报告与答辩 PPT。

**文档补件**（课件 1 本周任务）：功能模块图、用例图、角色权限矩阵作为 S7 交付物；权限矩阵直接由 R34 的角色/接口清单生成表格。

**注 · 为什么不直接上 ELK/Filebeat**（对课件 6）：量级不匹配——本机可用内存 4.2 GB，ELK 三件套起不来；何况课件课后练习本身就要求"搭建采集客户端，采集日志写入 MySQL 或 ES，再做可视化仪表盘"，自研采集器（游标 + 去重 + 坏行隔离 + 断点）正好是这条要求，且验收证据（行数核对、断点恢复）比黑盒 ES 更硬。答辩时用倒排索引 / doc values 讲清"为什么小数据量选择 SQL 索引"即可。

---

## 6. 工时

| 范围 | 人日 |
|---|---|
| S0 基线复现 | 2–3 |
| S1 口径对齐 | 2–3 |
| S2 采集 | 7–9 |
| S3 后端 | 7–9 |
| S4 前端 | 7–9 |
| S5 发布闭环 | 7–9 |
| S6 告警 | 4–6 |
| S7 验收文档 | 5–7 |
| S8 缓冲 | 5–8 |
| S9 运维六件套（可选，已做） | 2–3 |
| **合计** | **≈48–66 人日**，单人 9–12 周（每周 5–6 天），三人 5–6 周 |

比 v1.0 降了约 8 人日，因为引擎侧（原 S1 的 5–7 天）已被 `dev_2` 覆盖。

**三人分工建议**（对应卡片 3 人设定）：A 前端可视化（S4 + S6 页面 + S7 截图）、B 后端与权限（S3 + S5 执行器）、C 引擎与数据（S0/S1/S2 + S6 worker + S7 验收）。

---

## 7. 风险与回退

| 风险 | 概率 | 对策 |
|---|---|---|
| VM 磁盘/环境损坏（已发生过一次坏块） | 中 | 源码与文档都留在共享盘（`D:\网安综设`），VM 只当工具链；重建 ≤1 小时（`kali_setup.sh` + `s0_build.sh` 两条命令恢复）；关机用 `sudo poweroff` |
| nginx 1.31.1 下载或编译失败 | 低 | `NGINX_VERSION=1.26.2` 覆盖；或直接用 Dockerfile 镜像构建 |
| MariaDB 与 JPA 并发写冲突 | 低 | 采集器与后端分表写、事务短、连接池 ≤10；≤10 万行无压力 |
| Spring Boot 依赖下载慢 | 中 | 预热 `~/.m2`；或用 JDK 17 + Spring Boot 2.7 |
| 固定数据集对不上 | 中 | 先写 `tools/gen_fixture.py` 生成并冻结 hash（S1 就做） |
| 单人时间不足 | 高 | 严格按 §4.2 砍 P2；S6/S7 可延到答辩前一周 |
| **跨表比例失真**（实际踩到） | 中 | `access.log` 与 `waf_audit.log` 不同步时「拦截占比」会算出 7900%；演示前先跑 `s10_reset_data.sh` 恢复自洽，再跑 `s10_final_check.sh` 确认 |
| **日志时间戳单位**（实际踩到） | 中 | nginx `$msec` 是秒级小数，采集时未乘 1000 会落到 1970 年，24 小时窗口恒为 0；已在 `lwaf_collect.py` 里统一 `round(float(...) * 1000)` |

**回退原则**：每阶段打 tag（`s2-collector-ok`…），失败即可 checkout 上一 tag；答辩固定用最近已验证 tag。

---

## 8. 交付物

1. `WAF-lite` 的 `platform` 分支（基于 `dev_2`）：`ngx_http_lite_waf_module/`、`src/`、`collector/`、`backend/`、`frontend/`、`executor/`、`scripts/`、`conf/`
2. `s7_accept.sh`（15 项必选）+ `evaluations/<run_id>/report.json`（8 项评估结论）
3. 固定数据集 F20 / A5 / R（生成脚本 + hash）
4. 更新后的 8 份 docx + 验收记录（12 章模板）
5. 数据字典 + 接口文档（每接口含 URL/方法/参数/返回示例/状态码）、功能模块图、用例图、角色权限矩阵
6. 演示视频 + 答辩 PPT
7. "已支持 / 未支持"能力清单（CSRF、防盗链、RFI 执行级如实标"未支持"）
8. 运维与演示脚本：`console_static.sh`（静态站）、`db_backup.sh`/`db_restore.sh`、`s10_crash_drill.sh`、`s10_reset_data.sh`、`s10_final_check.sh`
9. 截图证据：`artifacts/` 23 张（F20 口径、事件列表/详情、规则页、告警页、误报三指标、评估混淆矩阵、性能页、规则试打、静态站）

---

## 9. 完成清单与剩余项

1. ~~进 VM 跑两条命令~~ ✅ 已完成（2026-10-22）：`kali_setup.sh` 全绿 → `s0_build.sh` 四条 curl 200/403/403/403 → `run_final_acceptance.sh` **14 步全过**。
2. ~~S1 口径对齐~~ ✅ 已完成（2026-10-22）：`time` 改 UTC 毫秒、`cost_us` 语义明确、rules-v1 冻结（hash `6242ec7a…`）、14 步验收复跑仍 PASS；`docs/基线说明.md` 已落盘。
3. ~~`tools/gen_fixture.py`~~ ✅ 已完成：`fixtures/` 7 个文件 + `MANIFEST.json`（F20 / A5 / R 三套）。
4. ~~S2 采集器~~ ✅ 已完成（2026-10-22）：`platform/collector/`（Python 3 + pymysql，1 秒轮询、批 ≤500、游标去重、rename 轮转、退避）；5 张表；F20 → 20 访问/5 拒绝，10 万行 5 秒灌完，kill -9 后无重无漏。
5. ~~S3 后端与权限~~ ✅ 已完成（2026-10-22）：`platform/backend/` 统计/事件/登录接口全通；F20 数字逐字段对上（N=20/B=5/25%/0.3333/100/190）；401/403/429/token 失效全部实测通过；10 万行首页 P95=53ms。
6. ~~S4 前端~~ ✅ 已完成（2026-10-22）：`platform/frontend/`（Vue 3.5 + Vite 7 + Pinia 3 + ECharts 6.1）九个页面（登录/总览/事件列表/详情/规则与 CC/告警/误报与调优/评估报告/性能与数据源）；F20 页面数字 20/5/25.0%/0.3333/100/190/300/500 与接口逐项一致；`scripts/api_check.py` 32/32；1366×768 与 1920×1080 截图存 `artifacts/`。
7. ~~S5 发布闭环~~ ✅ 已完成（2026-10-22）：`platform/executor/engine_exec.py`（127.0.0.1:18081 + token + 四动作白名单）；规则页支持编辑/检查/发布/回退；坏规则第 82 行被拒，发布 v11 三项探测通过，回退 v9；`operations` 审计留痕；`s5_api_check.py` 13/13。
8. ~~S6 告警~~ ✅ 已完成（2026-10-22）：`alert_rules/alerts/alert_events/alert_deliveries/alert_consumer_cursor` 五表 + 每 2 秒消费 + 固定桶阈值 + 抑制合并 + 本地 Webhook + 重试/已处理；A5 场景 trigger=3/event=5/delivery=1；`s6_alert_test.py` 19/19；前端告警页上线。
9. ~~S7 一键验收与文档~~ ✅ 已完成（2026-10-22）：`scripts/s7_accept.sh` 七阶段；交付 `docs/使用说明.md`、`docs/工作报告.md`；补做三张 P0 后扩到 **15 项必选全绿 + 1 项 SKIP**（`--skip-engine` 90 秒跑完）。
10. ~~R34-10 误报标记与调优闭环~~ ✅ 已完成（2026-10-22）：`false_positive_marks` 表 + 事件页三按钮（确认误报/驳回/撤销）+「误报与调优」页三指标分名展示（确认占全部拦截 / 复核覆盖率 / 已复核误拦占比）；F20 口径 20%/40%/50%；`s8_fp_test.py` 28/28。
11. ~~R34-11 带标签评估~~ ✅ 已完成（2026-10-22，2026-10-24 扩样本复测）：`scripts/s8_eval.py`（TP/FN/FP/TN + FNR/FPR/准确率/精确率/召回率 + CC 场景）；平台新增 `/api/evaluations` 与「评估报告」页；**首跑暴露真问题**：SQLi 只检出 7/20，补 7 条 8 分规则后 v2 跑分 **TP=40 FN=0 FP=0 TN=41**。**2026-10-24 按用户要求把样本扩到 201 条对抗样本**（`scripts/s8_expand_samples.py` 追加 116 条，覆盖 URL 编码嵌套、大小写混淆、内联注释拆词、双写、长载荷、`UNION%0aSELECT`、CC 数连打、正常业务边界值），rules-v2 首测暴露 16 条漏报 + 2 条误报，升 rules-v3 后 **TP=96 FN=4 FP=0 TN=101**（准确率 98.01%），4 条漏报均为"裸 SQL 语句"型，根因是引擎按规则计分不按命中次数。
12. ~~R36-01 脱敏导出~~ ✅ 已完成（2026-10-22）：`GET /api/export`（JSONL / CSV，CSV 带 BOM 与公式注入防护），事件页两个导出按钮；上限 1 万行且超限报 400 带提示；`s8_export_test.py` 13/13。
13. ~~S9 运维六件套~~ ✅ 已完成（2026-10-22，答辩加分项）：`db_backup.sh`/`db_restore.sh`（自动保留 7 份、恢复前先安全备份）、控制台静态站 18082（`console_static.sh`，不依赖 Node，演示推荐）、采集器健康（`collector_status.json` + `/api/collector` + 首页徽标 + 「性能与数据源」页）、规则试打沙箱（`POST /api/rules/test`，真打实例回读命中规则，12/12）、崩溃恢复演练（systemd 守护，kill -9 后实测 **4.1 秒**自动拉起，`s10_crash_drill.sh`）。一键验收随之扩到 **15 项必选全 PASS + 1 SKIP**。
14. **剩下的可选项**：共享内存热更（免 reload）、多实例规则下发、R33-05 周月报、防盗链（Nginx Referer 策略）。详见 `docs/工作报告.md` 第十节。


---

## 10. 变更记录

| 版本 | 日期 | 内容 |
|---|---|---|
| v1.0 | 2026-10-21 | 初版：基于 `dev_2` 盘点与环境方案 A/B/C |
| v1.1 | 2026-10-21 | 按 `dev_2` 完整版重写：引擎侧已完成，工作量全在平台化；裁剪表与阶段表按实际代码重排 |
| v1.2 | 2026-10-21 | 补四份课件（1/3/6/7）对照：接口口径、规则加载方案取舍、教师六问自检 |
| v1.3 | 2026-10-21 | 环境改「方案 D：VMware + Kali」；新增 3.5 节；脚本与路径按 VM 重写 |
| v1.4 | 2026-10-22 | S0 全绿实测入库（含 `config` CRLF、`libcrypt-dev`、`curl` UA 三条坑）；S1 完成并修正两处判断（不加 `event_id`、`category` 映射放适配层）；`fixtures/` 冻结 |
| v1.5 | 2026-10-22 | S2 采集器完成（5 表 + 游标去重 + rename 轮转，10 万行 5 秒、kill -9 无重无漏）；S3 后端完成（统计/事件/鉴权全通）；**修正分位数公式** `ceil(p×n)` → `ceil(p×(n+1))`（否则 F20 的 100/190 对不上）；记录 `pymysql ssl_disabled` 与 `--skip-ssl` 两条新坑 |
| v1.6 | 2026-10-22 | S4 前端完成（登录/总览/事件列表/详情四页，F20 数字逐项一致，`api_check.py` 32/32，`artifacts/` 6 张截图）；补 `trend`/`recent` 两个接口与参数校验 400；记录 Node 换源、npm 12 拦 esbuild、共享盘未 rsync 三条前端坑 |
| v1.7 | 2026-10-22 | S5 发布闭环（执行器 + 规则页 + 版本/回退 + `operations` 审计，`s5_api_check.py` 13/13）、S6 告警（五表 + 2 秒消费 + 固定桶 + 抑制 + Webhook，`s6_alert_test.py` 19/19）、S7 一键验收（`s7_accept.sh` 七阶段 11 项全绿）；交付 `docs/使用说明.md` 与 `docs/工作报告.md` |
| v1.8 | 2026-10-22 | 补做三张 P0：R34-10 误报闭环（三指标分名，`s8_fp_test.py` 28/28）、R34-11 带标签评估（首跑 SQLi 7/20 → 补规则 → **40/0/0/41**，平台新增评估接口与页面）、R36-01 脱敏导出（JSONL/CSV + 1 万行上限 + 公式注入防护，`s8_export_test.py` 13/13）；规则集升 **rules-v2**（29 条，走 check→publish 流程发布 v20，v1 可回退）；ECharts 5.6 → **6.1**（`npm audit` 0 漏洞，`richText` tooltip 规避 XSS 公告，轴标签改 `hideOverlap`） |
| v1.9 | 2026-10-22 | S9 运维六件套落地：数据库备份/恢复、控制台静态站（18082）、采集器健康（`collector_status.json` + `/api/collector`）、性能与数据源页（`/api/perf`，接口 P50/P95）、规则试打沙箱（`/api/rules/test`）、崩溃恢复演练（systemd 自动拉起实测 4.1 秒）；修两处真实数据 bug（审计日志 `$msec` 秒级未乘 1000 导致 24 小时窗口请求数为 0；access/audit 不同步导致拦截占比 7900%）；一键验收扩到 **15 项必选全 PASS**；新增截图 `artifacts/s10-*.png` |
| **v2.0** | 2026-10-24 | **对抗样本复测**：样本从 80 条扩到 **201 条**（`s8_expand_samples.py`，含编码嵌套/大小写混淆/内联注释拆词/双写/长载荷/`UNION%0aSELECT`/CC 数连打/正常业务边界值）；rules-v2 首测 **TP=84 FN=16 FP=2 TN=99**（暴露 `?user=guest` 误报、正常富文本被 `<[^>]+>` 打死）；修误报后 91/9/0/101；**升 rules-v3（38 条）**——补 1017 关键字拆词、1018 MySQL 版本注释、1019 and/or 比较式，1307 DOM 汇点 6→8 分，1302 补 `onstart/onpointerover`，1005 加 `union\s+(all\s+)?select`、1000 加 `using/limit`——终测 **TP=96 FN=4 FP=0 TN=101**（准确率 98.01%）。**记录三条引擎机制限制**：① 按规则计分不按命中次数（同规则命中两次只算一次分）→ 裸 SQL 语句拦不住；② CC 封禁会误伤规则发布的三次探测（评估后须等 70 秒或重启实例）；③ 试打接口对含空格/括号的 URI 返回 500（未 URL 编码） |
| **v2.1** | 2026-10-24 | **两项引擎优化（① ⑪）**：① 打分器改为**按命中次数计分**（`LWAF_MAX_HITS_PER_RULE=3`，新增 `lwaf_rule_match_count()`），裸 SQL 语句 `/?id=1 SELECT * FROM users` 由 200 变 403；⑪ 新增 `lite_waf_max_body_bytes`（默认 8192），请求体超限直接 **413 + `reason=body_too_large`**，堵住"垫 8KB 填充绕过检测"。201 条样本复测 **TP=98 FN=2 FP=0 TN=101（准确率 99.00%，SQLi 48/50、XSS 50/50）**，14 步验收仍 `FINAL ACCEPTANCE PASSED`，代价是 soak P95 989→3076 µs（79.97 RPS 下仍有约 30 倍余量）。新增 `s11_rebuild_engine.sh` / `s11_score_test.sh` / `s11_body_test.sh` / `s11_engine_check.sh`；`docs/基线说明.md` 补 §2.3 打分机制、§2.4 body 上限与坑 7–9 |
| **v2.2** | 2026-10-24 | **三项运维强化（1/2/4）**：① **日志轮转 + 数据保留**——`/etc/logrotate.d/litewaf` 每天 04:00、保留 7 份、超 20M 提前轮转、压缩，用 `copytruncate`（rename 会让采集器丢未读行），配 `litewaf-retain` 每日清 30 天前数据；因 `logs/` 收紧成 root:root 755，采集器心跳迁到新目录 `/opt/litewaf/state`。② **密钥外置**——`application.yml` 改 `${LITEWAF_JWT_SECRET:默认}` / `${LITEWAF_DB_PASSWORD:默认}`，启动加 `--preserve-env`（不加会被 sudo 清空），实测注入随机密钥后 `/proc/<pid>/environ` 可见、登录仍 200。④ **SSE 实时推送**——新增 `/api/stats/stream`（2 秒一帧，只推 recent + latest_id），EventSource 不能带 header 故 token 走 query 但 `JwtAuthFilter` **只对该路径**放行；前端断线 5 秒重连、失败退回 10 秒轮询，徽标显示「实时 / 轮询兜底」；实测新拦截 **3 秒内**自动出现在首页。新增 `s12_logrotate.sh` / `s12_restart.sh` / `s12_backend_rebuild.sh` / `s12_envtest.sh` / `s12_sse_test.sh` / `s12_front_rebuild.sh` / `s12_live_ping.sh`；顺带修 F20 校验在运行态下的假失败（常驻采集器并发写入，改成校验期间 `SIGSTOP` 挂起） |
| **v2.3** | 2026-10-24 | **引擎代码评审后的 6 处改动（性能 + 正确性）**：① CC 表满改为「回收已过期且最久未见」的槽位（原 `stats[now % 4096]` 同秒互相覆盖，可用 IP 池绕过 CC）；② **CC 漏水改毫秒精度**（`lwaf_ip_stat_t` 尾部加 `last_seen_ms`，跨秒不再白送 1 秒排水量，`D021/D022` 用例由偶发放行变稳定 403）；③ 审计日志路径 `merge_loc_conf` 解析一次 + `log_fd` 常驻 O_APPEND（去掉每条日志的 `ngx_conf_full_name` 与 open/close）；④ pcre2 match_data 进程内复用（38 条规则不再各 create/free）；⑤ 命中即判阈值提前退出；⑥ `lwaf_rule_match` 复用 `lwaf_rule_match_count`。**实测：ab 正常 13969→22786 RPS（+63%）、ab 攻击 12766→18947 RPS（+48%）、soak P95 3076→1395 µs（−55%）、P99 7208→2219 µs（−69%）；14 步验收 PASSED、201 条样本 TP98/FN2/FP0/TN101 不变**。`基线说明.md` 补 §4.2 复跑数据与坑 10–12、新增 §7 优化记录 |

| **v2.4** | 2026-11-02 | **用 OWASP CRS 公开样本压测规则（回应「样本量太少、容易过拟合」）**：从 `coreruleset-main.zip` 的 357 个回归 YAML 抽出 **2282 条攻击 + 676 条正常**样本（`s14_extract_crs.py`）；因 Windows 无 PCRE2，在 Kali 编离线评估器 `tools/lwaf_eval.c`（直接加载规则调引擎，**500 条/秒**）批量跑（`s14_bulk_eval2.py`）。**基线（38 条）全体检出 25.4% → 现在（74 条）28.3%**；三族：SQLi 32.2%→36.0%、XSS 49.8%→61.7%、穿越 31.3%→32.8%；误拦 8.73%→**8.14%**。补规则不是照抄：`s14_crs2rules.py` 抽 54 条 `@rx`，`s14_promote_crs.py` 逐条拿正常样本试误报、**零误报才留**（54 留 28）。**修掉 5 个真实误报**：1100 `https?://` 降 4 分改由 1102「危险参数名+scheme」把门；1200 改 `\.\.[\/]`（并要求规则文件里反斜杠写两份）；1303 排除 `<?xml`；删 1308（误吃 base64 的 `%3D`）；删 9005 的 `if(` 分支（正常表达式 `if(x<10,y,z)` 被误拦）。**201 条自建样本回归 TP=99 FN=1 FP=0 TN=101（99.50%）**、14 步验收 PASSED。规则集升 **rules-v5（74 条，sha256 `a436eda6…`）**。**已知局限**：URL path 不解码（`/post/1234%20OR%201=1` 这类漏）、RCE/PHP 注入不覆盖（占 CRS 样本 49%）、`x=https?` 这类无参数名的裸 scheme 不拦（避免正常业务传 URL 误伤） |
---

*本计划书基于 2026-10-22 实测与 `dev_2` 分支实际情况编制；数值口径引用需求卡片第七章，若卡片修订以原文为准。*
