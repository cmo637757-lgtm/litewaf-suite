# LiteWAF 平台后端（S3）

Spring Boot 3.5.6 + JDK 25 + MariaDB。只做三件事：**算对统计口径**、**查得动事件**、**管得住权限**。

> 设计上刻意不引 JPA / Lombok / MyBatis：统计口径本身就是 SQL，中间少一层转换，
> 就少一个「口径对不上」的地方；依赖少，排错时咖啡都少喝两杯。

## 目录

```
backend/
├── pom.xml
├── sql/users.sql                 # 账号表 + 初始账号（BCrypt 哈希，无明文）
└── src/main/java/com/litewaf/platform/
    ├── PlatformApplication.java
    ├── stats/                    # 首页聚合：KPI / 趋势 / Top
    ├── events/                   # 事件检索与详情
    ├── auth/                     # 登录、登出、账号读写
    ├── security/                 # JWT 签发校验、过滤器、限流、权限规则
    ├── error/                    # 统一错误体
    └── health/                   # /api/health
```

## 启动

```bash
# 1) 建账号表（只需一次）
sudo mariadb --skip-ssl litewaf < sql/users.sql

# 2) 编译
mvn -B package -DskipTests

# 3) 运行（默认 18080，连接 127.0.0.1:3306/litewaf）
java -jar target/platform-0.1.0.jar
```

## 初始账号

| 账号 | 口令 | 角色 | 能做什么 |
| --- | --- | --- | --- |
| admin | `LiteWaf@2026` | ADMIN | 全部读写：改规则、改 CC 参数、发布、回退、标误报 |
| viewer | `Viewer@2026` | VIEWER | 只读：看统计、看事件列表与详情 |

口令在库里只存 BCrypt 哈希。**部署后请立即改掉这两个口令**：

```sql
-- 先生成新哈希：python3 -c "import bcrypt;print(bcrypt.hashpw(b'新口令', bcrypt.gensalt(10)))"
UPDATE users SET password_hash='<新哈希>' WHERE username='admin';
```

## 接口（S3 已完成部分）

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| POST | `/api/auth/login` | 公开 | 返回 `token`、`role`、`expires_in` |
| POST | `/api/auth/logout` | 登录 | token_version+1，该账号旧 token 全失效 |
| GET | `/api/auth/me` | 登录 | 当前身份 |
| GET | `/api/stats/summary` | ADMIN/VIEWER | 首页聚合，窗口 `[from,to)` UTC 毫秒 |
| GET | `/api/events` | ADMIN/VIEWER | 事件检索，支持 from/to/ip/category/uri/page/page_size/sortby/order |
| GET | `/api/events/{id}` | ADMIN/VIEWER | 事件详情（14 字段） |
| GET | `/api/health` | 公开 | 200 + `config_marker` |

> 写接口（规则、CC、发布、回退、标误报）统一走 `POST /api/**` → 只允许 ADMIN，
> 新加的写接口默认就受保护，不需要逐个补授权。

## 统计口径（验收锚点）

固定数据集 F20：`2026-09-20T00:00:00Z ~ 00:01:00Z`，20 次访问 / 5 次拦截。

```bash
curl 'http://127.0.0.1:18080/api/stats/summary?from=1789862400000&to=1789862460000'
```

必须得到：

```json
{"window":{"seconds":60},"kpi":{"n":20,"b":5,"ratio":0.25,"qps":0.3333},
 "latency":{"request_p50_ms":100.0,"request_p95_ms":190.0,
            "reject_cost_mean_us":300.0,"reject_cost_p95_us":500.0},
 "categories":[{"key":"SQLi","count":3},{"key":"CC","count":1},{"key":"XSS","count":1}],
 "top_ips":[{"key":"10.0.0.10","count":3},{"key":"10.0.0.20","count":1},{"key":"10.0.0.30","count":1}]}
```

**分位数算法**：最近秩，`k = ceil(p × (n+1))`，1 起算。n=20 时 P50 取第 11 个、
P95 取第 20 个，正好对上固定数据集的 100ms / 190ms。用 `k = p×n` 会得到 90/180，对不上。

## 性能

10 万行（`gen_big.py` 生成）下首页聚合 20 次查询：

```
n=20 min=0.045s p50=0.049s p95=0.053s max=0.054s
```

远低于卡片 10.1 的「首页 P95 ≤ 2 秒」。

## 鉴权验证

```bash
bash /opt/litewaf/platform/backend/../../scripts/s3_auth_test.sh   # 或 /tmp/a.sh
```

| 场景 | 期望 | 实测 |
| --- | --- | --- |
| 未认证访问 `/api/stats/summary` | 401 | 401 |
| admin 登录后访问 | 200 | 200 |
| viewer 读 `/api/events` | 200 | 200 |
| viewer POST `/api/rules` | 403 | 403 |
| 错误口令 | 401 | 401 |
| 登出后旧 token | 401 | 401 |
| 连续 5 次错误口令后第 6 次 | 429 | 429 |
| `/api/health` | 200 + marker | 200 |

## 已知限制

- 登录失败计数在内存里，重启清零（单实例部署可接受）。
- JWT 密钥写在 `application.yml`，生产必须换成随机值（`openssl rand -base64 48`）。
- 一个进程只服务一个站点，不做多租户（卡片已裁定）。
- 首页只查热数据窗口，不做跨天报表（报表是 P1 卡片，暂不排期）。
