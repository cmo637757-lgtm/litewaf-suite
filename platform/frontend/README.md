# LiteWAF 控制台（前端）

Vue 3 + Vite + Pinia + Vue Router + ECharts。没有引 UI 框架——页面结构简单，手写 CSS 反而更可控，也少一层构建体积。

当前依赖（`package-lock.json` 已锁定，换机器请用 `npm ci`）：

| 包 | 版本 | 说明 |
|---|---|---|
| vue | 3.5.44 | |
| vue-router | 4.6.4 | |
| pinia | 3.0.4 | |
| **echarts** | **6.1.0** | 6.1.0 起修掉了 5.x 的 tooltip XSS（GHSA-fgmj-fm8m-jvvx） |
| vite | 7.3.7 | |
| @vitejs/plugin-vue | 6.0.10 | |

> 图表 tooltip 在 `EChart.vue` 里被强制成 `renderMode: 'richText'`（画在 canvas 上，不写 innerHTML）。
> 原因：图上展示的 IP / URI / 类型全部来自被防护站点的日志，是攻击者可控字符串；
> 换成 canvas 渲染后，即便哪天换了还有漏洞的版本也不会被注入。改这块前请先看 `EChart.vue` 的注释。

## 目录

```
src/
├── api/http.js            薄封装：带 token、解析统一错误体、401 清登录态
├── stores/auth.js         登录态（内存 + localStorage，Bearer token 不走 Cookie）
├── router/index.js        路由与守卫（未登录→/login；已登录访问 /login→首页）
├── components/EChart.vue  ECharts 封装（自动 resize、option 变化整体替换）
├── views/
│   ├── LoginView.vue      登录
│   ├── DashboardView.vue  总览：KPI / 趋势 / 分类 / 耗时 / Top IP·URI / 最近拦截
│   ├── EventsView.vue     事件列表：过滤 + 分页 + 排序
│   └── EventDetailView.vue 事件详情 + 同 IP 24 小时关联
├── App.vue                外壳：侧栏 + 顶栏
└── styles.css             深色主题（CSS 变量）
```

## 开发

```bash
# 1) 后端要先在 18080 跑起来（见 ../backend/README.md）
# 2) 装依赖并起开发服务器
npm ci --registry=https://registry.npmmirror.com   # 有 lock 文件时用 ci，装出来与验收时完全一致
npm run dev            # http://<本机IP>:5173，/api 由 vite proxy 转到 18080
```

> npm 12 会拦住 esbuild 的 postinstall 脚本，第一次装完要执行：
> `npm install-scripts approve esbuild && npm rebuild esbuild`，否则 `vite` 报找不到 esbuild 二进制。

## 构建

```bash
npm run build          # 产物在 dist/
```

Dashboard 这一个 chunk 约 1 MB（ECharts 全量引入）。要压体积可以把 `import * as echarts` 换成按需引入（`echarts/core` + 用到的图表/组件），当前不是瓶颈。

## 口径

- **时间窗口统一闭开区间 `[from, to)`**，毫秒时间戳，显示时转本地时区（Asia/Shanghai）。
- **KPI**：请求数 = `requests` 表行数；拦截数 = `waf_events` 表行数；占比 = 拦截 ÷ 请求；QPS = 请求 ÷ 窗口秒数。
- **趋势**：后端只返回有数据的桶，前端按窗口补零，并用阶梯线（`step: 'end'`）避免把「桶内计数」画成连续曲线。
- **分页**：`items / total / page / page_size / as_of`，排序字段走白名单 `time|ip|cost`。
- **演示数据**：下拉里「演示数据（F20 固定集）」对应 2026-09-20 16:00:00 CST 起 60 秒的固定集，用来复核 N=20 / B=5 / 25% / QPS 0.3333 / P50 100 / P95 190 / 300μs / 500μs。

## 已知限制

- 侧栏「规则与 CC」「告警」是灰显占位（S5/S6 才做），不出现点进去空白的页面。
- 实时性是 10 秒轮询（可选自动刷新），没有 SSE/WebSocket。
- 「最近拦截事件」是全局最近 8 条，不受顶部时间窗口限制（标题已注明）。
