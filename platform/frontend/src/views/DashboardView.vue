<script setup>
/**
 * 总览页：一张图看懂“现在什么情况”。
 *
 * 布局按需求卡片的顺序：
 *   第一行 4 个 KPI（请求数 / 拦截数 / 拦截占比 / 窗口平均 QPS）
 *   第二行 趋势 2/3 + 分类 1/3
 *   第三行 Top IP 与 Top URI 各一半
 *   底部 最近拦截事件表
 *
 * 数据源只有三张表：requests（全部访问）、waf_events（WAF 判定为拦截的）、
 * 都是采集器每秒从 JSONL 日志里落进来的真实数据，不是假数字。
 */
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { api, fmtClock, fmtNum, fmtTime } from '../api/http'
import EChart from '../components/EChart.vue'

const router = useRouter()

// F20 固定验收数据的窗口（2026-09-20 16:00:00 CST，共 60 秒）
const F20_FROM = 1789862400000
const F20_TO = 1789862460000

const PRESETS = [
  { key: '5m', label: '最近 5 分钟', ms: 5 * 60 * 1000 },
  { key: '1h', label: '最近 1 小时', ms: 60 * 60 * 1000 },
  { key: '24h', label: '最近 24 小时', ms: 24 * 60 * 60 * 1000 },
  { key: 'f20', label: '演示数据（F20 固定集）', from: F20_FROM, to: F20_TO }
]

const preset = ref('24h')
const loading = ref(false)
const error = ref('')
const autoRefresh = ref(true)

const summary = ref(null)
const trend = ref([])
const recent = ref([])
// 采集器心跳：null=还没查到（不显示），对象=有结果
const collector = ref(null)
const totalLag = computed(() =>
  (collector.value?.sources || []).reduce((a, s) => a + (s.lag_bytes || 0), 0)
)

let timer = null

function window() {
  const p = PRESETS.find((x) => x.key === preset.value) || PRESETS[2]
  if (p.from) return { from: p.from, to: p.to }
  const to = Date.now()
  return { from: to - p.ms, to }
}

async function load(silent = false) {
  const { from, to } = window()
  if (!silent) loading.value = true
  error.value = ''
  try {
    // 三个接口互不依赖，并行拉
    const [s, t, r] = await Promise.all([
      api(`/api/stats/summary?from=${from}&to=${to}`),
      api(`/api/stats/trend?from=${from}&to=${to}&bucket_s=${bucketSeconds(from, to)}`),
      api('/api/stats/recent?limit=8')
    ])
    // 采集器心跳单独拉，失败不阻塞看板（顶多状态点不显示）
    api('/api/collector/status').then((c) => { collector.value = c }).catch(() => {})
    // 后端只返回"有数据的桶"，但曲线要连续，所以前端按 [from, to) 补齐零值桶，
    // 否则两个点之间连一条直线，看着像"访问量一路下降"，其实只是没数据。
    const bucketMs = bucketSeconds(from, to) * 1000
    const got = new Map((t.points || []).map((p) => [p.t, p]))
    const filled = []
    for (let ts = Math.floor(from / bucketMs) * bucketMs; ts < to; ts += bucketMs) {
      filled.push(got.get(ts) || { t: ts, n: 0, b: 0 })
    }
    summary.value = s
    trend.value = filled
    recent.value = r.items || []
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

// 桶大小按窗口自适应：目标 60 个点左右，最少 10 秒（卡片限制）
function bucketSeconds(from, to) {
  const span = (to - from) / 1000
  return Math.max(10, Math.ceil(span / 60 / 10) * 10)
}

const kpi = computed(() => summary.value?.kpi || { n: 0, b: 0, ratio: 0, qps: 0 })
const latency = computed(() => summary.value?.latency || {})
const categories = computed(() => summary.value?.categories || [])
const topIps = computed(() => summary.value?.top_ips || [])
const topUris = computed(() => summary.value?.top_uris || [])

const ratioPercent = computed(() => (kpi.value.ratio * 100).toFixed(1) + '%')

const trendOption = computed(() => {
  const labels = trend.value.map((p) => fmtClock(p.t))
  const maxN = Math.max(1, ...trend.value.map((p) => p.n))
  return {
    backgroundColor: 'transparent',
    grid: { left: 44, right: 44, top: 34, bottom: 28 },
    tooltip: { trigger: 'axis' },
    legend: { data: ['访问数', '拦截数'], textStyle: { color: '#8b98a5' }, top: 0, right: 0 },
    xAxis: {
      type: 'category',
      data: labels,
      axisLine: { lineStyle: { color: '#2a3542' } },
      axisLabel: {
        color: '#6b7785', fontSize: 11,
        // 24 小时窗口有 60 个桶，全画出来会糊成一片；hideOverlap 在 6.1 上
        // 对这个场景不够稳，改成按桶数显式抽稀：最多显示 8 个标签。
        interval: labels.length > 12 ? Math.ceil(labels.length / 8) : 0,
        hideOverlap: true,
        rotate: labels.length > 12 ? 35 : 0
      }
    },
    yAxis: [
      {
        type: 'value',
        name: '访问',
        nameTextStyle: { color: '#6b7785', fontSize: 11 },
        splitLine: { lineStyle: { color: '#1e2731' } },
        axisLabel: { color: '#6b7785' }
      },
      {
        type: 'value',
        name: '拦截',
        nameTextStyle: { color: '#6b7785', fontSize: 11 },
        splitLine: { show: false },
        axisLabel: { color: '#6b7785' }
      }
    ],
    series: [
      {
        name: '访问数',
        type: 'line',
        // 阶梯线：时间桶是「这个区间内发生了多少」，不是连续函数，斜线会误导
        step: 'end',
        showSymbol: false,
        smooth: false,
        data: trend.value.map((p) => p.n),
        lineStyle: { color: '#3b82f6', width: 2 },
        itemStyle: { color: '#3b82f6' },
        areaStyle: { color: 'rgba(59,130,246,0.12)' }
      },
      {
        name: '拦截数',
        type: 'line',
        yAxisIndex: 1,
        step: 'end',
        showSymbol: false,
        data: trend.value.map((p) => p.b),
        lineStyle: { color: '#ef4444', width: 2 },
        itemStyle: { color: '#ef4444' }
      }
    ],
    // 副轴的最大值给主轴的 1/4，免得拦截图被压成一条直线看不见
    dataZoom: []
  }
})

// 分类：横向条形 + 直接标数字，不依赖颜色辨别（卡片要求不得只靠颜色表达）
const categoryOption = computed(() => {
  const rows = categories.value.slice(0, 6).slice().reverse()
  return {
    backgroundColor: 'transparent',
    grid: { left: 78, right: 44, top: 8, bottom: 8 },
    tooltip: { trigger: 'item' },
    xAxis: { type: 'value', splitLine: { lineStyle: { color: '#1e2731' } }, axisLabel: { color: '#6b7785' } },
    yAxis: {
      type: 'category',
      data: rows.map((c) => c.key),
      axisLine: { lineStyle: { color: '#2a3542' } },
      axisLabel: { color: '#c9d4df' }
    },
    series: [
      {
        type: 'bar',
        barWidth: 14,
        data: rows.map((c) => c.count),
        label: { show: true, position: 'right', color: '#e6edf3', formatter: '{c}' },
        itemStyle: { color: '#f59e0b', borderRadius: [0, 3, 3, 0] }
      }
    ]
  }
})

function maxOf(list, key = 'count') {
  return Math.max(1, ...list.map((x) => x[key]))
}

function tagClass(cat) {
  if (cat === 'SQLi') return 'tag sql'
  if (cat === 'XSS') return 'tag xss'
  if (cat === 'CC') return 'tag cc'
  return 'tag other'
}

function openEvent(row) {
  router.push('/events/' + row.id)
}

watch(preset, () => load())

// ---- 实时推送（SSE）----
// 连上就每 2 秒收一帧「最近 8 条 + 最新事件 id」；id 变了才回头拉一次全量，
// 没变化就零开销。连不上（或后端重启）自动退回 10 秒轮询，不让页面卡死。
let stream = null
let reconnectTimer = null
let lastEventId = 0
const streamState = ref('off') // off | connecting | live

function streamToken() {
  try {
    return JSON.parse(localStorage.getItem('litewaf.auth') || '{}').token || ''
  } catch {
    return ''
  }
}

function closeStream() {
  clearTimeout(reconnectTimer)
  reconnectTimer = null
  if (stream) {
    stream.close()
    stream = null
  }
  streamState.value = 'off'
}

function connectStream() {
  const token = streamToken()
  if (!token || stream) return
  streamState.value = 'connecting'
  stream = new EventSource(`/api/stats/stream?token=${encodeURIComponent(token)}`)

  stream.addEventListener('tick', (ev) => {
    streamState.value = 'live'
    let d
    try {
      d = JSON.parse(ev.data)
    } catch {
      return
    }
    recent.value = d.recent || []
    if (d.latest_id && d.latest_id !== lastEventId) {
      lastEventId = d.latest_id
      load(true)
    }
  })

  stream.onerror = () => {
    closeStream()
    // 5 秒后重连；期间靠轮询兜底
    reconnectTimer = setTimeout(connectStream, 5000)
  }
}

watch(autoRefresh, (on) => {
  if (on) connectStream()
  else closeStream()
})

onMounted(() => {
  load()
  if (autoRefresh.value) connectStream()
  // 兜底轮询：SSE 正常时这一路基本空转，断线时才真正补数据
  timer = setInterval(() => {
    if (autoRefresh.value && streamState.value !== 'live') load(true)
  }, 10000)
})

onBeforeUnmount(() => {
  clearInterval(timer)
  closeStream()
})
</script>

<template>
  <div>
    <div class="toolbar">
      <select v-model="preset">
        <option v-for="p in PRESETS" :key="p.key" :value="p.key">{{ p.label }}</option>
      </select>
      <button :disabled="loading" @click="load">{{ loading ? '加载中…' : '刷新' }}</button>
      <label class="muted" style="display: flex; align-items: center; gap: 6px">
        <input v-model="autoRefresh" type="checkbox" style="width: auto" />
        实时推送
      </label>
      <span
        v-if="autoRefresh"
        class="chip"
        :class="streamState === 'live' ? 'chip-ok' : 'chip-bad'"
        :title="streamState === 'live' ? 'SSE 已连接，新拦截会实时滚进下面的表' : 'SSE 未连上，每 10 秒轮询一次兜底'"
      >{{ streamState === 'live' ? '实时' : streamState === 'connecting' ? '连接中' : '轮询兜底' }}</span>
      <!-- 采集器是独立进程，挂了页面数字只会停涨，肉眼看不出来；这里给个显式心跳 -->
      <span
        v-if="collector"
        class="chip"
        :class="collector.alive ? 'chip-ok' : 'chip-bad'"
        :title="collector.hint"
      >
        <i class="dot"></i>
        {{ collector.alive
          ? '采集器正常'
          : '采集器停更 ' + Math.round((collector.age_ms || 0) / 1000) + ' 秒' }}
      </span>
      <span v-if="collector && collector.sources && collector.sources.length" class="muted" style="font-size: 12px">
        积压 {{ fmtNum(totalLag) }} 字节
      </span>
      <span
        v-if="summary"
        class="muted"
        style="margin-left: auto; font-size: 12px; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap"
      >
        窗口 {{ fmtTime(summary.window.start_ms) }} — {{ fmtTime(summary.window.end_ms) }}
        （{{ summary.window.seconds }} 秒，闭开区间）
      </span>
    </div>

    <div v-if="error" class="err">{{ error }}</div>

    <!-- 第一行：4 个 KPI -->
    <div class="grid-kpi">
      <div class="kpi">
        <div class="label">总请求数（窗口内）</div>
        <div class="value">{{ fmtNum(kpi.n) }}</div>
        <div class="hint">来自源站访问日志全部记录</div>
      </div>
      <div class="kpi danger">
        <div class="label">WAF 拦截数</div>
        <div class="value">{{ fmtNum(kpi.b) }}</div>
        <div class="hint">被判定为攻击并拦截的请求</div>
      </div>
      <div class="kpi">
        <div class="label">拦截占比</div>
        <div class="value">{{ ratioPercent }}</div>
        <div class="hint">拦截数 ÷ 总请求数</div>
      </div>
      <div class="kpi">
        <div class="label">窗口平均 QPS</div>
        <div class="value">{{ kpi.qps.toFixed(4) }}</div>
        <div class="hint">总请求数 ÷ 窗口秒数</div>
      </div>
    </div>

    <!-- 第二行：趋势 + 分类 -->
    <div class="grid-main">
      <div class="panel">
        <div class="panel-title">
          <span>访问与拦截趋势</span>
          <span class="muted" style="font-size: 11px">按固定时间桶聚合（点 = 一个桶）</span>
        </div>
        <EChart :option="trendOption" height="250px" />
      </div>
      <div class="panel">
        <div class="panel-title">攻击类型分布</div>
        <EChart v-if="categories.length" :option="categoryOption" height="250px" />
        <div v-else class="empty">窗口内没有拦截事件</div>
      </div>
    </div>

    <!-- 响应耗时：卡片 R33-06 的口径，放在显眼处便于验收 -->
    <div class="grid-kpi" style="grid-template-columns: repeat(4, minmax(0, 1fr))">
      <div class="kpi">
        <div class="label">请求耗时 P50</div>
        <div class="value">{{ latency.request_p50_ms ?? '-' }}<span class="unit">ms</span></div>
      </div>
      <div class="kpi">
        <div class="label">请求耗时 P95</div>
        <div class="value">{{ latency.request_p95_ms ?? '-' }}<span class="unit">ms</span></div>
      </div>
      <div class="kpi">
        <div class="label">拦截处理耗时 均值</div>
        <div class="value">{{ latency.reject_cost_mean_us ?? '-' }}<span class="unit">μs</span></div>
        <div class="hint">含异步读取 BODY 的等待</div>
      </div>
      <div class="kpi">
        <div class="label">拦截处理耗时 P95</div>
        <div class="value">{{ latency.reject_cost_p95_us ?? '-' }}<span class="unit">μs</span></div>
      </div>
    </div>

    <!-- 第三行：Top IP / Top URI -->
    <div class="grid-half">
      <div class="panel">
        <div class="panel-title">Top 攻击来源 IP</div>
        <div v-if="topIps.length">
          <div v-for="row in topIps" :key="row.key" class="bar-row">
            <span class="mono">{{ row.key }}</span>
            <span class="bar"><i :style="{ width: (row.count / maxOf(topIps)) * 100 + '%' }"></i></span>
            <span class="num">{{ row.count }}</span>
          </div>
        </div>
        <div v-else class="empty">无数据</div>
      </div>

      <div class="panel">
        <div class="panel-title">Top 被攻击 URI</div>
        <div v-if="topUris.length">
          <div v-for="row in topUris" :key="row.key" class="bar-row" style="grid-template-columns: 1fr 90px 40px">
            <span class="mono" :title="row.key">{{ row.key }}</span>
            <span class="bar"><i :style="{ width: (row.count / maxOf(topUris)) * 100 + '%' }"></i></span>
            <span class="num">{{ row.count }}</span>
          </div>
        </div>
        <div v-else class="empty">无数据</div>
      </div>
    </div>

    <!-- 底部：最近拦截 -->
    <div class="panel">
      <div class="panel-title">
        <span>最近拦截事件（全局最近 8 条，不受上方窗口限制）</span>
        <router-link to="/events">查看全部 →</router-link>
      </div>
      <table v-if="recent.length" class="data">
        <thead>
          <tr>
            <th>时间</th>
            <th>来源 IP</th>
            <th>方法</th>
            <th>URI</th>
            <th>类型</th>
            <th>规则</th>
            <th>状态</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in recent" :key="row.id" @click="openEvent(row)">
            <td class="mono">{{ fmtTime(Date.parse(row.event_time)) }}</td>
            <td class="mono">{{ row.client_ip }}</td>
            <td>{{ row.method }}</td>
            <td class="mono" style="max-width: 380px; overflow: hidden; text-overflow: ellipsis">
              {{ row.uri }}
            </td>
            <td><span :class="tagClass(row.category_display)">{{ row.category_display || '-' }}</span></td>
            <td class="mono">{{ row.rule_id }} {{ row.rule_name }}</td>
            <td>{{ row.status }}</td>
          </tr>
        </tbody>
      </table>
      <div v-else class="empty">还没有拦截事件</div>
    </div>
  </div>
</template>
