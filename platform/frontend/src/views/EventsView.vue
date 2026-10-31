<script setup>
/**
 * 拦截事件列表：按时间/IP/类型/URI 过滤 + 分页。
 *
 * 关键口径：
 * - 时间窗口是闭开区间 [from, to)，与后端、与验收脚本一致
 * - 分页是页码式（items/total/page/page_size），不是游标，10 万行内够用
 * - 排序字段走白名单（time/ip/cost），传别的值后端会忽略，避免 SQL 注入
 */
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { api, fmtTime } from '../api/http'

const router = useRouter()

const F20_FROM = 1789862400000
const F20_TO = 1789862460000

const WINDOWS = [
  { key: '1h', label: '最近 1 小时', ms: 3600_000 },
  { key: '24h', label: '最近 24 小时', ms: 86400_000 },
  { key: 'f20', label: '演示数据（F20 固定集）', from: F20_FROM, to: F20_TO }
]

const CATEGORIES = ['', 'SQLi', 'XSS', 'CC']

const win = ref('24h')
const ip = ref('')
const category = ref('')
const uriKeyword = ref('')
const page = ref(1)
const pageSize = ref(20)
const sortby = ref('time')
const order = ref('desc')

const data = ref(null)
const loading = ref(false)
const error = ref('')

const totalPages = computed(() => {
  if (!data.value) return 1
  return Math.max(1, Math.ceil(data.value.total / pageSize.value))
})

function windowRange() {
  const w = WINDOWS.find((x) => x.key === win.value) || WINDOWS[1]
  if (w.from) return { from: w.from, to: w.to }
  const to = Date.now()
  return { from: to - w.ms, to }
}

async function load() {
  const { from, to } = windowRange()
  const params = new URLSearchParams({
    from: String(from),
    to: String(to),
    page: String(page.value),
    page_size: String(pageSize.value),
    sortby: sortby.value,
    order: order.value
  })
  if (ip.value.trim()) params.set('ip', ip.value.trim())
  if (category.value) params.set('category', category.value)
  if (uriKeyword.value.trim()) params.set('uri', uriKeyword.value.trim())

  loading.value = true
  error.value = ''
  try {
    data.value = await api('/api/events?' + params.toString())
  } catch (e) {
    error.value = e.message
    data.value = null
  } finally {
    loading.value = false
  }
}

function search() {
  page.value = 1
  load()
}

/**
 * 导出当前筛选结果（R36-01）。
 * 不走 api() 帮助函数：导出要的是文件下载，用带 token 的 URL 直接让浏览器跳转，
 * 后端会回 Content-Disposition: attachment，浏览器自己弹保存框。
 * 上限 1 万行由后端把关，超了会回 400 并把「请缩小范围」写进 error.message。
 */
function exportAs(format) {
  const { from, to } = windowRange()
  const params = new URLSearchParams({
    format,
    from: String(from),
    to: String(to)
  })
  if (ip.value.trim()) params.set('ip', ip.value.trim())
  if (category.value) params.set('category', category.value)
  if (uriKeyword.value.trim()) params.set('uri', uriKeyword.value.trim())
  const token = JSON.parse(localStorage.getItem('litewaf.auth') || '{}').token
  // token 放 query 会进 access log，这里只能靠 cookie/header 二选一；
  // 因为后端用 Bearer，下载类操作改用 fetch + blob，避免把 token 写进 URL。
  fetch('/api/export?' + params.toString(), { headers: { Authorization: 'Bearer ' + token } })
    .then(async (r) => {
      if (!r.ok) {
        const j = await r.json().catch(() => ({}))
        throw new Error(j.message || ('导出失败 HTTP ' + r.status))
      }
      const blob = await r.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = 'waf-events.' + format
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
    })
    .catch((e) => { error.value = e.message })
}

function goto(p) {
  page.value = Math.min(Math.max(1, p), totalPages.value)
  load()
}

function sortBy(field) {
  if (sortby.value === field) {
    order.value = order.value === 'desc' ? 'asc' : 'desc'
  } else {
    sortby.value = field
    order.value = 'desc'
  }
  load()
}

function tagClass(cat) {
  if (cat === 'SQLi') return 'tag sql'
  if (cat === 'XSS') return 'tag xss'
  if (cat === 'CC') return 'tag cc'
  return 'tag other'
}

onMounted(load)
</script>

<template>
  <div>
    <div class="toolbar">
      <select v-model="win" @change="search">
        <option v-for="w in WINDOWS" :key="w.key" :value="w.key">{{ w.label }}</option>
      </select>
      <input v-model="ip" placeholder="来源 IP（精确）" style="width: 150px" @keyup.enter="search" />
      <select v-model="category" @change="search">
        <option v-for="c in CATEGORIES" :key="c" :value="c">{{ c || '全部类型' }}</option>
      </select>
      <input
        v-model="uriKeyword"
        placeholder="URI 包含…"
        style="width: 180px"
        @keyup.enter="search"
      />
      <button class="primary" :disabled="loading" @click="search">查询</button>
      <button :disabled="!data || !data.total" title="导出当前筛选结果（上限 1 万行）"
              @click="exportAs('csv')">导出 CSV</button>
      <button :disabled="!data || !data.total" title="每行一条 JSON，便于二次分析"
              @click="exportAs('jsonl')">导出 JSONL</button>
      <span class="muted" style="font-size: 12px">共 {{ data ? data.total : 0 }} 条</span>
    </div>

    <div v-if="error" class="err">{{ error }}</div>

    <div class="panel" style="padding: 0; overflow: auto">
      <table v-if="data && data.items.length" class="data">
        <thead>
          <tr>
            <th style="cursor: pointer" @click="sortBy('time')">时间 ⇅</th>
            <th style="cursor: pointer" @click="sortBy('ip')">来源 IP ⇅</th>
            <th>方法</th>
            <th>URI</th>
            <th>类型</th>
            <th>规则</th>
            <th>处置</th>
            <th style="cursor: pointer" @click="sortBy('cost')">耗时 ⇅</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="row in data.items"
            :key="row.id"
            @click="router.push('/events/' + row.id)"
          >
            <td class="mono">{{ fmtTime(Date.parse(row.event_time)) }}</td>
            <td class="mono">{{ row.client_ip }}</td>
            <td>{{ row.method }}</td>
            <td class="mono" style="max-width: 420px; overflow: hidden; text-overflow: ellipsis">
              {{ row.uri }}
            </td>
            <td><span :class="tagClass(row.category_display)">{{ row.category_display || '-' }}</span></td>
            <td class="mono">{{ row.rule_id }} {{ row.rule_name }}</td>
            <td>{{ row.action }} / {{ row.status }}</td>
            <td class="mono">{{ row.cost_us }} μs</td>
          </tr>
        </tbody>
      </table>
      <div v-else class="empty">{{ loading ? '加载中…' : '该条件下没有事件' }}</div>
    </div>

    <div class="pager">
      <button :disabled="page <= 1 || loading" @click="goto(page - 1)">上一页</button>
      <span>第 {{ page }} / {{ totalPages }} 页</span>
      <button :disabled="page >= totalPages || loading" @click="goto(page + 1)">下一页</button>
      <select v-model.number="pageSize" style="margin-left: 10px" @change="search">
        <option :value="20">20 条/页</option>
        <option :value="50">50 条/页</option>
        <option :value="100">100 条/页</option>
      </select>
    </div>
  </div>
</template>
