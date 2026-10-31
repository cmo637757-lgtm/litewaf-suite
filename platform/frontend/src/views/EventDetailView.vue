<script setup>
/**
 * 单条拦截事件详情（卡片 R33-03）。
 *
 * 三条硬要求都在这里：
 * 1. 字段与源日志一一对应；日志里没记到的（比如某些拦截没写规则名）显示「日志未记录」而不是空白
 * 2. URI 里的 <script> 之类只当文本渲染（Vue 的 {{ }} 默认转义，不用 v-html）
 * 3. 同 IP 近 24 小时的其他事件单独列出来，方便判断是不是同一拨攻击
 */
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, fmtTime } from '../api/http'

const route = useRoute()
const router = useRouter()

const event = ref(null)
const sameIp = ref([])
const loading = ref(true)
const error = ref('')
// R34-10：当前事件的人工复核结果（null 表示还没人看）
const mark = ref(null)
const report = ref('')
const saving = ref(false)

const DAY = 86400_000

const fields = computed(() => {
  const e = event.value
  if (!e) return []
  return [
    ['事件 ID', e.id],
    ['发生时间', fmtTime(Date.parse(e.event_time))],
    ['来源 IP', e.client_ip],
    ['请求方法', e.method],
    ['请求 URI', e.uri],
    ['HTTP 状态', e.status],
    ['处置动作', e.action],
    ['拦截原因', e.reason || '日志未记录'],
    ['命中规则 ID', e.rule_id],
    ['命中规则名', e.rule_name || '日志未记录'],
    ['匹配区域', e.category || '日志未记录'],
    ['攻击类型（展示）', e.category_display || '日志未记录'],
    ['规则得分', e.score],
    ['拦截处理耗时', e.cost_us + ' μs（含异步读 BODY）']
  ]
})

async function load() {
  loading.value = true
  error.value = ''
  try {
    const e = await api('/api/events/' + route.params.id)
    event.value = e
    // 同一个 IP 前后 12 小时，覆盖 24 小时窗口
    const t = Date.parse(e.event_time)
    const res = await api(
      `/api/events?from=${t - DAY / 2}&to=${t + DAY / 2}&ip=${encodeURIComponent(e.client_ip)}&page_size=50`
    )
    sameIp.value = res.items.filter((x) => x.id !== e.id)
    // 标记接口在没有标记时返回 204，http.js 会给出 null，正好当"未复核"
    mark.value = await api('/api/events/' + e.id + '/mark').catch(() => null)
  } catch (err) {
    error.value = err.message
  } finally {
    loading.value = false
  }
}

/**
 * 提交复核结论。confirmed=这条拦截其实是正常业务（误报），rejected=确实该拦。
 * 标记只写 false_positive_marks，绝不改 waf_events 本身——原始事实要留证据。
 */
async function submitMark(decision) {
  if (!event.value) return
  saving.value = true
  report.value = ''
  try {
    mark.value = await api('/api/events/' + event.value.id + '/mark', {
      method: 'POST',
      body: { decision, remark: report.value }
    })
  } catch (err) {
    error.value = err.message
  } finally {
    saving.value = false
  }
}

async function clearMark() {
  if (!event.value) return
  saving.value = true
  try {
    await api('/api/events/' + event.value.id + '/mark', { method: 'DELETE' })
    mark.value = null
  } catch (err) {
    error.value = err.message
  } finally {
    saving.value = false
  }
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
      <button @click="router.back()">← 返回</button>
      <span class="muted" style="font-size: 12px">事件 #{{ route.params.id }}</span>
    </div>

    <div v-if="error" class="err">{{ error }}</div>
    <div v-if="loading" class="empty">加载中…</div>

    <template v-if="event && !loading">
      <div class="panel" style="margin-bottom: 12px">
        <div class="panel-title">
          <span>事件详情</span>
          <span :class="tagClass(event.category_display)">{{ event.category_display || '未分类' }}</span>
        </div>
        <div class="kv">
          <template v-for="[k, v] in fields" :key="k">
            <div class="k">{{ k }}</div>
            <div class="v" :class="{ mono: k === '请求 URI' }">{{ v }}</div>
          </template>
        </div>
      </div>

      <div class="panel" style="margin-bottom: 12px">
        <div class="panel-title">
          <span>人工复核（R34-10）</span>
          <span v-if="mark" :class="mark.decision === 'confirmed' ? 'tag cc' : 'tag sql'">
            {{ mark.decision === 'confirmed' ? '已确认误报' : '已驳回（真攻击）' }}
          </span>
          <span v-else class="muted" style="font-size: 12px">未复核</span>
        </div>
        <div v-if="mark" class="muted" style="font-size: 12px; margin-bottom: 8px">
          {{ mark.operator }} 于 {{ fmtTime(mark.updated_at_ms) }} 标记<template v-if="mark.remark">：{{ mark.remark }}</template>
        </div>
        <div class="toolbar" style="margin-bottom: 0">
          <input
            v-model="report"
            placeholder="备注（可选，说明为什么误报）"
            style="flex: 1; min-width: 220px"
          />
          <button :disabled="saving" @click="submitMark('confirmed')">确认误报</button>
          <button :disabled="saving" @click="submitMark('rejected')">驳回（真攻击）</button>
          <button v-if="mark" :disabled="saving" class="btn-ghost" @click="clearMark">撤销标记</button>
        </div>
        <div class="muted" style="font-size: 11px; margin-top: 6px">
          标记只记录复核结论，不会改动原始拦截记录；三个误报指标见「误报与调优」页。
        </div>
      </div>

      <div class="panel">
        <div class="panel-title">
          同 IP（{{ event.client_ip }}）24 小时内的其他事件
          <span class="muted" style="font-size: 11px">{{ sameIp.length }} 条</span>
        </div>
        <table v-if="sameIp.length" class="data">
          <thead>
            <tr>
              <th>时间</th>
              <th>URI</th>
              <th>类型</th>
              <th>规则</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in sameIp" :key="row.id" @click="router.push('/events/' + row.id)">
              <td class="mono">{{ fmtTime(Date.parse(row.event_time)) }}</td>
              <td class="mono" style="max-width: 420px; overflow: hidden; text-overflow: ellipsis">
                {{ row.uri }}
              </td>
              <td><span :class="tagClass(row.category_display)">{{ row.category_display || '-' }}</span></td>
              <td class="mono">{{ row.rule_id }} {{ row.rule_name }}</td>
            </tr>
          </tbody>
        </table>
        <div v-else class="empty">这个 IP 在附近 24 小时内没有其他拦截记录</div>
      </div>
    </template>
  </div>
</template>
