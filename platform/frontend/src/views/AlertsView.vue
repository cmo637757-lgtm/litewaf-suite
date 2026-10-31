<script setup>
/**
 * 告警页 —— S6 的前端出口。
 *
 * 三块内容，按"发生 → 判断 → 处置"的顺序排：
 *   1. 消费器状态：告警 worker 消费到哪条事件、跳过了多少历史（数据源是否健康）
 *   2. 规则：哪类攻击、多少个、多长时间窗、抑制多久、投递到哪个 webhook
 *   3. 告警实例：触发了几次、关联了几个事件、投递成功没、处理了没
 *
 * 和规则页一样，页面不直接改文件也不拼命令，全部走 /api/alerts 与 /api/alert-rules。
 */
import { computed, onMounted, ref } from 'vue'
import { api, fmtTime } from '../api/http'

const rules = ref([])
const alerts = ref([])
const state = ref(null)
const detail = ref(null)
const selectedId = ref(null)
const busy = ref('')
const error = ref('')
const notice = ref('')
const filterHandled = ref('all')

// 规则编辑草稿：用 id 做键，避免编辑时整行被轮询刷掉
const draft = ref({})

const visibleAlerts = computed(() => {
  if (filterHandled.value === 'open') return alerts.value.filter((a) => !a.handled)
  if (filterHandled.value === 'handled') return alerts.value.filter((a) => a.handled)
  return alerts.value
})

const totalEvents = computed(() => alerts.value.reduce((s, a) => s + (a.event_count || 0), 0))

// 列表里只有最新一条投递的"状态字符串"，详情里是整条投递记录，两种形状都要能显示
const deliveryState = (d) => {
  if (!d) return { text: '未投递', cls: 'muted' }
  const status = typeof d === 'string' ? d : d.status
  const code = typeof d === 'string' ? null : d.http_code
  const suffix = code ? ' ' + code : ''
  if (status === 'sent') return { text: '已投递' + suffix, cls: 'ok' }
  if (status === 'failed') return { text: '失败' + suffix, cls: 'bad' }
  if (status === 'unknown') return { text: '结果未知', cls: 'warn' }
  return { text: status || '待投递', cls: 'muted' }
}

async function loadAll() {
  error.value = ''
  try {
    const [rs, as, st] = await Promise.all([
      api('/api/alert-rules'),
      api('/api/alerts?limit=100'),
      api('/api/alerts/state')
    ])
    // 后端这两个接口直接返回数组（不是分页包装），兼容两种形状
    rules.value = Array.isArray(rs) ? rs : rs.items || []
    alerts.value = Array.isArray(as) ? as : as.items || []
    state.value = st
    // 把规则字段种进草稿，但不要覆盖用户正在编辑的同一行
    for (const r of rules.value) {
      if (!draft.value[r.id]) draft.value[r.id] = { ...r }
    }
  } catch (e) {
    error.value = e.message || String(e)
  }
}

async function saveRule(rule) {
  const d = draft.value[rule.id]
  busy.value = 'rule-' + rule.id
  error.value = ''
  notice.value = ''
  try {
    const body = {
      name: d.name,
      category: d.category,
      threshold: Number(d.threshold),
      window_s: Number(d.window_s),
      suppress_s: Number(d.suppress_s),
      webhook_url: d.webhook_url,
      enabled: !!d.enabled
    }
    await api('/api/alert-rules/' + rule.id, { method: 'POST', body })
    notice.value = `规则 #${rule.id} 已保存，worker 下一轮（2 秒内）生效`
    await loadAll()
  } catch (e) {
    error.value = e.message || String(e)
  } finally {
    busy.value = ''
  }
}

async function openDetail(id) {
  selectedId.value = id
  detail.value = null
  try {
    detail.value = await api('/api/alerts/' + id)
  } catch (e) {
    error.value = e.message || String(e)
  }
}

async function retry() {
  if (!selectedId.value) return
  busy.value = 'retry'
  error.value = ''
  notice.value = ''
  try {
    const r = await api(`/api/alerts/${selectedId.value}/retry`, { method: 'POST' })
    notice.value = `已重新投递：${r.status}${r.http_code ? ' / ' + r.http_code : ''}`
    await loadAll()
    await openDetail(selectedId.value)
  } catch (e) {
    error.value = e.message || String(e)
  } finally {
    busy.value = ''
  }
}

async function markHandled() {
  if (!selectedId.value) return
  busy.value = 'handled'
  error.value = ''
  notice.value = ''
  try {
    await api(`/api/alerts/${selectedId.value}/handled`, { method: 'POST', body: { handled: true } })
    notice.value = '已标记为处理完成（只改处置状态，不影响投递记录）'
    await loadAll()
    await openDetail(selectedId.value)
  } catch (e) {
    error.value = e.message || String(e)
  } finally {
    busy.value = ''
  }
}

onMounted(loadAll)
</script>

<template>
  <div class="view">
    <div class="view-head">
      <div>
        <h1>告警</h1>
        <p class="hint">
          固定时间桶阈值 + 合并抑制 + 本地 Webhook 投递。同一 IP 的同类攻击在窗口内攒够阈值才触发，
          抑制期内只累加计数，不再重复打扰。
        </p>
      </div>
      <div class="head-actions">
        <select v-model="filterHandled" class="input">
          <option value="all">全部告警</option>
          <option value="open">未处理</option>
          <option value="handled">已处理</option>
        </select>
        <button class="btn btn-ghost" :disabled="!!busy" @click="loadAll">刷新</button>
      </div>
    </div>

    <p v-if="error" class="msg msg-bad">{{ error }}</p>
    <p v-if="notice" class="msg msg-ok">{{ notice }}</p>

    <!-- 消费器状态 -->
    <section class="panel">
      <div class="panel-title">
        <span>告警消费器</span>
        <span class="muted small">每 2 秒拉一批已入库事件；只对“事件时间距现在 ≤ 120 秒”的做实时通知</span>
      </div>
      <div v-if="state" class="stat-row">
        <div class="stat">
          <div class="label">已消费到事件 ID</div>
          <div class="value mono">{{ state.last_event_id }}</div>
        </div>
        <div class="stat">
          <div class="label">历史事件跳过</div>
          <div class="value mono">{{ state.skipped_total }}</div>
          <div class="sub">导入旧日志时不会补发实时告警，只记账</div>
        </div>
        <div class="stat">
          <div class="label">告警实例</div>
          <div class="value mono">{{ alerts.length }}</div>
          <div class="sub">关联事件合计 {{ totalEvents }} 条</div>
        </div>
      </div>
    </section>

    <!-- 规则 -->
    <section class="panel">
      <div class="panel-title">
        <span>告警规则</span>
        <span class="muted small">阈值 1–10000、窗口 5–3600 秒、抑制 ≥ 窗口且 ≤ 86400 秒</span>
      </div>
      <div v-for="r in rules" :key="r.id" class="rule-row">
        <div class="rule-head">
          <span class="chip">#{{ r.id }}</span>
          <span class="rule-name">{{ r.name }}</span>
          <span class="tag">{{ r.category || '任意类型' }}</span>
        </div>
        <div class="rule-fields">
          <label>
            <span>阈值（个）</span>
            <input v-model.number="draft[r.id].threshold" type="number" class="input w-90" />
          </label>
          <label>
            <span>窗口（秒）</span>
            <input v-model.number="draft[r.id].window_s" type="number" class="input w-90" />
          </label>
          <label>
            <span>抑制（秒）</span>
            <input v-model.number="draft[r.id].suppress_s" type="number" class="input w-90" />
          </label>
          <label class="grow">
            <span>Webhook</span>
            <input v-model="draft[r.id].webhook_url" class="input" />
          </label>
          <label class="inline-check">
            <input v-model="draft[r.id].enabled" type="checkbox" />
            <span>启用</span>
          </label>
          <button class="btn btn-primary" :disabled="busy === 'rule-' + r.id" @click="saveRule(r)">
            保存
          </button>
        </div>
      </div>
      <p v-if="!rules.length" class="muted">还没有告警规则。</p>
    </section>

    <!-- 告警列表 -->
    <section class="panel">
      <div class="panel-title">
        <span>告警实例（{{ visibleAlerts.length }} 条）</span>
        <span class="muted small">点击一行看详情：关联了哪些事件、投递了几次</span>
      </div>
      <table class="data">
        <thead>
          <tr>
            <th>ID</th>
            <th>首次触发</th>
            <th>来源 IP</th>
            <th>类型</th>
            <th>触发次数</th>
            <th>关联事件</th>
            <th>投递</th>
            <th>处置</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="a in visibleAlerts"
            :key="a.id"
            :class="{ selected: selectedId === a.id }"
            @click="openDetail(a.id)"
          >
            <td class="mono">{{ a.id }}</td>
            <td class="mono">{{ fmtTime(a.first_trigger_ms) }}</td>
            <td class="mono">{{ a.client_ip }}</td>
            <td><span class="tag">{{ a.category }}</span></td>
            <td class="mono">{{ a.trigger_count }}</td>
            <td class="mono">{{ a.event_count }}</td>
            <td>
              <span class="dot" :class="deliveryState(a.delivery_status).cls"></span>
              {{ deliveryState(a.delivery_status).text }}
            </td>
            <td>{{ a.handled ? '已处理' : '未处理' }}</td>
          </tr>
        </tbody>
      </table>
      <p v-if="!visibleAlerts.length" class="muted">当前筛选下没有告警。</p>
    </section>

    <!-- 详情 -->
    <section v-if="detail" class="panel">
      <div class="panel-title">
        <span>告警 #{{ detail.alert.id }} 详情</span>
        <div class="head-actions">
          <button class="btn btn-ghost" :disabled="!!busy" @click="retry">重新投递</button>
          <button
            class="btn btn-primary"
            :disabled="detail.alert.handled || !!busy"
            @click="markHandled"
          >
            标记已处理
          </button>
        </div>
      </div>

      <div class="stat-row">
        <div class="stat">
          <div class="label">IP / 类型</div>
          <div class="value mono">{{ detail.alert.client_ip }} · {{ detail.alert.category }}</div>
        </div>
        <div class="stat">
          <div class="label">固定时间桶</div>
          <div class="value mono">{{ fmtTime(detail.alert.bucket_start) }}</div>
          <div class="sub">桶 = floor(事件时间 / 窗口) × 窗口</div>
        </div>
        <div class="stat">
          <div class="label">触发 / 关联</div>
          <div class="value mono">{{ detail.alert.trigger_count }} 次 / {{ detail.alert.event_count }} 条</div>
        </div>
        <div class="stat">
          <div class="label">抑制至</div>
          <div class="value mono">{{ fmtTime(detail.alert.suppressed_until_ms) }}</div>
        </div>
      </div>

      <h3 class="sub-title">关联事件（{{ detail.event_ids.length }} 条）</h3>
      <table class="data">
        <thead>
          <tr>
            <th>事件 ID</th>
            <th>时间</th>
            <th>URI</th>
            <th>规则</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="ev in detail.events || []" :key="ev.id">
            <td class="mono">{{ ev.id }}</td>
            <td class="mono">{{ fmtTime(ev.event_time_ms) }}</td>
            <td class="mono">{{ ev.uri }}</td>
            <td class="mono">{{ ev.rule_name || '日志未记录' }}</td>
          </tr>
        </tbody>
      </table>

      <h3 class="sub-title">投递记录（{{ (detail.deliveries || []).length }} 条）</h3>
      <table class="data">
        <thead>
          <tr>
            <th>ID</th>
            <th>时间</th>
            <th>状态</th>
            <th>HTTP</th>
            <th>尝试</th>
            <th>错误</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="d in detail.deliveries || []" :key="d.id">
            <td class="mono">{{ d.id }}</td>
            <td class="mono">{{ fmtTime(d.updated_at) }}</td>
            <td>{{ deliveryState(d).text }}</td>
            <td class="mono">{{ d.http_code || '-' }}</td>
            <td class="mono">{{ d.attempts }}</td>
            <td class="mono small">{{ d.last_error || '-' }}</td>
          </tr>
        </tbody>
      </table>
    </section>
  </div>
</template>

<style scoped>
.view {
  padding: 18px 22px 40px;
}
.view-head {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
  margin-bottom: 14px;
}
.view-head h1 {
  font-size: 20px;
  margin: 0 0 6px;
}
.hint {
  color: var(--muted);
  font-size: 12px;
  line-height: 1.7;
  margin: 0;
  max-width: 760px;
}
.head-actions {
  display: flex;
  gap: 8px;
  align-items: center;
}
.panel {
  margin-bottom: 16px;
}
.stat-row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
  gap: 12px;
  padding: 4px 0 6px;
}
.stat .label {
  color: var(--muted);
  font-size: 12px;
}
.stat .value {
  font-size: 16px;
  margin-top: 4px;
}
.stat .sub {
  color: var(--muted);
  font-size: 11px;
  margin-top: 4px;
}
.rule-row {
  border-top: 1px solid var(--line);
  padding: 12px 0;
}
.rule-row:first-of-type {
  border-top: 0;
}
.rule-head {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}
.rule-name {
  font-size: 13px;
}
.rule-fields {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  align-items: flex-end;
}
.rule-fields label {
  display: flex;
  flex-direction: column;
  gap: 4px;
  font-size: 11px;
  color: var(--muted);
}
.rule-fields .grow {
  flex: 1;
  min-width: 260px;
}
.inline-check {
  flex-direction: row !important;
  align-items: center;
  gap: 6px !important;
  padding-bottom: 7px;
}
.w-90 {
  width: 90px;
}
tr.selected {
  background: rgba(58, 123, 213, 0.14);
}
.dot {
  display: inline-block;
  width: 7px;
  height: 7px;
  border-radius: 50%;
  margin-right: 5px;
}
.dot.ok {
  background: #3fb950;
}
.dot.bad {
  background: #f85149;
}
.dot.warn {
  background: #d29922;
}
.dot.muted {
  background: #6e7681;
}
.sub-title {
  font-size: 13px;
  margin: 16px 0 8px;
  color: var(--fg);
}
.msg {
  padding: 8px 12px;
  border-radius: 6px;
  font-size: 12px;
  margin: 0 0 12px;
}
.msg-bad {
  background: rgba(248, 81, 73, 0.12);
  color: #ff7b72;
}
.msg-ok {
  background: rgba(63, 185, 80, 0.12);
  color: #56d364;
}
.mono {
  font-family: var(--mono, ui-monospace, SFMono-Regular, Menlo, monospace);
}
.small {
  font-size: 11px;
}
.muted {
  color: var(--muted);
}
</style>
