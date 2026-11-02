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
// P6 站内信：与告警实例同源，但走独立接口（channel=inapp 的规则把消息落这里）
const messages = ref([])
const blocklist = ref([])
const health = ref(null)
const unread = ref(0)

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
    const [rs, as, st, ms, uc, bl, hl] = await Promise.all([
      api('/api/alert-rules'),
      api('/api/alerts?limit=100'),
      api('/api/alerts/state'),
      api('/api/messages?limit=8'),
      api('/api/messages/unread-count'),
      api('/api/blocklist?limit=20'),
      api('/api/alerts/health')
    ])
    messages.value = Array.isArray(ms) ? ms : ms.items || []
    blocklist.value = Array.isArray(bl) ? bl : bl.items || []
    health.value = hl
    unread.value = uc.count || 0
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
      ratio: Number(d.ratio ?? 5),
      severity: d.severity || 'yellow',
      channel: d.channel || 'webhook',
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

const deliveryRate = computed(() => {
  const h = health.value
  if (!h || !h.deliveries24h) return '—'
  return (((h.deliveries24h - h.failed24h) / h.deliveries24h) * 100).toFixed(1) + '%'
})

function fmtDelay(ms) {
  if (ms < 1000) return ms + ' ms'
  if (ms < 60000) return (ms / 1000).toFixed(1) + ' 秒'
  return (ms / 60000).toFixed(1) + ' 分钟'
}

async function unblockIp(ip) {
  busy.value = 'bl'
  error.value = ''
  try {
    await api(`/api/blocklist/${encodeURIComponent(ip)}/unblock`, { method: 'POST' })
    await loadAll()
  } catch (e) {
    error.value = e.status === 403 ? '只有管理员能解封' : e.message
  } finally {
    busy.value = ''
  }
}

async function readAllMessages() {
  busy.value = 'msg'
  try {
    const r = await api('/api/messages/read-all', { method: 'POST' })
    notice.value = `已把 ${r.updated} 条站内消息标记为已读`
    await loadAll()
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
        <span>告警健康（近 24 小时）</span>
        <span class="muted small">消费器是否跟得上、投递有没有失败、告警延迟有多大</span>
      </div>
      <div v-if="health" class="grid-kpi">
        <div class="kpi">
          <div class="label">事件量</div>
          <div class="value">{{ health.events_last24h }}</div>
          <div class="hint">24 小时内入库的拦截事件</div>
        </div>
        <div class="kpi">
          <div class="label">告警数</div>
          <div class="value">{{ health.alerts_last24h }}</div>
          <div class="hint">
            黄 {{ health.yellow24h }} · 红 {{ health.red24h }}
            <span v-if="health.red24h" class="sev sev-red" style="margin-left: 4px">有红警</span>
          </div>
        </div>
        <div class="kpi">
          <div class="label">投递成功率</div>
          <div class="value">{{ deliveryRate }}</div>
          <div class="hint">
            成功 {{ health.deliveries24h - health.failed24h }} / {{ health.deliveries24h }}
            <span v-if="health.failed24h" class="sev sev-red" style="margin-left: 4px">失败 {{ health.failed24h }}</span>
          </div>
        </div>
        <div class="kpi">
          <div class="label">告警延迟 P95</div>
          <div class="value">{{ health.p95_delay_ms < 0 ? '—' : fmtDelay(health.p95_delay_ms) }}</div>
          <div class="hint">事件发生到告警投递出去的 95 分位耗时</div>
        </div>
      </div>

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

    <!-- 站内信（P6：channel=inapp 的规则把消息落库，不再死等 webhook） -->
    <section class="panel">
      <div class="panel-title">
        <span>
          站内消息
          <span v-if="unread" class="sev sev-red" style="margin-left: 6px">{{ unread }} 条未读</span>
          <span v-else class="muted small" style="margin-left: 6px">全部已读</span>
        </span>
        <button class="btn btn-ghost" :disabled="!unread || busy === 'msg'" @click="readAllMessages">
          全部标记已读
        </button>
      </div>
      <ul v-if="messages.length" class="msg-list">
        <li v-for="m in messages" :key="m.id" :class="{ unread: !m.read_at_ms }">
          <span class="sev" :class="'sev-' + (m.severity || 'yellow')">
            {{ m.severity === 'red' ? '红' : '黄' }}
          </span>
          <span class="msg-title">{{ m.title }}</span>
          <span class="muted small">{{ m.body }}</span>
          <span class="msg-time mono">{{ fmtTime(m.created_at_ms) }}</span>
        </li>
      </ul>
      <p v-else class="muted">还没有站内消息。把某条规则的「渠道」改成「站内」再触发一次就会出现在这里。</p>
    </section>

    <!-- 自动封禁名单（红色告警触发时平台写进来的） -->
    <section class="panel">
      <div class="panel-title">
        <span>
          自动封禁名单
          <span v-if="blocklist.filter((b) => b.active).length" class="sev sev-red" style="margin-left: 6px">
            {{ blocklist.filter((b) => b.active).length }} 个 IP 封禁中
          </span>
          <span v-else class="muted small" style="margin-left: 6px">当前没有封禁</span>
        </span>
        <span class="muted small">红色告警自动写入引擎黑名单；解封会同时清引擎侧和这张表</span>
      </div>
      <table v-if="blocklist.length" class="data">
        <thead>
          <tr>
            <th>来源 IP</th><th>原因</th><th>关联告警</th><th>规则</th>
            <th>封禁时间</th><th>状态</th><th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="b in blocklist" :key="b.id">
            <td class="mono">{{ b.client_ip }}</td>
            <td>{{ b.reason === 'auto_alert' ? '红色告警自动' : b.reason }}</td>
            <td class="mono">{{ b.alert_id ? '#' + b.alert_id : '—' }}</td>
            <td>{{ b.rule_name || '—' }}</td>
            <td class="mono">{{ fmtTime(b.created_at_ms) }}</td>
            <td>
              <span class="tag" :class="{ 'tag-red': b.active }">{{ b.active ? '封禁中' : '已解除' }}</span>
            </td>
            <td>
              <button v-if="b.active" class="btn btn-ghost" :disabled="busy === 'bl'" @click="unblockIp(b.client_ip)">
                解封
              </button>
              <span v-else class="muted small mono">{{ fmtTime(b.released_at_ms) }}</span>
            </td>
          </tr>
        </tbody>
      </table>
      <p v-else class="muted">还没有封禁记录。红色告警（阈值两倍以上、或相对基线 10 倍）触发后会出现在这里。</p>
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
          <label>
            <span>突增倍数</span>
            <input v-model.number="draft[r.id].ratio" type="number" step="0.5" class="input w-90" />
          </label>
          <label>
            <span>默认等级</span>
            <select v-model="draft[r.id].severity" class="input" style="width: 96px">
              <option value="yellow">黄</option>
              <option value="red">红</option>
            </select>
          </label>
          <label>
            <span>渠道</span>
            <select v-model="draft[r.id].channel" class="input" style="width: 116px">
              <option value="webhook">Webhook</option>
              <option value="inapp">站内</option>
            </select>
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
            <th>等级</th>
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
            <td>
              <span class="sev" :class="'sev-' + (a.severity || 'yellow')">
                {{ a.severity === 'red' ? '红' : '黄' }}
              </span>
              <span v-if="a.burst_ratio > 1.05" class="muted small">突增 {{ a.burst_ratio.toFixed(1) }}×</span>
            </td>
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
