<script setup>
/**
 * 规则与 CC 配置页 —— S5 发布闭环的前端。
 *
 * 流程刻意做成三步，和卡片 R37-04 一致：
 *   编辑 → 检查（只校验，不动线上）→ 发布（原子替换 + reload + 三次探测）
 * 发布失败会自动回滚到发布前，所以这里不需要"手动撤销"的兜底按钮。
 *
 * 红线：页面从来不直接写文件、不拼命令，所有动作都发给后端 /api/rules/*，
 * 后端再转给只监听 127.0.0.1、带令牌的执行器。
 */
import { computed, onMounted, ref } from 'vue'
import { api, fmtTime } from '../api/http'

const text = ref('')
const cc = ref({ max_requests: 20, window: 10, block_duration: 60 })
const status = ref(null)
const loading = ref(false)
const busy = ref('')
const checkResult = ref(null)
const candidateId = ref('')
const opResult = ref(null)
const error = ref('')

const dirty = ref(false)
const currentHash = ref('')
const testUri = ref('')
const testResult = ref(null)

const versionLabel = computed(() => (status.value ? status.value.current || '-' : '-'))
const probeOk = computed(() => {
  const s = status.value
  return !!s && s.normal === 200 && s.sqli === 403 && s.marker === 200
})

async function loadAll() {
  loading.value = true
  error.value = ''
  try {
    const [rules, st] = await Promise.all([
      api('/api/rules'),
      api('/api/engine/status')
    ])
    text.value = rules.text || ''
    currentHash.value = rules.hash || ''
    if (rules.cc) cc.value = { ...cc.value, ...rules.cc }
    status.value = st
    dirty.value = false
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

function onEdit() {
  dirty.value = true
  checkResult.value = null
  candidateId.value = ''
}

function ccPayload() {
  return {
    max_requests: Number(cc.value.max_requests),
    window: Number(cc.value.window),
    block_duration: Number(cc.value.block_duration)
  }
}

async function doCheck() {
  busy.value = 'check'
  error.value = ''
  opResult.value = null
  try {
    const r = await api('/api/rules/check', {
      method: 'POST',
      body: { rules: text.value, cc: ccPayload(), name: '网页编辑' }
    })
    checkResult.value = r
    candidateId.value = r.ok ? r.candidate_id : ''
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = ''
  }
}

async function doPublish() {
  if (!candidateId.value) {
    error.value = '请先点「检查」通过，再发布'
    return
  }
  busy.value = 'publish'
  error.value = ''
  try {
    opResult.value = await api('/api/rules/publish', {
      method: 'POST',
      body: { candidate_id: candidateId.value }
    })
    candidateId.value = ''
    checkResult.value = null
    await loadAll()
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = ''
  }
}

async function doRollback() {
  busy.value = 'rollback'
  error.value = ''
  try {
    opResult.value = await api('/api/rules/rollback', { method: 'POST', body: {} })
    await loadAll()
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = ''
  }
}

async function doTest() {
  const uri = testUri.value.trim()
  if (!uri) return
  busy.value = 'test'
  error.value = ''
  testResult.value = null
  try {
    testResult.value = await api('/api/rules/test', { method: 'POST', body: { uri } })
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = ''
  }
}

onMounted(loadAll)
</script>

<template>
  <div>
    <div class="toolbar">
      <span class="badge" :class="status && status.nginx_alive ? 'ok' : 'bad'">
        nginx {{ status && status.nginx_alive ? '存活' : '未运行' }}
      </span>
      <span class="badge" :class="probeOk ? 'ok' : 'bad'">
        探针 正常 {{ status ? status.normal : '-' }} / SQLi {{ status ? status.sqli : '-' }} / marker
        {{ status ? status.marker : '-' }}
      </span>
      <span class="muted">当前 {{ versionLabel }} · 上一版 {{ status ? status.previous || '-' : '-' }}</span>
      <span v-if="dirty" class="warn-inline">有未检查的修改</span>
      <button :disabled="loading" @click="loadAll">重新载入</button>
    </div>

    <div v-if="error" class="err">{{ error }}</div>

    <div class="rules-grid">
      <div class="panel">
        <div class="panel-title">
          <span>规则文件（litewaf_rules.conf）</span>
          <span class="muted" style="font-size: 12px">
            语法：lwaf_rule id=… name="…" type=str|rx pattern="…" zones=… score=类别:分值 action=score|block|log
          </span>
        </div>
        <textarea
          v-model="text"
          class="editor"
          spellcheck="false"
          @input="onEdit"
        ></textarea>
      </div>

      <div class="side-col">
        <div class="panel">
          <div class="panel-title"><span>CC 参数（漏桶）</span></div>
          <div class="form-row">
            <label>容量 max_requests</label>
            <input v-model.number="cc.max_requests" type="number" min="2" max="1000" />
            <span class="hint">2–1000</span>
          </div>
          <div class="form-row">
            <label>窗口 window（秒）</label>
            <input v-model.number="cc.window" type="number" min="1" max="3600" />
            <span class="hint">1–3600</span>
          </div>
          <div class="form-row">
            <label>封禁 block_duration（秒）</label>
            <input v-model.number="cc.block_duration" type="number" min="1" max="86400" />
            <span class="hint">≥ 窗口</span>
          </div>
          <div class="muted" style="font-size: 12px; margin-top: 6px">
            语义：同一 IP 在窗口内前 N 次放行，第 N+1 次起封禁。参数随规则一起发布、一起回退。
          </div>
        </div>

        <div class="panel">
          <div class="panel-title"><span>操作</span></div>
          <div class="actions">
            <button class="primary" :disabled="!!busy" @click="doCheck">
              {{ busy === 'check' ? '检查中…' : '① 检查语法' }}
            </button>
            <button class="primary" :disabled="!!busy || !candidateId" @click="doPublish">
              {{ busy === 'publish' ? '发布中…' : '② 发布生效' }}
            </button>
            <button :disabled="!!busy" @click="doRollback">
              {{ busy === 'rollback' ? '回退中…' : '回退上一版' }}
            </button>
          </div>
          <div class="muted" style="font-size: 12px">
            检查只跑 nginx -t，不动线上；发布是「原子替换 → reload → 三次探测」，探测不过自动回滚。
          </div>
        </div>

        <div v-if="checkResult" class="panel" :class="checkResult.ok ? 'ok-panel' : 'bad-panel'">
          <div class="panel-title"><span>检查结果</span></div>
          <div v-if="checkResult.ok">
            通过 · 候选 {{ checkResult.candidate_id }} · {{ checkResult.bytes }} 字节
          </div>
          <div v-else>
            未通过
            <div class="mono small">{{ checkResult.line_no || checkResult.error }}</div>
            <details>
              <summary class="muted" style="font-size: 12px">nginx 原始输出</summary>
              <pre class="mono small">{{ checkResult.engine_output }}</pre>
            </details>
          </div>
        </div>

        <div v-if="opResult" class="panel" :class="opResult.ok ? 'ok-panel' : 'bad-panel'">
          <div class="panel-title"><span>发布结果</span></div>
          <div v-if="opResult.ok">
            成功 · 版本 {{ opResult.version }} · CC
            {{ opResult.cc && opResult.cc.max_requests }}/{{ opResult.cc && opResult.cc.window }}/{{
              opResult.cc && opResult.cc.block_duration
            }}
            <div v-if="opResult.probe" class="muted" style="font-size: 12px">
              探测：marker {{ opResult.probe.marker }}（试 {{ (opResult.probe.marker_tries || []).length }}
              次）、正常 {{ opResult.probe.normal }}、SQLi {{ opResult.probe.sqli }}
            </div>
          </div>
          <div v-else>失败：{{ opResult.error }}</div>
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-title">
        <span>规则试打（dry-run）</span>
        <span class="muted" style="font-size: 12px">
          把一条请求真打给运行中的 WAF，回读命中结果——改规则前先确认会不会误伤
        </span>
      </div>
      <div class="test-row">
        <input
          v-model="testUri"
          class="test-input"
          spellcheck="false"
          placeholder="/?id=1' OR 1=1--   或   /p1"
          @keyup.enter="doTest"
        />
        <button class="primary" :disabled="!!busy || !testUri.trim()" @click="doTest">
          {{ busy === 'test' ? '试打中…' : '试打' }}
        </button>
      </div>
      <div class="muted" style="font-size: 12px">
        真打实例 127.0.0.1:18010，会计入 CC 漏桶——短时间别连打超过容量。
      </div>

      <div v-if="testResult" class="test-result">
        <div class="test-head">
          <span class="tag" :class="testResult.blocked ? 'bad' : 'ok'">
            HTTP {{ testResult.status }}{{ testResult.blocked ? ' · 被拦截' : ' · 放行' }}
          </span>
          <span class="muted">耗时 {{ testResult.latency_ms }} ms</span>
        </div>
        <table v-if="testResult.blocked" class="data small-table">
          <tbody>
            <tr><th>命中规则</th><td>{{ testResult.rule_name || '—' }}</td></tr>
            <tr><th>规则 ID</th><td>{{ testResult.rule_id ?? '—' }}</td></tr>
            <tr><th>匹配类别</th><td>{{ testResult.category_display || testResult.category || '—' }}</td></tr>
            <tr><th>规则得分</th><td>{{ testResult.score ?? '—' }}</td></tr>
            <tr><th>拦截原因</th><td class="mono">{{ testResult.reason || '—' }}</td></tr>
          </tbody>
        </table>
        <div class="muted" style="font-size: 12px; margin-top: 6px">{{ testResult.note }}</div>
      </div>
    </div>

    <div class="panel" style="padding: 0; overflow: auto">
      <div class="panel-title" style="padding: 10px 12px">
        <span>版本历史（最近 10 个）</span>
      </div>
      <table class="data">
        <thead>
          <tr>
            <th>版本</th>
            <th>类型</th>
            <th>hash</th>
            <th>CC</th>
            <th>创建时间</th>
            <th>上一版</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="v in (status && status.versions) || []" :key="v.version">
            <td>
              <b>{{ v.version }}</b>
              <span v-if="status && v.version === status.current" class="tag cc">当前</span>
            </td>
            <td>{{ v.kind }}</td>
            <td class="mono small">{{ (v.hash || '').slice(0, 12) }}</td>
            <td class="small">
              {{ v.cc ? v.cc.max_requests + '/' + v.cc.window + '/' + v.cc.block_duration : '-' }}
            </td>
            <td class="small">{{ v.created_at }}</td>
            <td class="small">{{ v.previous || '-' }}</td>
          </tr>
          <tr v-if="!status || !status.versions || !status.versions.length">
            <td colspan="6" class="muted" style="text-align: center; padding: 16px">还没有版本记录</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<style scoped>
.rules-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 340px;
  gap: 12px;
  margin-bottom: 12px;
}
.side-col {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.editor {
  width: 100%;
  min-height: 430px;
  background: #0d1117;
  color: #c9d1d9;
  border: 1px solid #2a3542;
  border-radius: 6px;
  padding: 10px 12px;
  font-family: ui-monospace, 'Cascadia Code', Consolas, monospace;
  font-size: 12px;
  line-height: 1.55;
  resize: vertical;
}
.form-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
  font-size: 13px;
}
.form-row label {
  width: 150px;
  color: #9aa7b5;
}
.form-row input {
  width: 80px;
}
.hint {
  font-size: 11px;
  color: #6b7785;
}
.actions {
  display: flex;
  gap: 8px;
  margin-bottom: 8px;
}
.badge {
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 12px;
  border: 1px solid #2a3542;
}
.badge.ok {
  color: #35c08a;
  border-color: #1e5c46;
}
.badge.bad {
  color: #ff6b6b;
  border-color: #6b2b2b;
}
.warn-inline {
  color: #e0a33e;
  font-size: 12px;
}
.ok-panel {
  border-color: #1e5c46;
}
.bad-panel {
  border-color: #6b2b2b;
}
.mono {
  font-family: ui-monospace, Consolas, monospace;
}
.small {
  font-size: 12px;
}
@media (max-width: 1200px) {
  .rules-grid {
    grid-template-columns: minmax(0, 1fr);
  }
  .editor {
    min-height: 300px;
  }
}
.test-row {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-bottom: 6px;
}
.test-input {
  flex: 1;
  min-width: 0;
  font-family: ui-monospace, Menlo, Consolas, monospace;
  font-size: 13px;
}
.test-result {
  margin-top: 10px;
  padding: 10px 12px;
  border-radius: 6px;
  background: #131b24;
  border: 1px solid #2a3542;
}
.test-head {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 8px;
}
.small-table th {
  width: 110px;
  color: var(--muted, #6b7785);
  font-weight: 500;
  text-align: left;
}
</style>
