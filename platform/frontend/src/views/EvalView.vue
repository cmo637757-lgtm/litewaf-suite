<template>
  <div class="page">
    <div class="page-head">
      <div>
        <h1>评估报告</h1>
        <p class="sub">
          带标签样本的离线跑分（R34-11）。报告由 <code>scripts/s8_eval.py</code> 打到
          <code>/opt/litewaf/evaluations/&lt;run_id&gt;/report.json</code>，平台只读不重算。
        </p>
      </div>
      <div class="toolbar">
        <span v-if="list.length" class="muted">共 {{ list.length }} 次跑分</span>
        <button class="btn" :disabled="loading" @click="load">{{ loading ? '加载中…' : '刷新' }}</button>
      </div>
    </div>

    <div v-if="error" class="panel err">{{ error }}</div>

    <template v-if="latest">
      <div class="grid-kpi">
        <div class="kpi">
          <div class="label">检出率（召回）</div>
          <div class="value">{{ pct(latest.recall) }}</div>
          <div class="hint">{{ latest.tp }} / {{ latest.tp + latest.fn }} 条攻击被拦</div>
        </div>
        <div class="kpi">
          <div class="label">漏报率 FNR</div>
          <div class="value" :class="{ bad: latest.fnr > 0 }">{{ pct(latest.fnr) }}</div>
          <div class="hint">攻击没拦住的比例，越低越好</div>
        </div>
        <div class="kpi">
          <div class="label">误报率 FPR</div>
          <div class="value" :class="{ bad: latest.fpr > 0 }">{{ pct(latest.fpr) }}</div>
          <div class="hint">正常请求被拦的比例</div>
        </div>
        <div class="kpi">
          <div class="label">准确率</div>
          <div class="value">{{ pct(latest.accuracy) }}</div>
          <div class="hint">(TP+TN) / 全部样本</div>
        </div>
      </div>

      <div class="grid-2">
        <div class="panel">
          <div class="panel-title"><span>混淆矩阵（最新一次：{{ latest.run_id }}）</span></div>
          <table class="data matrix">
            <thead>
              <tr><th></th><th>判定：拦</th><th>判定：放</th></tr>
            </thead>
            <tbody>
              <tr>
                <th>实际：攻击</th>
                <td class="good">TP {{ latest.tp }}</td>
                <td class="bad">FN {{ latest.fn }}</td>
              </tr>
              <tr>
                <th>实际：正常</th>
                <td class="bad">FP {{ latest.fp }}</td>
                <td class="good">TN {{ latest.tn }}</td>
              </tr>
            </tbody>
          </table>
          <p class="hint block">
            样本构成：SQLi {{ latest.sqli_tp + latest.sqli_fn }} 条、XSS {{ latest.xss_tp + latest.xss_fn }} 条、
            正常 {{ latest.tn + latest.fp }} 条；连接失败 {{ latest.error }} 条（单列，不计入 TN）。
          </p>
        </div>

        <div class="panel">
          <div class="panel-title"><span>分类检出</span></div>
          <table class="data">
            <thead><tr><th>类别</th><th>检出</th><th>漏报</th><th>检出率</th></tr></thead>
            <tbody>
              <tr>
                <td><span class="tag">SQLi</span></td>
                <td>{{ latest.sqli_tp }}</td>
                <td :class="{ bad: latest.sqli_fn > 0 }">{{ latest.sqli_fn }}</td>
                <td>{{ pct(latest.sqli_tp / Math.max(1, latest.sqli_tp + latest.sqli_fn)) }}</td>
              </tr>
              <tr>
                <td><span class="tag">XSS</span></td>
                <td>{{ latest.xss_tp }}</td>
                <td :class="{ bad: latest.xss_fn > 0 }">{{ latest.xss_fn }}</td>
                <td>{{ pct(latest.xss_tp / Math.max(1, latest.xss_tp + latest.xss_fn)) }}</td>
              </tr>
              <tr>
                <td><span class="tag cc">CC</span></td>
                <td colspan="3">
                  第 {{ latest.cc_first_block }} 次请求开始 403
                  <span class="muted">（容量 {{ latest.cc_max }}、窗口 {{ latest.cc_window }}s）</span>
                </td>
              </tr>
            </tbody>
          </table>
          <p class="hint block">
            CC 不计入混淆矩阵：它不是「匹配样本」，而是同一来源连打后由漏桶自动封禁。
          </p>
        </div>
      </div>

      <div v-if="detail" class="grid-2">
        <div class="panel">
          <div class="panel-title"><span>漏报明细（{{ (detail.misses || []).length }}）</span></div>
          <div v-if="!(detail.misses || []).length" class="muted pad">没有漏报</div>
          <table v-else class="data">
            <thead><tr><th>请求路径</th><th>状态</th></tr></thead>
            <tbody>
              <tr v-for="m in detail.misses" :key="m.path">
                <td class="mono">{{ m.path }}</td><td class="bad">{{ m.status }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="panel">
          <div class="panel-title"><span>误报明细（{{ (detail.false_positives || []).length }}）</span></div>
          <div v-if="!(detail.false_positives || []).length" class="muted pad">没有误报</div>
          <table v-else class="data">
            <thead><tr><th>请求路径</th><th>状态</th></tr></thead>
            <tbody>
              <tr v-for="m in detail.false_positives" :key="m.path">
                <td class="mono">{{ m.path }}</td><td class="bad">{{ m.status }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <div v-if="detail" class="panel">
        <div class="panel-title"><span>跑次信息</span></div>
        <table class="data">
          <tbody>
            <tr><th>目标地址</th><td class="mono">{{ detail.target }}</td></tr>
            <tr><th>开始时间</th><td>{{ detail.run_at }}</td></tr>
            <tr><th>样本区隔间隔</th><td>{{ detail.gap_s }} 秒/条</td></tr>
            <tr><th>样本集指纹</th><td class="mono small">{{ detail.samples_sha256 }}</td></tr>
          </tbody>
        </table>
        <p class="hint block">
          样本集指纹变了，说明样本被改过，历史跑分就不能直接对比了。
        </p>
      </div>
    </template>

    <div class="panel">
      <div class="panel-title"><span>历史跑次</span></div>
      <table class="data">
        <thead>
          <tr>
            <th>跑次</th><th>时间</th><th>TP</th><th>FN</th><th>FP</th><th>TN</th>
            <th>漏报率</th><th>误报率</th><th>准确率</th><th>CC 首次拦截</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in list" :key="r.run_id" :class="{ active: r.run_id === currentRun }"
              @click="pick(r)">
            <td class="mono">{{ r.run_id }}</td>
            <td>{{ r.run_at }}</td>
            <td class="good">{{ r.tp }}</td>
            <td :class="{ bad: r.fn > 0 }">{{ r.fn }}</td>
            <td :class="{ bad: r.fp > 0 }">{{ r.fp }}</td>
            <td>{{ r.tn }}</td>
            <td>{{ pct(r.fnr) }}</td>
            <td>{{ pct(r.fpr) }}</td>
            <td>{{ pct(r.accuracy) }}</td>
            <td>{{ r.cc_first_block > 0 ? '第 ' + r.cc_first_block + ' 次' : '—' }}</td>
          </tr>
          <tr v-if="!list.length"><td colspan="10" class="muted">还没有跑分，先跑 scripts/s8_eval.py</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup>
import { onMounted, ref, computed } from 'vue'
import { api } from '../api/http.js'

const list = ref([])
const detail = ref(null)
const currentRun = ref('')
const loading = ref(false)
const error = ref('')

// 列表项已经带了混淆矩阵和指标，直接算出「最新一次」的展示用结构，
// 不用再等详情接口——详情只用来显示漏报/误报明细和指纹。
const latest = computed(() => {
  const r = list.value.find((x) => x.run_id === currentRun.value) || list.value[0]
  if (!r) return null
  const total = r.tp + r.fn + r.fp + r.tn
  return {
    ...r,
    recall: r.tp + r.fn ? r.tp / (r.tp + r.fn) : 0,
    accuracy: total ? (r.tp + r.tn) / total : 0,
    cc_max: 20,
    cc_window: 10
  }
})

function pct(v) {
  if (v === null || v === undefined || Number.isNaN(v)) return '—'
  return (v * 100).toFixed(2) + '%'
}

async function pick(row) {
  currentRun.value = row.run_id
  try {
    detail.value = await api('/api/evaluations/' + row.run_id)
  } catch (e) {
    error.value = e.message
  }
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const rs = await api('/api/evaluations')
    list.value = Array.isArray(rs) ? rs : rs.items || []
    if (list.value.length) {
      await pick(list.value.find((r) => r.run_id === currentRun.value) || list.value[0])
    }
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.matrix th {
  text-align: left;
  padding-right: 16px;
}
.good {
  color: var(--ok);
}
.bad {
  color: var(--danger);
}
.muted {
  color: var(--text-dim);
  font-size: 12px;
}
.pad {
  padding: 12px 4px;
}
.block {
  margin-top: 10px;
  line-height: 1.6;
}
.tr {
  width: 100%;
}
tr.active td {
  background: rgba(59, 130, 246, 0.12);
}
</style>
