<script setup>
/**
 * 误报与调优（需求卡片 R34-10）。
 *
 * 一屏回答三个必须分开看的问题：
 *   ① 已确认误拦占全部拦截比例 = confirmed / 全部拦截
 *   ② 复核覆盖率               = (confirmed + rejected) / 全部拦截
 *   ③ 已复核事件误拦占比       = confirmed / (confirmed + rejected)
 *
 * ③ 只在"已经人工看过的那部分"里算，所以它跟 ① 天然不是一个数——
 * 把两者混着叫"误报率"是这类系统最常见的口径事故。
 * 离线误报率（拿冻结样本跑的 FPR）不在这里，属于「评估报告」页（R34-11）。
 */
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { api, fmtNum, fmtTime } from '../api/http'

const router = useRouter()

const metrics = ref(null)
const rows = ref([])
const total = ref(0)
const page = ref(1)
const pageSize = 20
const filter = ref('')
const loading = ref(true)
const error = ref('')

// 时间窗：默认全部，切 F20 时可以只看演示数据
const PRESETS = [
  { key: 'all', label: '全部时间', from: null, to: null },
  { key: 'f20', label: '演示数据（F20 固定集）', from: 1789862400000, to: 1789862460000 },
  { key: '24h', label: '最近 24 小时', from: Date.now() - 86400_000, to: Date.now() }
]
const preset = ref('all')

const pct = (v) => (v === null || v === undefined ? '-' : (v * 100).toFixed(2) + '%')

const pages = computed(() => Math.max(1, Math.ceil(total.value / pageSize)))

async function load() {
  loading.value = true
  error.value = ''
  try {
    const p = PRESETS.find((x) => x.key === preset.value) || PRESETS[0]
    const qs = []
    if (p.from) qs.push('from=' + p.from)
    if (p.to) qs.push('to=' + p.to)
    const q = qs.join('&')
    metrics.value = await api('/api/fp/metrics' + (q ? '?' + q : ''))
    const mq = [q, 'page=' + page.value, 'page_size=' + pageSize, filter.value ? 'decision=' + filter.value : '']
      .filter(Boolean)
      .join('&')
    const res = await api('/api/fp/marks?' + mq)
    rows.value = res.items
    total.value = res.total
  } catch (err) {
    error.value = err.message
  } finally {
    loading.value = false
  }
}

function setPreset(k) {
  preset.value = k
  page.value = 1
  load()
}

function setFilter(v) {
  filter.value = v
  page.value = 1
  load()
}

function go(p) {
  if (p < 1 || p > pages.value) return
  page.value = p
  load()
}

onMounted(load)
</script>

<template>
  <div>
    <div class="toolbar">
      <h2 style="margin: 0; font-size: 20px">误报与调优</h2>
      <span class="muted" style="font-size: 12px">
        人工复核结果只记在标记表里，原始拦截事实不动
      </span>
      <span style="flex: 1"></span>
      <select :value="preset" @change="setPreset($event.target.value)">
        <option v-for="p in PRESETS" :key="p.key" :value="p.key">{{ p.label }}</option>
      </select>
      <button @click="load">刷新</button>
    </div>

    <div v-if="error" class="err">{{ error }}</div>
    <div v-if="loading && !metrics" class="empty">加载中…</div>

    <template v-if="metrics">
      <div class="grid-kpi">
        <div class="kpi">
          <div class="label">已确认误拦占全部拦截</div>
          <div class="value">{{ pct(metrics.confirmed_ratio) }}</div>
          <div class="hint">
            {{ metrics.confirmed }} / {{ fmtNum(metrics.total) }} 条拦截被确认为误报
          </div>
        </div>
        <div class="kpi">
          <div class="label">复核覆盖率</div>
          <div class="value">{{ pct(metrics.coverage_ratio) }}</div>
          <div class="hint">
            已看 {{ metrics.confirmed + metrics.rejected }} 条，剩 {{ fmtNum(metrics.unreviewed) }} 条没看
          </div>
        </div>
        <div class="kpi">
          <div class="label">已复核事件的误拦占比</div>
          <div class="value">{{ pct(metrics.reviewed_fp_ratio) }}</div>
          <div class="hint">分母只算复核过的，不能当整体误报率用</div>
        </div>
        <div class="kpi">
          <div class="label">复核结论分布</div>
          <div class="value" style="font-size: 20px">
            误报 {{ metrics.confirmed }} · 驳回 {{ metrics.rejected }}
          </div>
          <div class="hint">被驳回说明是真攻击，规则不必改</div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-title">
          <span>标记记录（{{ fmtNum(total) }} 条）</span>
          <select :value="filter" @change="setFilter($event.target.value)">
            <option value="">全部结论</option>
            <option value="confirmed">只看确认误报</option>
            <option value="rejected">只看驳回</option>
          </select>
        </div>
        <table v-if="rows.length" class="data">
          <thead>
            <tr>
              <th>更新于</th>
              <th>事件</th>
              <th>来源 IP</th>
              <th>URI</th>
              <th>类型</th>
              <th>规则</th>
              <th>结论</th>
              <th>标记人</th>
              <th>备注</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in rows" :key="r.event_id" @click="router.push('/events/' + r.event_id)">
              <td class="mono">{{ fmtTime(r.updated_at_ms) }}</td>
              <td class="mono">#{{ r.event_id }}</td>
              <td class="mono">{{ r.client_ip }}</td>
              <td class="mono" style="max-width: 260px; overflow: hidden; text-overflow: ellipsis">
                {{ r.uri }}
              </td>
              <td>{{ r.category_display || '-' }}</td>
              <td class="mono">{{ r.rule_name || '-' }}</td>
              <td>
                <span :class="r.decision === 'confirmed' ? 'tag cc' : 'tag sql'">
                  {{ r.decision === 'confirmed' ? '确认误报' : '驳回' }}
                </span>
              </td>
              <td>{{ r.operator }}</td>
              <td class="muted" style="max-width: 220px; overflow: hidden; text-overflow: ellipsis">
                {{ r.remark || '-' }}
              </td>
            </tr>
          </tbody>
        </table>
        <div v-else class="empty">还没有人工复核记录。去「拦截事件」里点开一条，给个结论试试。</div>

        <div class="toolbar" style="margin-bottom: 0" v-if="pages > 1">
          <button :disabled="page <= 1" @click="go(page - 1)">上一页</button>
          <span class="muted">第 {{ page }} / {{ pages }} 页</span>
          <button :disabled="page >= pages" @click="go(page + 1)">下一页</button>
        </div>
      </div>

      <div class="panel">
        <div class="panel-title">这个闭环怎么用</div>
        <div class="muted" style="font-size: 13px; line-height: 1.9">
          ① 在「拦截事件」里发现明显正常的请求被拦 → 点「确认误报」，顺手写清是哪条业务；<br />
          ② 攒够一批误报后去「规则与 CC」把那条规则的得分或指纹调窄，先「检查」再「发布」；<br />
          ③ 发布后到「评估报告」拿冻结的带标签样本重跑一遍，看 FN/FP 有没有变差；<br />
          ④ 上面的覆盖率就是"这套闭环跑到哪一步"的唯一指标——覆盖率低的误报比例不可信。
        </div>
      </div>
    </template>
  </div>
</template>
