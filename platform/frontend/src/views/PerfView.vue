<script setup>
/**
 * 性能与数据源状态（R33-06）。
 *
 * 这个页面回答三个运维问题：
 *   ① 平台接口本身慢不慢（P50/P95/最大）；
 *   ② 日志采到哪了、积压多少、采集器还活着吗；
 *   ③ 库里各表多大了，是不是该按保留策略清老数据。
 *
 * 口径提醒：源站 request_time 与 WAF cost_us 的分位数在「总览」页，
 * 这里只统计平台自己的接口耗时，两者不能混算。
 */
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { api, fmtNum } from '../api/http'

const data = ref(null)
const error = ref('')
const loading = ref(false)
let timer = null

const api_ = computed(() => data.value?.api || {})
const col = computed(() => data.value?.collector || {})

function fmtSize(bytes) {
  if (!bytes) return '0 B'
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
  return (bytes / 1024 / 1024).toFixed(2) + ' MB'
}

function fmtAgo(ms) {
  if (!ms) return '—'
  const d = Date.now() - ms
  if (d < 1000) return '刚刚'
  if (d < 60000) return Math.round(d / 1000) + ' 秒前'
  if (d < 3600000) return Math.round(d / 60000) + ' 分钟前'
  return Math.round(d / 3600000) + ' 小时前'
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    data.value = await api('/api/perf/summary')
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  load()
  timer = setInterval(load, 10000)
})
onBeforeUnmount(() => clearInterval(timer))
</script>

<template>
  <div>
    <div class="page-head">
      <div>
        <h2>性能与数据源状态</h2>
        <p class="muted">
          平台接口耗时取最近 200 次 /api 调用；日志与采集器状态每 10 秒刷新一次。
        </p>
      </div>
      <button :disabled="loading" @click="load">{{ loading ? '刷新中…' : '刷新' }}</button>
    </div>

    <div v-if="error" class="err">{{ error }}</div>

    <template v-if="data">
      <div class="grid-kpi">
        <div class="kpi">
          <div class="label">平台接口 P50</div>
          <div class="value">{{ api_.p50_ms }} <small>ms</small></div>
          <div class="hint">最近 {{ fmtNum(api_.window) }} 次调用的中位数</div>
        </div>
        <div class="kpi">
          <div class="label">平台接口 P95</div>
          <div class="value">{{ api_.p95_ms }} <small>ms</small></div>
          <div class="hint">95% 的请求快于这个值</div>
        </div>
        <div class="kpi">
          <div class="label">最慢一次</div>
          <div class="value">{{ api_.max_ms }} <small>ms</small></div>
          <div class="hint">累计 {{ fmtNum(api_.count) }} 次调用</div>
        </div>
        <div class="kpi" :class="col.alive ? '' : 'danger'">
          <div class="label">采集器心跳</div>
          <div class="value" style="font-size: 22px">
            {{ col.alive ? '正常' : '停更 ' + Math.round((col.age_ms || 0) / 1000) + 's' }}
          </div>
          <div class="hint">{{ col.hint }}</div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-title"><span>采集器</span></div>
        <table class="data">
          <tbody>
            <tr><th style="width: 160px">累计入库行数</th><td>{{ fmtNum(col.ingested_total) }}</td>
                <th style="width: 160px">解析失败行数</th><td>{{ fmtNum(col.errors_total) }}</td></tr>
            <tr><th>轮询轮数</th><td>{{ fmtNum(col.rounds) }}</td>
                <th>最近错误</th><td>{{ col.last_error || '无' }}</td></tr>
          </tbody>
        </table>
        <table class="data" style="margin-top: 12px">
          <thead>
            <tr><th>来源</th><th>类型</th><th>已读 / 总大小</th><th>积压</th><th>路径</th></tr>
          </thead>
          <tbody>
            <tr v-for="s in col.sources || []" :key="s.name">
              <td>{{ s.name }}</td>
              <td>{{ s.kind }}</td>
              <td>{{ fmtSize(s.offset) }} / {{ fmtSize(s.size) }}</td>
              <td :class="s.lag_bytes > 0 ? 'warn' : ''">{{ fmtSize(s.lag_bytes) }}</td>
              <td class="muted">{{ s.path }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="panel">
        <div class="panel-title"><span>日志文件</span></div>
        <table class="data">
          <thead>
            <tr><th>文件</th><th>大小</th><th>最后写入</th></tr>
          </thead>
          <tbody>
            <tr v-for="f in data.files" :key="f.path">
              <td class="muted">{{ f.path }}</td>
              <td>{{ f.exists ? fmtSize(f.size_bytes) : '不存在' }}</td>
              <td>{{ fmtAgo(f.modified_ms) }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="panel">
        <div class="panel-title">
          <span>数据表行数</span>
          <span class="muted" style="font-size: 12px">默认保留 7 天，超过 10 万行建议先评估查询耗时</span>
        </div>
        <table class="data">
          <thead><tr><th>表</th><th>行数</th></tr></thead>
          <tbody>
            <tr v-for="t in data.tables" :key="t.name">
              <td>{{ t.name }}</td>
              <td>{{ fmtNum(t.rows) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
  </div>
</template>

<style scoped>
.page-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 14px;
}
.page-head h2 {
  margin: 0 0 4px;
  font-size: 20px;
}
.page-head p {
  margin: 0;
  font-size: 12px;
}
.warn {
  color: var(--warn, #f59e0b);
}
</style>
