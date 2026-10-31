<script setup>
/**
 * ECharts 的薄封装：
 * - 传 option 就渲染，option 变了整体替换（notMerge=true，避免旧系列残留）
 * - 自己管 resize，父组件不用操心
 * - 容器高度由父组件用 height 指定
 */
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts'

const props = defineProps({
  option: { type: Object, required: true },
  height: { type: String, default: '260px' }
})

const el = ref(null)
let chart = null

/**
 * 强制把 tooltip 设成 richText（画在 canvas 上），不用默认的 HTML 注入。
 * 原因：图表里的 IP / URI / 类别都来自被防护站点的日志，是攻击者可控的字符串；
 * ECharts 5.6 的 HTML tooltip 会把它们塞进 innerHTML，
 * 一条 `GET /<img src=x onerror=...>` 就能在管理员页面上执行脚本（GHSA-fgmj-fm8m-jvvx）。
 * 升 6.x 是大版本跳跃，先用 richText 把注入面关掉，等 6.x 稳定再整体升级。
 */
function harden(option) {
  const base = {
    renderMode: 'richText',
    backgroundColor: '#131b24',
    borderColor: '#2a3542',
    borderWidth: 1,
    textStyle: { color: '#d7dee6', fontSize: 12 },
    padding: [8, 10]
  }
  return {
    ...option,
    tooltip: option.tooltip === false ? false : { ...base, ...(option.tooltip || {}) }
  }
}

function render() {
  if (chart) {
    chart.setOption(harden(props.option), true)
  }
}

function onResize() {
  chart && chart.resize()
}

onMounted(() => {
  chart = echarts.init(el.value, null, { renderer: 'canvas' })
  render()
  window.addEventListener('resize', onResize)
})

onBeforeUnmount(() => {
  window.removeEventListener('resize', onResize)
  chart && chart.dispose()
  chart = null
})

watch(() => props.option, render, { deep: true })
</script>

<template>
  <div ref="el" :style="{ height: height, width: '100%' }"></div>
</template>
