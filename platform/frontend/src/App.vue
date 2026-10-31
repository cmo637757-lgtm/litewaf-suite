<script setup>
/**
 * 外壳：左侧导航 + 顶栏。
 * 登录页不套外壳（路由 meta.public 控制），所以这里用 route 判断。
 */
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from './stores/auth'
import { api } from './api/http'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()

const isLogin = computed(() => route.name === 'login')

// 导航只放已经做出来的页面，避免“点进去空一片”（卡片 R34-01 的 AC03）
const navs = [
  { to: '/', label: '总览', name: 'dashboard' },
  { to: '/events', label: '拦截事件', name: 'events' }
]

async function logout() {
  try {
    await api('/api/auth/logout', { method: 'POST' })
  } catch {
    /* 令牌已失效也要能退出，忽略错误 */
  }
  auth.clear()
  router.push({ name: 'login' })
}
</script>

<template>
  <router-view v-if="isLogin" />

  <div v-else class="shell">
    <aside class="sidebar">
      <div class="brand">
        LiteWAF
        <small>Web 应用层防护平台</small>
      </div>
      <div class="nav-group">观测</div>
      <router-link
        v-for="n in navs"
        :key="n.to"
        :to="n.to"
        class="nav-item"
        :class="{ active: route.name === n.name || (n.name === 'events' && route.name === 'event-detail') }"
      >
        {{ n.label }}
      </router-link>
      <div class="nav-group">管理</div>
      <router-link to="/rules" class="nav-item" :class="{ active: route.name === 'rules' }">
        规则与 CC
      </router-link>
      <router-link to="/alerts" class="nav-item" :class="{ active: route.name === 'alerts' }">
        告警
      </router-link>
      <router-link to="/fp" class="nav-item" :class="{ active: route.name === 'fp' }">
        误报与调优
      </router-link>
      <router-link to="/eval" class="nav-item" :class="{ active: route.name === 'eval' }">
        评估报告
      </router-link>
      <div class="nav-group">运维</div>
      <router-link to="/perf" class="nav-item" :class="{ active: route.name === 'perf' }">
        性能与数据源
      </router-link>
    </aside>

    <div class="main">
      <header class="topbar">
        <div>{{ route.meta.title || '' }}</div>
        <div class="who">
          <span>{{ auth.username }}</span>
          <span class="tag" style="margin: 0 12px">{{ auth.role }}</span>
          <button @click="logout">退出</button>
        </div>
      </header>
      <main class="content">
        <router-view />
      </main>
    </div>
  </div>
</template>
