import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '../stores/auth'

const routes = [
  { path: '/login', name: 'login', component: () => import('../views/LoginView.vue'), meta: { public: true } },
  { path: '/', name: 'dashboard', component: () => import('../views/DashboardView.vue') },
  { path: '/events', name: 'events', component: () => import('../views/EventsView.vue') },
  { path: '/events/:id', name: 'event-detail', component: () => import('../views/EventDetailView.vue') },
  { path: '/rules', name: 'rules', component: () => import('../views/RulesView.vue') },
  { path: '/alerts', name: 'alerts', component: () => import('../views/AlertsView.vue') },
  { path: '/fp', name: 'fp', component: () => import('../views/FpView.vue') },
  { path: '/eval', name: 'eval', component: () => import('../views/EvalView.vue') },
  { path: '/perf', name: 'perf', component: () => import('../views/PerfView.vue') },
  { path: '/:pathMatch(.*)*', redirect: '/' }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

// 没有登录态就回登录页；已登录还去 /login 就送回首页
router.beforeEach((to) => {
  const auth = useAuthStore()
  if (!to.meta.public && !auth.isLoggedIn) {
    return { name: 'login', query: { next: to.fullPath } }
  }
  if (to.name === 'login' && auth.isLoggedIn) {
    return { name: 'dashboard' }
  }
  return true
})

export default router
