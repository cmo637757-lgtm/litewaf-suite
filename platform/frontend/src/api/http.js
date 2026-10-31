/**
 * 极薄的一层 HTTP 封装。
 *
 * 为什么不用 axios：只有 6 个接口、都是 GET，多一个依赖不值得。
 * 统一处理三件事：带 token、解析统一错误体、401 时把登录态清掉并跳登录页。
 */
import { useAuthStore } from '../stores/auth'

const BASE = '' // vite 的 proxy 会把 /api 转到 18080

export class ApiError extends Error {
  constructor(message, code, status) {
    super(message)
    this.code = code
    this.status = status
  }
}

export async function api(path, { method = 'GET', body, auth = true } = {}) {
  const store = useAuthStore()
  const headers = { 'Content-Type': 'application/json' }
  if (auth && store.token) {
    headers.Authorization = 'Bearer ' + store.token
  }

  let res
  try {
    res = await fetch(BASE + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body)
    })
  } catch (e) {
    throw new ApiError('无法连接服务端，请确认后端是否启动', 'NETWORK', 0)
  }

  const text = await res.text()
  let data = null
  if (text) {
    try {
      data = JSON.parse(text)
    } catch {
      data = text
    }
  }

  if (!res.ok) {
    // 令牌过期/无效：清掉本地状态，让路由守卫把人送回登录页
    if (res.status === 401 && auth) {
      store.clear()
    }
    const msg = (data && data.message) || '请求失败（HTTP ' + res.status + '）'
    const code = (data && data.error_code) || 'HTTP_' + res.status
    throw new ApiError(msg, code, res.status)
  }
  return data
}

/** 把毫秒时间戳格式化成 YYYY-MM-DD HH:mm:ss（本地时区） */
export function fmtTime(ms) {
  const d = new Date(ms)
  const p = (n) => String(n).padStart(2, '0')
  return (
    d.getFullYear() +
    '-' +
    p(d.getMonth() + 1) +
    '-' +
    p(d.getDate()) +
    ' ' +
    p(d.getHours()) +
    ':' +
    p(d.getMinutes()) +
    ':' +
    p(d.getSeconds())
  )
}

/** 毫秒时间戳 → HH:mm:ss，趋势图的横轴用 */
export function fmtClock(ms) {
  const d = new Date(ms)
  const p = (n) => String(n).padStart(2, '0')
  return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds())
}

/** 大数字加千分位 */
export function fmtNum(n) {
  if (n === null || n === undefined) return '-'
  return Number(n).toLocaleString('zh-CN')
}
