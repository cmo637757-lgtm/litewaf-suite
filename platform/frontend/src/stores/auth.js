/**
 * 登录态。
 *
 * 存两处：内存（Pinia）+ localStorage（刷新页面不掉线）。
 * token 放 localStorage 而不是 Cookie，是刻意选的：走 Bearer 头，天然没有 CSRF 面，
 * 不用再补 CSRF token + SameSite 那一套。
 */
import { defineStore } from 'pinia'

const KEY = 'litewaf.auth'

function load() {
  try {
    const raw = localStorage.getItem(KEY)
    if (!raw) return null
    const obj = JSON.parse(raw)
    if (!obj.token || !obj.expiresAt || obj.expiresAt < Date.now()) return null
    return obj
  } catch {
    return null
  }
}

export const useAuthStore = defineStore('auth', {
  state: () => {
    const saved = load()
    return {
      token: saved ? saved.token : '',
      username: saved ? saved.username : '',
      role: saved ? saved.role : '',
      expiresAt: saved ? saved.expiresAt : 0
    }
  },
  getters: {
    isLoggedIn: (s) => !!s.token && s.expiresAt > Date.now(),
    isAdmin: (s) => s.role === 'ADMIN'
  },
  actions: {
    save({ token, username, role, expires_in }) {
      this.token = token
      this.username = username
      this.role = role
      this.expiresAt = Date.now() + expires_in * 1000
      localStorage.setItem(
        KEY,
        JSON.stringify({
          token,
          username,
          role,
          expiresAt: this.expiresAt
        })
      )
    },
    clear() {
      this.token = ''
      this.username = ''
      this.role = ''
      this.expiresAt = 0
      localStorage.removeItem(KEY)
    }
  }
})
