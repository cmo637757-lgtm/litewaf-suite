<script setup>
/** 登录页：账号口令换 JWT，成功后进总览。 */
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from '../api/http'
import { useAuthStore } from '../stores/auth'

const router = useRouter()
const route = useRoute()
const auth = useAuthStore()

const username = ref('admin')
const password = ref('')
const error = ref('')
const loading = ref(false)

async function submit() {
  error.value = ''
  loading.value = true
  try {
    const res = await api('/api/auth/login', {
      method: 'POST',
      auth: false,
      body: { username: username.value.trim(), password: password.value }
    })
    auth.save({ ...res, username: username.value.trim() })
    router.push(route.query.next || '/')
  } catch (e) {
    error.value = e.message || '登录失败'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="login-wrap">
    <form class="login-box" @submit.prevent="submit">
      <h1>LiteWAF 控制台</h1>
      <div class="sub">Web 应用层防护平台 · 登录</div>

      <div class="field">
        <label for="u">账号</label>
        <input id="u" v-model="username" autocomplete="username" />
      </div>
      <div class="field">
        <label for="p">口令</label>
        <input id="p" v-model="password" type="password" autocomplete="current-password" />
      </div>

      <div class="err">{{ error }}</div>

      <button class="primary" style="width: 100%" :disabled="loading">
        {{ loading ? '登录中…' : '登录' }}
      </button>
    </form>
  </div>
</template>
