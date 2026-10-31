import { createApp } from 'vue'
import { createPinia } from 'pinia'
import router from './router'
import App from './App.vue'
import './styles.css'

// 入口：装 Pinia（存登录态）、装路由、挂载
const app = createApp(App)
app.use(createPinia())
app.use(router)
app.mount('#app')
