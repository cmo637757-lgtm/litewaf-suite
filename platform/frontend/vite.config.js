import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 开发时把 /api 代理到后端（Kali 本机 18080），这样前端只写相对路径，
// 部署到 nginx 或任意静态服务器时只需在那一层配同样的转发。
export default defineConfig({
  plugins: [vue()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:18080',
        changeOrigin: true
      }
    }
  },
  build: {
    outDir: 'dist',
    // echarts 体积本来就大，500KB 的告警没意义
    chunkSizeWarningLimit: 1500
  }
})
