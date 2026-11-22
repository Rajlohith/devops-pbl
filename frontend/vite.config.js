import { fileURLToPath, URL } from 'node:url'

import vue from '@vitejs/plugin-vue'
import { defineConfig, loadEnv } from 'vite'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')

  // The Flask development server (`flask --app backend/wsgi run`).
  const flaskTarget = env.VITE_DEV_PROXY_TARGET || 'http://127.0.0.1:5000'

  // The browser only ever talks to Vite; `/api` is forwarded to Flask. Requests stay same-origin,
  // so session cookies and CSRF work unchanged and no CORS configuration is needed on Flask.
  // `changeOrigin` stays off on purpose: Flask-WTF compares the Host and Referer of HTTPS
  // requests, and rewriting Host would make them disagree.
  const proxy = { '/api': { target: flaskTarget, changeOrigin: false } }

  return {
    plugins: [vue()],
    resolve: {
      alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
    },
    server: { port: 5173, strictPort: true, proxy },
    preview: { port: 4173, strictPort: true, proxy },
    build: {
      // Flask serves this directory in production (see NETSCOPE_FRONTEND_DIST).
      outDir: 'dist',
      emptyOutDir: true,
      sourcemap: false,
    },
    test: {
      environment: 'jsdom',
      globals: true,
      setupFiles: ['./tests/setup.js'],
      include: ['tests/**/*.spec.js'],
    },
  }
})
