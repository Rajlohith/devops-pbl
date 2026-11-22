import { createPinia } from 'pinia'
import { createApp } from 'vue'

import { setUnauthorizedHandler } from '@/api/client'
import { useAuthStore } from '@/stores/auth'

import App from './App.vue'
import './assets/main.css'
import { createAppRouter, redirectOnUnauthorized } from './router'

const app = createApp(App)
const pinia = createPinia()
const router = createAppRouter()

app.use(pinia)
app.use(router)

// Any 401 for a signed-in user means the session is gone: clear state and go to sign-in.
setUnauthorizedHandler(redirectOnUnauthorized(router, useAuthStore(pinia)))

app.mount('#app')
