import { createPinia } from 'pinia'
import { createApp } from 'vue'

import { setUnauthorizedHandler } from '@/api/client'
import { useAuthStore } from '@/stores/auth'

import App from './App.vue'
import './assets/main.css'
import router from './router'

const app = createApp(App)
const pinia = createPinia()
app.use(pinia)
app.use(router)

// Any 401 from the API means the session is gone; keep the auth store in step with it.
const auth = useAuthStore(pinia)
setUnauthorizedHandler(() => auth.clear())
auth.loadUser()

app.mount('#app')
