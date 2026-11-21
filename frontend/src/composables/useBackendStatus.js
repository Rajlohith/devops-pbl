import { onBeforeUnmount, onMounted, ref } from 'vue'

import { healthApi } from '@/api/health'

/** Polls the API health endpoint so the UI can show whether Flask is reachable. */
export function useBackendStatus(intervalMs = 30_000) {
  const state = ref('checking') // 'checking' | 'online' | 'offline'
  let timer = null

  async function check() {
    try {
      await healthApi.check()
      state.value = 'online'
    } catch {
      state.value = 'offline'
    }
  }

  onMounted(() => {
    check()
    timer = setInterval(() => {
      if (!document.hidden) check()
    }, intervalMs)
  })

  onBeforeUnmount(() => clearInterval(timer))

  return { state, check }
}
