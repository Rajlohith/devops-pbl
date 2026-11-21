import { defineStore } from 'pinia'
import { computed, ref } from 'vue'

import { authApi } from '@/api/auth'

/** Session state for the signed-in user. Sign-in itself still happens on the Flask pages. */
export const useAuthStore = defineStore('auth', () => {
  const user = ref(null)
  // 'unknown' until the first /auth/me answer (or if the server could not be reached).
  const status = ref('unknown')

  const isAuthenticated = computed(() => status.value === 'authenticated')

  async function loadUser() {
    try {
      const data = await authApi.me()
      user.value = data.user
      status.value = 'authenticated'
    } catch (error) {
      if (error.isUnauthorized) clear()
      else status.value = 'unknown'
    }
  }

  async function signOut() {
    await authApi.logout()
    clear()
  }

  /** Forget the user locally, e.g. after sign-out or any 401 from the API. */
  function clear() {
    user.value = null
    status.value = 'anonymous'
  }

  return { user, status, isAuthenticated, loadUser, signOut, clear }
})
