import { defineStore } from 'pinia'
import { computed, ref } from 'vue'

import { authApi } from '@/api/auth'
import { resetCsrfToken } from '@/api/client'

import { resetSessionData } from './session'

/**
 * Who is signed in. The session itself lives in an HttpOnly cookie the browser manages, so
 * nothing about the user is written to localStorage, sessionStorage or any other browser
 * storage: reloading the page simply asks the server again (`/auth/me`).
 */
export const useAuthStore = defineStore('auth', () => {
  const user = ref(null)
  // 'unknown' until the first /auth/me answer (or if the server could not be reached).
  const status = ref('unknown')
  let pending = null

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

  /** Resolve the session once; concurrent callers share the same request. */
  function ensureLoaded() {
    if (status.value !== 'unknown') return Promise.resolve()
    if (!pending) {
      pending = loadUser().finally(() => {
        pending = null
      })
    }
    return pending
  }

  function setUser(next) {
    resetSessionData() // never show a previous user's data to the next one
    user.value = next
    status.value = 'authenticated'
  }

  async function login(credentials) {
    const data = await authApi.login(credentials)
    setUser(data.user)
  }

  async function register(credentials) {
    const data = await authApi.register(credentials)
    setUser(data.user)
  }

  async function signOut() {
    try {
      await authApi.logout()
    } finally {
      // Whatever the server said, this browser is done with the session.
      clear()
    }
  }

  /** Forget the user locally, e.g. after sign-out or any 401 from the API. */
  function clear() {
    user.value = null
    status.value = 'anonymous'
    resetCsrfToken()
    resetSessionData()
  }

  return { user, status, isAuthenticated, loadUser, ensureLoaded, login, register, signOut, clear }
})
