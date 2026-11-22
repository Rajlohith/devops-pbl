<script setup>
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import AlertBanner from '@/components/common/AlertBanner.vue'
import TextField from '@/components/common/TextField.vue'
import { useAuthStore } from '@/stores/auth'
import { safeNext } from '@/utils/safeNext'

const auth = useAuthStore()
const route = useRoute()
const router = useRouter()

const email = ref('')
const password = ref('')
const error = ref('')
const submitting = ref(false)

const expired = computed(() => route.query.reason === 'expired')
const registerTarget = computed(() => ({
  name: 'register',
  query: safeNext(route.query.next) ? { next: route.query.next } : {},
}))

async function submit() {
  if (submitting.value) return
  submitting.value = true
  error.value = ''
  try {
    await auth.login({ email: email.value, password: password.value })
    await router.replace(safeNext(route.query.next) || { name: 'dashboard' })
  } catch (e) {
    error.value = e.message
    password.value = ''
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <div>
    <h1 class="mb-4 text-xl font-semibold text-slate-900">Sign in</h1>

    <AlertBanner v-if="expired && !error" kind="info" class="mb-4">
      Your session has expired. Please sign in again.
    </AlertBanner>
    <AlertBanner v-if="error" kind="error" class="mb-4">{{ error }}</AlertBanner>

    <form class="space-y-4" novalidate @submit.prevent="submit">
      <TextField id="email" v-model="email" label="Email" type="email" autocomplete="email" />
      <TextField
        id="password"
        v-model="password"
        label="Password"
        type="password"
        autocomplete="current-password"
      />
      <button type="submit" class="btn btn-primary w-full py-2" :disabled="submitting">
        {{ submitting ? 'Signing in…' : 'Sign in' }}
      </button>
    </form>

    <p class="mt-4 text-sm">
      No account? <RouterLink class="link" :to="registerTarget">Create one</RouterLink>
    </p>
  </div>
</template>
