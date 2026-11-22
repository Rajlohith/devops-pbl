<script setup>
import { computed, reactive, ref } from 'vue'
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
const fieldErrors = reactive({ email: '', password: '' })
const formError = ref('')
const submitting = ref(false)

const loginTarget = computed(() => ({
  name: 'login',
  query: safeNext(route.query.next) ? { next: route.query.next } : {},
}))

async function submit() {
  if (submitting.value) return
  submitting.value = true
  fieldErrors.email = fieldErrors.password = formError.value = ''
  try {
    await auth.register({ email: email.value, password: password.value })
    await router.replace(safeNext(route.query.next) || { name: 'dashboard' })
  } catch (e) {
    if (e.errors) {
      fieldErrors.email = e.errors.email || ''
      fieldErrors.password = e.errors.password || ''
    } else if (e.status === 409) {
      fieldErrors.email = e.message // "An account with this email already exists."
    } else {
      formError.value = e.message
    }
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <div>
    <h1 class="mb-4 text-xl font-semibold text-slate-900">Create an account</h1>

    <AlertBanner v-if="formError" kind="error" class="mb-4">{{ formError }}</AlertBanner>

    <form class="space-y-4" novalidate @submit.prevent="submit">
      <TextField
        id="email"
        v-model="email"
        label="Email"
        type="email"
        autocomplete="email"
        :error="fieldErrors.email"
      />
      <TextField
        id="password"
        v-model="password"
        label="Password"
        type="password"
        autocomplete="new-password"
        hint="At least 8 characters."
        :error="fieldErrors.password"
      />
      <button type="submit" class="btn btn-primary w-full py-2" :disabled="submitting">
        {{ submitting ? 'Creating account…' : 'Create account' }}
      </button>
    </form>

    <p class="mt-4 text-sm">
      Already registered? <RouterLink class="link" :to="loginTarget">Sign in</RouterLink>
    </p>
  </div>
</template>
