<script setup>
import { useRoute } from 'vue-router'

import StatusPill from '@/components/StatusPill.vue'
import { useBackendStatus } from '@/composables/useBackendStatus'
import { useAuthStore } from '@/stores/auth'

defineProps({ sidebarOpen: { type: Boolean, default: false } })
defineEmits(['toggle-sidebar'])

const route = useRoute()
const auth = useAuthStore()
const { state: apiState } = useBackendStatus()
</script>

<template>
  <header
    class="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-slate-200 bg-white px-4 sm:px-6 lg:px-8"
  >
    <button
      type="button"
      class="-ml-1 rounded-md p-2 text-slate-500 hover:bg-slate-100 hover:text-slate-700 lg:hidden"
      aria-controls="app-sidebar"
      :aria-expanded="sidebarOpen"
      aria-label="Toggle navigation"
      @click="$emit('toggle-sidebar')"
    >
      <svg class="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true">
        <path d="M4 6h16M4 12h16M4 18h16" />
      </svg>
    </button>

    <h1 class="truncate text-base font-semibold text-slate-900">
      {{ route.meta.title ?? 'NetScope' }}
    </h1>

    <div class="ml-auto flex items-center gap-3">
      <StatusPill :state="apiState" />
      <span
        v-if="auth.isAuthenticated"
        class="hidden max-w-[12rem] truncate text-xs text-slate-500 sm:inline"
        :title="auth.user?.email"
      >
        {{ auth.user?.email }}
      </span>
    </div>
  </header>
</template>
