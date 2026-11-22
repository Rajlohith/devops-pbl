<script setup>
import { useRoute, useRouter } from 'vue-router'

import { useAuthStore } from '@/stores/auth'

defineProps({
  /** Whether the off-canvas drawer is open (only relevant below the lg breakpoint). */
  open: { type: Boolean, default: false },
})
const emit = defineEmits(['close'])

const auth = useAuthStore()
const route = useRoute()
const router = useRouter()

const items = [
  {
    label: 'Dashboard',
    to: { name: 'dashboard' },
    section: '/dashboard',
    icon: 'M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z',
  },
  { label: 'Captures', to: { name: 'captures' }, section: '/captures', icon: 'M4 6h16M4 12h16M4 18h10' },
  {
    label: 'Compare',
    to: { name: 'compare' },
    section: '/compare',
    icon: 'M8 4 4 8l4 4M4 8h16M16 12l4 4-4 4M20 16H4',
  },
]

// A section stays highlighted on its sub-pages (a capture's tabs belong to "Captures").
const isActive = (item) => route.path === item.section || route.path.startsWith(`${item.section}/`)

async function signOut() {
  emit('close')
  await auth.signOut()
  router.push({ name: 'login' })
}
</script>

<template>
  <aside
    id="app-sidebar"
    class="fixed inset-y-0 left-0 z-40 flex w-64 flex-col bg-slate-900 text-slate-300 transition-transform duration-200 lg:visible lg:translate-x-0"
    :class="open ? 'translate-x-0' : 'invisible -translate-x-full'"
    aria-label="Sidebar"
  >
    <div class="flex h-14 shrink-0 items-center gap-2.5 border-b border-slate-800 px-5">
      <svg
        class="h-6 w-6 text-blue-400"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="2.25"
        stroke-linecap="round"
        stroke-linejoin="round"
        aria-hidden="true"
      >
        <path d="M2 12h5l3-8 4 16 3-8h5" />
      </svg>
      <span class="text-base font-semibold tracking-tight text-white">NetScope</span>
    </div>

    <nav class="flex-1 overflow-y-auto px-3 py-4" aria-label="Main">
      <ul class="space-y-1">
        <li v-for="item in items" :key="item.label">
          <RouterLink
            :to="item.to"
            class="flex items-center gap-3 rounded-md border-l-2 px-3 py-2 text-sm font-medium hover:bg-slate-800 hover:text-white"
            :class="
              isActive(item) ? 'border-blue-500 bg-slate-800 text-white' : 'border-transparent'
            "
            :aria-current="isActive(item) ? 'page' : undefined"
            @click="emit('close')"
          >
            <svg
              class="h-5 w-5 shrink-0"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="1.75"
              stroke-linecap="round"
              stroke-linejoin="round"
              aria-hidden="true"
            >
              <path :d="item.icon" />
            </svg>
            {{ item.label }}
          </RouterLink>
        </li>
      </ul>
    </nav>

    <div class="shrink-0 border-t border-slate-800 p-3 text-xs">
      <template v-if="auth.isAuthenticated">
        <p class="truncate px-2 text-slate-400" :title="auth.user?.email">{{ auth.user?.email }}</p>
        <button
          type="button"
          class="mt-2 w-full rounded-md px-2 py-1.5 text-left font-medium text-slate-300 hover:bg-slate-800 hover:text-white"
          @click="signOut"
        >
          Sign out
        </button>
      </template>
      <p v-else class="px-2 text-slate-500">Not signed in</p>
    </div>
  </aside>
</template>
