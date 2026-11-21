<script setup>
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'

import AppSidebar from '@/components/AppSidebar.vue'
import AppTopbar from '@/components/AppTopbar.vue'

const route = useRoute()
const sidebarOpen = ref(false)

const closeSidebar = () => {
  sidebarOpen.value = false
}
const onKeydown = (event) => {
  if (event.key === 'Escape') closeSidebar()
}

watch(() => route.fullPath, closeSidebar)
onMounted(() => window.addEventListener('keydown', onKeydown))
onBeforeUnmount(() => window.removeEventListener('keydown', onKeydown))
</script>

<template>
  <div class="min-h-screen">
    <a
      href="#main"
      class="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-50 focus:rounded-md focus:bg-white focus:px-3 focus:py-2 focus:text-blue-700 focus:shadow"
    >
      Skip to content
    </a>

    <AppSidebar :open="sidebarOpen" @close="closeSidebar" />

    <!-- Backdrop for the mobile drawer. -->
    <div
      v-if="sidebarOpen"
      class="fixed inset-0 z-30 bg-slate-900/50 lg:hidden"
      aria-hidden="true"
      @click="closeSidebar"
    ></div>

    <div class="flex min-h-screen min-w-0 flex-col lg:pl-64">
      <AppTopbar :sidebar-open="sidebarOpen" @toggle-sidebar="sidebarOpen = !sidebarOpen" />
      <main id="main" class="mx-auto w-full max-w-7xl flex-1 px-4 py-6 sm:px-6 lg:px-8">
        <RouterView />
      </main>
    </div>
  </div>
</template>
