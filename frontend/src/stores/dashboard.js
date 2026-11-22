import { defineStore } from 'pinia'
import { computed, ref } from 'vue'

import { dashboardApi } from '@/api/dashboard'

export const useDashboardStore = defineStore('dashboard', () => {
  const data = ref(null)
  const loading = ref(false)
  const error = ref(null)

  const inProgress = computed(() => data.value?.in_progress ?? 0)
  const isEmpty = computed(() => data.value !== null && data.value.totals.captures === 0)

  /** @param {{silent?: boolean}} [options] silent: background refresh, keep the page as it is. */
  async function fetch({ silent = false } = {}) {
    if (!silent) {
      loading.value = true
      error.value = null
    }
    try {
      data.value = await dashboardApi.overview()
      error.value = null
    } catch (e) {
      if (!silent) error.value = e
    } finally {
      if (!silent) loading.value = false
    }
  }

  function reset() {
    data.value = null
    loading.value = false
    error.value = null
  }

  return { data, loading, error, inProgress, isEmpty, fetch, reset }
})
