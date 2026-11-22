import { defineStore } from 'pinia'
import { computed, ref } from 'vue'

import { analyticsApi } from '@/api/analytics'

/**
 * The aggregate Phase 4 document (KPIs, distributions, definitions, thresholds) for the capture
 * being viewed. Every analytics tab reads it, so it is fetched once per capture.
 */
export const useAnalyticsStore = defineStore('analytics', () => {
  const captureId = ref(null)
  const document = ref(null)
  const loading = ref(false)
  const error = ref(null)
  let generation = 0

  const unavailable = computed(() => error.value?.status === 409)

  async function load(id, { force = false } = {}) {
    if (!force && id === captureId.value && document.value) return document.value
    const mine = ++generation
    if (id !== captureId.value) document.value = null
    captureId.value = id
    loading.value = true
    error.value = null
    try {
      const result = await analyticsApi.document(id)
      if (mine === generation) document.value = result
      return result
    } catch (e) {
      if (mine === generation) error.value = e
      return null
    } finally {
      if (mine === generation) loading.value = false
    }
  }

  function reset() {
    generation += 1
    captureId.value = null
    document.value = null
    loading.value = false
    error.value = null
  }

  return { captureId, document, loading, error, unavailable, load, reset }
})
