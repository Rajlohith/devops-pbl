import { defineStore } from 'pinia'
import { computed, ref } from 'vue'

import { capturesApi } from '@/api/captures'

export const CAPTURES_PER_PAGE = 15

/** The capture history: one page of captures plus the actions that change them. */
export const useCapturesStore = defineStore('captures', () => {
  const items = ref([])
  const page = ref(1)
  const perPage = ref(CAPTURES_PER_PAGE)
  const total = ref(0)
  const loaded = ref(false)
  const loading = ref(false)
  const error = ref(null)
  const actionError = ref(null)
  let lastParams = { page: 1, status: '' }

  const hasActiveJobs = computed(() =>
    items.value.some((c) => c.status === 'pending' || c.status === 'processing'),
  )
  /** Completed captures only matter to the comparison page. */
  const completed = ref([])

  async function fetch(params = lastParams, { silent = false } = {}) {
    lastParams = { page: 1, status: '', ...params }
    if (!silent) {
      loading.value = true
      error.value = null
    }
    try {
      const data = await capturesApi.list({ ...lastParams, per_page: perPage.value })
      // The last page can empty out (e.g. after a delete): step back to the real last page.
      if (data.items.length === 0 && data.total > 0 && lastParams.page > 1) {
        return fetch({ ...lastParams, page: Math.ceil(data.total / perPage.value) }, { silent })
      }
      items.value = data.items
      page.value = data.page
      total.value = data.total
      loaded.value = true
      error.value = null
    } catch (e) {
      if (!silent) error.value = e
    } finally {
      if (!silent) loading.value = false
    }
  }

  const refresh = () => fetch(lastParams, { silent: true })

  /** Analyse or retry. Errors are kept in `actionError` for the page to show. */
  async function analyze(id) {
    actionError.value = null
    try {
      await capturesApi.analyze(id)
    } catch (e) {
      actionError.value = `Analysis could not be started: ${e.message}`
    }
    await refresh()
  }

  async function remove(id) {
    actionError.value = null
    try {
      await capturesApi.remove(id)
    } catch (e) {
      actionError.value = `Delete failed: ${e.message}`
    }
    await refresh()
  }

  /** Every completed capture (up to the API's page limit), for the comparison pickers. */
  async function loadCompleted() {
    const data = await capturesApi.list({ status: 'completed', per_page: 100 })
    completed.value = data.items
    return data.items
  }

  function reset() {
    items.value = []
    completed.value = []
    page.value = 1
    total.value = 0
    loaded.value = false
    loading.value = false
    error.value = null
    actionError.value = null
    lastParams = { page: 1, status: '' }
  }

  return {
    items, page, perPage, total, loaded, loading, error, actionError, hasActiveJobs, completed,
    fetch, refresh, analyze, remove, loadCompleted, reset,
  }
})
