import { ref } from 'vue'

import { dashboardApi } from '@/api/dashboard'
import { useCapturesStore } from '@/stores/captures'

/** Choose two completed captures and compare them. */
export function useComparison() {
  const captures = useCapturesStore()
  const options = ref([])
  const optionsState = ref('loading') // 'loading' | 'ready' | 'error'
  const optionsError = ref(null)

  const result = ref(null)
  const comparing = ref(false)
  const error = ref('')

  async function loadOptions() {
    optionsState.value = 'loading'
    optionsError.value = null
    try {
      options.value = await captures.loadCompleted()
      optionsState.value = 'ready'
    } catch (e) {
      optionsError.value = e
      optionsState.value = 'error'
    }
  }

  /** @returns {Promise<boolean>} whether a comparison is now shown */
  async function compare(a, b) {
    error.value = ''
    result.value = null
    if (!a || !b) {
      error.value = 'Choose two captures.'
      return false
    }
    if (a === b) {
      error.value = 'Choose two different captures to compare.'
      return false
    }
    comparing.value = true
    try {
      result.value = await dashboardApi.compare(a, b)
      return true
    } catch (e) {
      error.value = e.message
      return false
    } finally {
      comparing.value = false
    }
  }

  return { options, optionsState, optionsError, result, comparing, error, loadOptions, compare }
}
