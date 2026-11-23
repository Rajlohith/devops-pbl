import { ref } from 'vue'

import { dashboardApi } from '@/api/dashboard'
import { useCapturesStore } from '@/stores/captures'

/**
 * Choose completed captures and compare them. Capture A is the baseline; B and any extra
 * captures (C, D, E) are each compared against A, one `/compare` request apiece.
 */
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

  /**
   * @param {string} a baseline capture
   * @param {string} b second capture
   * @param {string[]} [extras] further captures (empty slots are ignored)
   * @returns {Promise<boolean>} whether a comparison is now shown
   */
  async function compare(a, b, extras = []) {
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
    const more = extras.filter(Boolean)
    if (new Set([a, b, ...more]).size !== 2 + more.length) {
      error.value = 'Choose a different capture for each slot.'
      return false
    }
    comparing.value = true
    try {
      const [first, ...others] = await Promise.all([
        dashboardApi.compare(a, b),
        ...more.map((id) => dashboardApi.compare(a, id)),
      ])
      result.value = { ...first, others }
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
