import { defineStore } from 'pinia'
import { computed, ref } from 'vue'

import { analysisApi } from '@/api/analysis'
import { capturesApi } from '@/api/captures'

import { useCapturesStore } from './captures'
import { useDashboardStore } from './dashboard'

const POLL_MS = 1500

/**
 * The capture being viewed: its record, its processing state, and the shared analysis
 * documents (summary, performance) that several tabs read.
 */
export const useCaptureDetailStore = defineStore('captureDetail', () => {
  const id = ref(null)
  const capture = ref(null)
  const loading = ref(false)
  const error = ref(null)
  const actionError = ref(null)

  // Several tabs need the same documents; fetch each at most once per analysis.
  let memo = {}
  let pollTimer = null
  let generation = 0

  const isCompleted = computed(() => capture.value?.status === 'completed')
  const isActive = computed(
    () => capture.value?.status === 'pending' || capture.value?.status === 'processing',
  )

  function getSummary() {
    return (memo.summary ||= analysisApi.summary(id.value).catch((e) => {
      delete memo.summary // do not cache a failure
      throw e
    }))
  }

  function getPerformance() {
    return (memo.performance ||= analysisApi.performance(id.value).catch((e) => {
      delete memo.performance
      throw e
    }))
  }

  async function load(captureId) {
    if (captureId !== id.value) resetState()
    id.value = captureId
    const mine = ++generation
    loading.value = capture.value === null
    error.value = null
    try {
      const record = await capturesApi.get(captureId)
      if (mine !== generation) return
      capture.value = record
    } catch (e) {
      if (mine !== generation) return
      error.value = e
    } finally {
      if (mine === generation) loading.value = false
    }
    if (mine === generation) schedulePoll()
  }

  const reload = () => load(id.value)

  function schedulePoll() {
    stopPolling()
    if (isActive.value) pollTimer = setTimeout(poll, POLL_MS)
  }

  async function poll() {
    const mine = generation
    try {
      const status = await capturesApi.status(id.value)
      if (mine !== generation) return
      if (status.status !== capture.value.status) {
        memo = {}
        await reload()
        return
      }
      capture.value = { ...capture.value, packet_count: status.packet_count }
    } catch {
      /* transient: keep polling */
    }
    if (mine === generation) schedulePoll()
  }

  function stopPolling() {
    clearTimeout(pollTimer)
    pollTimer = null
  }

  async function startAnalysis() {
    actionError.value = null
    try {
      await capturesApi.analyze(id.value)
      memo = {}
    } catch (e) {
      actionError.value = e.message
    }
    await reload()
  }

  /** @returns {Promise<boolean>} whether the capture was deleted */
  async function remove() {
    actionError.value = null
    try {
      await capturesApi.remove(id.value)
      // The cached list and totals still include this capture; drop them so the next page
      // shows a fresh load instead of briefly listing something that no longer exists.
      useCapturesStore().reset()
      useDashboardStore().reset()
      return true
    } catch (e) {
      actionError.value = `Delete failed: ${e.message}`
      return false
    }
  }

  function resetState() {
    stopPolling()
    generation += 1
    capture.value = null
    error.value = null
    actionError.value = null
    loading.value = false
    memo = {}
  }

  function reset() {
    resetState()
    id.value = null
  }

  return {
    id, capture, loading, error, actionError, isCompleted, isActive,
    load, reload, startAnalysis, remove, getSummary, getPerformance, stopPolling, reset,
  }
})
