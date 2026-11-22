import { onBeforeUnmount, ref, shallowRef } from 'vue'

/**
 * Loading / error / data state for one request.
 *
 * `load()` shows the loading state; `refresh()` re-runs silently (keeping the data on screen and
 * swallowing errors) for background updates. If calls overlap, only the newest one may write
 * state, so a slow earlier response can never overwrite a later one.
 *
 * @template T
 * @param {(...args: any[]) => Promise<T>} fetcher
 */
export function useAsyncData(fetcher) {
  const data = shallowRef(null)
  const error = ref(null)
  const loading = ref(false)
  let latest = 0
  let alive = true

  onBeforeUnmount(() => {
    alive = false
  })

  async function run(args, { silent }) {
    const id = ++latest
    if (!silent) {
      loading.value = true
      error.value = null
    }
    try {
      const result = await fetcher(...args)
      if (alive && id === latest) {
        data.value = result
        error.value = null
      }
      return result
    } catch (e) {
      if (alive && id === latest && !silent) error.value = e
      return undefined
    } finally {
      if (alive && id === latest && !silent) loading.value = false
    }
  }

  return {
    data,
    error,
    loading,
    load: (...args) => run(args, { silent: false }),
    refresh: (...args) => run(args, { silent: true }),
    reset() {
      latest += 1
      data.value = null
      error.value = null
      loading.value = false
    },
  }
}
