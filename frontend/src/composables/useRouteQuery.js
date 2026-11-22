import { computed } from 'vue'
import { NavigationFailureType, isNavigationFailure, useRoute, useRouter } from 'vue-router'

/**
 * Keep filter / paging state in the URL query string, so it survives reloads, works with the
 * Back button, and can be shared as a link.
 *
 * `defaults` declares every key and its type: a string, a number or a boolean. Values equal to
 * their default are left out of the URL.
 *
 * @template {Record<string, string | number | boolean>} T
 * @param {T} defaults
 * @param {{onUnchanged?: () => void}} [options] called when a navigation would not change the
 *   URL (e.g. pressing Apply twice), so the caller can still refresh its data.
 */
export function useRouteQuery(defaults, { onUnchanged } = {}) {
  const route = useRoute()
  const router = useRouter()

  const first = (raw) => (Array.isArray(raw) ? raw[0] : raw)

  function parse(query) {
    const out = {}
    for (const [key, fallback] of Object.entries(defaults)) {
      const raw = first(query[key])
      if (raw === undefined || raw === null) out[key] = fallback
      else if (typeof fallback === 'boolean') out[key] = raw === 'true'
      else if (typeof fallback === 'number') {
        const n = Number(raw)
        out[key] = Number.isFinite(n) && n >= 1 ? Math.floor(n) : fallback
      } else out[key] = String(raw)
    }
    return out
  }

  function serialise(values) {
    const query = {}
    for (const [key, fallback] of Object.entries(defaults)) {
      const value = values[key]
      if (value === fallback || value === undefined || value === null || value === '') continue
      query[key] = String(value)
    }
    return query
  }

  /** The current, validated filter values. */
  const applied = computed(() => parse(route.query))

  async function go(query) {
    const failure = await router.push({ query })
    if (isNavigationFailure(failure, NavigationFailureType.duplicated)) onUnchanged?.()
  }

  /** Merge `values` into the filters and navigate (adds a history entry). */
  const apply = (values) => go(serialise({ ...applied.value, ...values }))

  /** Navigate to exactly `values` (filters not mentioned go back to their defaults). */
  const replaceAll = (values) => go(serialise({ ...defaults, ...values }))

  const setPage = (page) => apply({ page })
  const reset = () => go({})

  return { applied, apply, replaceAll, setPage, reset }
}
