import { computed, watch } from 'vue'

import { useAsyncData } from './useAsyncData'
import { useRouteQuery } from './useRouteQuery'

/**
 * A filterable, sortable, paginated list whose state lives in the URL.
 *
 * @param {(params: object) => Promise<{items: any[], total: number, page: number, per_page: number}>} fetcher
 * @param {Record<string, string|number|boolean>} defaults every filter key and its default; must include `page`
 * @param {{perPage?: number}} [options]
 */
export function usePagedList(fetcher, defaults, { perPage = 25 } = {}) {
  const request = useAsyncData(fetcher)
  const params = () => ({ ...query.applied.value, per_page: perPage })
  const query = useRouteQuery(defaults, { onUnchanged: () => request.load(params()) })

  watch(query.applied, () => request.load(params()), { immediate: true })

  return {
    ...query,
    perPage,
    data: request.data,
    error: request.error,
    loading: request.loading,
    items: computed(() => request.data.value?.items ?? []),
    total: computed(() => request.data.value?.total ?? 0),
    reload: () => request.load(params()),
  }
}
