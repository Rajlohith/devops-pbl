import { ref, toValue } from 'vue'

import { fetchReport } from '@/api/reports'
import { saveBlob } from '@/utils/download'

/**
 * Download PDF / CSV reports for a capture through the authenticated API client (so errors such
 * as "capture not completed" show up in the page instead of navigating to raw JSON).
 *
 * @param {import('vue').MaybeRefOrGetter<string>} captureId
 */
export function useReportDownload(captureId) {
  const busy = ref('') // key of the download in progress, '' when idle
  const error = ref('')

  /** @param {string} key identifies the report in the UI @param {string} path e.g. '/report.pdf' */
  async function download(key, path, params = {}) {
    if (busy.value) return false
    busy.value = key
    error.value = ''
    const id = toValue(captureId)
    const fallback = `netscope-${id.slice(0, 8)}-${path.replace(/^\/(export\/)?/, '')}`
    try {
      const { blob, filename } = await fetchReport(id, path, params, fallback)
      saveBlob(blob, filename)
      return true
    } catch (e) {
      error.value = `Download failed: ${e.message}`
      return false
    } finally {
      busy.value = ''
    }
  }

  return { busy, error, download }
}
