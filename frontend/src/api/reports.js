import { apiClient } from './client'
import { ApiError } from './errors'
import { cleanParams } from './params'

export const REPORTS = [
  { key: 'pdf', label: 'PDF report', path: '/report.pdf' },
  { key: 'packets', label: 'CSV — packets', path: '/export/packets.csv' },
  { key: 'flows', label: 'CSV — flows', path: '/export/flows.csv' },
  { key: 'protocols', label: 'CSV — protocols', path: '/export/protocols.csv' },
  { key: 'performance', label: 'CSV — performance', path: '/export/performance.csv' },
  { key: 'timeseries', label: 'CSV — traffic over time', path: '/export/timeseries.csv' },
  { key: 'tcp-connections', label: 'CSV — TCP connections', path: '/export/tcp-connections.csv' },
  { key: 'tcp-windows', label: 'CSV — TCP windows', path: '/export/tcp-windows.csv' },
  { key: 'tcp-indicators', label: 'CSV — loss indicators', path: '/export/tcp-indicators.csv' },
  { key: 'dns-transactions', label: 'CSV — DNS transactions', path: '/export/dns-transactions.csv' },
  { key: 'top-talkers', label: 'CSV — top talkers', path: '/export/top-talkers.csv' },
  { key: 'anomalies', label: 'CSV — anomaly findings', path: '/export/anomalies.csv' },
  { key: 'analytics-summary', label: 'CSV — analytics summary', path: '/export/analytics-summary.csv' },
]

/** Pull a filename out of a `Content-Disposition: attachment; filename="..."` header. */
export function filenameFromDisposition(header, fallback) {
  const match = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(header || '')
  if (!match) return fallback
  try {
    return decodeURIComponent(match[1])
  } catch {
    return match[1]
  }
}

// With responseType 'blob' an error body arrives as a Blob; recover the server's message from it.
async function withServerMessage(error) {
  const blob = error?.cause?.response?.data
  if (!(blob instanceof Blob)) return error
  try {
    const envelope = JSON.parse(await blob.text()).error
    if (envelope?.message) {
      return new ApiError({
        message: envelope.message,
        status: error.status,
        reason: envelope.name || error.reason,
        cause: error.cause,
      })
    }
  } catch {
    /* not JSON: keep the generic message */
  }
  return error
}

/**
 * Download a report through the authenticated API client.
 * @returns {Promise<{blob: Blob, filename: string}>}
 */
export async function fetchReport(captureId, path, params, fallbackName = 'netscope-report') {
  try {
    const response = await apiClient.get(`/captures/${captureId}${path}`, {
      params: cleanParams(params),
      responseType: 'blob',
      timeout: 120_000, // a PDF over a large capture can take a while to render
    })
    return {
      blob: response.data,
      filename: filenameFromDisposition(response.headers?.['content-disposition'], fallbackName),
    }
  } catch (error) {
    throw await withServerMessage(error)
  }
}
