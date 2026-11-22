import { apiClient } from './client'
import { cleanParams } from './params'

export const capturesApi = {
  /** @returns {Promise<{items: object[], page: number, per_page: number, total: number}>} */
  list: (params) => apiClient.get('/captures', { params: cleanParams(params) }).then((r) => r.data),
  get: (id) => apiClient.get(`/captures/${id}`).then((r) => r.data.capture),
  status: (id) => apiClient.get(`/captures/${id}/status`).then((r) => r.data),
  analyze: (id) => apiClient.post(`/captures/${id}/analyze`).then((r) => r.data.capture),
  remove: (id) => apiClient.delete(`/captures/${id}`).then(() => undefined),

  /**
   * Upload a capture as multipart form data.
   * @param {File} file
   * @param {{analyze?: boolean, onProgress?: (fraction: number) => void, signal?: AbortSignal}} [options]
   */
  upload(file, { analyze = true, onProgress, signal } = {}) {
    const form = new FormData()
    form.append('file', file)
    form.append('analyze', analyze ? 'true' : 'false')
    return apiClient
      .post('/captures', form, {
        signal,
        timeout: 0, // large captures: the default request timeout would cut a slow upload short
        onUploadProgress: (event) => {
          if (onProgress && event.total) onProgress(Math.min(1, event.loaded / event.total))
        },
      })
      .then((r) => r.data.capture)
  },
}
