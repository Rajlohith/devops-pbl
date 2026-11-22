import { apiClient } from './client'
import { cleanParams } from './params'

const base = (id) => `/captures/${id}`

/** Read-only results for a completed capture. */
export const analysisApi = {
  summary: (id) => apiClient.get(`${base(id)}/summary`).then((r) => r.data),
  protocols: (id) => apiClient.get(`${base(id)}/protocols`).then((r) => r.data.protocols),
  performance: (id, params) =>
    apiClient.get(`${base(id)}/performance`, { params: cleanParams(params) }).then((r) => r.data),
  packets: (id, params) =>
    apiClient.get(`${base(id)}/packets`, { params: cleanParams(params) }).then((r) => r.data),
  packet: (id, number) => apiClient.get(`${base(id)}/packets/${number}`).then((r) => r.data.packet),
  flows: (id, params) =>
    apiClient.get(`${base(id)}/flows`, { params: cleanParams(params) }).then((r) => r.data),
}
