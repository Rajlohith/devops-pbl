import { apiClient } from './client'

export const dashboardApi = {
  overview: () => apiClient.get('/dashboard').then((r) => r.data),
  compare: (a, b) => apiClient.get('/compare', { params: { a, b } }).then((r) => r.data),
}
