import { apiClient } from './client'

export const healthApi = {
  check: () => apiClient.get('/health', { timeout: 5_000 }).then((response) => response.data),
}
