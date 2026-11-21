import { apiClient } from './client'

export const authApi = {
  /** The signed-in user, or an ApiError with status 401. */
  me: () => apiClient.get('/auth/me').then((response) => response.data),
  logout: () => apiClient.post('/auth/logout').then((response) => response.data),
}
