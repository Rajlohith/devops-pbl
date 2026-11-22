import { apiClient } from './client'

// 401 is an expected answer for these calls, not a sign that a session expired.
const expect401 = { skipAuthRedirect: true }

export const authApi = {
  /** The signed-in user, or an ApiError with status 401. */
  me: () => apiClient.get('/auth/me', expect401).then((r) => r.data),
  login: ({ email, password }) =>
    apiClient.post('/auth/login', { email, password }, expect401).then((r) => r.data),
  register: ({ email, password }) =>
    apiClient.post('/auth/register', { email, password }, expect401).then((r) => r.data),
  logout: () => apiClient.post('/auth/logout', null, expect401).then((r) => r.data),
}
