/**
 * The one Axios instance the app uses to talk to the Flask API.
 *
 * - Same-origin base URL (see config.js); cookies are sent for session authentication.
 * - State-changing requests carry the CSRF token in `X-CSRFToken`; a rejected token is
 *   refreshed and the request retried once.
 * - Every failure is rethrown as an ApiError; 401s also notify the registered handler.
 */
import axios from 'axios'

import {
  API_BASE_URL,
  CSRF_HEADER,
  REQUEST_TIMEOUT_MS,
  STATE_CHANGING_METHODS,
} from './config'
import { createCsrfTokenStore } from './csrf'
import { toApiError } from './errors'

const baseConfig = {
  baseURL: API_BASE_URL,
  timeout: REQUEST_TIMEOUT_MS,
  withCredentials: true,
  headers: { Accept: 'application/json' },
}

// Interceptor-free instance, used only to fetch CSRF tokens (avoids recursion).
const tokenClient = axios.create(baseConfig)

const csrf = createCsrfTokenStore(async () => {
  const { data } = await tokenClient.get('/auth/csrf')
  return data?.csrf_token
})

/** Forget the cached token; the next state-changing request fetches a fresh one. */
export const resetCsrfToken = csrf.reset

export const apiClient = axios.create(baseConfig)

const isStateChanging = (config) =>
  STATE_CHANGING_METHODS.includes((config?.method || 'get').toLowerCase())

// Login, registration and logout replace the server-side session, which invalidates the token.
const SESSION_CHANGING_URL = /\/auth\/(login|register|logout)$/

let unauthorizedHandler = null

/** Register a function called whenever the API answers 401 (e.g. to clear the signed-in user). */
export function setUnauthorizedHandler(handler) {
  unauthorizedHandler = handler
}

apiClient.interceptors.request.use(async (config) => {
  if (isStateChanging(config)) {
    config.headers.set(CSRF_HEADER, await csrf.get())
  }
  return config
})

apiClient.interceptors.response.use(
  (response) => {
    if (isStateChanging(response.config) && SESSION_CHANGING_URL.test(response.config.url || '')) {
      csrf.reset()
    }
    return response
  },
  (error) => {
    const apiError = toApiError(error)
    const config = error?.config

    if (apiError.isCsrfFailure && config && !config._csrfRetried && isStateChanging(config)) {
      config._csrfRetried = true
      csrf.reset()
      return apiClient.request(config)
    }

    if (apiError.isUnauthorized && unauthorizedHandler) unauthorizedHandler(apiError)
    return Promise.reject(apiError)
  },
)
