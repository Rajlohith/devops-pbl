/**
 * Central API configuration.
 *
 * Requests are same-origin by default: in development Vite proxies `/api` to Flask, and in
 * production Flask serves both the app and the API. Only override VITE_API_BASE_URL with a
 * cross-origin URL if the backend has been configured for it (it deliberately has no CORS).
 */
export const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '/api/v1').replace(/\/+$/, '')

export const REQUEST_TIMEOUT_MS = 30_000

/** Header Flask-WTF reads the CSRF token from. */
export const CSRF_HEADER = 'X-CSRFToken'

export const STATE_CHANGING_METHODS = ['post', 'put', 'patch', 'delete']
