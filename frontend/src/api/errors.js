/**
 * One error type for everything the API layer throws.
 *
 * The backend answers errors with `{"error": {"code", "name", "message", ...}}`; this turns
 * that envelope, and network failures, into an ApiError so callers never inspect Axios errors.
 */

const FALLBACK_MESSAGES = {
  400: 'The request was not valid.',
  401: 'Authentication required.',
  403: 'You do not have permission to do that.',
  404: 'Not found.',
  409: 'The request conflicts with the current state.',
  413: 'The upload is too large.',
  503: 'The service is temporarily unavailable.',
}

function fallbackMessage(status) {
  if (FALLBACK_MESSAGES[status]) return FALLBACK_MESSAGES[status]
  if (status >= 500) return 'The server ran into a problem. Please try again.'
  return `Request failed (HTTP ${status}).`
}

export class ApiError extends Error {
  /**
   * @param {object} details
   * @param {string} details.message
   * @param {number} [details.status] HTTP status; 0 when no response was received.
   * @param {string} [details.reason] HTTP reason from the envelope, e.g. "Not Found".
   * @param {object|null} [details.errors] Per-field validation messages, when provided.
   * @param {'http'|'network'|'timeout'|'canceled'|'unknown'} [details.kind]
   * @param {unknown} [details.cause]
   */
  constructor({ message, status = 0, reason = '', errors = null, kind = 'http', cause } = {}) {
    super(message, { cause })
    this.name = 'ApiError'
    this.status = status
    this.reason = reason
    this.errors = errors
    this.kind = kind
  }

  get isNetworkError() {
    return this.kind === 'network'
  }

  get isTimeout() {
    return this.kind === 'timeout'
  }

  get isCanceled() {
    return this.kind === 'canceled'
  }

  get isUnauthorized() {
    return this.status === 401
  }

  /** Flask-WTF rejects a missing, stale or mismatched token with a 400 that names CSRF. */
  get isCsrfFailure() {
    return this.status === 400 && /csrf/i.test(this.message)
  }
}

/** Convert anything thrown by Axios (or by our interceptors) into an ApiError. */
export function toApiError(error) {
  if (error instanceof ApiError) return error

  if (error?.code === 'ERR_CANCELED') {
    return new ApiError({ message: 'The request was cancelled.', kind: 'canceled', cause: error })
  }

  const response = error?.response
  if (response) {
    const envelope =
      response.data && typeof response.data === 'object' ? response.data.error : null
    const message =
      envelope && typeof envelope.message === 'string' && envelope.message
        ? envelope.message
        : fallbackMessage(response.status)
    return new ApiError({
      message,
      status: response.status,
      reason: envelope?.name || response.statusText || '',
      errors: envelope?.errors ?? null,
      cause: error,
    })
  }

  if (error?.code === 'ECONNABORTED' || error?.code === 'ETIMEDOUT') {
    return new ApiError({ message: 'The request timed out.', kind: 'timeout', cause: error })
  }

  if (error?.isAxiosError || error?.request) {
    return new ApiError({
      message: 'Unable to reach the NetScope server.',
      kind: 'network',
      cause: error,
    })
  }

  return new ApiError({
    message: error?.message || 'An unexpected error occurred.',
    kind: 'unknown',
    cause: error,
  })
}
