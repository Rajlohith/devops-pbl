/**
 * Caches the CSRF token the backend issues for the current session.
 *
 * Concurrent callers share one in-flight request. `reset()` drops the token (and ignores any
 * fetch still in flight) after the session changes, e.g. on login or logout.
 *
 * @param {() => Promise<string>} fetchToken
 */
export function createCsrfTokenStore(fetchToken) {
  let token = null
  let pending = null
  let generation = 0

  async function get() {
    if (token) return token
    if (!pending) {
      const startedIn = generation
      const request = fetchToken()
        .then((value) => {
          if (typeof value !== 'string' || value === '') {
            throw new Error('The server returned an empty CSRF token.')
          }
          if (startedIn === generation) token = value
          return value
        })
        .finally(() => {
          if (pending === request) pending = null
        })
      pending = request
    }
    return pending
  }

  function reset() {
    token = null
    pending = null
    generation += 1
  }

  return { get, reset }
}
