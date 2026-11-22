import axios, { AxiosError } from 'axios'
import { beforeEach, describe, expect, it, vi } from 'vitest'

// The real Axios, with the real interceptors; only the network layer is replaced.
let calls
let respond

function adapter(config) {
  const call = {
    method: config.method,
    url: config.url,
    csrf: config.headers.get('X-CSRFToken'),
    withCredentials: config.withCredentials,
    baseURL: config.baseURL,
  }
  calls.push(call)
  const { status = 200, data = {} } = respond(call) ?? {}
  const response = { data, status, statusText: '', headers: {}, config, request: {} }
  if (status >= 400) {
    return Promise.reject(new AxiosError(`HTTP ${status}`, 'ERR_BAD_REQUEST', config, {}, response))
  }
  return Promise.resolve(response)
}

async function loadClient() {
  vi.resetModules()
  axios.defaults.adapter = adapter
  return import('@/api/client')
}

const csrfError = { status: 400, data: { error: { code: 400, name: 'Bad Request', message: 'The CSRF token is missing.' } } }

beforeEach(() => {
  calls = []
  let n = 0
  respond = (call) => (call.url === '/auth/csrf' ? { data: { csrf_token: `token-${++n}` } } : { data: { ok: true } })
})

describe('request configuration', () => {
  it('is same-origin, sends cookies, and does not fetch a token for GETs', async () => {
    const { apiClient } = await loadClient()
    await apiClient.get('/captures')
    expect(calls).toHaveLength(1)
    expect(calls[0]).toMatchObject({ baseURL: '/api/v1', withCredentials: true, csrf: undefined })
  })
})

describe('CSRF handling', () => {
  it.each(['post', 'put', 'patch', 'delete'])('adds the token to %s requests', async (method) => {
    const { apiClient } = await loadClient()
    await apiClient[method]('/captures/1')
    expect(calls.map((c) => c.url)).toEqual(['/auth/csrf', '/captures/1'])
    expect(calls[1].csrf).toBe('token-1')
  })

  it('fetches once and reuses the token', async () => {
    const { apiClient } = await loadClient()
    await apiClient.post('/a')
    await apiClient.post('/b')
    expect(calls.filter((c) => c.url === '/auth/csrf')).toHaveLength(1)
    expect(calls.filter((c) => c.method === 'post').map((c) => c.csrf)).toEqual(['token-1', 'token-1'])
  })

  it('shares one token fetch between concurrent requests', async () => {
    const { apiClient } = await loadClient()
    await Promise.all([apiClient.post('/a'), apiClient.post('/b'), apiClient.delete('/c')])
    expect(calls.filter((c) => c.url === '/auth/csrf')).toHaveLength(1)
  })

  it('refreshes a rejected token and retries exactly once', async () => {
    const { apiClient } = await loadClient()
    respond = (call) => {
      if (call.url === '/auth/csrf') return { data: { csrf_token: `token-${calls.filter((c) => c.url === '/auth/csrf').length}` } }
      return call.csrf === 'token-1' ? csrfError : { data: { ok: true } }
    }
    const response = await apiClient.post('/captures')
    expect(response.data).toEqual({ ok: true })
    expect(calls.filter((c) => c.url === '/captures').map((c) => c.csrf)).toEqual(['token-1', 'token-2'])
  })

  it('does not retry forever when the token keeps being rejected', async () => {
    const { apiClient } = await loadClient()
    respond = (call) => (call.url === '/auth/csrf' ? { data: { csrf_token: 't' } } : csrfError)
    await expect(apiClient.post('/captures')).rejects.toMatchObject({ status: 400, isCsrfFailure: true })
    expect(calls.filter((c) => c.url === '/captures')).toHaveLength(2)
  })

  it('does not retry other 400s', async () => {
    const { apiClient } = await loadClient()
    respond = (call) =>
      call.url === '/auth/csrf'
        ? { data: { csrf_token: 't' } }
        : { status: 400, data: { error: { message: 'Validation failed.', errors: { email: 'Enter a valid email address.' } } } }
    await expect(apiClient.post('/auth/register', {})).rejects.toMatchObject({
      status: 400, message: 'Validation failed.', errors: { email: 'Enter a valid email address.' },
    })
    expect(calls.filter((c) => c.url === '/auth/register')).toHaveLength(1)
  })

  it.each(['/auth/login', '/auth/register', '/auth/logout'])('forgets the token after %s (the session was replaced)', async (url) => {
    const { apiClient } = await loadClient()
    await apiClient.post(url)
    await apiClient.post('/captures')
    expect(calls.filter((c) => c.url === '/auth/csrf')).toHaveLength(2)
    expect(calls.find((c) => c.url === '/captures').csrf).toBe('token-2')
  })

  it('fails clearly if the server returns no token', async () => {
    const { apiClient } = await loadClient()
    respond = () => ({ data: {} })
    await expect(apiClient.post('/captures')).rejects.toMatchObject({ kind: 'unknown' })
  })
})

describe('centralised error handling', () => {
  it('turns the JSON error envelope into an ApiError', async () => {
    const { apiClient } = await loadClient()
    respond = () => ({ status: 409, data: { error: { code: 409, name: 'Conflict', message: 'Already running.' } } })
    await expect(apiClient.get('/x')).rejects.toMatchObject({
      name: 'ApiError', status: 409, message: 'Already running.', reason: 'Conflict',
    })
  })

  it('falls back to a friendly message when the body is not the envelope', async () => {
    const { apiClient } = await loadClient()
    respond = () => ({ status: 502, data: '<html>Bad gateway</html>' })
    await expect(apiClient.get('/x')).rejects.toMatchObject({ status: 502, message: 'The server ran into a problem. Please try again.' })
  })

  it('reports an unreachable server as a network error', async () => {
    const { apiClient } = await loadClient()
    axios.defaults.adapter = undefined
    apiClient.defaults.adapter = () => Promise.reject(new AxiosError('Network Error', 'ERR_NETWORK', {}, {}))
    await expect(apiClient.get('/x')).rejects.toMatchObject({ kind: 'network', isNetworkError: true })
  })

  it('tells the registered handler about 401s, except where a 401 is expected', async () => {
    const { apiClient, setUnauthorizedHandler } = await loadClient()
    const handler = vi.fn()
    setUnauthorizedHandler(handler)
    respond = (call) => (call.url === '/auth/csrf' ? { data: { csrf_token: 't' } } : { status: 401, data: { error: { message: 'Authentication required.' } } })

    await expect(apiClient.get('/captures')).rejects.toMatchObject({ isUnauthorized: true })
    expect(handler).toHaveBeenCalledTimes(1)

    await expect(apiClient.post('/auth/login', {}, { skipAuthRedirect: true })).rejects.toBeTruthy()
    expect(handler).toHaveBeenCalledTimes(1) // a wrong password is not an expired session
  })
})
