import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '@/api/errors'
import { useAuthStore } from '@/stores/auth'
import { useCapturesStore } from '@/stores/captures'
import { useDashboardStore } from '@/stores/dashboard'

vi.mock('@/api/auth', () => ({ authApi: { me: vi.fn(), login: vi.fn(), register: vi.fn(), logout: vi.fn() } }))
vi.mock('@/api/client', () => ({ resetCsrfToken: vi.fn() }))
const { authApi } = await import('@/api/auth')
const { resetCsrfToken } = await import('@/api/client')

const alice = { id: '1', email: 'alice@example.com' }

beforeEach(() => {
  setActivePinia(createPinia())
  vi.clearAllMocks()
})

describe('auth store', () => {
  it('starts unknown and resolves the session once', async () => {
    authApi.me.mockResolvedValue({ user: alice })
    const auth = useAuthStore()
    expect(auth.status).toBe('unknown')
    await Promise.all([auth.ensureLoaded(), auth.ensureLoaded()])
    await auth.ensureLoaded()
    expect(authApi.me).toHaveBeenCalledTimes(1)
    expect(auth.isAuthenticated).toBe(true)
    expect(auth.user).toEqual(alice)
  })

  it('is anonymous after a 401 and unknown when the server is unreachable', async () => {
    authApi.me.mockRejectedValueOnce(new ApiError({ message: 'no', status: 401 }))
    const auth = useAuthStore()
    await auth.ensureLoaded()
    expect(auth.status).toBe('anonymous')

    setActivePinia(createPinia())
    authApi.me.mockRejectedValueOnce(new ApiError({ message: 'down', kind: 'network' }))
    const second = useAuthStore()
    await second.ensureLoaded()
    expect(second.status).toBe('unknown') // not claimed anonymous: the API will still decide
  })

  it('logs in and registers, and starts from a clean slate for the new user', async () => {
    authApi.login.mockResolvedValue({ user: alice })
    authApi.register.mockResolvedValue({ user: alice })
    const captures = useCapturesStore()
    captures.items = [{ id: 'someone-elses' }]
    const auth = useAuthStore()

    await auth.login({ email: 'alice@example.com', password: 'pw' })
    expect(authApi.login).toHaveBeenCalledWith({ email: 'alice@example.com', password: 'pw' })
    expect(auth.user).toEqual(alice)
    expect(captures.items).toEqual([]) // nothing of a previous session survives a login

    await auth.register({ email: 'alice@example.com', password: 'pw' })
    expect(auth.isAuthenticated).toBe(true)
  })

  it('leaves state untouched when login fails, and lets the error reach the caller', async () => {
    authApi.login.mockRejectedValue(new ApiError({ message: 'Invalid email or password.', status: 401 }))
    const auth = useAuthStore()
    await expect(auth.login({})).rejects.toThrow('Invalid email or password.')
    expect(auth.isAuthenticated).toBe(false)
  })

  it('signs out locally even if the server call fails, wiping user data and the CSRF token', async () => {
    authApi.logout.mockRejectedValue(new ApiError({ message: 'down', kind: 'network' }))
    const auth = useAuthStore()
    auth.user = alice
    auth.status = 'authenticated'
    useDashboardStore().data = { totals: {} }
    await expect(auth.signOut()).rejects.toBeTruthy()
    expect(auth.status).toBe('anonymous')
    expect(auth.user).toBeNull()
    expect(useDashboardStore().data).toBeNull()
    expect(resetCsrfToken).toHaveBeenCalled()
  })

  it('never writes anything to browser storage', async () => {
    authApi.login.mockResolvedValue({ user: alice })
    await useAuthStore().login({ email: 'a', password: 'b' })
    expect(localStorage.length).toBe(0)
    expect(sessionStorage.length).toBe(0)
  })
})
