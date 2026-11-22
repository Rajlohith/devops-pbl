import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createMemoryHistory } from 'vue-router'

import { ApiError } from '@/api/errors'
import { createAppRouter, redirectOnUnauthorized } from '@/router'
import { useAuthStore } from '@/stores/auth'

vi.mock('@/api/auth', () => ({ authApi: { me: vi.fn(), login: vi.fn(), register: vi.fn(), logout: vi.fn() } }))
vi.mock('@/api/client', () => ({ resetCsrfToken: vi.fn() }))
const { authApi } = await import('@/api/auth')

const ID = '4318f5fd-f4e1-4d55-ac79-dd10306bf35a'
const signedIn = () => authApi.me.mockResolvedValue({ user: { id: '1', email: 'a@example.com' } })
const signedOut = () => authApi.me.mockRejectedValue(new ApiError({ message: 'Authentication required.', status: 401 }))

function setup() {
  setActivePinia(createPinia())
  return createAppRouter(createMemoryHistory())
}

beforeEach(() => vi.clearAllMocks())

describe('route protection', () => {
  it.each(['/dashboard', '/captures', '/compare', `/captures/${ID}`, `/captures/${ID}/packets`])(
    'sends a signed-out visitor from %s to sign-in, remembering the page',
    async (path) => {
      signedOut()
      const router = setup()
      await router.push(path)
      expect(router.currentRoute.value.name).toBe('login')
      expect(router.currentRoute.value.query.next).toBe(path)
    },
  )

  it('lets a signed-in user through, and asks the server only once', async () => {
    signedIn()
    const router = setup()
    await router.push('/captures')
    await router.push('/compare')
    expect(router.currentRoute.value.name).toBe('compare')
    expect(authApi.me).toHaveBeenCalledTimes(1)
  })

  it('redirects / to the dashboard', async () => {
    signedIn()
    const router = setup()
    await router.push('/')
    expect(router.currentRoute.value.name).toBe('dashboard')
  })

  it('keeps signed-in users away from the login and register pages', async () => {
    signedIn()
    const router = setup()
    await router.push('/login')
    expect(router.currentRoute.value.name).toBe('dashboard')
    await router.push('/register')
    expect(router.currentRoute.value.name).toBe('dashboard')
  })

  it('returns a signed-in user to a safe ?next, never to another site', async () => {
    signedIn()
    const router = setup()
    await router.push('/login?next=/compare')
    expect(router.currentRoute.value.path).toBe('/compare')
    await router.push('/login?next=//evil.example')
    expect(router.currentRoute.value.name).toBe('dashboard')
  })

  it('shows sign-in pages to a signed-out visitor', async () => {
    signedOut()
    const router = setup()
    await router.push('/register')
    expect(router.currentRoute.value.name).toBe('register')
  })

  it('does not treat an unreachable server as "signed out"', async () => {
    authApi.me.mockRejectedValue(new ApiError({ message: 'down', kind: 'network' }))
    const router = setup()
    await router.push('/dashboard')
    expect(router.currentRoute.value.name).toBe('dashboard') // the page shows its own error state
  })

  it('treats a malformed capture id as page-not-found', async () => {
    signedIn()
    const router = setup()
    await router.push('/captures/not-a-uuid')
    expect(router.currentRoute.value.name).toBe('not-found')
  })

  it('names every capture tab as a route', async () => {
    signedIn()
    const router = setup()
    for (const [name, suffix] of [['capture-overview', ''], ['capture-protocols', '/protocols'], ['capture-flows', '/flows'], ['capture-packets', '/packets'], ['capture-performance', '/performance']]) {
      await router.push(`/captures/${ID}${suffix}`)
      expect(router.currentRoute.value.name).toBe(name)
    }
  })
})

describe('session expiry', () => {
  it('clears the user and returns to sign-in with the current page remembered', async () => {
    signedIn()
    const router = setup()
    const auth = useAuthStore()
    await router.push('/captures?status=failed')
    expect(auth.isAuthenticated).toBe(true)

    redirectOnUnauthorized(router, auth)()
    await new Promise((r) => setTimeout(r))
    expect(auth.isAuthenticated).toBe(false)
    expect(router.currentRoute.value.name).toBe('login')
    expect(router.currentRoute.value.query).toMatchObject({ next: '/captures?status=failed', reason: 'expired' })
  })

  it('does not redirect when already on a sign-in page', async () => {
    signedOut()
    const router = setup()
    await router.push('/login')
    redirectOnUnauthorized(router, useAuthStore())()
    await new Promise((r) => setTimeout(r))
    expect(router.currentRoute.value.fullPath).toBe('/login')
  })
})
