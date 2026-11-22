import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '@/api/errors'
import LoginView from '@/views/LoginView.vue'
import RegisterView from '@/views/RegisterView.vue'
import { useAuthStore } from '@/stores/auth'

import { mountAt, settle, text } from '../helpers'

vi.mock('@/api/auth', () => ({ authApi: { me: vi.fn(), login: vi.fn(), register: vi.fn(), logout: vi.fn() } }))
vi.mock('@/api/client', () => ({ resetCsrfToken: vi.fn() }))
const { authApi } = await import('@/api/auth')

const user = { id: '1', email: 'alice@example.com' }
beforeEach(() => vi.clearAllMocks())

async function fill(wrapper, email, password) {
  await wrapper.find('#email').setValue(email)
  await wrapper.find('#password').setValue(password)
  await wrapper.find('form').trigger('submit')
  await settle()
}

describe('LoginView', () => {
  it('signs in and goes to the dashboard', async () => {
    authApi.login.mockResolvedValue({ user })
    const { wrapper, router } = await mountAt(LoginView, '/login')
    await fill(wrapper, 'alice@example.com', 'correct-horse-battery')
    expect(authApi.login).toHaveBeenCalledWith({ email: 'alice@example.com', password: 'correct-horse-battery' })
    expect(useAuthStore().isAuthenticated).toBe(true)
    await vi.waitFor(() => expect(router.currentRoute.value.name).toBe('dashboard'))
  })

  it('returns to the page the user was trying to reach', async () => {
    authApi.login.mockResolvedValue({ user })
    const { wrapper, router } = await mountAt(LoginView, '/login?next=/captures%3Fstatus%3Dfailed')
    await fill(wrapper, 'a@example.com', 'pw')
    await vi.waitFor(() => expect(router.currentRoute.value.fullPath).toBe('/captures?status=failed'))
  })

  it('ignores an off-site next parameter', async () => {
    authApi.login.mockResolvedValue({ user })
    const { wrapper, router } = await mountAt(LoginView, '/login?next=//evil.example')
    await fill(wrapper, 'a@example.com', 'pw')
    await vi.waitFor(() => expect(router.currentRoute.value.name).toBe('dashboard'))
  })

  it('shows the server message for bad credentials and clears the password', async () => {
    authApi.login.mockRejectedValue(new ApiError({ message: 'Invalid email or password.', status: 401 }))
    const { wrapper, router } = await mountAt(LoginView, '/login')
    await fill(wrapper, 'alice@example.com', 'wrong')
    expect(wrapper.get('[data-alert="error"]').text()).toBe('Invalid email or password.')
    expect(wrapper.get('#password').element.value).toBe('')
    expect(wrapper.get('#email').element.value).toBe('alice@example.com')
    expect(router.currentRoute.value.name).toBe('login')
  })

  it('explains an unreachable server', async () => {
    authApi.login.mockRejectedValue(new ApiError({ message: 'Unable to reach the NetScope server.', kind: 'network' }))
    const { wrapper } = await mountAt(LoginView, '/login')
    await fill(wrapper, 'a@example.com', 'pw')
    expect(text(wrapper)).toContain('Unable to reach the NetScope server.')
  })

  it('says when the session has expired, but not alongside a login error', async () => {
    authApi.login.mockRejectedValue(new ApiError({ message: 'Invalid email or password.', status: 401 }))
    const { wrapper } = await mountAt(LoginView, '/login?reason=expired')
    expect(wrapper.get('[data-alert="info"]').text()).toContain('session has expired')
    await fill(wrapper, 'a@example.com', 'x')
    expect(wrapper.find('[data-alert="info"]').exists()).toBe(false)
  })

  it('disables the button while signing in, so it cannot be double-submitted', async () => {
    let finish
    authApi.login.mockReturnValue(new Promise((resolve) => (finish = resolve)))
    const { wrapper } = await mountAt(LoginView, '/login')
    await wrapper.find('#email').setValue('a@example.com')
    await wrapper.find('#password').setValue('pw')
    await wrapper.find('form').trigger('submit')
    await wrapper.find('form').trigger('submit')
    expect(authApi.login).toHaveBeenCalledTimes(1)
    expect(wrapper.get('button[type="submit"]').attributes('disabled')).toBeDefined()
    finish({ user })
    await settle()
  })

  it('labels its fields and uses password-manager-friendly autocomplete', async () => {
    const { wrapper } = await mountAt(LoginView, '/login')
    expect(wrapper.get('label[for="email"]').text()).toBe('Email')
    expect(wrapper.get('#email').attributes('autocomplete')).toBe('email')
    expect(wrapper.get('#password').attributes('autocomplete')).toBe('current-password')
    expect(wrapper.get('#password').attributes('type')).toBe('password')
  })
})

describe('RegisterView', () => {
  it('creates the account and goes to the dashboard', async () => {
    authApi.register.mockResolvedValue({ user })
    const { wrapper, router } = await mountAt(RegisterView, '/register')
    await fill(wrapper, 'alice@example.com', 'correct-horse-battery')
    expect(authApi.register).toHaveBeenCalledWith({ email: 'alice@example.com', password: 'correct-horse-battery' })
    await vi.waitFor(() => expect(router.currentRoute.value.name).toBe('dashboard'))
  })

  it('shows validation errors next to the fields they belong to', async () => {
    authApi.register.mockRejectedValue(
      new ApiError({ message: 'Validation failed.', status: 400, errors: { email: 'Enter a valid email address.', password: 'Password must be at least 8 characters.' } }),
    )
    const { wrapper } = await mountAt(RegisterView, '/register')
    await fill(wrapper, 'nope', 'x')
    expect(wrapper.get('#email-error').text()).toBe('Enter a valid email address.')
    expect(wrapper.get('#password-error').text()).toContain('at least 8')
    expect(wrapper.get('#email').attributes('aria-invalid')).toBe('true')
    expect(wrapper.get('#email').attributes('aria-describedby')).toContain('email-error')
  })

  it('reports a duplicate email on the email field', async () => {
    authApi.register.mockRejectedValue(new ApiError({ message: 'An account with this email already exists.', status: 409 }))
    const { wrapper } = await mountAt(RegisterView, '/register')
    await fill(wrapper, 'alice@example.com', 'correct-horse-battery')
    expect(wrapper.get('#email-error').text()).toBe('An account with this email already exists.')
  })

  it('shows other failures as a banner', async () => {
    authApi.register.mockRejectedValue(new ApiError({ message: 'The server ran into a problem. Please try again.', status: 500 }))
    const { wrapper } = await mountAt(RegisterView, '/register')
    await fill(wrapper, 'a@example.com', 'correct-horse-battery')
    expect(wrapper.get('[data-alert="error"]').text()).toContain('ran into a problem')
  })

  it('clears old errors when resubmitting', async () => {
    authApi.register.mockRejectedValueOnce(new ApiError({ message: 'x', status: 400, errors: { email: 'bad' } }))
    authApi.register.mockResolvedValueOnce({ user })
    const { wrapper } = await mountAt(RegisterView, '/register')
    await fill(wrapper, 'a', 'b')
    expect(wrapper.find('#email-error').exists()).toBe(true)
    await fill(wrapper, 'a@example.com', 'correct-horse-battery')
    expect(wrapper.find('#email-error').exists()).toBe(false)
  })
})
