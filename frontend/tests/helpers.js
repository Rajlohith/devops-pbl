import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter } from 'vue-router'

import { routes } from '@/router'

export const ID = '4318f5fd-f4e1-4d55-ac79-dd10306bf35a'
export const OTHER_ID = '9d0c2f3a-1b6e-4a57-8e3b-0a1f5c7d9e21'

/**
 * Mount a view the way the app does: a fresh Pinia, and the application's real route table on an
 * in-memory history (without the auth guard, which has its own spec).
 */
export async function mountAt(component, path, { props = {}, stubs = {} } = {}) {
  const pinia = createPinia()
  setActivePinia(pinia)
  const router = createRouter({ history: createMemoryHistory(), routes })
  router.push(path)
  await router.isReady()
  const wrapper = mount(component, {
    props,
    global: { plugins: [pinia, router], stubs },
    attachTo: document.body,
  })
  await flushPromises()
  return { wrapper, router, pinia }
}

export const text = (wrapper) => wrapper.text().replace(/\s+/g, ' ')
export const settle = () => flushPromises()
