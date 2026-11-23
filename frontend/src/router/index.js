import { createRouter, createWebHistory } from 'vue-router'

import AppLayout from '@/layouts/AppLayout.vue'
import AuthLayout from '@/layouts/AuthLayout.vue'
import { useAuthStore } from '@/stores/auth'
import { safeNext } from '@/utils/safeNext'

// Capture ids are UUIDs; anything else is simply "page not found".
const UUID = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'

export const routes = [
  {
    path: '/login',
    component: AuthLayout,
    meta: { guestOnly: true },
    children: [
      {
        path: '',
        name: 'login',
        component: () => import('@/views/LoginView.vue'),
        meta: { title: 'Sign in', guestOnly: true },
      },
    ],
  },
  {
    path: '/register',
    component: AuthLayout,
    meta: { guestOnly: true },
    children: [
      {
        path: '',
        name: 'register',
        component: () => import('@/views/RegisterView.vue'),
        meta: { title: 'Create account', guestOnly: true },
      },
    ],
  },
  {
    path: '/',
    component: AppLayout,
    meta: { requiresAuth: true },
    children: [
      { path: '', redirect: { name: 'dashboard' } },
      {
        path: 'dashboard',
        name: 'dashboard',
        component: () => import('@/views/DashboardView.vue'),
        meta: { title: 'Dashboard' },
      },
      {
        path: 'captures',
        name: 'captures',
        component: () => import('@/views/CapturesView.vue'),
        meta: { title: 'Captures' },
      },
      {
        path: `captures/:id(${UUID})`,
        component: () => import('@/views/CaptureDetailView.vue'),
        props: true,
        meta: { title: 'Capture' },
        children: [
          {
            path: '',
            name: 'capture-overview',
            component: () => import('@/views/CaptureOverviewView.vue'),
          },
          {
            path: 'protocols',
            name: 'capture-protocols',
            component: () => import('@/views/CaptureProtocolsView.vue'),
          },
          {
            path: 'flows',
            name: 'capture-flows',
            component: () => import('@/views/CaptureFlowsView.vue'),
          },
          {
            path: 'packets',
            name: 'capture-packets',
            component: () => import('@/views/CapturePacketsView.vue'),
          },
          {
            path: 'performance',
            name: 'capture-performance',
            component: () => import('@/views/CapturePerformanceView.vue'),
          },
          {
            path: 'tcp',
            name: 'capture-tcp',
            component: () => import('@/views/CaptureTcpView.vue'),
          },
          {
            path: 'dns',
            name: 'capture-dns',
            component: () => import('@/views/CaptureDnsView.vue'),
          },
          {
            path: 'traffic',
            name: 'capture-traffic',
            component: () => import('@/views/CaptureTrafficView.vue'),
          },
        ],
      },
      {
        path: 'compare',
        name: 'compare',
        component: () => import('@/views/CompareView.vue'),
        meta: { title: 'Compare captures' },
      },
      {
        path: ':pathMatch(.*)*',
        name: 'not-found',
        component: () => import('@/views/NotFoundView.vue'),
        meta: { title: 'Page not found' },
      },
    ],
  },
]

/** Build the router. A factory, so tests can use an in-memory history. */
export function createAppRouter(history = createWebHistory(import.meta.env.BASE_URL)) {
  const router = createRouter({
    history,
    routes,
    scrollBehavior: (to, from, saved) => saved || (to.path === from.path ? false : { top: 0 }),
  })

  router.beforeEach(async (to) => {
    const auth = useAuthStore()
    await auth.ensureLoaded()

    // Only a definite "not signed in" redirects. If the server could not be reached the status
    // stays 'unknown' and pages show their own error state; the API still enforces access.
    if (to.matched.some((r) => r.meta.requiresAuth) && auth.status === 'anonymous') {
      return { name: 'login', query: to.fullPath === '/' ? {} : { next: to.fullPath } }
    }
    if (to.meta.guestOnly && auth.isAuthenticated) {
      return safeNext(to.query.next) || { name: 'dashboard' }
    }
    return true
  })

  router.afterEach((to) => {
    document.title = to.meta.title ? `${to.meta.title} · NetScope` : 'NetScope'
  })

  return router
}

/**
 * What to do when the API answers 401 for a signed-in user: forget them and go to the sign-in
 * page, remembering where they were so they return there afterwards.
 */
export function redirectOnUnauthorized(router, auth) {
  return () => {
    auth.clear()
    const route = router.currentRoute.value
    if (route.matched.some((r) => r.meta.requiresAuth)) {
      router.replace({ name: 'login', query: { next: route.fullPath, reason: 'expired' } })
    }
  }
}
