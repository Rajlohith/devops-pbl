import { Chart } from 'chart.js'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '@/api/errors'
import DashboardView from '@/views/DashboardView.vue'

import { dashboard } from '../fixtures'
import { ID, mountAt, settle, text } from '../helpers'

vi.mock('@/api/dashboard', () => ({ dashboardApi: { overview: vi.fn(), compare: vi.fn() } }))
const { dashboardApi } = await import('@/api/dashboard')

const stat = (wrapper, label) => wrapper.get(`[data-stat="${label}"]`).text()

beforeEach(() => vi.clearAllMocks())
afterEach(() => vi.useRealTimers())

describe('DashboardView', () => {
  it('shows a loading state, then the KPI cards', async () => {
    let finish
    dashboardApi.overview.mockReturnValue(new Promise((resolve) => (finish = resolve)))
    const { wrapper } = await mountAt(DashboardView, '/dashboard')
    expect(wrapper.find('[data-state="loading"]').exists()).toBe(true)
    finish(dashboard())
    await settle()
    expect(wrapper.find('[data-state="loading"]').exists()).toBe(false)
    expect(stat(wrapper, 'Total captures')).toBe('2')
    expect(stat(wrapper, 'Packets analysed')).toBe('18')
    expect(stat(wrapper, 'Data processed')).toBe('1.23 KB')
    expect(stat(wrapper, 'Unique IPs')).toBe('6')
    expect(stat(wrapper, 'Flows')).toBe('5')
  })

  it('shows status counts and recent sessions that link to the capture', async () => {
    dashboardApi.overview.mockResolvedValue(dashboard({ status_counts: { completed: 2, processing: 0, pending: 0, uploaded: 1, failed: 3 } }))
    const { wrapper } = await mountAt(DashboardView, '/dashboard')
    expect(wrapper.get('[data-status-count="failed"]').text()).toContain('3')
    expect(wrapper.get('[data-status-count="uploaded"]').text()).toContain('1')
    const rows = wrapper.findAll('tbody tr')
    expect(rows).toHaveLength(2)
    const link = rows[0].get('a')
    expect(link.text()).toBe('full.pcap')
    expect(link.attributes('href')).toBe(`/captures/${ID}`)
    expect(rows[0].text()).toContain('1.07 KB')
  })

  it('draws a bar chart of bytes per capture and a protocol doughnut', async () => {
    dashboardApi.overview.mockResolvedValue(dashboard())
    const { wrapper } = await mountAt(DashboardView, '/dashboard')
    expect(Chart.instances.map((c) => c.config.type).sort()).toEqual(['bar', 'doughnut'])
    const bar = Chart.instances.find((c) => c.config.type === 'bar')
    expect(bar.config.data.labels).toEqual(['full.pcap', 'head.pcap'])
    expect(bar.config.data.datasets[0].data).toEqual([1070, 162])
    const doughnut = Chart.instances.find((c) => c.config.type === 'doughnut')
    expect(doughnut.config.data.labels).toEqual(['TCP', 'UDP'])
    expect(doughnut.config.data.datasets[0].data).toEqual([9, 2])
    // charts are exposed to assistive technology
    expect(wrapper.findAll('canvas[role="img"]').every((c) => c.attributes('aria-label'))).toBe(true)
    wrapper.unmount()
    expect(Chart.instances.every((c) => c.destroyed)).toBe(true) // no leaked charts
  })

  it('invites the user to upload when there are no captures', async () => {
    dashboardApi.overview.mockResolvedValue(
      dashboard({ totals: { captures: 0, packets: 0, bytes: 0, unique_ips: 0, flows: 0 }, recent_sessions: [], recent_traffic: [] }),
    )
    const { wrapper } = await mountAt(DashboardView, '/dashboard')
    expect(wrapper.get('[data-state="empty"]').text()).toContain('No captures yet')
    expect(wrapper.get('a.btn').attributes('href')).toBe('/captures')
    expect(Chart.instances).toHaveLength(0)
  })

  it('explains when captures exist but none is analysed yet', async () => {
    dashboardApi.overview.mockResolvedValue(
      dashboard({
        totals: { captures: 1, packets: 0, bytes: 0, unique_ips: 0, flows: 0 },
        status_counts: { completed: 0, processing: 0, pending: 0, uploaded: 1, failed: 0 },
        recent_traffic: [], protocols: { transport: [], application: [] },
      }),
    )
    const { wrapper } = await mountAt(DashboardView, '/dashboard')
    expect(text(wrapper)).toContain('None of your captures has been analysed yet')
    expect(text(wrapper)).toContain('No completed analyses yet.')
    expect(text(wrapper)).toContain('No protocol data yet.')
  })

  it('shows an error with a working retry', async () => {
    dashboardApi.overview.mockRejectedValueOnce(new ApiError({ message: 'The server ran into a problem. Please try again.', status: 500 }))
    dashboardApi.overview.mockResolvedValueOnce(dashboard())
    const { wrapper } = await mountAt(DashboardView, '/dashboard')
    expect(wrapper.get('[role="alert"]').text()).toContain('ran into a problem')
    await wrapper.get('[data-state="error"] button').trigger('click')
    await settle()
    expect(stat(wrapper, 'Total captures')).toBe('2')
  })

  it('refreshes by itself while analyses are running, and stops when they finish', async () => {
    vi.useFakeTimers()
    const running = dashboard({ in_progress: 1, status_counts: { completed: 1, processing: 1, pending: 0, uploaded: 0, failed: 0 } })
    dashboardApi.overview.mockResolvedValueOnce(running).mockResolvedValue(dashboard())
    const { wrapper } = await mountAt(DashboardView, '/dashboard')
    expect(text(wrapper)).toContain('1 analysis job in progress')
    expect(dashboardApi.overview).toHaveBeenCalledTimes(1)

    await vi.advanceTimersByTimeAsync(2600)
    expect(dashboardApi.overview).toHaveBeenCalledTimes(2)
    expect(text(wrapper)).not.toContain('analysis job')

    await vi.advanceTimersByTimeAsync(10_000)
    expect(dashboardApi.overview).toHaveBeenCalledTimes(2) // idle: no more polling
  })

  it('keeps the numbers on screen if a background refresh fails', async () => {
    vi.useFakeTimers()
    dashboardApi.overview.mockResolvedValueOnce(dashboard({ in_progress: 1 })).mockRejectedValue(new ApiError({ message: 'down', kind: 'network' }))
    const { wrapper } = await mountAt(DashboardView, '/dashboard')
    await vi.advanceTimersByTimeAsync(2600)
    expect(stat(wrapper, 'Total captures')).toBe('2')
    expect(wrapper.find('[data-state="error"]').exists()).toBe(false)
  })
})
