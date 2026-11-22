import { Chart } from 'chart.js'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '@/api/errors'
import CompareView from '@/views/CompareView.vue'

import { capture, comparison, page } from '../fixtures'
import { ID, OTHER_ID, mountAt, settle, text } from '../helpers'

vi.mock('@/api/captures', () => ({ capturesApi: { list: vi.fn() } }))
vi.mock('@/api/dashboard', () => ({ dashboardApi: { overview: vi.fn(), compare: vi.fn() } }))
const { capturesApi } = await import('@/api/captures')
const { dashboardApi } = await import('@/api/dashboard')

const both = [
  capture({ id: ID, original_filename: 'full.pcap' }),
  capture({ id: OTHER_ID, original_filename: 'head.pcap', uploaded_at: '2023-11-14T22:14:20+00:00' }),
]
const cell = (wrapper, key) => wrapper.get(`[data-cell="${key}"]`).text()

beforeEach(() => {
  vi.clearAllMocks()
  capturesApi.list.mockResolvedValue(page(both, { per_page: 100 }))
})

describe('CompareView', () => {
  it('asks only for completed captures', async () => {
    await mountAt(CompareView, '/compare')
    expect(capturesApi.list).toHaveBeenCalledWith({ status: 'completed', per_page: 100 })
  })

  it('explains that two analysed captures are needed', async () => {
    capturesApi.list.mockResolvedValue(page([both[0]]))
    const { wrapper } = await mountAt(CompareView, '/compare')
    expect(wrapper.get('[data-state="empty"]').text()).toContain('at least two analysed captures')
    expect(wrapper.find('#compare-btn').exists()).toBe(false)
  })

  it('shows an error with retry if the capture list cannot be loaded', async () => {
    capturesApi.list.mockRejectedValueOnce(new ApiError({ message: 'Unable to reach the NetScope server.', kind: 'network' }))
    const { wrapper } = await mountAt(CompareView, '/compare')
    expect(wrapper.get('[role="alert"]').text()).toContain('Unable to reach')
    await wrapper.get('[data-state="error"] button').trigger('click')
    await settle()
    expect(wrapper.find('#cmp-a').exists()).toBe(true)
  })

  it('compares two captures: metrics, deltas, chart and IP overlap', async () => {
    dashboardApi.compare.mockResolvedValue(comparison())
    const { wrapper, router } = await mountAt(CompareView, '/compare')
    expect(wrapper.findAll('#cmp-a option')).toHaveLength(3)
    await wrapper.get('#cmp-a').setValue(ID)
    await wrapper.get('#cmp-b').setValue(OTHER_ID)
    await wrapper.get('form').trigger('submit')
    await settle()

    expect(dashboardApi.compare).toHaveBeenCalledWith(ID, OTHER_ID)
    expect(cell(wrapper, 'total_packets-a')).toBe('15')
    expect(cell(wrapper, 'total_packets-b')).toBe('3')
    expect(cell(wrapper, 'total_packets-delta')).toBe('-12')
    expect(cell(wrapper, 'total_bytes-delta')).toBe('-908 B')
    expect(wrapper.findAll('tbody tr')[0].text()).toContain('-80.0%')
    // a metric one capture does not have is shown as a dash, not as zero
    expect(cell(wrapper, 'avg_rtt-b')).toBe('—')
    expect(cell(wrapper, 'avg_rtt-delta')).toBe('—')
    // column headers name the captures being compared
    expect(wrapper.findAll('th').map((th) => th.text())).toContain('A — full.pcap')

    const chart = Chart.instances.at(-1)
    expect(chart.config.type).toBe('bar')
    expect(chart.config.data.labels).toEqual(['TCP', 'ARP'])
    expect(chart.config.data.datasets.map((d) => d.data)).toEqual([[700, 42], [54, 0]])

    expect(wrapper.get('[data-ips="In both captures"]').text()).toContain('In both captures: 2')
    expect(wrapper.get('[data-ips="Only in A"]').text()).toContain('8.8.8.8')
    expect(wrapper.get('[data-ips="Only in B"]').text()).toContain('None')
    expect(router.currentRoute.value.query).toEqual({ a: ID, b: OTHER_ID }) // shareable
  })

  it('starts a comparison from a link, preselecting captures', async () => {
    dashboardApi.compare.mockResolvedValue(comparison())
    const { wrapper } = await mountAt(CompareView, `/compare?a=${ID}&b=${OTHER_ID}`)
    await vi.waitFor(() => expect(dashboardApi.compare).toHaveBeenCalledWith(ID, OTHER_ID))
    await settle()
    expect(wrapper.get('#cmp-a').element.value).toBe(ID)
    expect(cell(wrapper, 'total_packets-delta')).toBe('-12')
  })

  it('preselects only A when coming from a capture page, without comparing yet', async () => {
    const { wrapper } = await mountAt(CompareView, `/compare?a=${ID}`)
    expect(wrapper.get('#cmp-a').element.value).toBe(ID)
    expect(wrapper.get('#cmp-b').element.value).toBe('')
    expect(dashboardApi.compare).not.toHaveBeenCalled()
  })

  it('requires two different captures', async () => {
    const { wrapper } = await mountAt(CompareView, '/compare')
    await wrapper.get('form').trigger('submit')
    expect(wrapper.get('#compare-result').text()).toContain('Choose two captures.')
    await wrapper.get('#cmp-a').setValue(ID)
    await wrapper.get('#cmp-b').setValue(ID)
    await wrapper.get('form').trigger('submit')
    expect(wrapper.get('#compare-result').text()).toContain('two different captures')
    expect(dashboardApi.compare).not.toHaveBeenCalled()
  })

  it("shows the server's reason when a comparison is refused", async () => {
    dashboardApi.compare.mockRejectedValue(new ApiError({ message: 'Capture not found.', status: 404 }))
    const { wrapper } = await mountAt(CompareView, '/compare')
    await wrapper.get('#cmp-a').setValue(ID)
    await wrapper.get('#cmp-b').setValue(OTHER_ID)
    await wrapper.get('form').trigger('submit')
    await settle()
    expect(wrapper.get('#compare-result [role="alert"]').text()).toBe('Capture not found.')
    expect(wrapper.find('[data-cell]').exists()).toBe(false)
  })

  it('shows a loading state and disables the button while comparing', async () => {
    let finish
    dashboardApi.compare.mockReturnValue(new Promise((resolve) => (finish = resolve)))
    const { wrapper } = await mountAt(CompareView, '/compare')
    await wrapper.get('#cmp-a').setValue(ID)
    await wrapper.get('#cmp-b').setValue(OTHER_ID)
    await wrapper.get('form').trigger('submit')
    expect(wrapper.get('#compare-result [data-state="loading"]').exists()).toBe(true)
    expect(wrapper.get('#compare-btn').attributes('disabled')).toBeDefined()
    finish(comparison())
    await settle()
    expect(wrapper.get('#compare-btn').attributes('disabled')).toBeUndefined()
  })

  it('treats capture names as text', async () => {
    const evil = '<img src=x onerror=alert(1)>.pcap'
    capturesApi.list.mockResolvedValue(page([capture({ id: ID, original_filename: evil }), both[1]]))
    const cmp = comparison()
    cmp.a.filename = evil
    dashboardApi.compare.mockResolvedValue(cmp)
    const { wrapper } = await mountAt(CompareView, `/compare?a=${ID}&b=${OTHER_ID}`)
    await settle()
    expect(wrapper.find('img').exists()).toBe(false)
    expect(text(wrapper)).toContain(evil)
  })
})
