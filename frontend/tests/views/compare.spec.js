import { Chart } from 'chart.js'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '@/api/errors'
import CompareView from '@/views/CompareView.vue'

import { capture, comparison, page } from '../fixtures'
import { ID, OTHER_ID, mountAt, settle, text } from '../helpers'

const THIRD_ID = '7a1b9c3d-5e2f-4a68-9b0c-1d2e3f4a5b6c'
const FOURTH_ID = '2c3d4e5f-6a7b-4c8d-9e0f-a1b2c3d4e5f6'

vi.mock('@/api/captures', () => ({ capturesApi: { list: vi.fn() } }))
vi.mock('@/api/dashboard', () => ({ dashboardApi: { overview: vi.fn(), compare: vi.fn() } }))
const { capturesApi } = await import('@/api/captures')
const { dashboardApi } = await import('@/api/dashboard')

const both = [
  capture({ id: ID, original_filename: 'full.pcap' }),
  capture({ id: OTHER_ID, original_filename: 'head.pcap', uploaded_at: '2023-11-14T22:14:20+00:00' }),
]
const all = [
  ...both,
  capture({ id: THIRD_ID, original_filename: 'third.pcap', uploaded_at: '2023-11-14T22:15:20+00:00' }),
  capture({ id: FOURTH_ID, original_filename: 'fourth.pcap', uploaded_at: '2023-11-14T22:16:20+00:00' }),
]
/** What `/compare?a=ID&b=<id>` returns when B is a third capture with 20 packets. */
const againstThird = () => {
  const c = comparison()
  c.b = { id: THIRD_ID, filename: 'third.pcap', uploaded_at: '2023-11-14T22:15:20+00:00' }
  c.metrics[0] = { ...c.metrics[0], b: 20, delta: 5, delta_percent: 33.3 }
  c.protocols = [{ protocol: 'UDP', a: null, b: { packets: 2, bytes: 300 } }, ...c.protocols]
  return c
}
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

  it('no longer shows the explanatory dash note', async () => {
    dashboardApi.compare.mockResolvedValue(comparison())
    const { wrapper } = await mountAt(CompareView, `/compare?a=${ID}&b=${OTHER_ID}`)
    await settle()
    expect(text(wrapper)).not.toContain('A dash')
    expect(cell(wrapper, 'avg_rtt-b')).toBe('—') // the dash itself is still shown
  })
})

describe('CompareView: switch', () => {
  it('swaps captures A and B without comparing when nothing is shown yet', async () => {
    const { wrapper } = await mountAt(CompareView, '/compare')
    await wrapper.get('#cmp-a').setValue(ID)
    await wrapper.get('#cmp-b').setValue(OTHER_ID)
    await wrapper.get('#switch-btn').trigger('click')
    expect(wrapper.get('#cmp-a').element.value).toBe(OTHER_ID)
    expect(wrapper.get('#cmp-b').element.value).toBe(ID)
    expect(dashboardApi.compare).not.toHaveBeenCalled()
  })

  it('is placed next to the Compare button and refreshes a shown comparison', async () => {
    dashboardApi.compare.mockResolvedValue(comparison())
    const { wrapper, router } = await mountAt(CompareView, `/compare?a=${ID}&b=${OTHER_ID}`)
    await settle()
    const buttons = wrapper.findAll('form button').map((b) => b.attributes('id'))
    expect(buttons.indexOf('switch-btn')).toBe(buttons.indexOf('compare-btn') + 1)
    await wrapper.get('#switch-btn').trigger('click')
    await settle()
    expect(dashboardApi.compare).toHaveBeenLastCalledWith(OTHER_ID, ID)
    expect(router.currentRoute.value.query).toEqual({ a: OTHER_ID, b: ID })
  })

  it('swaps a half-filled pair harmlessly', async () => {
    const { wrapper } = await mountAt(CompareView, `/compare?a=${ID}`)
    await wrapper.get('#switch-btn').trigger('click')
    expect(wrapper.get('#cmp-a').element.value).toBe('')
    expect(wrapper.get('#cmp-b').element.value).toBe(ID)
    expect(dashboardApi.compare).not.toHaveBeenCalled()
  })
})

describe('CompareView: more captures (C, D, E)', () => {
  beforeEach(() => capturesApi.list.mockResolvedValue(page(all, { per_page: 100 })))

  it('adds capture slots C, D and E with + and then stops offering more', async () => {
    const { wrapper } = await mountAt(CompareView, '/compare')
    expect(wrapper.find('#cmp-c').exists()).toBe(false)
    expect(wrapper.get('#add-capture-btn').text()).toContain('C')
    await wrapper.get('#add-capture-btn').trigger('click')
    await wrapper.get('#add-capture-btn').trigger('click')
    await wrapper.get('#add-capture-btn').trigger('click')
    expect(['#cmp-c', '#cmp-d', '#cmp-e'].every((id) => wrapper.find(id).exists())).toBe(true)
    expect(wrapper.find('#add-capture-btn').exists()).toBe(false)
    await wrapper.get('[data-remove="D"]').trigger('click')
    expect(wrapper.find('#cmp-e').exists()).toBe(false)
    expect(wrapper.find('#add-capture-btn').exists()).toBe(true)
  })

  it('compares every extra capture against A and shows them as extra columns', async () => {
    dashboardApi.compare.mockImplementation(async (a, b) => (b === THIRD_ID ? againstThird() : comparison()))
    const { wrapper, router } = await mountAt(CompareView, '/compare')
    await wrapper.get('#cmp-a').setValue(ID)
    await wrapper.get('#cmp-b').setValue(OTHER_ID)
    await wrapper.get('#add-capture-btn').trigger('click')
    await wrapper.get('#cmp-c').setValue(THIRD_ID)
    await wrapper.get('form').trigger('submit')
    await settle()

    expect(dashboardApi.compare).toHaveBeenCalledWith(ID, OTHER_ID)
    expect(dashboardApi.compare).toHaveBeenCalledWith(ID, THIRD_ID)
    const headers = wrapper.findAll('th').map((th) => th.text())
    expect(headers).toEqual(expect.arrayContaining(['A — full.pcap', 'B — head.pcap', 'C — third.pcap', 'Change (C − A)']))
    expect(cell(wrapper, 'total_packets-b')).toBe('3')
    expect(cell(wrapper, 'total_packets-c')).toBe('20')
    expect(cell(wrapper, 'total_packets-c-delta')).toBe('+5')
    expect(router.currentRoute.value.query).toEqual({ a: ID, b: OTHER_ID, c: THIRD_ID })
    // the protocol chart gains a series per capture and the union of protocols
    const chart = Chart.instances.at(-1)
    expect(chart.config.data.datasets.map((d) => d.label)).toEqual(['A', 'B', 'C'])
    expect(chart.config.data.labels).toEqual(expect.arrayContaining(['TCP', 'ARP', 'UDP']))
  })

  it('scrolls horizontally with the metric column pinned', async () => {
    dashboardApi.compare.mockImplementation(async (a, b) => (b === THIRD_ID ? againstThird() : comparison()))
    const { wrapper } = await mountAt(CompareView, `/compare?a=${ID}&b=${OTHER_ID}&c=${THIRD_ID}`)
    await settle()
    expect(wrapper.get('table').classes()).toContain('min-w-max')
    expect(wrapper.get('table').element.parentElement.className).toContain('overflow-x-auto')
    expect(wrapper.get('th').classes()).toContain('sticky')
  })

  it('starts from c, d, e in the URL', async () => {
    dashboardApi.compare.mockImplementation(async (a, b) => (b === THIRD_ID ? againstThird() : comparison()))
    const { wrapper } = await mountAt(CompareView, `/compare?a=${ID}&b=${OTHER_ID}&c=${THIRD_ID}`)
    await settle()
    expect(wrapper.get('#cmp-c').element.value).toBe(THIRD_ID)
    expect(dashboardApi.compare).toHaveBeenCalledTimes(2)
  })

  it('refuses the same capture in two slots and ignores empty extra slots', async () => {
    dashboardApi.compare.mockResolvedValue(comparison())
    const { wrapper } = await mountAt(CompareView, '/compare')
    await wrapper.get('#cmp-a').setValue(ID)
    await wrapper.get('#cmp-b').setValue(OTHER_ID)
    await wrapper.get('#add-capture-btn').trigger('click')
    await wrapper.get('#cmp-c').setValue(OTHER_ID)
    await wrapper.get('form').trigger('submit')
    expect(wrapper.get('#compare-result').text()).toContain('different capture for each slot')
    expect(dashboardApi.compare).not.toHaveBeenCalled()
    await wrapper.get('#cmp-c').setValue('')
    await wrapper.get('form').trigger('submit')
    await settle()
    expect(dashboardApi.compare).toHaveBeenCalledTimes(1) // the empty slot costs no request
  })
})
