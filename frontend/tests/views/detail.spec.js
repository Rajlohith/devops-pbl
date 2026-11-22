import { Chart } from 'chart.js'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '@/api/errors'
import CaptureDetailView from '@/views/CaptureDetailView.vue'

import { capture, flow, packet, page, performance, summary } from '../fixtures'
import { ID, mountAt, settle, text } from '../helpers'

vi.mock('@/api/captures', () => ({
  capturesApi: { list: vi.fn(), get: vi.fn(), status: vi.fn(), analyze: vi.fn(), remove: vi.fn(), upload: vi.fn() },
}))
vi.mock('@/api/analysis', () => ({
  analysisApi: { summary: vi.fn(), protocols: vi.fn(), performance: vi.fn(), packets: vi.fn(), packet: vi.fn(), flows: vi.fn() },
}))
vi.mock('@/utils/download', () => ({ saveBlob: vi.fn() }))
vi.mock('@/api/reports', async (original) => ({ ...(await original()), fetchReport: vi.fn() }))
const { capturesApi } = await import('@/api/captures')
const { analysisApi } = await import('@/api/analysis')
const { fetchReport } = await import('@/api/reports')
const { saveBlob } = await import('@/utils/download')

const stat = (wrapper, label) => wrapper.get(`[data-stat="${label}"]`).text()
const open = (path = '') => mountAt(CaptureDetailView, `/captures/${ID}${path}`, { props: { id: ID } })

beforeEach(() => {
  vi.clearAllMocks()
  capturesApi.get.mockResolvedValue(capture())
  analysisApi.summary.mockResolvedValue(summary())
  analysisApi.performance.mockResolvedValue(performance())
  analysisApi.protocols.mockResolvedValue(summary().protocols)
  analysisApi.flows.mockResolvedValue(page([flow(1), flow(2, { protocol: 'UDP', application_protocol: 'DNS' })], { per_page: 20 }))
  analysisApi.packets.mockResolvedValue(page([packet(1), packet(2)], { per_page: 50 }))
})
afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('capture page states', () => {
  it('shows loading, then the header, actions and tabs of a completed capture', async () => {
    let finish
    capturesApi.get.mockReturnValue(new Promise((resolve) => (finish = resolve)))
    const { wrapper } = await open()
    expect(wrapper.find('[data-state="loading"]').exists()).toBe(true)
    finish(capture())
    await settle()
    expect(wrapper.get('#cap-title').text()).toContain('full.pcap')
    expect(wrapper.get('#cap-title').text()).toContain('completed')
    expect(text(wrapper)).toContain('PCAP · 1.33 KB · uploaded 2023-11-14 22:13:20 UTC')
    const tabs = wrapper.get('nav[aria-label="Capture sections"]').findAll('a')
    expect(tabs.map((t) => t.text())).toEqual(['Overview', 'Protocols', 'Flows', 'Packets', 'Performance'])
    expect(tabs[0].attributes('href')).toBe(`/captures/${ID}`)
    expect(tabs[3].attributes('href')).toBe(`/captures/${ID}/packets`)
    expect(wrapper.get('a[href^="/compare"]').attributes('href')).toBe(`/compare?a=${ID}`)
  })

  it('says so when the capture does not exist or is not yours', async () => {
    capturesApi.get.mockRejectedValue(new ApiError({ message: 'Capture not found.', status: 404 }))
    const { wrapper } = await open()
    expect(text(wrapper)).toContain('Capture not found')
    expect(wrapper.find('nav[aria-label="Capture sections"]').exists()).toBe(false)
    expect(analysisApi.summary).not.toHaveBeenCalled()
  })

  it('shows other errors with a retry', async () => {
    capturesApi.get.mockRejectedValueOnce(new ApiError({ message: 'Unable to reach the NetScope server.', kind: 'network' }))
    const { wrapper } = await open()
    expect(wrapper.get('[role="alert"]').text()).toContain('Unable to reach')
    await wrapper.get('[data-state="error"] button').trigger('click')
    await settle()
    expect(wrapper.get('#cap-title').text()).toContain('full.pcap')
  })

  it('offers to start an analysis for an uploaded capture, and shows the queue afterwards', async () => {
    capturesApi.get.mockResolvedValue(capture({ status: 'uploaded' }))
    capturesApi.analyze.mockResolvedValue(capture({ status: 'pending' }))
    const { wrapper } = await open()
    expect(wrapper.get('#progress-card').text()).toContain('has not been analysed yet')
    expect(wrapper.find('nav[aria-label="Capture sections"]').exists()).toBe(false)
    expect(wrapper.get('#analyze-btn').text()).toBe('Start analysis')
    capturesApi.get.mockResolvedValue(capture({ status: 'pending' }))
    await wrapper.get('#analyze-btn').trigger('click')
    await settle()
    expect(capturesApi.analyze).toHaveBeenCalledWith(ID)
    expect(wrapper.get('#progress-text').text()).toContain('Queued')
  })

  it('shows why an analysis failed, and offers a retry', async () => {
    capturesApi.get.mockResolvedValue(capture({ status: 'failed', error_message: 'File ended unexpectedly (truncated).' }))
    const { wrapper } = await open()
    expect(wrapper.get('#fail-reason').text()).toContain('truncated')
    expect(wrapper.get('#progress-card').text()).toContain('No partial results were kept')
    expect(wrapper.get('#analyze-btn').text()).toBe('Retry analysis')
  })

  it('reports a retry that the server refuses, and keeps the page usable', async () => {
    capturesApi.get.mockResolvedValue(capture({ status: 'failed', error_message: 'x' }))
    capturesApi.analyze.mockRejectedValue(new ApiError({ message: 'Job service unavailable.', status: 503 }))
    const { wrapper } = await open()
    await wrapper.get('#analyze-btn').trigger('click')
    await settle()
    expect(wrapper.get('[data-alert="error"]').text()).toContain('Job service unavailable.')
    expect(wrapper.find('#analyze-btn').exists()).toBe(true)
  })

  it('follows a running analysis and switches to the results by itself', async () => {
    vi.useFakeTimers()
    capturesApi.get.mockResolvedValueOnce(capture({ status: 'processing', packet_count: 4000 }))
    capturesApi.status
      .mockResolvedValueOnce({ id: ID, status: 'processing', packet_count: 9000 })
      .mockResolvedValue({ id: ID, status: 'completed', packet_count: 15 })
    const { wrapper } = await open()
    expect(wrapper.get('#progress-text').text()).toContain('4,000 packets processed so far')
    expect(wrapper.get('[role="progressbar"]').exists()).toBe(true)

    await vi.advanceTimersByTimeAsync(1600)
    expect(wrapper.get('#progress-text').text()).toContain('9,000 packets processed so far')

    capturesApi.get.mockResolvedValue(capture({ status: 'completed' }))
    await vi.advanceTimersByTimeAsync(1600)
    await vi.waitFor(() => expect(wrapper.find('#progress-card').exists()).toBe(false), { interval: 1 })
    expect(wrapper.find('nav[aria-label="Capture sections"]').exists()).toBe(true)
  })

  it('stops polling when leaving the page', async () => {
    vi.useFakeTimers()
    capturesApi.get.mockResolvedValue(capture({ status: 'processing' }))
    capturesApi.status.mockResolvedValue({ id: ID, status: 'processing', packet_count: 1 })
    const { wrapper } = await open()
    await vi.advanceTimersByTimeAsync(1600)
    const calls = capturesApi.status.mock.calls.length
    wrapper.unmount()
    await vi.advanceTimersByTimeAsync(10_000)
    expect(capturesApi.status.mock.calls.length).toBe(calls)
  })

  it('deletes after confirmation and returns to the list', async () => {
    capturesApi.remove.mockResolvedValue(undefined)
    const confirm = vi.spyOn(window, 'confirm').mockReturnValueOnce(false).mockReturnValue(true)
    const { wrapper, router } = await open()
    await wrapper.get('#delete-btn').trigger('click')
    expect(capturesApi.remove).not.toHaveBeenCalled()
    await wrapper.get('#delete-btn').trigger('click')
    await settle()
    expect(confirm).toHaveBeenLastCalledWith(expect.stringContaining('full.pcap'))
    expect(capturesApi.remove).toHaveBeenCalledWith(ID)
    await vi.waitFor(() => expect(router.currentRoute.value.name).toBe('captures'))
  })

  it('drops the cached capture list and dashboard after a delete', async () => {
    capturesApi.remove.mockResolvedValue(undefined)
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    const { wrapper, pinia } = await open()
    const { useCapturesStore } = await import('@/stores/captures')
    const { useDashboardStore } = await import('@/stores/dashboard')
    useCapturesStore(pinia).items = [capture()]
    useCapturesStore(pinia).loaded = true
    useDashboardStore(pinia).data = { totals: { captures: 1 } }
    await wrapper.get('#delete-btn').trigger('click')
    await settle()
    expect(useCapturesStore(pinia).items).toEqual([])
    expect(useCapturesStore(pinia).loaded).toBe(false)
    expect(useDashboardStore(pinia).data).toBeNull()
  })

  it('keeps you on the page and explains when a delete fails', async () => {
    capturesApi.remove.mockRejectedValue(new ApiError({ message: 'The server ran into a problem.', status: 500 }))
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    const { wrapper, router } = await open()
    await wrapper.get('#delete-btn').trigger('click')
    await settle()
    expect(wrapper.get('[data-alert="error"]').text()).toContain('Delete failed')
    expect(router.currentRoute.value.name).toBe('capture-overview')
  })
})

describe('reports', () => {
  it('downloads a PDF through the API client and hands it to the browser', async () => {
    const blob = new Blob(['%PDF-1.4'])
    fetchReport.mockResolvedValue({ blob, filename: 'netscope-4318f5fd-report.pdf' })
    const { wrapper } = await open()
    expect(wrapper.find('#reports-list').exists()).toBe(false)
    await wrapper.get('#reports-menu > button').trigger('click')
    expect(wrapper.get('#reports-menu > button').attributes('aria-expanded')).toBe('true')
    expect(wrapper.findAll('#reports-list button')).toHaveLength(6)
    await wrapper.get('button[data-report="/report.pdf"]').trigger('click')
    await settle()
    expect(fetchReport).toHaveBeenCalledWith(ID, '/report.pdf', {}, expect.any(String))
    expect(saveBlob).toHaveBeenCalledWith(blob, 'netscope-4318f5fd-report.pdf')
    expect(wrapper.find('#reports-list').exists()).toBe(false) // closes after choosing
  })

  it('shows a failed download instead of navigating to raw JSON', async () => {
    fetchReport.mockRejectedValue(new ApiError({ message: 'Reports are not available: capture is processing.', status: 409 }))
    const { wrapper } = await open()
    await wrapper.get('#reports-menu > button').trigger('click')
    await wrapper.get('button[data-report="/export/flows.csv"]').trigger('click')
    await settle()
    expect(wrapper.get('#reports-menu [role="alert"]').text()).toContain('capture is processing')
    expect(saveBlob).not.toHaveBeenCalled()
  })

  it('closes on Escape', async () => {
    const { wrapper } = await open()
    await wrapper.get('#reports-menu > button').trigger('click')
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    await settle()
    expect(wrapper.find('#reports-list').exists()).toBe(false)
  })
})

describe('Overview tab', () => {
  it('shows totals, two charts and the busiest flows', async () => {
    const { wrapper } = await open()
    await vi.waitFor(() => expect(wrapper.find('#panel-overview').exists()).toBe(true))
    expect(stat(wrapper, 'Packets')).toBe('15')
    expect(stat(wrapper, 'Data')).toBe('1.07 KB')
    expect(stat(wrapper, 'Duration')).toBe('5.00 s')
    expect(stat(wrapper, 'Unique IPs')).toBe('6')
    expect(stat(wrapper, 'Flows')).toBe('4')
    expect(stat(wrapper, 'Malformed')).toBe('1')
    expect(Chart.instances.map((c) => c.config.type).sort()).toEqual(['doughnut', 'line'])
    expect(wrapper.get('#panel-overview tbody tr').text()).toContain('10.0.0.1:40000 ↔ 10.0.0.2:80')
    expect(analysisApi.flows).toHaveBeenCalledWith(ID, { per_page: 5 })
  })

  it('shares the summary between tabs instead of refetching it', async () => {
    const { wrapper, router } = await open()
    await vi.waitFor(() => expect(wrapper.find('#panel-overview').exists()).toBe(true))
    await router.push(`/captures/${ID}/packets`)
    await vi.waitFor(() => expect(wrapper.find('#panel-packets').exists()).toBe(true))
    expect(analysisApi.summary).toHaveBeenCalledTimes(1)
    expect(analysisApi.performance).toHaveBeenCalledTimes(1)
  })

  it('shows an error state with retry when results cannot be loaded', async () => {
    analysisApi.summary.mockRejectedValueOnce(new ApiError({ message: 'The server ran into a problem.', status: 500 }))
    const { wrapper } = await open()
    await vi.waitFor(() => expect(wrapper.find('#panel-overview [data-state="error"], [data-state="error"]').exists()).toBe(true))
    await wrapper.get('[data-state="error"] button').trigger('click')
    await vi.waitFor(() => expect(stat(wrapper, 'Packets')).toBe('15'))
  })
})

describe('Protocols tab', () => {
  it('shows transport and application protocols with charts and a link into the packet explorer', async () => {
    const { wrapper, router } = await open('/protocols')
    await vi.waitFor(() => expect(wrapper.find('#panel-protocols').exists()).toBe(true))
    const transport = wrapper.get('[data-layer="transport"]')
    expect(transport.findAll('tbody tr')).toHaveLength(2)
    expect(transport.text()).toContain('65.4%')
    expect(wrapper.get('[data-layer="application"]').text()).toContain('HTTP')
    expect(Chart.instances.map((c) => c.config.type).sort()).toEqual(['bar', 'bar', 'doughnut', 'doughnut'])

    await transport.findAll('tbody tr')[0].get('button').trigger('click')
    await vi.waitFor(() => expect(router.currentRoute.value.name).toBe('capture-packets'))
    expect(router.currentRoute.value.query).toEqual({ protocol: 'TCP' })
  })

  it('says when no application protocol was identified', async () => {
    analysisApi.protocols.mockResolvedValue({ transport: summary().protocols.transport, application: [] })
    const { wrapper } = await open('/protocols')
    await vi.waitFor(() => expect(wrapper.find('[data-layer="application"]').exists()).toBe(true))
    expect(wrapper.get('[data-layer="application"] [data-state="empty"]').text()).toContain('No DNS or HTTP traffic')
  })
})

describe('Flows tab', () => {
  it('lists flows, draws the top-10 chart and links to a flow\'s packets', async () => {
    const { wrapper, router } = await open('/flows')
    await vi.waitFor(() => expect(wrapper.findAll('#flow-results tbody tr')).toHaveLength(2))
    const first = wrapper.get('#flow-results tbody tr').text()
    expect(first).toContain('TCP / HTTP')
    expect(first).toContain('10.0.0.1:40000')
    expect(first).toContain('8 (4→ / ←4)')
    expect(first).toContain('50.00 ms')
    const bar = Chart.instances.find((c) => c.config.type === 'bar')
    expect(bar.config.options.indexAxis).toBe('y')
    expect(analysisApi.flows).toHaveBeenCalledWith(ID, { per_page: 10, sort: 'bytes', order: 'desc' })

    await wrapper.get('[data-flow="2"]').trigger('click')
    await vi.waitFor(() => expect(router.currentRoute.value.name).toBe('capture-packets'))
    expect(router.currentRoute.value.query).toEqual({ flow_id: '2' })
  })

  it('applies filters through the URL and requests them from the API', async () => {
    const { wrapper, router } = await open('/flows')
    await vi.waitFor(() => expect(wrapper.find('#flow-results tbody').exists()).toBe(true))
    analysisApi.flows.mockClear()
    await wrapper.get('#ff-protocol').setValue('udp')
    await wrapper.get('#ff-sort').setValue('start')
    await wrapper.get('#ff-order').setValue('asc')
    await wrapper.get('#flow-filters').trigger('submit')
    await settle()
    expect(router.currentRoute.value.query).toEqual({ protocol: 'udp', sort: 'start', order: 'asc' })
    expect(analysisApi.flows).toHaveBeenCalledWith(ID, expect.objectContaining({ protocol: 'udp', sort: 'start', order: 'asc', page: 1, per_page: 20 }))
  })

  it('shows empty and error states', async () => {
    analysisApi.flows.mockResolvedValue(page([], { per_page: 20 }))
    const { wrapper } = await open('/flows')
    await vi.waitFor(() => expect(wrapper.get('#flow-results [data-state="empty"]').text()).toContain('No flows match these filters.'))
    analysisApi.flows.mockRejectedValue(new ApiError({ message: 'port must be between 0 and 65535.', status: 400 }))
    await wrapper.get('#flow-filters').trigger('submit')
    await settle()
    expect(wrapper.get('#flow-results [role="alert"]').text()).toContain('port must be between')
  })

  it('paginates', async () => {
    analysisApi.flows.mockResolvedValue(page(Array.from({ length: 20 }, (_, i) => flow(i + 1)), { per_page: 20, total: 45 }))
    const { wrapper, router } = await open('/flows')
    await vi.waitFor(() => expect(wrapper.find('#flow-results [data-role="range"]').exists()).toBe(true))
    expect(wrapper.get('#flow-results [data-role="range"]').text()).toBe('1–20 of 45')
    await wrapper.findAll('#flow-results nav button')[1].trigger('click')
    await settle()
    expect(router.currentRoute.value.query.page).toBe('2')
    expect(analysisApi.flows).toHaveBeenLastCalledWith(ID, expect.objectContaining({ page: 2 }))
  })
})

describe('Packets tab (explorer)', () => {
  const load = async (path = '/packets') => {
    const ctx = await open(path)
    await vi.waitFor(() => expect(ctx.wrapper.findAll('#packet-results tbody tr').length).toBeGreaterThan(0))
    return ctx
  }

  it('lists packets and offers the capture\'s protocols as a filter', async () => {
    const { wrapper } = await load()
    expect(wrapper.findAll('#packet-results tbody tr')).toHaveLength(2)
    expect(wrapper.get('#packet-results tbody tr').text()).toContain('[S] seq=100 ack=0')
    const options = wrapper.findAll('#pf-protocol option').map((o) => o.text())
    expect(options).toEqual(['All protocols', 'HTTP', 'TCP', 'UDP'])
  })

  it('applies every filter through the URL and the API call', async () => {
    const { wrapper, router } = await load()
    analysisApi.packets.mockClear()
    await wrapper.get('#pf-q').setValue('8.8.8.8')
    await wrapper.get('#pf-protocol').setValue('TCP')
    await wrapper.get('#pf-port').setValue('80')
    await wrapper.get('#pf-tcp_flags').setValue('SA')
    await wrapper.get('#pf-retransmission').setValue(true)
    await wrapper.get('#pf-per_page').setValue('25')
    await wrapper.get('#packet-filters').trigger('submit')
    await settle()
    expect(router.currentRoute.value.query).toEqual({
      q: '8.8.8.8', protocol: 'TCP', port: '80', tcp_flags: 'SA', retransmission: 'true', per_page: '25',
    })
    expect(analysisApi.packets).toHaveBeenCalledWith(ID, expect.objectContaining({
      q: '8.8.8.8', protocol: 'TCP', port: '80', tcp_flags: 'SA', retransmission: true, per_page: 25, page: 1,
    }))
  })

  it('starts from filters in the URL (cross-links and shared links)', async () => {
    const { wrapper } = await load('/packets?flow_id=1&protocol=TCP&malformed=true')
    expect(wrapper.get('#pf-flow_id').element.value).toBe('1')
    expect(wrapper.get('#pf-protocol').element.value).toBe('TCP')
    expect(wrapper.get('#pf-malformed').element.checked).toBe(true)
    expect(analysisApi.packets).toHaveBeenCalledWith(ID, expect.objectContaining({ flow_id: '1', protocol: 'TCP', malformed: true }))
  })

  it('resets all filters', async () => {
    const { wrapper, router } = await load('/packets?q=abc&protocol=TCP')
    await wrapper.get('#pf-reset').trigger('click')
    await settle()
    expect(router.currentRoute.value.query).toEqual({})
    expect(wrapper.get('#pf-q').element.value).toBe('')
  })

  it('distinguishes "no packets" from "no matches"', async () => {
    analysisApi.packets.mockResolvedValue(page([], { per_page: 50 }))
    const { wrapper } = await open('/packets')
    await vi.waitFor(() => expect(wrapper.find('#packet-results [data-state="empty"]').exists()).toBe(true))
    expect(wrapper.get('#packet-results').text()).toContain('This capture contains no packets.')
    await wrapper.get('#pf-q').setValue('nothing')
    await wrapper.get('#packet-filters').trigger('submit')
    await settle()
    expect(wrapper.get('#packet-results').text()).toContain('No packets match these filters.')
  })

  it('shows server-side filter errors in the results area', async () => {
    const { wrapper } = await load()
    analysisApi.packets.mockRejectedValue(new ApiError({ message: 'ip must be a valid IPv4 or IPv6 address.', status: 400 }))
    await wrapper.get('#pf-ip').setValue('not-an-ip')
    await wrapper.get('#packet-filters').trigger('submit')
    await settle()
    expect(wrapper.get('#packet-results [role="alert"]').text()).toContain('valid IPv4 or IPv6')
  })

  it('paginates', async () => {
    analysisApi.packets.mockResolvedValue(page(Array.from({ length: 50 }, (_, i) => packet(i + 1)), { per_page: 50, total: 120 }))
    const { wrapper, router } = await load()
    expect(wrapper.get('#packet-results [data-role="range"]').text()).toBe('1–50 of 120')
    await wrapper.findAll('#packet-results nav button')[1].trigger('click')
    await settle()
    expect(router.currentRoute.value.query.page).toBe('2')
    expect(analysisApi.packets).toHaveBeenLastCalledWith(ID, expect.objectContaining({ page: 2, per_page: 50 }))
  })

  it('opens packet details from a row, by click or keyboard, and closes them', async () => {
    analysisApi.packet.mockResolvedValue(packet(7, { application_protocol: 'DNS', protocol: 'DNS', application_metadata: { query: 'example.test', is_response: false } }))
    const { wrapper } = await load()
    const row = wrapper.get('#packet-results tbody tr')
    expect(row.attributes('tabindex')).toBe('0')
    await row.trigger('keydown.enter')
    await settle()
    expect(analysisApi.packet).toHaveBeenCalledWith(ID, 1)
    expect(wrapper.get('#packet-detail-card').text()).toContain('Packet 7')
    expect(wrapper.get('[data-role="metadata"]').text()).toContain('"query": "example.test"')
    expect(row.attributes('aria-selected')).toBe('true')
    await wrapper.get('#packet-detail-card button').trigger('click')
    expect(wrapper.find('#packet-detail-card').exists()).toBe(false)
  })

  it('shows hostile packet content as inert text', async () => {
    const evil = '<img src=x onerror=alert(1)>'
    analysisApi.packets.mockResolvedValue(page([packet(1, { application_protocol: 'HTTP', application_metadata: { start_line: evil } })], { per_page: 50 }))
    analysisApi.packet.mockResolvedValue(packet(1, { application_metadata: { start_line: evil } }))
    const { wrapper } = await load()
    expect(wrapper.find('#packet-results img').exists()).toBe(false)
    expect(wrapper.get('#packet-results tbody').text()).toContain(evil)
    await wrapper.get('#packet-results tbody tr').trigger('click')
    await settle()
    expect(wrapper.find('#packet-detail img').exists()).toBe(false)
    expect(wrapper.get('[data-role="metadata"]').text()).toContain(evil)
  })

  it('exports the matches with the active filters (but not the paging)', async () => {
    fetchReport.mockResolvedValue({ blob: new Blob(['x']), filename: 'netscope-4318f5fd-packets.csv' })
    const { wrapper } = await load('/packets?q=8.8.8.8&malformed=true&page=1')
    await wrapper.get('#pf-export').trigger('click')
    await settle()
    const [id, path, params] = fetchReport.mock.calls[0]
    expect([id, path]).toEqual([ID, '/export/packets.csv'])
    expect(params).toMatchObject({ q: '8.8.8.8', malformed: true })
    expect(params).not.toHaveProperty('page')
    expect(params).not.toHaveProperty('per_page')
    expect(saveBlob).toHaveBeenCalledWith(expect.any(Blob), 'netscope-4318f5fd-packets.csv')
  })
})

describe('Performance tab', () => {
  it('shows throughput, packet and TCP statistics, charts and latency distributions', async () => {
    const { wrapper } = await open('/performance')
    await vi.waitFor(() => expect(wrapper.find('#panel-performance').exists()).toBe(true))
    expect(stat(wrapper, 'Avg throughput')).toBe('1.71 Kbit/s')
    expect(stat(wrapper, 'Peak throughput (1 s)')).toBe('6.00 Kbit/s')
    expect(stat(wrapper, 'Peak packets/s (1 s)')).toBe('8')
    expect(stat(wrapper, 'Avg packet size')).toBe('71.3 B')
    expect(stat(wrapper, 'Min / max size')).toBe('17 / 153 B')
    expect(stat(wrapper, 'TCP retransmissions')).toBe('1')
    expect(text(wrapper)).toContain('11.10% of 9 TCP packets')
    expect(Chart.instances.map((c) => c.config.type)).toEqual(['line', 'line'])
    expect(wrapper.get('[data-card="TCP handshake RTT"]').text()).toContain('50.00 ms')
    expect(wrapper.get('[data-card="Flow jitter"]').text()).toContain('Not available for this capture.')
  })

  it('estimates utilisation only from a link speed the user provides', async () => {
    const { wrapper } = await open('/performance')
    await vi.waitFor(() => expect(wrapper.find('#utilization-result').exists()).toBe(true))
    expect(wrapper.get('#utilization-result').text()).toContain('so it is not guessed')
    analysisApi.performance.mockResolvedValue({ ...performance(), utilization: { link_capacity_mbps: 0.001, avg_percent: 171.2, peak_percent: 600 } })
    await wrapper.get('#link-mbps').setValue('0.001')
    await wrapper.get('#util-btn').trigger('submit')
    await wrapper.get('form').trigger('submit')
    await settle()
    expect(analysisApi.performance).toHaveBeenLastCalledWith(ID, { link_mbps: 0.001 })
    expect(wrapper.get('#utilization-result').text()).toContain('average 171.200%, peak 600.000% of capacity')
  })

  it('shows the server\'s message for an invalid link speed', async () => {
    const { wrapper } = await open('/performance')
    await vi.waitFor(() => expect(wrapper.find('#utilization-result').exists()).toBe(true))
    analysisApi.performance.mockRejectedValue(new ApiError({ message: 'link_mbps must be a positive number.', status: 400 }))
    await wrapper.get('#link-mbps').setValue('-3')
    await wrapper.get('form').trigger('submit')
    await settle()
    expect(wrapper.get('#utilization-result').text()).toContain('positive number')
  })

  it('shows an empty chart message for a capture with no traffic', async () => {
    const empty = performance()
    empty.performance.timeseries.points = []
    analysisApi.performance.mockResolvedValue(empty)
    const { wrapper } = await open('/performance')
    await vi.waitFor(() => expect(wrapper.find('#panel-performance').exists()).toBe(true))
    expect(wrapper.findAll('[data-state="empty"]').map((e) => e.text())).toEqual(['No traffic in this capture.', 'No traffic in this capture.'])
    expect(Chart.instances).toHaveLength(0)
  })
})
