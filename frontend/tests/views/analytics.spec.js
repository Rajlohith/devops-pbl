import { Chart } from 'chart.js'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '@/api/errors'
import CaptureAnomaliesView from '@/views/CaptureAnomaliesView.vue'
import CaptureDiagnosticsView from '@/views/CaptureDiagnosticsView.vue'
import CaptureDnsView from '@/views/CaptureDnsView.vue'
import CaptureTcpView from '@/views/CaptureTcpView.vue'
import CaptureTrafficView from '@/views/CaptureTrafficView.vue'
import DashboardView from '@/views/DashboardView.vue'

import { analyticsDoc, connection, dnsTxn, finding, listPage } from '../analytics-fixtures'
import { dashboard } from '../fixtures'
import { ID, mountAt, settle, text } from '../helpers'

vi.mock('@/api/analytics', () => ({
  analyticsApi: {
    document: vi.fn(), connections: vi.fn(), connection: vi.fn(), indicators: vi.fn(), windows: vi.fn(),
    dnsTransactions: vi.fn(), talkers: vi.fn(), direction: vi.fn(), anomalies: vi.fn(),
  },
}))
vi.mock('@/api/dashboard', () => ({ dashboardApi: { overview: vi.fn(), compare: vi.fn() } }))
const { analyticsApi } = await import('@/api/analytics')
const { dashboardApi } = await import('@/api/dashboard')

const stat = (wrapper, label) => wrapper.get(`[data-stat="${label}"]`).text()
const unavailable = () => new ApiError({ message: 'not available', status: 409, reason: 'analytics_unavailable' })

beforeEach(() => {
  vi.clearAllMocks()
  analyticsApi.document.mockResolvedValue(analyticsDoc())
  analyticsApi.connections.mockResolvedValue(listPage([connection(), connection({ connection_id: 2, state: 'incomplete', incomplete_reason: 'no_synack', handshake_ms: null })]))
  analyticsApi.connection.mockResolvedValue({ connection: connection(), indicators: [] })
  analyticsApi.dnsTransactions.mockResolvedValue(listPage([dnsTxn(), dnsTxn({ transaction_id: 2, status: 'unanswered_indeterminate', latency_ms: null, rcode_name: null, rcode: null })]))
  analyticsApi.indicators.mockResolvedValue(listPage([]))
  analyticsApi.windows.mockResolvedValue({ windows: {}, zero_window_connections: [] })
  analyticsApi.talkers.mockResolvedValue({ items: [] })
  analyticsApi.direction.mockResolvedValue({ configured: false, directions: {}, rule: '' })
  analyticsApi.anomalies.mockResolvedValue(listPage([finding()]))
})

describe('TCP connections tab', () => {
  it('shows KPIs with explicit denominators and distinguishes incomplete from refused', async () => {
    const { wrapper } = await mountAt(CaptureTcpView, `/captures/${ID}/tcp`)
    expect(stat(wrapper, 'Connection success rate')).toBe('50.0%')
    expect(text(wrapper)).toContain('2 of 4 observable attempts')
    expect(stat(wrapper, 'Incomplete')).toBe('1')
    expect(text(wrapper)).toContain('not confirmed failures')
    expect(stat(wrapper, 'Refused (confirmed)')).toBe('1')
    expect(stat(wrapper, 'Reset packet rate')).toBe('10.00%')
    expect(wrapper.get('[data-testid="reset-breakdown"]').text()).toContain('Reset before establishment: 1')
  })

  it('shows an unavailable rate as a dash rather than zero', async () => {
    const doc = analyticsDoc()
    doc.tcp.success_rate = null
    doc.tcp.observable_attempts = 0
    analyticsApi.document.mockResolvedValue(doc)
    const { wrapper } = await mountAt(CaptureTcpView, `/captures/${ID}/tcp`)
    expect(stat(wrapper, 'Connection success rate')).toBe('\u2014')
  })

  it('lists connections, charts them, and opens a detail panel on click', async () => {
    const { wrapper } = await mountAt(CaptureTcpView, `/captures/${ID}/tcp`)
    expect(wrapper.findAll('tbody tr')).toHaveLength(2)
    expect(wrapper.text()).toContain('no synack')
    expect(Chart.instances.length).toBeGreaterThanOrEqual(3)
    await wrapper.findAll('tbody tr')[0].trigger('click')
    await settle()
    expect(analyticsApi.connection).toHaveBeenCalledWith(ID, 1)
    expect(wrapper.get('[data-testid="connection-detail"]').text()).toContain('Handshake total')
  })

  it('sends filters from the form to the API and keeps them in the URL', async () => {
    const { wrapper, router } = await mountAt(CaptureTcpView, `/captures/${ID}/tcp`)
    await wrapper.get('[data-filter="state"]').setValue('refused')
    await wrapper.get('form [data-action="apply"]').trigger('submit')
    await settle()
    expect(router.currentRoute.value.query.state).toBe('refused')
    expect(analyticsApi.connections).toHaveBeenLastCalledWith(ID, expect.objectContaining({ state: 'refused', page: 1, per_page: 25 }))
  })

  it('shows the unavailable notice for a capture analysed before Phase 4', async () => {
    analyticsApi.document.mockRejectedValue(unavailable())
    const { wrapper } = await mountAt(CaptureTcpView, `/captures/${ID}/tcp`)
    expect(wrapper.find('[data-state="unavailable"]').exists()).toBe(true)
  })

  it('shows an error state with retry when the document cannot be loaded', async () => {
    analyticsApi.document.mockRejectedValueOnce(new ApiError({ message: 'boom', status: 500 }))
    const { wrapper } = await mountAt(CaptureTcpView, `/captures/${ID}/tcp`)
    expect(wrapper.get('[data-state="error"]').text()).toContain('boom')
  })

  it('shows an empty state when no connection matches', async () => {
    analyticsApi.connections.mockResolvedValue(listPage([]))
    const { wrapper } = await mountAt(CaptureTcpView, `/captures/${ID}/tcp`)
    expect(wrapper.find('[data-state="empty"]').exists()).toBe(true)
  })
})

describe('DNS tab', () => {
  it('shows latency and the separate failure and timeout figures', async () => {
    const { wrapper } = await mountAt(CaptureDnsView, `/captures/${ID}/dns`)
    expect(stat(wrapper, 'Median response time')).toBe('25.0 ms')
    expect(stat(wrapper, 'Error response rate')).toBe('33.3%')
    expect(stat(wrapper, 'Inferred timeouts')).toBe('1')
    expect(stat(wrapper, 'Indeterminate')).toBe('1')
    expect(stat(wrapper, 'Unmatched responses')).toBe('1')
    expect(text(wrapper)).toContain('excl. NXDOMAIN')
  })

  it('renders transactions, with a dash for unmeasured latency', async () => {
    const { wrapper } = await mountAt(CaptureDnsView, `/captures/${ID}/dns`)
    const rows = wrapper.findAll('tbody tr')
    expect(rows.length).toBeGreaterThanOrEqual(2)
    expect(text(wrapper)).toContain('example.test')
    expect(text(wrapper)).toContain('unanswered indeterminate')
  })

  it('shows evidence for a clicked transaction', async () => {
    const { wrapper } = await mountAt(CaptureDnsView, `/captures/${ID}/dns`)
    const row = wrapper.findAll('tbody tr').find((r) => r.text().includes('example.test'))
    await row.trigger('click')
    expect(wrapper.get('[data-testid="dns-detail"]').text()).toContain('Query transmissions')
  })

  it('says so when the capture has no DNS', async () => {
    const doc = analyticsDoc()
    doc.dns = { ...doc.dns, available: false }
    analyticsApi.document.mockResolvedValue(doc)
    const { wrapper } = await mountAt(CaptureDnsView, `/captures/${ID}/dns`)
    expect(wrapper.get('[data-state="empty"]').text()).toContain('No DNS traffic')
  })
})

describe('Traffic tab', () => {
  it('requests the ranking with the chosen controls', async () => {
    analyticsApi.talkers.mockResolvedValue({
      items: [{ rank: 1, ip: '10.0.0.1', ip_version: 4, packets: 5, bytes: 500, sent_packets: 3, sent_bytes: 300, received_packets: 2, received_bytes: 200, percent_of_bytes: 5, percent_of_packets: 5 }],
    })
    const { wrapper } = await mountAt(CaptureTrafficView, `/captures/${ID}/traffic?by=packets&limit=5`)
    expect(analyticsApi.talkers).toHaveBeenCalledWith(ID, expect.objectContaining({ by: 'packets', limit: 5 }))
    expect(wrapper.text()).toContain('10.0.0.1')
    expect(wrapper.text()).toContain('5.0%')
  })

  it('explains that direction is unknown until local networks are configured', async () => {
    const { wrapper } = await mountAt(CaptureTrafficView, `/captures/${ID}/traffic`)
    expect(wrapper.text()).toContain('No local networks configured')
    expect(wrapper.text()).toContain('Private address ranges are')
  })

  it('classifies with the networks typed by the user', async () => {
    const { wrapper } = await mountAt(CaptureTrafficView, `/captures/${ID}/traffic`)
    await wrapper.get('[data-filter="local"]').setValue('10.0.0.0/24')
    await wrapper.findAll('form')[1].trigger('submit')
    await settle()
    expect(analyticsApi.direction).toHaveBeenLastCalledWith(ID, { local: '10.0.0.0/24' })
  })

  it('surfaces an API validation error for a bad network', async () => {
    analyticsApi.direction.mockRejectedValue(new ApiError({ message: 'not a valid network', status: 400 }))
    const { wrapper } = await mountAt(CaptureTrafficView, `/captures/${ID}/traffic?local=bad`)
    expect(wrapper.text()).toContain('not a valid network')
  })
})

describe('TCP diagnostics tab', () => {
  it('never presents indicators as measured packet loss', async () => {
    const { wrapper } = await mountAt(CaptureDiagnosticsView, `/captures/${ID}/diagnostics`)
    expect(stat(wrapper, 'Packet loss')).toBe('Not measurable')
    expect(wrapper.get('[data-testid="loss-disclaimer"]').text()).toContain('not measured packet loss')
    expect(stat(wrapper, 'Retransmissions')).toBe('2')
    expect(stat(wrapper, 'Duplicate ACKs')).toBe('3')
    expect(stat(wrapper, 'Largest effective window')).toBe('Unknown')
  })

  it('shows evidence for a clicked indicator', async () => {
    analyticsApi.indicators.mockResolvedValue(listPage([{
      indicator_id: 1, connection_id: 1, flow_id: 3, endpoint_a: '10.0.0.1:1', endpoint_b: '10.0.0.2:80',
      type: 'duplicate_ack', sender: 'b', packet_count: 3, first_packet: 7, last_packet: 9, severity: 'medium',
      confidence: 'medium', evidence: [{ packet: 7, ack: 201, run: 1 }], detail: { max_run: 3 },
    }]))
    const { wrapper } = await mountAt(CaptureDiagnosticsView, `/captures/${ID}/diagnostics`)
    await wrapper.get('tbody tr').trigger('click')
    expect(wrapper.get('[data-testid="indicator-detail"]').text()).toContain('packet=7')
    expect(wrapper.find('[data-severity="medium"]').exists()).toBe(true)
  })

  it('reports raw windows without inventing an effective size when scaling is unknown', async () => {
    analyticsApi.windows.mockResolvedValue({
      windows: {},
      zero_window_connections: [connection({
        window_scaling: 'unknown_handshake_not_observed',
        window: {
          scaling: 'unknown_handshake_not_observed',
          a: { samples: 2, effective: null, raw: { min: 10, max: 100, last: 50 }, zero_window_evidence: [] },
          b: { samples: 1, effective: null, raw: { min: 0, max: 0, last: 0 }, zero_window_evidence: [9] },
        },
      })],
    })
    const { wrapper } = await mountAt(CaptureDiagnosticsView, `/captures/${ID}/diagnostics`)
    expect(wrapper.text()).toContain('raw, scale unknown')
  })
})

describe('Anomaly tab', () => {
  it('states the heuristic disclaimer and the severity counts', async () => {
    const { wrapper } = await mountAt(CaptureAnomaliesView, `/captures/${ID}/anomalies`)
    expect(wrapper.get('[data-testid="anomaly-disclaimer"]').text()).toContain('not proof of malicious activity')
    expect(stat(wrapper, 'Findings')).toBe('3')
    expect(stat(wrapper, 'medium severity')).toBe('2')
  })

  it('shows rule, reason, evidence, thresholds and packet references for a finding', async () => {
    const { wrapper } = await mountAt(CaptureAnomaliesView, `/captures/${ID}/anomalies`)
    await wrapper.get('tbody tr').trigger('click')
    const detail = wrapper.get('[data-testid="anomaly-detail"]').text()
    expect(detail).toContain('25 distinct TCP ports')
    expect(detail).toContain('port_scan_distinct_ports = 20')
    expect(detail).toContain('21, 22')
    expect(detail).toContain('does not prove malicious activity')
  })

  it('filters by severity', async () => {
    const { wrapper } = await mountAt(CaptureAnomaliesView, `/captures/${ID}/anomalies`)
    await wrapper.get('[data-filter="severity"]').setValue('high')
    await wrapper.get('form [data-action="apply"]').trigger('submit')
    await settle()
    expect(analyticsApi.anomalies).toHaveBeenLastCalledWith(ID, expect.objectContaining({ severity: 'high' }))
  })

  it('shows an empty state when nothing triggered', async () => {
    analyticsApi.anomalies.mockResolvedValue(listPage([]))
    const { wrapper } = await mountAt(CaptureAnomaliesView, `/captures/${ID}/anomalies`)
    expect(wrapper.find('[data-state="empty"]').exists()).toBe(true)
  })
})

describe('Dashboard network intelligence', () => {
  const intel = {
    captures_included: 2,
    tcp: { observable_attempts: 10, established: 8, incomplete: 2, refused: 0, success_rate: 0.8 },
    dns: { queries: 20, unanswered: 1, responses: 19, error_rate: 0.1, server_failure_rate: 0.05 },
    resets: { rst_packets: 2, tcp_packets: 200, packet_rate: 0.01 },
    retransmission_packets: 4,
    anomalies: { total: 3, by_severity: { info: 0, low: 1, medium: 2, high: 0 } },
  }

  it('shows pooled figures when the API provides them', async () => {
    dashboardApi.overview.mockResolvedValue(dashboard({ network_intelligence: intel }))
    const { wrapper } = await mountAt(DashboardView, '/dashboard')
    expect(stat(wrapper, 'TCP connection success')).toBe('80.0%')
    expect(stat(wrapper, 'Anomaly findings')).toBe('3')
  })

  it('shows nothing extra when no capture has advanced analytics', async () => {
    dashboardApi.overview.mockResolvedValue(dashboard({ network_intelligence: { ...intel, captures_included: 0 } }))
    const { wrapper } = await mountAt(DashboardView, '/dashboard')
    expect(wrapper.find('[data-testid="network-intelligence"]').exists()).toBe(false)
  })
})
