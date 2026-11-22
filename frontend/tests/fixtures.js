import { ID } from './helpers'

export const capture = (overrides = {}) => ({
  id: ID,
  original_filename: 'full.pcap',
  file_format: 'pcap',
  file_size_bytes: 1330,
  uploaded_at: '2023-11-14T22:13:20+00:00',
  status: 'completed',
  packet_count: 15,
  error_message: null,
  processing_started_at: null,
  processing_completed_at: null,
  ...overrides,
})

export const page = (items, extra = {}) => ({ items, page: 1, per_page: 15, total: items.length, ...extra })

export const dashboard = (overrides = {}) => ({
  totals: { captures: 2, packets: 18, bytes: 1230, unique_ips: 6, flows: 5 },
  status_counts: { completed: 2, processing: 0, pending: 0, uploaded: 0, failed: 0 },
  in_progress: 0,
  recent_sessions: [
    { id: ID, filename: 'full.pcap', status: 'completed', packets: 15, bytes: 1070, flows: 4, uploaded_at: '2023-11-14T22:13:20+00:00' },
    { id: 'b', filename: 'head.pcap', status: 'completed', packets: 3, bytes: 162, flows: 1, uploaded_at: '2023-11-14T22:14:20+00:00' },
  ],
  recent_traffic: [
    { filename: 'full.pcap', bytes: 1070, packets: 15 },
    { filename: 'head.pcap', bytes: 162, packets: 3 },
  ],
  protocols: {
    transport: [
      { protocol: 'TCP', packets: 9, bytes: 700, packet_percent: 60, byte_percent: 65 },
      { protocol: 'UDP', packets: 2, bytes: 172, packet_percent: 13.3, byte_percent: 16 },
    ],
    application: [],
  },
  ...overrides,
})

export const summary = () => ({
  capture: capture(),
  totals: {
    total_packets: 15, total_bytes: 1070, duration_seconds: 5, unique_ips: 6, flow_count: 4, malformed_packets: 1,
  },
  protocols: {
    transport: [
      { protocol: 'TCP', packets: 9, bytes: 700, packet_percent: 60, byte_percent: 65.4 },
      { protocol: 'UDP', packets: 2, bytes: 172, packet_percent: 13.3, byte_percent: 16 },
    ],
    application: [{ protocol: 'HTTP', packets: 3, bytes: 308, packet_percent: 20, byte_percent: 28.8 }],
  },
})

export const performance = () => ({
  performance: {
    avg_throughput_bps: 1712, peak_throughput_bps: 6000, avg_packets_per_second: 3, peak_packets_per_second: 8,
    avg_packet_size_bytes: 71.3, min_packet_size_bytes: 17, max_packet_size_bytes: 153, duration_seconds: 5,
    timeseries: {
      points: [
        { time: '2023-11-14T22:13:20+00:00', packets: 8, bytes: 700, packets_per_second: 8, bits_per_second: 5600 },
        { time: '2023-11-14T22:13:21+00:00', packets: 2, bytes: 200, packets_per_second: 2, bits_per_second: 1600 },
      ],
    },
  },
  utilization: null,
  tcp: { retransmissions: 1, retransmission_rate: 0.111, packets: 9 },
  latency: {
    handshake_rtt_ms: { count: 1, mean: 50, median: 50, p95: 50, min: 50, max: 50 },
    flow_jitter_ms: null,
  },
})

export const flow = (n, overrides = {}) => ({
  flow_id: n,
  protocol: 'TCP',
  application_protocol: 'HTTP',
  endpoint_a: { ip: '10.0.0.1', port: 40000 },
  endpoint_b: { ip: '10.0.0.2', port: 80 },
  packets: { total: 8, a_to_b: 4, b_to_a: 4 },
  bytes: { total: 700 },
  duration_seconds: 1.25,
  retransmissions: 1,
  handshake_rtt_ms: 50,
  jitter_ms: null,
  ...overrides,
})

export const packet = (n, overrides = {}) => ({
  packet_number: n,
  timestamp: `2023-11-14T22:13:20.${String(n).padStart(2, '0')}0000+00:00`,
  source_ip: '10.0.0.1', source_port: 40000,
  destination_ip: '10.0.0.2', destination_port: 80,
  protocol: 'TCP', application_protocol: null, original_length: 54,
  tcp_flags: 'S', tcp_sequence_number: 100, tcp_acknowledgement_number: 0,
  is_retransmission: false, malformed_reason: null, application_metadata: null,
  ...overrides,
})

export const comparison = () => ({
  a: { id: ID, filename: 'full.pcap', uploaded_at: '2023-11-14T22:13:20+00:00' },
  b: { id: 'b', filename: 'head.pcap', uploaded_at: '2023-11-14T22:14:20+00:00' },
  metrics: [
    { key: 'total_packets', label: 'Packets', unit: 'count', a: 15, b: 3, delta: -12, delta_percent: -80 },
    { key: 'total_bytes', label: 'Bytes', unit: 'bytes', a: 1070, b: 162, delta: -908, delta_percent: -84.9 },
    { key: 'avg_rtt', label: 'Handshake RTT', unit: 'ms', a: 50, b: null, delta: null, delta_percent: null },
  ],
  protocols: [
    { protocol: 'TCP', a: { packets: 9, bytes: 700 }, b: { packets: 1, bytes: 54 } },
    { protocol: 'ARP', a: { packets: 1, bytes: 42 }, b: null },
  ],
  ips: { shared: 2, only_a: 4, only_b: 0, sample: { shared: ['10.0.0.1', '10.0.0.2'], only_a: ['8.8.8.8'], only_b: [] } },
})
