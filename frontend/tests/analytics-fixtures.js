import { ID } from './helpers'

export const hist = (counts) => counts.map((count, i) => ({ label: `b${i}`, min: i, count }))

export const analyticsDoc = (overrides = {}) => ({
  schema_version: 1,
  tcp: {
    total_connections: 4,
    states: { established: 2, incomplete: 1, refused: 1, unclassified: 0 },
    observable_attempts: 4,
    success_rate: 0.5,
    confirmed_failure_rate: 0.25,
    incomplete_rate: 0.25,
    incomplete_reasons: { no_synack: 1, no_final_ack: 0 },
    terminations: { fin: 1, reset: 1, half_closed: 0, none: 2 },
    capture_truncated_connections: 1,
    handshake_ms: { count: 2, min: 40, mean: 50, median: 50, p95: 58, max: 60 },
    syn_to_synack_ms: null,
    lifetime_seconds: { count: 4, min: 0, mean: 1, median: 0.8, p95: 2, max: 2 },
    charts: { handshake_histogram: hist([0, 2, 0]), lifetime_histogram: hist([3, 1]) },
  },
  resets: {
    rst_packets: 3, tcp_packets: 30, packet_rate: 0.1, connections_with_reset: 1, tcp_connections: 4,
    connection_rate: 0.25, reset_before_established: 1, reset_after_established: 0, reset_unclassified: 0,
    top_senders: [{ ip: '10.0.0.2', rst_packets: 3 }],
  },
  diagnostics: {
    indicator_types: { retransmission: { events: 2, connections: 1 }, duplicate_ack: { events: 3, connections: 1 } },
    connections_with_indicators: 1, tcp_connections: 4, tcp_packets: 30, retransmission_packets: 2,
    retransmission_rate: 2 / 30, packet_loss_percent: null, packet_loss_status: 'not_measurable_from_a_single_capture',
  },
  windows: {
    connections: 4, scaling_status: { negotiated: 1, unknown_handshake_not_observed: 3 },
    connections_with_zero_window: 1, zero_window_events: 2, max_effective_window_bytes: null, effective_window_available_for: 0,
  },
  dns: {
    available: true, transactions: 5, queries: 4, answered: 2,
    unanswered: { inferred_timeout: 1, indeterminate: 1 }, unanswered_rate: 0.5, inferred_timeout_rate: 0.25,
    unmatched_responses: 1, query_packets: 5, response_packets: 3, query_retransmission_packets: 1,
    transactions_with_retransmitted_query: 1, duplicate_responses: 0, mismatched_responses: 0,
    responses_observed: 3, rcodes: { NOERROR: 2, NXDOMAIN: 1 }, error_responses: 1, error_response_rate: 1 / 3,
    server_failures: 0, server_failure_rate: 0, nxdomain_rate: 1 / 3, truncated_responses: 0,
    latency_ms: { count: 2, min: 20, mean: 25, median: 25, p95: 29, max: 30 },
    latency_by_transport_ms: { udp: null, tcp: null }, qtypes: { A: 4 },
    servers: [{ server_ip: '8.8.8.8', queries: 4, answered: 2, errors: 1, mean_latency_ms: 25, max_latency_ms: 30 }],
    charts: { latency_histogram: hist([0, 1, 1]) },
  },
  traffic: {
    total_ip_packets: 100, total_ip_bytes: 10000, unique_addresses: 3,
    ip_versions: { ipv4: { packets: 90, bytes: 9000 }, ipv6: { packets: 10, bytes: 1000 } },
    top_by_bytes: [],
  },
  anomalies: { total: 3, by_severity: { info: 0, low: 1, medium: 2, high: 0 }, by_rule: { port_scan_vertical: 2, icmp_heavy: 1 }, disclaimer: 'x' },
  thresholds: { port_scan_distinct_ports: 20 },
  definitions: {
    tcp_success_rate: 'Established / observable attempts.', tcp_incomplete: 'Not a confirmed failure.', tcp_refused: 'RST.',
    tcp_handshake_ms: 'SYN to ACK.', tcp_observed_duration: 'First to last packet.', dns_latency: 'Query to response.',
    dns_failure_rate: 'Non-NOERROR / responses.', dns_inferred_timeout: 'Inferred.', tcp_reset_packet_rate: 'RST / TCP packets.',
    tcp_reset_connection_rate: 'Reset connections / connections.', top_talkers: 'Ranked.', direction: 'Local only.',
    packet_loss_indicators: 'Indicators only.', tcp_window: 'Scaling needs the handshake.', anomalies: 'Heuristics.',
  },
  limitations: ['A passive capture sees only one vantage point.'],
  ...overrides,
})

export const connection = (overrides = {}) => ({
  connection_id: 1, flow_id: 3, ip_version: 4,
  endpoint_a: { ip: '10.0.0.1', port: 40000 }, endpoint_b: { ip: '10.0.0.2', port: 80 },
  initiator_known: true, state: 'established', incomplete_reason: null,
  first_seen: '2023-11-14T22:13:20+00:00', last_seen: '2023-11-14T22:13:21+00:00', first_packet: 1, last_packet: 15,
  duration_seconds: 0.82, syn_packet: 1, syn_retransmissions: 0, syn_to_synack_ms: 50, synack_to_ack_ms: 10,
  handshake_ms: 60, termination: 'fin', terminated_by: 'both', capture_truncated: false, truncation_reasons: [],
  packets: 15, bytes: 1500, packets_a_to_b: 8, packets_b_to_a: 7, bytes_a_to_b: 800, bytes_b_to_a: 700,
  rst_packets: 0, retransmissions: 1, duplicate_acks: 3, zero_window_events: 1, window_scaling: 'negotiated',
  rst_from_a: 0, rst_from_b: 0, rst_evidence: [], window: { scaling: 'negotiated' },
  ...overrides,
})

export const dnsTxn = (overrides = {}) => ({
  transaction_id: 1, transport: 'udp', client: { ip: '10.0.0.1', port: 5000 }, server: { ip: '8.8.8.8', port: 53 },
  dns_id: 7, qname: 'example.test', qtype: 'A', question_count: 1, questions: [{ name: 'example.test', type: 'A' }],
  query_packet: 7, response_packet: 8, query_time: null, response_time: null, query_count: 1,
  latency_ms: 30, latency_from_last_query_ms: 30, rcode: 0, rcode_name: 'NOERROR', truncated: false,
  answer_count: 1, status: 'answered', note: null, ...overrides,
})

export const finding = (overrides = {}) => ({
  finding_id: 1, rule: 'port_scan_vertical', name: 'Many destination ports contacted on one host', severity: 'medium',
  description: 'One source attempted many ports.', reason: '10.0.0.9 contacted 25 distinct TCP ports on 10.0.0.2 (threshold 20)',
  evidence: { distinct_ports: 25, sample_ports: [2000, 2001] }, affected_ips: ['10.0.0.9', '10.0.0.2'],
  affected_flows: [4], packet_refs: [21, 22], thresholds: { port_scan_distinct_ports: 20 },
  note: 'Heuristic indicator from threshold rules; it does not prove malicious activity.', ...overrides,
})

export const listPage = (items, extra = {}) => ({ items, page: 1, per_page: 25, total: items.length, ...extra })
export { ID }
