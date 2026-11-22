# Phase 4 — Advanced Network Intelligence

Ten analytics are computed in the **same single pass** as the existing flow tracker and
statistics accumulator (`app/services/analysis_pipeline.py`), by the pure-Python modules in
`backend/app/services/analytics/`. They reuse FlowTracker's flow ids and retransmission flags
and persist into new tables (migration `a4f1c2d9b7e3`). Nothing from Phases 1–3 was removed.

| Module | Capability |
|---|---|
| `tcp_connections.py` | 1.1 success rate, 1.2 durations, 3.1 reset rate |
| `dns_analytics.py` | 2.1 response time, 2.2 failure rate |
| `traffic_intel.py` | 3.2 top talkers, 3.3 inbound/outbound |
| `tcp_diagnostics.py` | 4.1 packet-loss indicators, 4.2 window analysis |
| `anomalies.py` | 5 rule-based anomaly detection |
| `engine.py` | orchestration, definitions and limitations shipped with every result |

## Metric definitions and denominators

* **TCP connection success rate** = established ÷ *observable attempts* (connections whose
  initial SYN was captured: established + incomplete + refused). Mid-stream connections are
  `unclassified` and excluded. **Incomplete** (SYN without a completed handshake) is *not* a
  confirmed failure; only **refused** (SYN answered by RST-ACK) is. Null when there are no attempts.
* **Handshake time** = first SYN → completing client ACK (established only; includes SYN
  retransmission delay). **Observed lifetime** = first → last captured packet.
  Connections lacking a captured start, or established ones lacking a captured end, are `capture_truncated`.
* **DNS response time** = first query transmission → response, matched on client/server
  address+port, DNS id and transport (UDP and TCP are never cross-matched). Retransmitted
  queries and duplicate responses are not double counted; unmatched queries/responses are
  separate counters. Multi-question messages are one transaction.
* **DNS failure rate** = responses with RCODE ≠ NOERROR ÷ responses observed (NXDOMAIN included;
  `server_failure_rate` excludes it). Unanswered queries are never part of it. An unanswered query is an
  **inferred timeout** only if the capture continued ≥ `NETSCOPE_DNS_TIMEOUT_SECONDS` (default 5) after
  its last transmission; otherwise **indeterminate**.
* **TCP reset rates**: packet rate = RST packets ÷ TCP packets; connection rate = connections with ≥1 RST ÷ tracked
  TCP connections.
* **Top talkers**: sent/received/both by bytes or packets, denominators = total IP bytes/packets
  (bidirectional shares add up to ≈200 %). IPv4 and IPv6.
* **Direction**: relative to *configured* local networks only (`?local=10.0.0.0/24,2001:db8::/32`); private
  ranges are never assumed local; with none configured everything is `unknown`.
* **Loss indicators**: retransmissions (exact duplicate segments, counted once), duplicate ACKs (RFC 5681
  sense), sequence gaps, out-of-order and partial overlaps, each with severity and confidence. **No loss
  percentage is ever reported** (`packet_loss_percent` is `null`).
* **Windows**: raw advertised window, changes, zero-window episodes; effective size only when SYN and
  SYN-ACK were both captured *and* both carried window scaling, otherwise `null`.
* **Anomalies**: threshold rules (see `anomalies.py`); every finding carries rule, severity, description,
  reason (value vs threshold), evidence, affected IPs/flows, packet refs and the thresholds used.
  Findings are heuristics, not proof of malicious activity.

## API (all authenticated, owner-scoped, `/api/v1/captures/<id>/…`)

`analytics`, `tcp/summary`, `tcp/connections[/<n>]`, `tcp/resets`, `tcp/indicators`, `tcp/windows`,
`dns/summary`, `dns/transactions[/<n>]`, `traffic/talkers`, `traffic/direction`, `anomalies[/<n>]`,
plus CSV `export/{tcp-connections,tcp-windows,tcp-indicators,tcp-summary,dns-transactions,dns-summary,top-talkers,traffic-direction,anomalies,analytics-summary}.csv`
and `report.pdf` (extended). Lists support `page`, `per_page`, filters and `sort`/`order`. Captures analysed before
Phase 4 answer `409` with `reason: "analytics_unavailable"`.

## Configuration

* `NETSCOPE_ANOMALY_THRESHOLDS` — JSON overrides, e.g. `{"port_scan_distinct_ports": 30}` (validated at startup).
* `NETSCOPE_DNS_TIMEOUT_SECONDS` — inferred-timeout horizon.

## Running the tests

```bash
# Dependency-free unit tests of every metric (72 tests)
PYTHONPATH=backend python -m unittest backend/tests/test_analytics_core.py
# Full backend suite (needs the project environment: uv sync)
uv run pytest
# Frontend
cd frontend && npm ci && npm test
```

## Known limitations

* Per-capture state (connections, DNS transactions, address pairs) is held in memory until the end of the
  pass: memory grows with the number of distinct connections, not packets (≈340 MB traced for 40 k
  connections + 30 k DNS transactions + 70 k addresses).
* DNS over TCP is parsed only when a whole message sits in one segment; retransmission detection is a
  lower bound (exact repeats within FlowTracker's window).
* Sequence gaps cannot distinguish network loss, capture loss and reordering.
* Anomaly thresholds are applied when a capture is analysed; changing them needs re-analysis.
* Captures analysed before Phase 4 have no advanced results and cannot be re-analysed in place.
