# NetScope

![Python](https://img.shields.io/badge/Python-3.12+-3776AB?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.1+-000000?logo=flask&logoColor=white)
![Vue](https://img.shields.io/badge/Vue-3-4FC08D?logo=vuedotjs&logoColor=white)
![Vite](https://img.shields.io/badge/Vite-7-646CFF?logo=vite&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?logo=postgresql&logoColor=white)
![Celery](https://img.shields.io/badge/Celery-5.4+-37814A?logo=celery&logoColor=white)
![Scapy](https://img.shields.io/badge/Packet_Analysis-Scapy-informational)
![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)

> A multi-user network traffic analysis platform: upload PCAP/PCAPNG captures, process them in the background with Scapy, and explore packets, flows, protocol and performance metrics, and explainable network-intelligence analytics through a Vue web interface.

NetScope analyses **capture files that users upload**. It does not sniff live traffic. A user registers, uploads a `.pcap`, `.pcapng` or `.cap` file, and a Celery worker streams it through a single-pass analysis pipeline. Packets, flows, summary statistics and advanced analytics are persisted in PostgreSQL, and the Vue interface renders them as dashboards, tables, charts and downloadable PDF/CSV reports.

Packet-capture analysis has an inherent limit: a capture taken at one point shows only what passed that point. A missing SYN-ACK, a sequence gap or a repeated ACK is *evidence* worth investigating, not proof of network loss or an attack. NetScope is built around that distinction. Wherever a result is inferred rather than observed, the API labels it as such, ships the metric definition alongside the numbers, and refuses to invent figures (for example, it never reports a packet-loss percentage).

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
  - [Authentication and User Isolation](#authentication-and-user-isolation)
  - [Capture Management](#capture-management)
  - [Packet Analysis](#packet-analysis)
  - [Flow Analysis](#flow-analysis)
  - [Traditional Analytics](#traditional-analytics)
  - [Advanced Network Intelligence](#advanced-network-intelligence)
  - [Frontend](#frontend)
  - [Reporting](#reporting)
- [Technology Stack](#technology-stack)
- [System Architecture](#system-architecture)
  - [Capture Processing Workflow](#capture-processing-workflow)
  - [Analysis Architecture](#analysis-architecture)
  - [Capture Lifecycle and Job Semantics](#capture-lifecycle-and-job-semantics)
- [Observed Versus Inferred: How to Read the Results](#observed-versus-inferred-how-to-read-the-results)
- [Metric Definitions](#metric-definitions)
  - [Traditional Metrics](#traditional-metrics)
  - [Network Intelligence Metrics](#network-intelligence-metrics)
  - [Anomaly Rules](#anomaly-rules)
- [Frontend Application](#frontend-application)
- [Repository Structure](#repository-structure)
- [Installation and Local Development](#installation-and-local-development)
  - [Prerequisites](#prerequisites)
  - [1. Clone and Install Dependencies](#1-clone-and-install-dependencies)
  - [2. Start PostgreSQL and Valkey](#2-start-postgresql-and-valkey)
  - [3. Create the Database](#3-create-the-database)
  - [4. Configure Environment Variables](#4-configure-environment-variables)
  - [5. Apply Migrations and Build the Frontend](#5-apply-migrations-and-build-the-frontend)
  - [6. Run the Application](#6-run-the-application)
  - [Optional: Vite Development Workflow](#optional-vite-development-workflow)
- [Configuration Reference](#configuration-reference)
- [API Reference](#api-reference)
  - [Conventions](#conventions)
  - [Health and Authentication](#health-and-authentication)
  - [Captures](#captures)
  - [Summary and Analytics](#summary-and-analytics)
  - [Packets](#packets)
  - [Flows](#flows)
  - [Advanced Network Intelligence Endpoints](#advanced-network-intelligence-endpoints)
  - [Dashboard and Comparison](#dashboard-and-comparison)
  - [Reports and Exports](#reports-and-exports)
- [Testing and Validation](#testing-and-validation)
- [Security Notes](#security-notes)
- [Operational Notes](#operational-notes)
- [Limitations and Interpretation Notes](#limitations-and-interpretation-notes)
- [Contributing](#contributing)
- [License](#license)

## Overview

Analysing a capture is a pipeline with several distinct responsibilities, and NetScope keeps them separate:

| Concern | What happens | Where |
| --- | --- | --- |
| **Ingestion and validation** | The upload is streamed to disk with a size limit, its format is detected from file signatures (not the extension), and its record framing is checked without loading packet bodies. | `capture_storage.py`, `capture_reader.py` |
| **Background processing** | An authenticated request creates a database record and enqueues a Celery task; a worker claims the capture and runs the analysis outside the web process. | `capture_service.py`, `workers/tasks.py` |
| **Packet and flow persistence** | Packets are decoded one at a time and inserted in batches; flows are reconstructed bidirectionally and written once the pass ends. | `packet_extractor.py`, `flow_tracker.py`, `analysis_pipeline.py` |
| **Traditional analytics** | Protocol distribution, throughput, packet-size statistics, time series, retransmissions, handshake RTT, jitter. | `traffic_stats.py` |
| **Advanced network intelligence** | TCP connection outcomes, DNS transactions, resets, top talkers, direction, loss indicators, window analysis, rule-based anomalies. | `services/analytics/` |
| **Visualisation and reporting** | A Vue single-page application renders results; the API generates PDF and CSV reports on demand. | `frontend/`, `export_service.py` |

Two design decisions shape the whole system:

- **One pass over the capture.** The traditional statistics and all advanced analytics consume the same decoded packet stream. The advanced analyzers reuse the flow ids and retransmission flags already produced by the flow tracker instead of re-deriving them, so the two layers cannot disagree about what a flow or a retransmission is.
- **All-or-nothing results.** Packets are inserted in batches while the capture is processed, but a capture only becomes `completed` after flows, summary and advanced analytics are written. If anything fails, everything stored for that capture is deleted, so a partial analysis is never served.

## Key Features

### Authentication and User Isolation

- Registration, login, logout and a "current user" endpoint under `/api/v1/auth`. Passwords are 8 to 128 characters and hashed with Werkzeug.
- Session authentication through an HttpOnly, SameSite=Lax cookie (Flask-Login). The Vue app keeps no credentials in `localStorage` or `sessionStorage`.
- CSRF protection (Flask-WTF) on every state-changing request. Clients fetch a token from `GET /api/v1/auth/csrf` and send it in the `X-CSRFToken` header.
- Every capture lookup is filtered by owner. Another user's capture is indistinguishable from a missing one: the API answers `404`.
- Login responses do not reveal whether an email exists, and a dummy password hash is checked for unknown emails so response timing does not leak account existence.

### Capture Management

- Upload of `.pcap`, `.pcapng` and `.cap` files, validated by content, streamed to disk with a configurable size limit (default 200 MB) and a SHA-256 digest recorded.
- Files are stored at `<upload folder>/<user id>/<capture id>.<format>`. The client's filename is used for display only and never forms part of a path.
- Capture list (paginated, filterable by status) and detail views with live processing progress.
- Status lifecycle `uploaded → pending → processing → completed | failed`. A failed capture keeps a user-visible error message and can be retried.
- Deletion removes the stored file and the database record, together with every dependent row.
- Background processing through Celery. The worker only processes `pending` captures, so duplicate message deliveries are harmless.

### Packet Analysis

Implemented in `packet_extractor.py` with Scapy, plus signature-based identification in `protocol_detector.py`.

- **Layer 2:** Ethernet (source/destination MAC, EtherType) and the 802.1Q VLAN identifier.
- **Layer 3:** IPv4 and IPv6, including TTL/hop limit. IPv6 extension headers (hop-by-hop, routing, fragment, destination options) are skipped to find the real upper-layer protocol, and later fragments without a transport header are treated as expected rather than malformed.
- **Layer 4:** TCP (flags, sequence/acknowledgement numbers, advertised window, window-scale option), UDP, ICMP and ICMPv6, plus ARP.
- **Application layer:** DNS over UDP and over TCP (when the complete message is in one TCP segment), HTTP identified from a request or status line in a TCP payload, and a wider set of protocols named by payload signature or, failing that, well-known port when a payload is present (TLS with SNI, SSH, SMB, QUIC, DHCP, NTP, and others; see [`docs/phase4-network-intelligence.md`](docs/phase4-network-intelligence.md#application-protocol-identification)). Every packet records whether its application label came from a `signature` or a `port`.
- **Malformed packets are stored, not dropped,** with a reason (`truncated_ip_header`, `truncated_transport_header`, `unparsed_frame` or `extraction_error:<type>`), so packet counts stay accurate. A decoding failure in one packet never aborts the capture.
- Byte counts use the on-the-wire frame size (`original_length`), so they remain correct for captures cut short by a snap length.

### Flow Analysis

- Bidirectional flows keyed by protocol and the two address/port pairs; endpoint A is the side that sent the flow's first packet. ICMP flows are keyed by address pair, and non-IP packets belong to no flow.
- Per-flow packet and byte totals in each direction, first/last seen, duration, retransmission count, handshake RTT and jitter.
- Top flows (the default flow sort is by bytes), plus filtering and sorting by protocol, application, address, port, bytes, packets, duration and start time.
- Packet-level and flow-level inspection: any packet can be opened with every extracted field, and the packet list can be narrowed to one flow.

### Traditional Analytics

Computed by `traffic_stats.py` and stored as a summary document per capture.

- Protocol distribution at the transport layer and the application layer.
- Average and peak throughput and packets per second.
- Packet-size statistics.
- Traffic-over-time series.
- TCP retransmission counts (a lower bound; see [Metric Definitions](#traditional-metrics)).
- Handshake RTT and arrival-time jitter, where the capture contains what is needed to compute them.
- Link utilisation, computed on request only when the caller supplies a link speed (`link_mbps`), because a capture does not record one.

### Advanced Network Intelligence

Ten analytics added in "Phase 4" and documented in [`docs/phase4-network-intelligence.md`](docs/phase4-network-intelligence.md). They are computed in the same pass as the traditional metrics by the modules in `backend/app/services/analytics/`.

| Capability | Module | What it reports |
| --- | --- | --- |
| TCP connection outcomes and success rate | `tcp_connections.py` | Per-connection state: `established`, `incomplete`, `refused` or `unclassified`, and a success rate over observable attempts. |
| Incomplete versus refused | `tcp_connections.py` | A SYN with no completed handshake is `incomplete` (not a confirmed failure). Only a SYN answered by RST-ACK is `refused`. |
| Handshake timing and observed duration | `tcp_connections.py` | SYN to SYN-ACK, SYN to completing ACK, and first-to-last captured packet, with histograms. Connections lacking a captured start or end are flagged `capture_truncated`. |
| TCP reset analysis | `tcp_connections.py` | Reset packet rate, reset connection rate, and reset evidence per connection. |
| DNS response latency | `dns_analytics.py` | Query-to-response time for matched transactions. |
| DNS failure analysis | `dns_analytics.py` | Response-code breakdown, error and server-failure rates, and unanswered queries classified as inferred timeout or indeterminate. |
| Top talkers | `traffic_intel.py` | Addresses ranked by bytes or packets, as source, destination or both; IPv4 and IPv6. |
| Direction classification | `traffic_intel.py` | Inbound, outbound, internal or unknown, relative to local networks you configure. |
| Packet-loss indicators | `tcp_diagnostics.py` | Retransmissions, duplicate ACKs, sequence gaps, out-of-order segments and partial overlaps, each with severity and confidence. |
| Receive-window analysis | `tcp_diagnostics.py` | Advertised window, window changes, zero-window episodes, and window scaling when both handshake packets were captured. |
| Anomaly detection | `anomalies.py` | Sixteen explainable threshold rules; every finding states the rule, the measured value against the threshold, the evidence and the supporting packets. |

Observed facts and inferences are kept apart. See [Observed Versus Inferred](#observed-versus-inferred-how-to-read-the-results).

### Frontend

A Vue 3 single-page application with a dashboard, capture upload and history, a capture detail area with eight tabs, a two-capture comparison page, and report downloads. Details are in [Frontend Application](#frontend-application).

### Reporting

- **PDF report** with capture details, summary totals, protocol tables and chart, performance metrics, throughput chart and top flows. For captures that have advanced analytics, the report is extended with network-intelligence content and the leading anomaly findings.
- **CSV exports** for packets, flows, protocols, performance and traffic over time, plus ten advanced exports (TCP connections, windows, indicators and summary; DNS transactions and summary; top talkers; traffic direction; anomalies; analytics summary).
- Packet and flow CSVs honour the same filters as their list endpoints. Spreadsheet-formula-looking cells (`=`, `+`, `-`, `@`, tab, CR) are prefixed with an apostrophe. Reports are generated on demand, sent with `Cache-Control: no-store` and never written to disk.

## Technology Stack

| Layer | Technology | Notes |
| --- | --- | --- |
| Backend language | Python 3.12+ | `requires-python = ">=3.12.16"`; `.python-version` pins `3.12.16` |
| Web framework | Flask 3.1+ | Application factory in `backend/app/__init__.py` |
| Authentication and CSRF | Flask-Login, Flask-WTF | Session cookies and CSRF tokens |
| ORM | SQLAlchemy 2 via Flask-SQLAlchemy | PostgreSQL through `psycopg` 3 |
| Database | PostgreSQL | Tests use SQLite; developed locally against PostgreSQL 18 |
| Migrations | Alembic via Flask-Migrate | `backend/migrations/` |
| Background processing | Celery 5.4+ | Tasks run inside a Flask application context |
| Message broker | Valkey (Redis protocol) | Addressed with a `redis://` URL through `redis-py`; see [Configuration](#configuration-reference) |
| Packet analysis | Scapy 2.8+ | Streaming reader and dissection |
| Data processing | Pandas 2.2+ | Used by the statistics accumulator |
| Validation and models | Pydantic 2 | Domain models for packets and captures |
| Reports | ReportLab | PDF generation; CSV is streamed from the standard library |
| WSGI server | Gunicorn | Declared as a dependency for deployment |
| Frontend framework | Vue 3 | Composition API |
| Build tooling | Vite 7 | Also proxies `/api` in development |
| Routing | Vue Router 4 | History mode, lazy-loaded views |
| State management | Pinia 3 | Stores for auth, captures, dashboard, detail and analytics |
| Styling | Tailwind CSS 3.4 | System fonts only; no runtime CDN dependencies |
| Visualisation | Chart.js 4.4 | Wrapped by `BaseChart.vue` |
| HTTP client | Axios | CSRF handling and error normalisation in `src/api/client.js` |
| Python tests | pytest | Backend unit and API tests |
| Frontend tests | Vitest, Vue Test Utils, jsdom | Unit and component tests |
| Browser tests | Playwright (Python) | Optional; skipped when Chromium is unavailable |
| Package management | uv (Python), npm (frontend) | Node `^20.19.0 || >=22.12.0` |

## System Architecture

In production the same Flask process serves both the JSON API and the built Vue application, so the browser talks to a single origin. Analysis runs in a separate Celery worker that shares the database and the upload directory with the web process.

```mermaid
flowchart TD
    Browser["Browser"]

    subgraph WebProcess["Flask application (one origin)"]
        SPA["SPA host<br/>serves frontend/dist<br/>CSP and index.html fallback"]
        API["JSON API<br/>/api/v1"]
        Services["Service layer<br/>capture, auth, queries,<br/>dashboard, export"]
    end

    Valkey[("Valkey<br/>Celery broker")]

    subgraph Worker["Celery worker process"]
        Task["analyze_capture task"]
        Pipeline["Analysis pipeline<br/>Scapy reader, extractor,<br/>flow tracker, statistics,<br/>advanced analytics"]
    end

    Storage[("Upload folder<br/>user id / capture id.format")]
    PG[("PostgreSQL<br/>users, captures, packets, flows,<br/>analysis results, advanced tables")]

    Browser -->|"HTML, JS, CSS"| SPA
    Browser -->|"XHR with session cookie<br/>and X-CSRFToken"| API
    API --> Services
    Services --> PG
    Services -->|"stream upload"| Storage
    Services -->|"enqueue task"| Valkey
    Valkey -->|"deliver task"| Task
    Task --> Pipeline
    Pipeline -->|"read capture file"| Storage
    Pipeline -->|"batched inserts,<br/>status updates"| PG
```

Engineering decisions worth knowing:

- **Job state lives in PostgreSQL, not in the Celery result backend.** Tasks are configured with `task_ignore_result`, and status, progress and error messages are columns on the capture record. The result backend setting exists but the application does not rely on it.
- **Uploads are stored on disk, not in the database.** The database holds metadata and a relative storage path, and the path is resolved against the upload root with a check that it cannot escape it.
- **The frontend and API share an origin.** In production Flask serves the build; in development Vite proxies `/api`. Cookies and CSRF behave identically in both and the backend needs no CORS configuration.
- **Pure analysis logic is separated from I/O.** The extractor, flow tracker, statistics and every module under `services/analytics/` are plain Python with no Flask or database access, which is what makes them unit-testable in isolation.

### Capture Processing Workflow

```mermaid
flowchart TD
    A["Upload: POST /api/v1/captures"] --> B{"Extension and content valid,<br/>within size limit?"}
    B -- "No" --> R["400 or 413 with a safe message"]
    B -- "Yes" --> C["Stream to disk, compute SHA-256,<br/>create capture record: uploaded"]
    C --> D{"analyze requested?<br/>default: yes"}
    D -- "No" --> U["Stays uploaded<br/>POST /analyze later"]
    D -- "Yes" --> E["Atomic claim: pending<br/>enqueue Celery task"]
    E -- "Broker unreachable" --> F1["failed with message<br/>retry available"]
    E --> G["Worker claims pending capture:<br/>processing"]
    G --> H["Validate and stream packets<br/>one at a time with Scapy"]
    H --> I["Extract packet fields,<br/>track flows and retransmissions,<br/>update statistics and analytics"]
    I --> J["Insert packets in batches<br/>packet_count grows after each batch"]
    J --> K["Write flows, summary document,<br/>then advanced analytics tables"]
    K --> L["completed"]
    H -- "Error or limit exceeded" --> M["Delete partial results<br/>failed with error_message"]
    I -- "Error or limit exceeded" --> M
    L --> N["Frontend polls status,<br/>then loads summary, packets,<br/>flows and analytics"]
```

### Analysis Architecture

```mermaid
flowchart LR
    File["Capture file"] --> Reader["capture_reader.py<br/>signature detection, framing checks,<br/>streaming Scapy packets"]
    Reader --> Extractor["packet_extractor.py<br/>ExtractedPacket per packet<br/>malformed packets kept with a reason"]
    Extractor --> Detector["protocol_detector.py<br/>signature and port labels"]
    Extractor --> Flows["flow_tracker.py<br/>bidirectional flows,<br/>retransmission flag, RTT, jitter"]

    Flows -->|"flow id and<br/>retransmission flag"| Adv
    Extractor --> Stats["traffic_stats.py<br/>protocols, throughput,<br/>sizes, time series"]
    Flows --> Stats

    subgraph Adv["AdvancedAnalyzer: services/analytics"]
        TCP["tcp_connections.py<br/>outcomes, timing, resets"]
        Diag["tcp_diagnostics.py<br/>loss indicators, windows"]
        DNS["dns_analytics.py<br/>latency, failures, timeouts"]
        Intel["traffic_intel.py<br/>talkers, direction"]
        Anom["anomalies.py<br/>rule-based findings"]
    end

    Extractor --> Adv
    TCP --> Anom
    Diag --> Anom
    DNS --> Anom
    Intel --> Anom

    Extractor --> PGp[("packets")]
    Flows --> PGf[("flows")]
    Stats --> PGs[("analysis_results")]
    Adv --> PGa[("advanced tables")]
```

`AdvancedAnalyzer.observe` is called per packet with the flow id and retransmission flag the flow tracker produced, and `finalize` is called once at the end. Per-capture state for connections, DNS transactions and address pairs is held in memory until the pass ends, so memory grows with the number of distinct connections and addresses, not with the number of packets.

### Capture Lifecycle and Job Semantics

`uploaded → pending → processing → completed | failed`

| Transition | Behaviour |
| --- | --- |
| `uploaded` or `failed` → `pending` | An atomic conditional update claims the capture, so two concurrent requests cannot queue it twice. If the broker is unreachable the capture becomes `failed` with a retryable message. |
| `pending` → `processing` | The worker claims only `pending` captures. A duplicate or redelivered message finds no `pending` row and exits. |
| `processing` → `completed` | Set only after flows, summary and advanced analytics are persisted. |
| `processing` → `failed` | Partial results are deleted. Messages shown to users have server file paths removed. A capture deleted mid-run is left alone. |
| `failed` → `pending` | `POST /captures/<id>/analyze` retries, clearing the previous error and any stale results. |

While a capture is `processing`, `packet_count` grows after every stored batch. The UI shows packets processed rather than a percentage, because the total is unknown until the file has been read.

## Observed Versus Inferred: How to Read the Results

| Observed directly in the capture | Inferred, and therefore qualified |
| --- | --- |
| Packet headers, flags, sequence and acknowledgement numbers, advertised window values | Whether a missing packet was lost in the network, lost by the capture tool, or only reordered |
| A SYN, SYN-ACK and completing ACK in order (an `established` connection) | That an `incomplete` connection actually failed |
| A SYN answered by RST-ACK (`refused`, the only confirmed connection failure) | A DNS "timeout" (only an `unanswered_inferred_timeout` when the capture ran on long enough; otherwise `indeterminate`) |
| An exact duplicate segment in the same direction (a counted retransmission) | Effective TCP window size (reported only when both handshake packets carried window scaling, otherwise `null`) |
| DNS query/response pairs and their RCODE | Traffic direction (relative only to local networks you supply; with none, everything is `unknown`) |
| Timestamps as recorded by the capture point | Anomaly findings (threshold heuristics; not proof of malicious activity) |

Packet-loss indicators are evidence commonly associated with loss, not measurements of it. `packet_loss_percent` is always `null`.

## Metric Definitions

Every analytics response ships the definitions relevant to it (the `definitions` field), and the frontend renders them next to the numbers.

### Traditional Metrics

- **Bytes** are on-the-wire frame sizes (`original_length`), headers included.
- **Protocols.** `transport` counts by TCP, UDP, ICMP and ICMPv6 (non-IP traffic such as ARP is listed by name), so HTTP and DNS packets still count towards TCP and UDP. `application` lists DNS and HTTP as identified by the extractor, plus the further protocols named by `protocol_detector.py`.
- **Flow.** A bidirectional protocol + address/port pair. Endpoint A is the side that sent the first packet.
- **Retransmission.** A TCP segment carrying payload (or SYN/FIN) whose exact `(sequence number, length)` was already seen in the same direction. The tracker remembers a window of 1,024 segments per direction. Re-segmented or coalesced retransmissions are not detected, so the count is a lower bound. Pure ACKs and RSTs are never counted.
- **Handshake RTT.** First SYN to its SYN-ACK as seen at the capture point. Only flows whose handshake was captured have one.
- **Jitter.** Mean absolute difference between consecutive packet inter-arrival gaps within a flow. This is arrival-time jitter; a capture has no send timestamps, so RFC 3550 transit-time jitter is not possible. It needs at least three packets in the flow.
- **Utilisation.** Computed only when `link_mbps` is supplied.

### Network Intelligence Metrics

- **TCP connection success rate** = established ÷ observable attempts, where observable attempts are connections whose initial SYN was captured (established + incomplete + refused). Mid-stream connections are `unclassified` and excluded. The rate is `null` when there are no attempts.
- **Handshake time** = first SYN to the completing client ACK, for established connections only. It includes SYN retransmission delay because it starts at the first SYN. **Observed lifetime** = first to last captured packet.
- **Termination** is `fin` (FIN from both sides), `reset`, `half_closed` (FIN from one side) or `none`.
- **DNS response time** = first query transmission to the response, matched on client and server address and port, DNS transaction id and transport (UDP and TCP are never cross-matched). Retransmitted queries and duplicate responses are not double counted.
- **DNS failure rate** = responses with RCODE other than NOERROR ÷ responses observed (NXDOMAIN included). `server_failure_rate` excludes NXDOMAIN. Unanswered queries are never part of either rate.
- **TCP reset rates.** Packet rate = RST packets ÷ TCP packets. Connection rate = connections with at least one RST ÷ tracked TCP connections.
- **Top talkers.** Ranked by bytes or packets as source, destination or bidirectional, with total IP bytes/packets as denominators. Bidirectional shares across addresses add up to about 200 %, because each packet has two endpoints.
- **Direction.** Source local and destination local is `internal`; local to remote is `outbound`; remote to local is `inbound`; neither is `unknown`. Private address ranges are never assumed local.
- **Loss indicators.** `retransmission`, `duplicate_ack` (RFC 5681 sense: a pure ACK repeating the previous ACK number and window while the peer has unacknowledged data in flight), `sequence_gap`, `out_of_order` and `partial_overlap`. Sequence arithmetic is modulo 2³². Keep-alive and zero-window probes are ignored.
- **Windows.** The advertised window is what the packet's sender announces. A raw value is scaled by 2^shift only when both SYN and SYN-ACK were captured and both carried a window-scale option.

### Anomaly Rules

Anomaly detection is plain threshold rules over metrics NetScope already measured. There is no machine learning and no threat intelligence. Each finding carries its rule, severity, description, the value against the threshold, evidence, affected addresses and flows, packet references, and the thresholds in force.

| Rule | Fires when |
| --- | --- |
| `http_on_nonstandard_port` | Cleartext HTTP is seen on ports other than the usual HTTP ports |
| `non_dns_on_dns_port` | Payload on port 53 did not parse as DNS |
| `udp_on_tcp_service_port` | UDP payload to ports normally used only by TCP services |
| `high_volume_host` | One address sent more than the byte threshold |
| `traffic_burst` | Peak packet rate is far above the median interval rate |
| `high_connection_rate` | One source opened many TCP connections in a short window |
| `repeated_connection_attempts` | Many attempts to one destination service that mostly never completed |
| `port_scan_vertical` | One source tried many destination ports on one host |
| `port_scan_horizontal` | One source tried one port on many hosts |
| `dns_nxdomain_burst` | A client received many NXDOMAIN answers |
| `dns_long_names` | A client queried unusually long DNS names or labels |
| `dns_many_subdomains` | A client queried many distinct subdomains of one domain |
| `high_reset_rate` | An unusually large share of TCP packets were resets |
| `reset_source_host` | One address sent many TCP resets |
| `host_traffic_concentration` | A single address sent almost all bytes among many hosts |
| `icmp_heavy` | ICMP made up a large share of packets |

Default thresholds live in `AnomalyThresholds` in `backend/app/services/analytics/anomalies.py` and can be overridden with `NETSCOPE_ANOMALY_THRESHOLDS`. Unknown names and non-positive values are rejected at startup. Thresholds are applied when a capture is analysed, so changing them affects only captures analysed afterwards.

## Frontend Application

The interface is a Vue 3 single-page application in `frontend/`. Routes are defined in `frontend/src/router/index.js`; every route except sign-in and registration requires authentication.

| Route | View | Purpose |
| --- | --- | --- |
| `/login`, `/register` | Sign in, create account | Guest-only; signed-in users are redirected away. After sign-in the user returns to the page they were trying to reach. |
| `/dashboard` | Dashboard | Totals across your captures, processing-status summary, recent sessions, recent traffic and aggregated protocol distribution. |
| `/captures` | Captures | Drag-and-drop upload with progress, capture history with status filter, retry and delete. |
| `/captures/<id>` | Overview | Capture details, live processing progress, summary statistics, and the **Reports** menu. |
| `/captures/<id>/protocols` | Protocols | Transport and application protocol distribution. |
| `/captures/<id>/flows` | Flows | Flow table with filters; top flows by default sort. |
| `/captures/<id>/packets` | Packets | Packet explorer with search, filters, pagination and a packet detail panel. |
| `/captures/<id>/performance` | Performance | Throughput, packets per second, packet sizes, time series, retransmissions, RTT and jitter; optional link-speed input for utilisation. |
| `/captures/<id>/tcp` | TCP Connections | Connection outcomes, success rate, handshake and lifetime distributions, resets, loss indicators, window analysis. |
| `/captures/<id>/dns` | DNS Analytics | Response-time and failure analysis, transaction list with filters. |
| `/captures/<id>/traffic` | Traffic Intelligence | Top talkers, inbound/outbound classification relative to local networks you enter, and rule-based anomaly findings. |
| `/compare` | Compare | Choose two completed captures for metric-by-metric deltas, protocol comparison and IP overlap; shareable via `?a=<id>&b=<id>`. |

The capture detail page has two tab rows: the five core tabs (Overview, Protocols, Flows, Packets, Performance) and a second row for the network-intelligence tabs (TCP Connections, DNS Analytics, Traffic Intelligence).

Implementation notes:

- Filters and paging live in the URL, so views can be bookmarked and the Back button works.
- Each data-driven page has loading, empty and error states. Captures without advanced analytics show an "unavailable" notice instead of empty charts.
- All capture-derived text is rendered through Vue text interpolation; the app never uses `v-html`, so hostile filenames or packet contents cannot inject markup.
- Downloads go through the authenticated Axios client; the server's error message is recovered from error responses even when the expected body was a PDF or CSV.
- A 401 from the API signs the user out locally and sends them to the sign-in page with a return path.

## Repository Structure

```text
netscope/
├── pyproject.toml                  Python project, dependencies, pytest configuration
├── .python-version                 Pinned Python version
├── .env.example                    Documented environment variables (not auto-loaded)
├── .gitignore
├── LICENSE                         Apache License 2.0
├── README.md
│
├── backend/
│   ├── wsgi.py                     WSGI entry point and Celery app (celery_app)
│   ├── app/
│   │   ├── __init__.py             Application factory: config, extensions, blueprints, headers
│   │   ├── config.py               Environment-based configuration classes
│   │   ├── extensions.py           db, migrate, login_manager, csrf
│   │   ├── celery_app.py           Celery bound to the Flask application context
│   │   ├── api/                    JSON API blueprints, mounted under /api/v1
│   │   │   ├── health.py           Liveness
│   │   │   ├── auth.py             CSRF token, register, login, logout, me
│   │   │   ├── captures.py         Upload, list, detail, status, analyze, delete
│   │   │   ├── analysis.py         Summary, protocols, performance, packets, flows
│   │   │   ├── advanced.py         TCP, DNS, traffic and anomaly endpoints
│   │   │   ├── dashboard.py        Dashboard aggregates and capture comparison
│   │   │   └── reports.py          CSV exports and PDF report
│   │   ├── models/                 Pydantic domain models (Capture, Packet)
│   │   ├── schemas/                Pydantic schemas
│   │   ├── orm/                    SQLAlchemy tables (users, captures, packets, flows,
│   │   │                           analysis results, advanced analytics tables)
│   │   ├── services/
│   │   │   ├── capture_reader.py       Format detection, structure validation, streaming reader
│   │   │   ├── capture_storage.py      Secure file storage and path resolution
│   │   │   ├── capture_service.py      Upload, ownership-scoped queries, job submission, delete
│   │   │   ├── packet_extractor.py     Scapy packet to NetScope packet (pure logic)
│   │   │   ├── protocol_detector.py    Application protocol identification
│   │   │   ├── flow_tracker.py         Flows, retransmissions, RTT, jitter (pure logic)
│   │   │   ├── traffic_stats.py        Protocol, throughput and time-series statistics
│   │   │   ├── analysis_pipeline.py    Reader, extractor, trackers and persistence in one pass
│   │   │   ├── analysis_queries.py     Packet and flow filtering, sorting, pagination
│   │   │   ├── advanced_queries.py     Filters and queries for Phase 4 data
│   │   │   ├── advanced_persistence.py Persists Phase 4 results
│   │   │   ├── dashboard_service.py    Dashboard aggregates and comparison
│   │   │   ├── export_service.py       Streaming CSV and PDF generation
│   │   │   ├── auth_service.py         Registration and authentication
│   │   │   └── analytics/              Phase 4 analytics (pure logic)
│   │   │       ├── engine.py               AdvancedAnalyzer orchestration and definitions
│   │   │       ├── tcp_connections.py      Connection outcomes, timing, resets
│   │   │       ├── tcp_diagnostics.py      Loss indicators and window analysis
│   │   │       ├── dns_analytics.py        DNS transactions, latency, failures
│   │   │       ├── traffic_intel.py        Top talkers and direction
│   │   │       ├── anomalies.py            Rule-based anomaly detection
│   │   │       └── common.py               Shared helpers
│   │   ├── web/spa.py              Serves the built Vue app, CSP and index.html fallback
│   │   └── workers/tasks.py        Celery task: analyze_capture
│   ├── migrations/                 Alembic environment
│   │   └── versions/               Three revisions: users and captures; packets, flows and
│   │                               analysis results; Phase 4 network intelligence
│   └── tests/                      Backend unit and API tests (pytest)
│
├── frontend/
│   ├── package.json                Scripts and dependencies
│   ├── vite.config.js              Vite, dev and preview proxy, Vitest configuration
│   ├── tailwind.config.js, postcss.config.js
│   ├── .env.example                Optional Vite variables
│   ├── index.html
│   ├── src/
│   │   ├── main.js, App.vue
│   │   ├── router/                 Routes, auth guards, safe post-login redirect
│   │   ├── api/                    Axios client (CSRF, errors) and one module per API area
│   │   ├── stores/                 Pinia stores
│   │   ├── composables/            Polling, async state, URL-backed filters, upload, downloads
│   │   ├── layouts/                AppLayout (sidebar and top bar), AuthLayout
│   │   ├── views/                  One view per route
│   │   ├── components/             common, dashboard, captures, packets, flows, analytics, charts
│   │   └── utils/                  Formatting, chart configuration, safe redirects
│   └── tests/                      Vitest unit and component tests
│
├── tests/
│   └── e2e/                        Real-browser tests (Playwright) against the production build
│
└── docs/
    └── phase4-network-intelligence.md   Network-intelligence design, definitions and limitations
```

Entry points: `backend/wsgi.py` (Flask `app` and Celery `celery_app`), `backend/app/__init__.py` (`create_app`), and `frontend/src/main.js`.

Note: the repository does not currently include a `uv.lock` file, so `uv sync` resolves dependencies from `pyproject.toml` and creates one locally.

## Installation and Local Development

These instructions target Fedora/Linux. Run every command from the repository root unless stated otherwise.

### Prerequisites

| Requirement | Notes |
| --- | --- |
| Python 3.12 or newer | The project requires `>=3.12.16`; `uv` can fetch it |
| [uv](https://docs.astral.sh/uv/) | Python dependency management |
| Node.js `^20.19.0` or `>=22.12.0`, and npm | Frontend build |
| PostgreSQL | The development setup used PostgreSQL 18; the repository does not pin a version |
| Valkey | Celery broker; speaks the Redis protocol |
| Chromium (optional) | Only for the browser tests |

### 1. Clone and Install Dependencies

```bash
git clone <repository-url> netscope
cd netscope

uv sync
npm --prefix frontend ci
```

`uv sync` also installs the `dev` dependency group (pytest and Playwright).

### 2. Start PostgreSQL and Valkey

On the development machine these run as systemd services:

```bash
sudo systemctl start postgresql-18
sudo systemctl start valkey
```

Service names depend on how PostgreSQL was installed (the `postgresql-18` name matches the PostgreSQL project's own packages). A first-time PostgreSQL install also needs its data directory initialised according to your packaging's instructions.

### 3. Create the Database

These credentials are **local development examples only**. They match the default `NETSCOPE_DATABASE_URL`, which is why nothing needs configuring in development.

```bash
sudo -u postgres psql -c "CREATE USER netscope WITH PASSWORD 'netscope';"
sudo -u postgres psql -c "CREATE DATABASE netscope OWNER netscope;"
```

For anything other than a local machine, use a strong generated password and a dedicated database user. Never commit credentials.

### 4. Configure Environment Variables

NetScope reads real environment variables only. It does **not** load `.env` files itself. `.env.example` documents the variables; to use a local copy, load it into your shell:

```bash
cp .env.example .env
set -a; source .env; set +a
```

`.env` is ignored by Git. For the local setup above, the two settings that matter are:

```bash
export NETSCOPE_DATABASE_URL="postgresql+psycopg://netscope:netscope@localhost:5432/netscope"
export NETSCOPE_REDIS_URL="redis://localhost:6379/0"
```

Both are also the built-in defaults. `NETSCOPE_ENV` defaults to `development`, which uses an insecure built-in `SECRET_KEY` and non-secure session cookies. The full list is in the [Configuration Reference](#configuration-reference).

The variable is named `NETSCOPE_REDIS_URL` because Valkey is accessed over the Redis protocol with a `redis://` URL and the `redis` Python client; point it at your Valkey instance.

Environment variables must be set in **every** terminal that runs Flask or Celery.

### 5. Apply Migrations and Build the Frontend

```bash
uv run python -m flask --app backend/wsgi db upgrade
npm --prefix frontend run build
```

The build writes `frontend/dist`, which Flask serves. If it is missing, Flask answers `503` with the build command.

### 6. Run the Application

Terminal 1, the Flask server:

```bash
uv run python -m flask --app backend/wsgi run
```

Terminal 2, the Celery worker:

```bash
uv run python -m celery --workdir backend -A wsgi:celery_app worker --loglevel=info
```

Open <http://localhost:5000>, register an account, and upload a capture. Without a running worker, uploaded captures remain `pending` and are never processed.

### Optional: Vite Development Workflow

For hot reload, run Flask and Celery as above, then start the Vite dev server in a third terminal:

```bash
npm --prefix frontend run dev
```

The app is then at <http://localhost:5173>. The Vite server (port 5173, `strictPort`) proxies `/api` to the Flask development server at `http://127.0.0.1:5000`, so the browser only ever talks to one origin, session cookies and CSRF work exactly as in production, and Flask needs no CORS settings. `changeOrigin` is deliberately off so the `Host` and `Referer` headers that Flask-WTF compares stay consistent.

Override the proxy target or API base URL by copying `frontend/.env.example` to `frontend/.env.local` (ignored by Git):

| Variable | Default | Purpose |
| --- | --- | --- |
| `VITE_DEV_PROXY_TARGET` | `http://127.0.0.1:5000` | Where the dev server proxies `/api` |
| `VITE_API_BASE_URL` | `/api/v1` | API base URL. Keep the same-origin default; a cross-origin URL would need CORS on Flask, which is not configured. |

`npm --prefix frontend run preview` serves the production build on port 4173 with the same proxy.

## Configuration Reference

Configuration is defined in `backend/app/config.py`. All variables are optional in development; `NETSCOPE_SECRET_KEY` is required in production.

| Variable | Purpose | Required | Default | Example |
| --- | --- | --- | --- | --- |
| `NETSCOPE_ENV` | `development`, `testing` or `production`. Any other value stops startup. | No | `development` | `production` |
| `NETSCOPE_SECRET_KEY` | Signs session cookies and CSRF tokens. | Yes in production (startup fails without it) | Development only: an insecure built-in key | A long random string (see below) |
| `NETSCOPE_DATABASE_URL` | SQLAlchemy database URL. | No | `postgresql+psycopg://netscope:netscope@localhost:5432/netscope` | `postgresql+psycopg://user:***@db-host:5432/netscope` |
| `NETSCOPE_REDIS_URL` | Celery broker **and** result backend URL (Valkey over the Redis protocol). | No | `redis://localhost:6379/0` | `redis://localhost:6379/0` |
| `NETSCOPE_UPLOAD_FOLDER` | Where uploaded captures are stored. | No | `backend/instance/uploads` | `/var/lib/netscope/uploads` |
| `NETSCOPE_MAX_UPLOAD_BYTES` | Maximum upload size; also sets Flask's `MAX_CONTENT_LENGTH`. | No | `209715200` (200 MB) | `104857600` |
| `NETSCOPE_MAX_PACKETS` | Per-capture packet limit; a larger capture fails with a clear message. | No | `2000000` | `500000` |
| `NETSCOPE_PACKET_BATCH_SIZE` | Packets inserted per database batch (also the progress-update cadence). | No | `5000` | `5000` |
| `NETSCOPE_FRONTEND_DIST` | Directory of the built Vue app Flask serves. | No | `frontend/dist` | `/srv/netscope/dist` |
| `NETSCOPE_ANOMALY_THRESHOLDS` | JSON object overriding anomaly-rule thresholds, validated at startup. Names are the fields of `AnomalyThresholds`. | No | Built-in thresholds | `{"port_scan_distinct_ports": 30}` |
| `NETSCOPE_DNS_TIMEOUT_SECONDS` | Seconds a DNS query must stay unanswered, with the capture still running, to be an inferred timeout. Must be positive. | No | `5` | `5` |
| `NETSCOPE_CHROMIUM_PATH` | Use a specific Chromium executable for the browser tests. Read by `tests/e2e` only. | No | Playwright's Chromium | `/usr/bin/chromium` |
| `NETSCOPE_SHOTS` | Directory where the browser tests write screenshots. Read by `tests/e2e` only. | No | `/tmp/netscope-shots` | `/tmp/netscope-shots` |

Generate a production secret without storing it anywhere:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Other behaviour fixed in code: session cookies are HttpOnly and SameSite=Lax; `SESSION_COOKIE_SECURE` is on in production (serve it over HTTPS) and off in development and testing; CSRF tokens are tied to the session and do not expire on their own; `.pcap`, `.pcapng` and `.cap` are the accepted extensions.

## API Reference

All routes are mounted under `/api/v1`. The interface is JSON, except where a route returns a file.

### Conventions

- **Authentication.** Every route except `GET /health`, `GET /auth/csrf`, `POST /auth/register` and `POST /auth/login` requires a session. A missing session returns `401`.
- **CSRF.** Every state-changing request (`POST`, `DELETE`) must carry an `X-CSRFToken` header whose value comes from `GET /api/v1/auth/csrf`. This includes login and registration.
- **Ownership.** Capture routes are owner-scoped; another user's capture returns `404`.
- **Completion.** Analysis, packet, flow, advanced, comparison and report routes return `409` until the capture is `completed`.
- **Errors** use one envelope: `{"error": {"code", "name", "message"}}`, with extra fields where relevant (for example validation `errors`, or `reason`).
- **Pagination.** List routes accept `page` and `per_page` and return `items`, `page`, `per_page` and `total`. Invalid filter values return `400` with the reason.

### Health and Authentication

| Method | Route | Description |
| --- | --- | --- |
| GET | `/health` | Liveness check |
| GET | `/auth/csrf` | Returns a CSRF token for JSON clients |
| POST | `/auth/register` | JSON `{email, password}`; creates the account and starts a session (`201`). `400` on validation errors, `409` if the email exists. |
| POST | `/auth/login` | JSON `{email, password}`; starts a session. `401` for bad credentials. |
| POST | `/auth/logout` | Ends the session |
| GET | `/auth/me` | The current user |

### Captures

| Method | Route | Description |
| --- | --- | --- |
| POST | `/captures` | Multipart upload with a `file` field (and optional `analyze=false` to skip queueing). Returns `201`; `413` if over the size limit. |
| GET | `/captures` | Paginated capture list (`per_page` up to 100) with an optional `status` filter |
| GET | `/captures/<id>` | Capture details |
| GET | `/captures/<id>/status` | Processing status and live `packet_count` |
| POST | `/captures/<id>/analyze` | Queue analysis or retry (`202`). `409` unless the capture is `uploaded` or `failed`; `503` if the broker is unavailable. |
| DELETE | `/captures/<id>` | Delete the record and file (`204`) |

### Summary and Analytics

| Method | Route | Description |
| --- | --- | --- |
| GET | `/captures/<id>/summary` | Capture info, totals (packets, bytes, unique IPs, flows, malformed) and protocols |
| GET | `/captures/<id>/protocols` | Packet and byte counts per transport and per application protocol |
| GET | `/captures/<id>/performance` | Throughput, packets per second, packet sizes, time series, TCP retransmissions, RTT and jitter. Optional `link_mbps` adds link utilisation. |

### Packets

| Method | Route | Description |
| --- | --- | --- |
| GET | `/captures/<id>/packets` | Paginated packets. Filters: `protocol`, `src_ip`, `dst_ip`, `ip`, `src_port`, `dst_port`, `port`, `flow_id`, `min_length`, `max_length`, `tcp_flags`, `malformed`, `retransmission`, `q` (search). `sort` is `number`, `time` or `length`; `order` is `asc` or `desc`; `per_page` up to 200. |
| GET | `/captures/<id>/packets/<n>` | One packet with every extracted field |

### Flows

| Method | Route | Description |
| --- | --- | --- |
| GET | `/captures/<id>/flows` | Paginated flows. Filters: `protocol`, `application`, `ip`, `port`. `sort` is `bytes`, `packets`, `duration` or `start`. Default sort by bytes gives the top flows. |
| GET | `/captures/<id>/flows/<flow_id>` | One flow |

### Advanced Network Intelligence Endpoints

All are owner-scoped, require a `completed` capture, and answer `409` with `reason: "analytics_unavailable"` for captures analysed before the advanced analytics existed.

| Method | Route | Description |
| --- | --- | --- |
| GET | `/captures/<id>/analytics` | The complete stored analytics document, including metric definitions and limitations |
| GET | `/captures/<id>/tcp/summary` | TCP connection outcomes, success rate, timing distributions, reset and indicator summaries |
| GET | `/captures/<id>/tcp/connections` | Paginated connections. Filters: `state`, `ip`, `port`, `flow_id`, `termination`, `truncated`, `has_reset`, `zero_window`, `retransmissions`. `sort` is `start`, `duration`, `handshake`, `packets`, `bytes`, `resets` or `zero_window`. |
| GET | `/captures/<id>/tcp/connections/<connection_id>` | One connection with detail |
| GET | `/captures/<id>/tcp/resets` | TCP reset analysis |
| GET | `/captures/<id>/tcp/indicators` | Paginated loss indicators. Filters include `type` (`retransmission`, `duplicate_ack`, `sequence_gap`, `out_of_order`, `partial_overlap`) and `severity`. |
| GET | `/captures/<id>/tcp/windows` | Receive-window analysis and the connections with the most zero-window events |
| GET | `/captures/<id>/dns/summary` | DNS latency, response-code breakdown and failure rates |
| GET | `/captures/<id>/dns/transactions` | Paginated DNS transactions. Filters include `status` (`answered`, `unanswered`, `unanswered_inferred_timeout`, `unanswered_indeterminate`, `unmatched_response`), `rcode`, `transport`, `q`. |
| GET | `/captures/<id>/dns/transactions/<transaction_id>` | One DNS transaction |
| GET | `/captures/<id>/traffic/talkers` | Top talkers. Parameters: `by` (`bytes`/`packets`), `role` (`source`/`destination`/`bidirectional`), `limit` (up to 100), `ip_version` (`4`/`6`). |
| GET | `/captures/<id>/traffic/direction` | Inbound/outbound/internal/unknown breakdown. `local` takes comma-separated networks, for example `local=10.0.0.0/24,2001:db8::/32`. |
| GET | `/captures/<id>/anomalies` | Paginated anomaly findings. Filters: `severity` (`info`, `low`, `medium`, `high`), `rule`, `ip`. |
| GET | `/captures/<id>/anomalies/<finding_id>` | One finding with evidence and thresholds |

### Dashboard and Comparison

| Method | Route | Description |
| --- | --- | --- |
| GET | `/dashboard` | Totals across your captures, status counts, recent sessions, recent traffic and aggregated protocol distribution |
| GET | `/compare?a=<id>&b=<id>` | Metric-by-metric deltas, protocol comparison and IP overlap for two different completed captures |

### Reports and Exports

| Method | Route | Description |
| --- | --- | --- |
| GET | `/captures/<id>/report.pdf` | PDF report; extended with network-intelligence content when available. Optional `local` for direction classification. |
| GET | `/captures/<id>/export/<kind>.csv` | CSV export. `kind` is one of `packets`, `flows`, `protocols`, `performance`, `timeseries`, `tcp-connections`, `tcp-windows`, `tcp-indicators`, `tcp-summary`, `dns-transactions`, `dns-summary`, `top-talkers`, `traffic-direction`, `anomalies`, `analytics-summary`. |

List-style exports accept the same filters as the matching list endpoint. An unknown `kind` returns `404` listing the valid kinds. The Reports menu in the UI exposes the PDF and the five core CSV exports. The TCP, DNS and Traffic Intelligence pages add export buttons for `tcp-connections`, `dns-transactions`, `top-talkers` and `traffic-direction`; the remaining advanced CSVs (`tcp-windows`, `tcp-indicators`, `tcp-summary`, `dns-summary`, `anomalies`, `analytics-summary`) are available through the API only.

## Testing and Validation

Test configuration lives in `pyproject.toml` (`testpaths = ["backend/tests", "tests"]`, `pythonpath = ["backend"]`).

**Backend** (pytest):

```bash
uv run pytest backend/tests
```

The backend suite does not need PostgreSQL or Valkey: it uses SQLite and runs Celery in eager mode (`TestingConfig`), with broker failures simulated. It covers the packet extractor, flow tracker, traffic statistics, protocol detector, analytics core, capture reader and validation, authentication, the capture, analysis, advanced-analytics, dashboard and report APIs, the SPA host, the worker, and a check that the Alembic migrations produce exactly the schema the models declare. Behaviour against a live PostgreSQL and a live Valkey broker is therefore exercised by running the application, not by this suite.

The analytics core can also be run without the project environment:

```bash
PYTHONPATH=backend python -m unittest backend/tests/test_analytics_core.py
```

**Frontend** (Vitest, jsdom):

```bash
npm --prefix frontend test
```

**Browser end-to-end** (Playwright):

```bash
uv run python -m playwright install chromium
npm --prefix frontend run build
uv run pytest tests/e2e
```

These tests start a live Flask server with CSRF enforcement on, serve the production build, and drive Chromium through the application. They are **skipped automatically** when Playwright, a Chromium build or `frontend/dist` is unavailable. Set `NETSCOPE_CHROMIUM_PATH` to use an existing Chromium. Screenshots are written to `/tmp/netscope-shots` (override with `NETSCOPE_SHOTS`).

**Everything:**

```bash
uv run pytest
```

runs the backend and browser suites together (the browser tests skip if unavailable).

## Security Notes

- **Isolation.** Every capture query is filtered by owner, and ownership failures look identical to missing resources.
- **Uploads.** Validated by file signature and structure rather than extension, streamed with a hard size limit, stored under server-generated names, and error messages never include server paths.
- **Sessions and CSRF.** HttpOnly, SameSite=Lax cookies (Secure in production), and CSRF tokens on all state-changing requests with a single refresh-and-retry on rejection.
- **Content Security Policy.** The app shell is served with `script-src 'self'`, no inline script and no framing. Capture-derived text is never rendered as markup, and PDF text is XML-escaped.
- **Headers.** `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY` are set on all responses.
- **Public shell, protected data.** The app shell contains no user data; access control is enforced by the API on every request. Router guards are a convenience only.
- **Not implemented:** login rate limiting, email verification and password reset.

## Operational Notes

- **Run a worker.** Without a Celery worker, captures stay `pending`. Run the worker with time limits generous enough for your largest expected captures.
- **Throughput.** Analysis speed is bounded by Scapy's dissection. The earlier sandbox measurement recorded roughly 1 to 2 thousand packets per second on a shared two-core machine (a 300,000-packet capture took about four minutes with a peak process size of about 230 MB). Treat that as an order-of-magnitude indication, not a guarantee: a capture near the default 2,000,000-packet limit can take tens of minutes on similar hardware.
- **Memory** grows with the number of distinct flows, addresses, connections and DNS transactions, and the seconds a capture spans, not with the number of packets.
- **Uploads on disk.** Back up or mount `NETSCOPE_UPLOAD_FOLDER` consistently for both the Flask process and the worker, since both read it.
- **Production.** Set `NETSCOPE_ENV=production` and `NETSCOPE_SECRET_KEY`, serve over HTTPS, and run Flask under a WSGI server rather than the development server. Gunicorn is a declared dependency and `backend/wsgi.py` exposes `app`, but a Gunicorn deployment is not covered by the repository's tests and no deployment configuration (container, proxy, process manager) is provided.
- **Migrations.** Run `db upgrade` after pulling changes. The three revisions are `3ad16f3f764b` (users and captures), `6384d2549255` (packets, flows, analysis results) and `a4f1c2d9b7e3` (Phase 4 network intelligence).

## Limitations and Interpretation Notes

Implemented behaviour first, then what is not implemented.

**Interpretation**

- **Loss indicators are not loss measurements.** Retransmissions, duplicate ACKs and sequence gaps cannot independently establish whether loss happened in the network, in the capture tool, or whether packets were merely reordered. NetScope never reports a loss percentage.
- **Direction depends on configuration.** Inbound/outbound/internal classification exists only relative to the local networks you supply. With none, every packet is `unknown`; private ranges are never assumed local.
- **Anomaly findings are heuristics.** They are explainable threshold rules, not a replacement for a dedicated intrusion detection system, and they do not prove malicious activity. Busy servers, administrator-run scanners and legitimate bursts can all trigger them.
- **`incomplete` is not `failed`.** Only `refused` (SYN answered by RST-ACK) is a confirmed connection failure.
- **DNS timeouts are inferences.** An unanswered query is an inferred timeout only when the capture continued long enough afterwards; even then the response may have bypassed the capture point.
- **A capture shows only what it saw.** Analysis is limited to the traffic and payload visible in the supplied file: snap-length truncation, a mid-connection start, or a capture point that sees one direction only all limit what can be concluded.

**Known limitations**

- **Earlier captures lack advanced analytics.** Captures processed before the Phase 4 migration have no advanced results and cannot be re-analysed in place. Advanced endpoints answer `409` with `reason: "analytics_unavailable"`, and the interface shows an "unavailable" notice.
- **Retransmission counts are a lower bound** (exact repeats within a 1,024-segment window per direction; re-segmented retransmissions appear as partial overlaps instead).
- **DNS over TCP** is recognised only when a whole message sits in one TCP segment; messages split across several segments are not reassembled.
- **Application identification is best effort.** Only DNS (UDP and TCP) and HTTP (request or status line) are parsed from payload by the extractor; other protocols are labelled by signature or well-known port. Bare handshake/ACK packets and TLS continuation segments are deliberately left unlabelled rather than guessed.
- **Anomaly thresholds** apply when a capture is analysed; changing them requires re-analysis, which for completed captures is not offered in place.
- **Dashboard protocol distribution** uses your 100 most recent analysed captures.
- **Progress** shows packets processed, not a percentage.
- **Not verified:** operation against a live Valkey broker is not covered by automated tests (see [Testing](#testing-and-validation)).
- **Not implemented:** login rate limiting, email verification, password reset, live packet capture, and any shipped deployment configuration.

## Contributing

1. Fork the repository and create a branch from the default branch.
2. Install dependencies as described in [Installation](#installation-and-local-development).
3. Keep analysis logic pure (no Flask or database access in extractor, tracker and analytics modules) and add unit tests alongside changes; the API and browser suites cover the integration.
4. Run `uv run pytest` and `npm --prefix frontend test` before opening a pull request.
5. A change that alters the database schema needs an Alembic migration (`uv run python -m flask --app backend/wsgi db migrate`); the migration test fails if migrations and models disagree.
6. Never commit `.env` files, capture files (`*.pcap`, `*.pcapng`) or credentials; `.gitignore` already excludes them.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
