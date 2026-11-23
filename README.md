# NetScope

![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.1-000000?logo=flask&logoColor=white)
![Vue](https://img.shields.io/badge/Vue-3-4FC08D?logo=vuedotjs&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-18-4169E1?logo=postgresql&logoColor=white)
![Celery](https://img.shields.io/badge/Celery-5.4-37814A?logo=celery&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2.8-1F6FEB)
![License](https://img.shields.io/badge/License-Apache_2.0-blue)

**A multi-user web platform for analysing uploaded packet captures: Scapy-based dissection, bidirectional flow reconstruction, traffic analytics, and rule-based network intelligence, delivered through a Flask API and a Vue 3 interface.**

NetScope analyses **capture files that users upload** (PCAP and PCAPNG). It does not sniff live interfaces.

---

## Table of Contents

- [Overview](#overview)
- [Capabilities](#capabilities)
  - [Authentication and user isolation](#authentication-and-user-isolation)
  - [Capture management](#capture-management)
  - [Packet analysis](#packet-analysis)
  - [Flow analysis](#flow-analysis)
  - [Traditional analytics](#traditional-analytics)
  - [Advanced Network Intelligence (Phase 4)](#advanced-network-intelligence-phase-4)
  - [Frontend](#frontend)
  - [Reporting](#reporting)
- [Technology Stack](#technology-stack)
- [Architecture](#architecture)
  - [System architecture](#system-architecture)
  - [Capture processing workflow](#capture-processing-workflow)
  - [Analysis architecture](#analysis-architecture)
  - [Design decisions](#design-decisions)
  - [Data model](#data-model)
- [Repository Structure](#repository-structure)
- [Installation and Local Development](#installation-and-local-development)
- [Docker Deployment](#docker-deployment)
  - [Why Docker](#why-docker)
  - [Image build architecture](#image-build-architecture)
  - [Docker Compose service architecture](#docker-compose-service-architecture)
  - [Prerequisites](#prerequisites)
  - [Configure the environment](#configure-the-environment)
  - [Build the image](#build-the-image)
  - [Start the application](#start-the-application)
  - [Inspect the services](#inspect-the-services)
  - [Access the application](#access-the-application)
  - [Stop the services](#stop-the-services)
  - [Persistent data](#persistent-data)
  - [Troubleshooting](#troubleshooting)
- [Configuration Reference](#configuration-reference)
- [API Reference](#api-reference)
- [Testing and Validation](#testing-and-validation)
- [Operational Notes](#operational-notes)
- [Limitations and Interpretation Notes](#limitations-and-interpretation-notes)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

A packet capture is a flat, time-ordered record of frames. Answering practical questions from one ("Which conversations dominate the traffic?", "Do connections complete their handshakes?", "Are DNS lookups slow or failing?", "Is this TCP session showing signs of loss?") means decoding every frame, grouping frames into conversations, and aggregating the result, usually by hand in a desktop tool and without a shared, queryable record of the outcome.

NetScope turns that into a repeatable, multi-user workflow. An authenticated user uploads a capture, a background worker analyses it once, and every result is persisted in PostgreSQL so that packets, flows, charts, reports and comparisons are served from the database rather than recomputed on demand.

The platform deliberately separates six concerns:

| Concern | What it is | Where it lives |
|---|---|---|
| **Capture ingestion and validation** | Streaming the upload to disk with a size limit, checking the file by content (magic bytes and record framing), storing it under a server-chosen path, recording a database row. | `services/capture_storage.py`, `services/capture_reader.py`, `services/capture_service.py` |
| **Background processing** | A Celery task that claims the capture, runs the analysis pipeline, and records `completed` or `failed`. | `workers/tasks.py`, `celery_app.py` |
| **Packet and flow persistence** | Per-packet rows, bidirectional flow rows, and the aggregate summary document. | `orm/analysis.py`, `services/analysis_pipeline.py` |
| **Traditional analytics** | Protocol distribution, throughput, packet sizes, time series, TCP retransmissions, handshake RTT, jitter, optional link utilisation. | `services/flow_tracker.py`, `services/traffic_stats.py` |
| **Advanced network intelligence (Phase 4)** | TCP connection outcomes, DNS transactions, reset analysis, top talkers, direction classification, loss indicators, window analysis, rule-based anomaly findings. | `services/analytics/`, `orm/advanced.py` |
| **Frontend visualisation and reporting** | A Vue 3 single-page application, plus on-demand CSV and PDF exports. | `frontend/`, `services/export_service.py` |

Phase 4 does not re-read the capture. Its trackers run in the **same single pass** as the flow tracker and statistics accumulator, reusing the flow identifiers and retransmission flags that pass already produced.

---

## Capabilities

### Authentication and user isolation

- **Registration and sign-in** with email and password (`POST /api/v1/auth/register`, `/login`, `/logout`; `GET /me`). Emails are normalised to lower case; passwords must be 8 to 128 characters and are hashed with Werkzeug's `generate_password_hash`. Login failures return one generic message, and the unknown-email path spends comparable time so response timing does not reveal which emails exist.
- **Session authentication** with Flask-Login. The session cookie is `HttpOnly` and `SameSite=Lax`; it is `Secure` in production. The session is cleared on login, registration and logout.
- **CSRF protection** with Flask-WTF. Every state-changing request needs an `X-CSRFToken` header whose value comes from `GET /api/v1/auth/csrf`. The bundled Vue client fetches, attaches, refreshes (once, on rejection) and resets the token automatically.
- **Per-user data isolation.** Every capture lookup filters on the owning user. Another user's capture is indistinguishable from a missing one: the API returns `404`, never `403`. All packet, flow, analytics, export and comparison routes go through the same ownership check.
- **Browser-side hardening.** The app shell is served with a Content-Security-Policy (`script-src 'self'`, no framing, `object-src 'none'`) and `X-Content-Type-Options` / `X-Frame-Options` headers. The Vue app renders capture-derived text through interpolation and does not use `v-html`.

### Capture management

- **Upload** of `.pcap`, `.pcapng` and `.cap` filenames (`POST /api/v1/captures`, multipart field `file`). The extension is only a first filter: the content must be a valid classic PCAP or PCAPNG file, and the stored format is determined from the content.
- **Validation by content.** The reader recognises PCAP (both byte orders, microsecond and nanosecond variants) and PCAPNG signatures, then walks record or block framing with seeks, without loading packet bodies, rejecting truncated files, impossible lengths and (for PCAP) captured lengths above the original or snapshot length.
- **Secure storage.** The upload is streamed in 1 MiB chunks to a temporary file inside the owner's directory, checked against the size limit while streaming (`413` when exceeded), hashed (SHA-256), validated, then moved into place as `<UPLOAD_FOLDER>/<user_id>/<capture_id>.<pcap|pcapng>`. The client's filename never takes part in the path; it is sanitised and kept for display only. Error messages shown to users have server paths removed.
- **Listing and detail.** Paginated listing (`per_page` up to 100) with a `status` filter, per-capture detail, and a lightweight status endpoint that reports live progress (`packet_count` grows as packet batches are stored).
- **Lifecycle:** `uploaded → pending → processing → completed | failed`.
- **Retry.** Analysis can be queued from `uploaded` or `failed` (`POST /captures/<id>/analyze`); any other state returns `409`. If the broker is unreachable the capture is recorded as `failed` with an explanatory message and the endpoint answers `503`, so the user can retry. Uploading with `analyze=false` stores the file without queueing analysis.
- **Deletion** removes the stored file first, then the database row; packets, flows and analytics are removed by `ON DELETE CASCADE`.
- **Background processing.** Analysis runs in a Celery worker. The task atomically claims a capture only if it is `pending`, so duplicate or redelivered messages are harmless. On any failure the capture's partial results are deleted and the user-visible `error_message` is set, so half-finished results are never served.

### Packet analysis

`services/packet_extractor.py` converts each Scapy packet into a structured record (the `Packet` Pydantic model plus analysis-only fields).

| Layer | Support |
|---|---|
| Ethernet | Source and destination MAC, EtherType. |
| VLAN | 802.1Q: the VLAN ID of the tag Scapy exposes is recorded. |
| IPv4 | Addresses, TTL, protocol. |
| IPv6 | Addresses, hop limit; **extension headers** (hop-by-hop, routing, fragment, destination options) are skipped to find the real next header. Later IPv6 fragments, which carry no transport header, are treated as expected rather than malformed. |
| TCP | Ports, flags, sequence and acknowledgement numbers, advertised window, window-scale option, payload length (taken from the IP header, so snaplen-truncated captures stay correct). |
| UDP | Ports and length. |
| ICMP / ICMPv6 | Type and code. |
| ARP | Labelled as ARP; belongs to no flow. |
| DNS | Dissected by Scapy over UDP and TCP; header fields, up to 8 questions, and the response code are captured for transaction matching. |
| HTTP | Identified from a request or status line at the start of a TCP payload (method prefixes and `HTTP/1.`). |
| Other application protocols | `services/protocol_detector.py` labels common protocols from payload signatures (for example TLS, SSH, SMB, QUIC, DHCP, NTP) and, where a payload is present, from well-known ports. Each packet's metadata records whether the label came from a `signature` or a `port`. Bare handshake and ACK packets are left unlabelled rather than guessed. |

**Malformed packets are kept, not dropped.** A packet that cannot be fully decoded is stored with a `malformed_reason` (`truncated_ip_header`, `truncated_transport_header`, `unparsed_frame`, or `extraction_error:<type>`), so packet counts stay faithful to the capture and malformed packets can be filtered in the explorer.

### Flow analysis

- **Bidirectional flow identification.** A flow is the 5-tuple (protocol, address, port, address, port) treated symmetrically. Endpoint A is the side that sent the flow's first packet. ICMP flows are keyed by address pair; non-IP packets belong to no flow.
- **Per-flow statistics:** packets and bytes in total and per direction, first and last seen, duration, application protocol, retransmission count, handshake RTT and jitter.
- **Top flows** are the default ordering of the flow list (by bytes, descending); flows can also be sorted by packets, duration or start time.
- **Packet-level and flow-level inspection.** Packets can be listed with filters and opened individually with every extracted field; each packet carries its `flow_id`, so a packet can be traced to its flow and back.

### Traditional analytics

All values below are computed during analysis and stored; the API reads them back.

| Metric | Definition and caveats |
|---|---|
| **Protocol distribution** | Transport counts (TCP, UDP, ICMP, ICMPv6; non-IP traffic such as ARP is listed by name) and application counts (DNS, HTTP, plus protocols the detector recognises). Application packets also count towards their transport. |
| **Bytes** | On-the-wire frame size (`original_length`), headers included. |
| **Throughput and packets per second** | Average and peak, from the time series. |
| **Packet-size statistics** | Distribution of frame sizes. |
| **Time series** | Packets, bytes, packets/s and bits/s per bucket. The bucket width is the smallest of a set of candidate widths that yields at most 300 points. |
| **TCP retransmissions** | A segment whose exact (sequence number, length) was already seen in the same direction; a window of 1024 segments per direction is remembered. Re-segmented or coalesced retransmissions are not detected, so the count is a **lower bound**. Pure ACKs are never counted. |
| **Handshake RTT** | First SYN to its SYN-ACK as seen **at the capture point**; only flows whose handshake was captured have one. |
| **Jitter** | Mean absolute change between consecutive packet inter-arrival gaps within a flow. It is arrival-time jitter, not RFC 3550 transit-time jitter, because a capture has no send timestamps. Needs at least 3 packets. |
| **Link utilisation** | A capture does not contain link speed, so utilisation is computed only when a link capacity is supplied (`link_mbps` query parameter; the Performance page has an input for it). |

### Advanced Network Intelligence (Phase 4)

Phase 4 adds ten analytics, implemented as pure-Python trackers in `backend/app/services/analytics/` and persisted by migration `a4f1c2d9b7e3`. Every result ships with its own **definitions** and **limitations**, which the API returns and the interface displays next to the numbers.

#### Observed versus inferred

A single capture shows packets at one point on the path. NetScope is explicit about which values are read directly from packets and which are conclusions drawn from them.

| Observed directly | Inferred (and therefore qualified) |
|---|---|
| SYN, SYN-ACK, ACK, FIN and RST packets and their timestamps | That a connection "failed" (only a *refused* connection, SYN answered by RST-ACK, is a confirmed failure; an *incomplete* one is not) |
| DNS query and response packets, response codes | That a query "timed out" (inferred, and only if the capture ran on long enough) |
| Sequence and acknowledgement numbers, advertised windows | That "loss occurred" (retransmissions, duplicate ACKs and sequence gaps are *indicators*, never a measurement) |
| Source and destination addresses and byte counts | Direction (inbound or outbound), which depends on the local networks you configure |
| Counts of packets matching a rule's condition | That traffic is "malicious" (findings are heuristics) |

#### TCP connection outcomes and success rate

Connections are tracked per flow; a flow may contain several connections when a port pair is reused (a new SYN with a different initial sequence number starts a new connection record). Each connection is classified only from what was captured:

| State | Meaning |
|---|---|
| `established` | SYN, matching SYN-ACK (ack = client ISN + 1) and the client's completing ACK were all seen. |
| `refused` | SYN followed by an RST-ACK from the server acknowledging the SYN, before any SYN-ACK. The only *confirmed* failure a passive capture can show. |
| `incomplete` | SYN seen, handshake not completed in the capture (`no_synack` or `no_final_ack`). **Not** a confirmed failure: packets may have been filtered, answered on a path the capture did not see, or the capture may have ended. |
| `unclassified` | No initial SYN was captured (capture started mid-connection), so the connection is not judged. |

**Connection success rate** = `established / (established + incomplete + refused)`. The denominator is *observable attempts*, connections whose initial SYN was captured; `unclassified` connections are excluded. The rate is `null` when there are no observable attempts.

#### TCP handshake timing and observed duration

- **Handshake time**: first SYN to the completing client ACK, established connections only. It starts at the *first* SYN, so it includes SYN retransmission delay. (`syn_to_synack_ms` is the shorter SYN-to-SYN-ACK interval, the handshake RTT at the capture point.)
- **Observed lifetime**: first to last captured packet of the connection. It is not the true lifetime when the capture starts or ends mid-connection.
- **Termination**: `reset`, `fin` (FIN from both sides), `half_closed` (FIN from one side) or `none`. Connections whose start or end is not visible are flagged `capture_truncated`.
- Timings are reported as distributions (including median and p95) and histograms.

#### DNS response latency, failures and timeouts

A DNS *transaction* is a query (possibly retransmitted) and its response, matched on client address and port, server address and port, DNS transaction ID **and transport**. A UDP query is never matched to a TCP response.

- **Latency** is the first query transmission to the response (what the client waited); a second figure measures from the last retransmission (server and path time).
- Retransmitted queries and duplicate responses are not double counted; unmatched queries and unmatched responses are separate counters. A message with several questions is one transaction.
- **Failure rate** = responses with RCODE other than NOERROR ÷ responses observed. NXDOMAIN counts as an error response; a separate `server_failure_rate` excludes it (FORMERR, SERVFAIL, REFUSED and so on). Unanswered queries are never part of these rates.
- **Inferred timeouts.** An unanswered query is an `unanswered_inferred_timeout` only if the capture continued at least `NETSCOPE_DNS_TIMEOUT_SECONDS` (default 5) after its last transmission; otherwise it is `unanswered_indeterminate`, because the response might simply fall after the capture ended. Even an inferred timeout remains an inference: the response may have bypassed the capture point.
- DNS over TCP is recognised only when the whole message is in one TCP segment.

#### TCP reset analysis

Two distinct rates are reported: the **packet rate** (RST packets ÷ TCP packets) and the **connection rate** (connections with at least one RST ÷ tracked TCP connections). Resets are attributed to the sending host, with a capped set of evidence packets.

#### Top talkers

Addresses ranked by bytes or packets **sent**, **received**, or **both**, for IPv4 and IPv6 (optionally filtered to one IP version). Percentages use total IP bytes or packets as the denominator, so bidirectional shares across addresses sum to roughly 200 %, because each packet has two endpoints.

#### Inbound, outbound, internal and unknown traffic

Direction is relative to the **local networks you configure** (`?local=10.0.0.0/24,2001:db8::/32`, up to 64 entries; a bare address is treated as a host):

| Source | Destination | Class |
|---|---|---|
| local | local | `internal` |
| local | remote | `outbound` |
| remote | local | `inbound` |
| remote | remote | `unknown` (transit, mirror or third-party traffic) |

Private address ranges are **not** assumed to be local. With no local networks configured, everything is `unknown`. IPv4-mapped IPv6 addresses are matched against IPv4 networks.

#### Packet-loss indicators

Five kinds of per-connection, per-direction evidence, each with a severity and confidence:

| Indicator | What was observed |
|---|---|
| `retransmission` | An exact duplicate segment (counted once, by the flow tracker). |
| `duplicate_ack` | A pure ACK repeating the previous ACK number and window while the peer had data in flight (RFC 5681 sense). |
| `sequence_gap` | A segment ahead of the next expected sequence number, leaving a byte range not seen. |
| `out_of_order` | A non-duplicate segment arriving behind the highest sequence seen, inside an earlier gap. |
| `partial_overlap` | A segment overlapping already-seen data without being an exact duplicate (typically a re-segmented retransmission). |

These are indicators commonly associated with loss or reordering. **NetScope reports no loss percentage** (`packet_loss_percent` is `null`): a sequence gap cannot distinguish network loss from capture-tool loss or reordering.

#### TCP receive-window analysis

Per connection and direction: the raw advertised window, window changes, **zero-window episodes**, and window scaling. A raw value is multiplied by 2^shift only when both the SYN and SYN-ACK were captured and both carried the window-scale option; otherwise effective window sizes are `null`, never guessed. Keep-alive and zero-window probes are ignored by the sequence tracking.

#### Rule-based protocol anomaly detection

Sixteen explainable threshold rules run over measures NetScope already computed. There is no machine learning and no external threat intelligence.

| Area | Rules |
|---|---|
| Protocol and port | `http_on_nonstandard_port`, `non_dns_on_dns_port`, `udp_on_tcp_service_port` |
| Volume and shape | `high_volume_host`, `traffic_burst`, `host_traffic_concentration`, `icmp_heavy` |
| Connection behaviour | `high_connection_rate`, `repeated_connection_attempts`, `port_scan_vertical`, `port_scan_horizontal` |
| TCP resets | `high_reset_rate`, `reset_source_host` |
| DNS | `dns_nxdomain_burst`, `dns_long_names`, `dns_many_subdomains` |

Every finding records the rule, severity (`info`, `low`, `medium`, `high`), a description, a **reason** (measured value against threshold), evidence, affected addresses and flows, supporting packet numbers, and the thresholds in force. Thresholds can be overridden with `NETSCOPE_ANOMALY_THRESHOLDS` (see [Configuration Reference](#configuration-reference)). A finding is a heuristic indicator and **not** proof of malicious activity: busy servers, administrator-run scanners, misconfigured clients and legitimate bursts all trigger these rules.

> **Interface coverage.** The Vue interface presents TCP, DNS and traffic intelligence. Loss indicators and window details appear per connection in the TCP connection detail panel. **Anomaly findings, aggregate loss-indicator lists and window summaries are exposed through the API, CSV exports and the PDF report, not as dedicated pages.**

### Frontend

The interface is a Vue 3 single-page application using history-mode routing. Navigation is derived from `frontend/src/router/index.js`:

| Route | View | Purpose |
|---|---|---|
| `/login`, `/register` | Sign in / create account | Guest-only; returns the user to the page they were trying to reach. |
| `/dashboard` | Dashboard | Totals across the user's captures, status counts, recent sessions, recent traffic and aggregated protocol distribution; refreshes while jobs run. |
| `/captures` | Captures | Upload (with progress), capture history, status filter, retry and delete. |
| `/captures/:id` | Capture overview | Processing progress, then summary of the completed capture; Reports menu; link to comparison. |
| `/captures/:id/protocols` | Protocol analytics | Transport and application distribution. |
| `/captures/:id/flows` | Flow inspection | Filterable, sortable flow table (top flows by default). |
| `/captures/:id/packets` | Packet inspection | Filterable, searchable packet table with per-packet detail. |
| `/captures/:id/performance` | Performance analytics | Throughput, packets per second, packet sizes, time series, retransmissions, handshake RTT, jitter, optional link utilisation. |
| `/captures/:id/tcp` | TCP Connections | Success rate, outcome counts, handshake and lifetime histograms, reset analysis, filterable connection table with per-connection detail. |
| `/captures/:id/dns` | DNS Analytics | Latency, response codes, servers, and filterable transactions with evidence. |
| `/captures/:id/traffic` | Traffic Intelligence | Top talkers and inbound/outbound classification for user-supplied local networks. |
| `/compare` | Compare captures | Two completed captures side by side; shareable via `?a=<id>&b=<id>`. |

Filters and paging live in the URL, so views can be bookmarked and the Back button works. Capture IDs are matched as UUIDs in the route; anything else falls through to a not-found page.

### Reporting

Reports are generated on demand for **completed** captures, sent with `Cache-Control: no-store`, and never written to disk.

- **PDF** (`GET /captures/<id>/report.pdf`): capture details, summary, protocol tables and chart, performance with a throughput chart, and the top 15 flows. When Phase 4 results exist, an *Advanced network analytics* section is added: TCP connections, resets, loss indicators and windows, DNS, top talkers, inbound/outbound traffic, the top 15 anomaly findings, and the metric definitions and measurement limitations. The optional `local` query parameter feeds the direction table. User-controlled text is XML-escaped before it is rendered.
- **CSV** (`GET /captures/<id>/export/<kind>.csv`): `packets` and `flows` honour the same filters as their list endpoints; the other kinds are listed in the [API reference](#reports-and-exports). Cells that a spreadsheet could read as formulas (starting `=`, `+`, `-`, `@`, tab or carriage return) are prefixed with an apostrophe.
- **In the interface**, the capture page's *Reports* menu offers the PDF and the five base CSVs (packets, flows, protocols, performance, traffic over time). The TCP, DNS and Traffic pages add *Export CSV* buttons for TCP connections, DNS transactions, top talkers and traffic direction. Other advanced CSV kinds are available through the API only.

---

## Technology Stack

Versions are the constraints declared in `pyproject.toml` and `frontend/package.json`.

| Layer | Technology |
|---|---|
| Language (backend) | Python ≥ 3.12.16 (`.python-version` pins 3.12.16) |
| Web framework | Flask ≥ 3.1 |
| Authentication | Flask-Login (sessions), Flask-WTF (CSRF) |
| ORM | SQLAlchemy ≥ 2.0 via Flask-SQLAlchemy |
| Database | PostgreSQL (driver: psycopg 3, URL scheme `postgresql+psycopg`) |
| Migrations | Alembic via Flask-Migrate |
| Background processing | Celery ≥ 5.4 |
| Message broker and result-backend URL | Valkey or Redis, via the `redis` Python client (`redis://` URL) |
| Packet analysis | Scapy ≥ 2.8 |
| Data processing | Pandas ≥ 2.2 (time-series bucketing) |
| Validation and domain models | Pydantic ≥ 2.7 |
| PDF generation | ReportLab ≥ 4.2 |
| WSGI server (optional) | Gunicorn ≥ 22 |
| Python dependency management | uv |
| Frontend framework | Vue 3 (^3.5) |
| Build tooling | Vite (^7) |
| Routing | Vue Router (^4.5) |
| State management | Pinia (^3) |
| Styling | Tailwind CSS 3.4.17 (PostCSS, Autoprefixer) |
| Visualisation | Chart.js 4.4.7 |
| HTTP client | Axios (^1.7) |
| Backend testing | pytest (≥ 9.2) |
| Frontend testing | Vitest with Vue Test Utils and jsdom |
| Browser testing | Playwright for Python (optional dev dependency; tests skip when unavailable) |

> The repository refers to the broker as Redis (the setting is named `NETSCOPE_REDIS_URL` and the client is `redis`). Valkey is wire-compatible with the Redis protocol, so a Valkey server is addressed through the same `redis://` URL. The PostgreSQL 18 and Valkey versions used in the instructions below describe the development environment this guide targets; the repository itself does not pin server versions.

---

## Architecture

### System architecture

```mermaid
flowchart LR
    subgraph Client["Browser"]
        SPA["Vue 3 single-page app"]
    end

    subgraph Web["Flask application"]
        WEB["web blueprint: serves frontend/dist"]
        API["JSON API under /api/v1"]
        SVC["services: capture, queries, exports"]
    end

    subgraph Async["Background processing"]
        BROKER[("Valkey broker")]
        WORKER["Celery worker"]
        PIPE["Analysis pipeline using Scapy"]
    end

    DB[("PostgreSQL")]
    FILES[("Capture files on disk")]

    SPA -->|"static assets and index.html"| WEB
    SPA -->|"fetch with session cookie and CSRF header"| API
    API --> SVC
    SVC -->|"SQLAlchemy"| DB
    SVC -->|"save and delete uploads"| FILES
    SVC -->|"enqueue analyze_capture"| BROKER
    BROKER --> WORKER
    WORKER --> PIPE
    PIPE -->|"stream packets"| FILES
    PIPE -->|"batched inserts and results"| DB
```

In production the browser talks to a single origin: Flask serves the built SPA and the API. In development the Vite dev server serves the SPA and proxies `/api` to Flask, so requests remain same-origin and no CORS configuration is needed.

### Capture processing workflow

```mermaid
sequenceDiagram
    actor User
    participant UI as Vue app
    participant API as Flask API
    participant Disk as Upload folder
    participant DB as PostgreSQL
    participant Q as Valkey
    participant W as Celery worker

    User->>UI: choose PCAP or PCAPNG file
    UI->>API: POST /api/v1/captures (multipart, CSRF token)
    API->>Disk: stream to temp file, enforce size limit, hash
    API->>API: validate magic bytes and record framing
    API->>Disk: move to user_id/capture_id.format
    API->>DB: insert capture row (status uploaded)
    API->>DB: claim for queueing (status pending)
    API->>Q: enqueue netscope.analyze_capture(capture_id)
    API-->>UI: 201 with capture record

    Q->>W: deliver task
    W->>DB: claim pending capture (status processing)
    W->>Disk: stream packets with Scapy
    loop every PACKET_BATCH_SIZE packets
        W->>DB: insert packet rows and update packet_count
    end
    W->>DB: insert flows and analysis summary
    W->>DB: insert Phase 4 documents and tables
    W->>DB: status completed

    UI->>API: poll status, then load summary, flows, packets, analytics
    API->>DB: read persisted results
    API-->>UI: JSON
```

The capture status moves through a small state machine:

```mermaid
stateDiagram-v2
    [*] --> uploaded: upload accepted
    uploaded --> pending: analysis queued
    failed --> pending: retry
    pending --> processing: worker claims capture
    processing --> completed: all results stored
    processing --> failed: error, partial results deleted
    pending --> failed: broker unavailable
```

### Analysis architecture

```mermaid
flowchart TD
    R["capture_reader: stream Scapy packets"] --> X["packet_extractor: ExtractedPacket"]
    X --> FT["FlowTracker: flow_id, retransmission flag, RTT, jitter"]
    X --> SA["StatsAccumulator: protocols, throughput, time series"]
    X --> AA["AdvancedAnalyzer"]
    FT -->|"flow_id and retransmission flag"| AA

    subgraph Phase4["Phase 4 trackers inside AdvancedAnalyzer"]
        TC["TcpConnectionTracker: outcomes, timing, resets, windows"]
        DN["DnsTracker: transactions, latency, failures"]
        TI["TrafficIntel: talkers, direction pairs"]
        DG["tcp_diagnostics: loss indicators, window analysis"]
        AN["anomalies: threshold rules"]
    end
    AA --> TC
    AA --> DN
    AA --> TI
    TC --> DG
    TC --> AN
    DN --> AN
    TI --> AN

    X -->|"batched"| P1[("packets")]
    FT --> P2[("flows")]
    SA --> P3[("analysis_results")]
    Phase4 --> P4[("advanced_analyses plus tcp_connections, tcp_indicators, dns_transactions, ip_traffic, ip_pairs, anomaly_findings")]
```

`services/analysis_pipeline.py` drives the loop: for each packet it calls `extract_packet`, then `FlowTracker.observe`, `StatsAccumulator.observe` and `AdvancedAnalyzer.observe`. Packets are inserted in batches while the pass runs. Flows, the summary document and the Phase 4 results are written after the last packet, and only then is the capture marked `completed`.

### Design decisions

- **One pass, bounded memory per packet.** Packets stream from disk and are persisted in batches, so memory does not grow with packet count. State that needs the whole capture (flows, connections, DNS transactions, address pairs) is held until the end of the pass, so memory grows with the number of distinct flows, connections, DNS transactions and addresses.
- **Analyse once, query many times.** Results are persisted, so the interface, exports and comparison are database reads. Indexes on `(capture_id, …)` support the filters and sort orders the API offers.
- **Job state lives in the database.** Celery results are ignored (`task_ignore_result`); the capture row is the source of truth. The conditional `pending → processing` update makes the worker idempotent, and the queueing step uses an atomic conditional update so two concurrent requests cannot enqueue the same capture.
- **Never serve partial results.** A capture becomes `completed` only after everything is stored; on failure, everything stored for it is deleted.
- **Owner scoping is part of the query, not an afterthought.** A single `get_owned_capture` helper backs every capture route, and a miss is always `404`.
- **Passive-capture honesty.** Definitions, denominators and limitations are part of the stored result and are returned by the API, so the interface can show them beside the numbers.
- **Flask serves the built SPA.** Production needs one process type for web traffic and no separate static host. Authentication is enforced by the API on every request; the app shell is public and contains no user data.
- **Pure-logic core.** Extraction, flow tracking, statistics and the Phase 4 analytics are plain Python over data objects, which keeps them unit-testable without a database or a broker.

### Data model

| Table | Contents |
|---|---|
| `users` | Email (unique) and password hash. |
| `captures` | Owner, display filename, format, size, SHA-256, relative storage path, status, timestamps, packet count, error message, Celery task ID. |
| `packets` | One row per packet: link, network and transport fields, TCP sequence and window fields, `flow_id`, retransmission flag, `malformed_reason`, application metadata (JSON). |
| `flows` | One row per bidirectional flow, with per-direction packet and byte counts, timing, retransmissions, RTT and jitter. |
| `analysis_results` | Aggregate columns plus the `summary` JSON document (protocols, performance, TCP, latency). |
| `advanced_analyses` | The Phase 4 summary document: results, definitions, limitations and thresholds used. |
| `tcp_connections` | One row per tracked TCP connection: state, timings, termination, resets, window and truncation details. |
| `tcp_indicators` | Loss indicators per connection and direction, with severity and evidence. |
| `dns_transactions` | One row per DNS transaction: client, server, question, status, RCODE, latencies, retries. |
| `ip_traffic`, `ip_pairs` | Per-address and per-address-pair totals that back top talkers and direction classification. |
| `anomaly_findings` | One row per rule finding, with evidence, affected addresses and flows, packet references and thresholds. |

Tables hanging off a capture reference `captures.id` with `ON DELETE CASCADE`. The schema is managed by three Alembic migrations in `backend/migrations/versions/`: users and captures; packets, flows and analysis results; and Phase 4 network intelligence.

---

## Repository Structure

```text
netscope/
├── pyproject.toml            # Python project, dependencies, pytest configuration
├── .python-version           # Python 3.12.16
├── .env.example              # Template of supported environment variables
├── uv.lock                   # Locked Python dependency versions (uv)
├── Dockerfile                # Multi-stage image build (frontend, Python dependencies, runtime)
├── compose.yaml              # Docker Compose stack: db, redis, migrate, web, worker
├── .dockerignore             # Keeps secrets, captures and local files out of the build context
├── LICENSE                   # Apache License 2.0
├── backend/
│   ├── wsgi.py               # Entry point for Flask (app) and Celery (celery_app)
│   ├── app/
│   │   ├── __init__.py       # create_app() application factory
│   │   ├── config.py         # Environment-driven configuration classes
│   │   ├── extensions.py     # db, migrate, login_manager, csrf
│   │   ├── celery_app.py     # Celery bound to the Flask app context
│   │   ├── api/              # Blueprints under /api/v1 (auth, captures, analysis, advanced, dashboard, reports, health)
│   │   ├── models/           # Pydantic domain models (Capture, Packet)
│   │   ├── schemas/          # Pydantic schemas
│   │   ├── orm/              # SQLAlchemy tables (users, captures, packets, flows, results, Phase 4 tables)
│   │   ├── services/
│   │   │   ├── capture_reader.py        # Format detection, structural validation, streaming Scapy reader
│   │   │   ├── capture_storage.py       # Secure upload storage and path resolution
│   │   │   ├── capture_service.py       # Upload, ownership-scoped queries, queueing, deletion
│   │   │   ├── packet_extractor.py      # Scapy packet to structured record
│   │   │   ├── protocol_detector.py     # Signature and port based application labels
│   │   │   ├── flow_tracker.py          # Bidirectional flows, retransmissions, RTT, jitter
│   │   │   ├── traffic_stats.py         # Protocol, throughput and time-series statistics
│   │   │   ├── analysis_pipeline.py     # Single-pass reader to extractor to trackers to database
│   │   │   ├── analysis_queries.py      # Packet and flow filtering, search, sorting
│   │   │   ├── advanced_persistence.py  # Writes Phase 4 results
│   │   │   ├── advanced_queries.py      # Phase 4 filters and queries
│   │   │   ├── dashboard_service.py     # Dashboard aggregates and capture comparison
│   │   │   ├── export_service.py        # CSV and PDF generation
│   │   │   ├── auth_service.py          # Registration and authentication
│   │   │   └── analytics/               # Phase 4: tcp_connections, tcp_diagnostics, dns_analytics,
│   │   │                                #          traffic_intel, anomalies, engine, common
│   │   ├── web/spa.py        # Serves frontend/dist with history-mode fallback and CSP
│   │   └── workers/tasks.py  # Celery task: netscope.analyze_capture
│   ├── migrations/           # Alembic environment and versions/
│   └── tests/                # pytest unit and API tests (SQLite)
├── frontend/
│   ├── package.json          # Scripts and dependencies
│   ├── vite.config.js        # Dev server, /api proxy, build output, Vitest settings
│   ├── tailwind.config.js
│   ├── .env.example          # Optional Vite settings
│   ├── src/
│   │   ├── main.js           # App bootstrap, 401 handling
│   │   ├── router/           # Routes, auth guards
│   │   ├── api/              # Axios client (CSRF, errors) and per-area API modules
│   │   ├── stores/           # Pinia stores (auth, captures, dashboard, captureDetail, analytics, session)
│   │   ├── composables/      # Polling, paged lists, URL-backed filters, upload, downloads, comparison
│   │   ├── layouts/          # AppLayout, AuthLayout
│   │   ├── views/            # One view per route
│   │   ├── components/       # common, dashboard, captures, packets, flows, analytics, charts
│   │   └── utils/            # Formatting, chart configuration, safe redirects
│   └── tests/                # Vitest unit and component tests
├── tests/
│   └── e2e/                  # Playwright browser tests (skipped without Chromium or a frontend build)
└── docs/
    └── phase4-network-intelligence.md   # Phase 4 metric definitions and limitations
```

---

## Installation and Local Development

These steps target Fedora (or a similar Linux distribution). Run everything from the repository root.

### 1. Prerequisites

| Requirement | Notes |
|---|---|
| Python | ≥ 3.12.16. [uv](https://docs.astral.sh/uv/) can provision the interpreter named in `.python-version`. |
| uv | Python dependency management. |
| Node.js and npm | Node `^20.19.0` or `>=22.12.0` (the range declared in `frontend/package.json`). Check with `node --version`. |
| PostgreSQL | The development environment used here runs PostgreSQL 18. |
| Valkey (or Redis) | Used as the Celery broker. |
| Git | To clone the repository. |

### 2. Clone the repository

```bash
git clone <repository-url> netscope
cd netscope
```

### 3. Install Python dependencies

```bash
uv sync
```

`uv sync` installs the project and the `dev` dependency group (pytest and Playwright) into `.venv`.

### 4. Install frontend dependencies

```bash
npm --prefix frontend ci
```

### 5. Start and configure PostgreSQL and Valkey

Start both services (service names as installed in this development environment; yours may differ):

```bash
sudo systemctl start postgresql-18
sudo systemctl start valkey
```

Create a database role and database. **These credentials are an example for local development only.** Use a strong, unique password anywhere else.

```bash
sudo -u postgres psql <<'SQL'
CREATE ROLE netscope LOGIN PASSWORD 'netscope';
CREATE DATABASE netscope OWNER netscope;
SQL
```

### 6. Configure environment variables

NetScope reads **real environment variables only**. It does not load `.env` files itself. Export the variables in each terminal that runs Flask, Celery or the migration command:

```bash
export NETSCOPE_DATABASE_URL="postgresql+psycopg://netscope:netscope@localhost:5432/netscope"
export NETSCOPE_REDIS_URL="redis://localhost:6379/0"
```

These match the defaults in `backend/app/config.py`, so they may be omitted for a stock local setup. To keep settings in a file instead:

```bash
cp .env.example .env     # .env is git-ignored; never commit it
set -a; source .env; set +a
```

> **Edit the copy first.** `.env.example` contains the line `NETSCOPE_SECRET_KEY=` with no value. Sourcing it unchanged sets the variable to an empty string, which overrides the development default and makes the application refuse to start (`NETSCOPE_SECRET_KEY must be set outside development and testing`). Either delete that line or give it a value.

For anything beyond local development, set `NETSCOPE_ENV=production` and generate a secret key:

```bash
export NETSCOPE_ENV=production
export NETSCOPE_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
```

### 7. Apply database migrations

```bash
uv run python -m flask --app backend/wsgi db upgrade
```

### 8. Build the frontend

```bash
npm --prefix frontend run build
```

This writes `frontend/dist`, which Flask serves.

### 9. Start the Flask server (terminal 1)

```bash
uv run python -m flask --app backend/wsgi run
```

### 10. Start the Celery worker (terminal 2)

Export the same environment variables in this terminal, then:

```bash
uv run python -m celery --workdir backend -A wsgi:celery_app worker --loglevel=info
```

### 11. Open the application

Visit <http://localhost:5000>, register an account, and upload a `.pcap` or `.pcapng` file. Without a running worker, uploaded captures stay `pending`.

### Optional: Vite development workflow

For hot reload, keep Flask and the Celery worker running, then start the Vite dev server in a third terminal:

```bash
npm --prefix frontend run dev
```

Open <http://localhost:5173>. Vite proxies `/api` to `http://127.0.0.1:5000` (override with `VITE_DEV_PROXY_TARGET`). Because the browser only talks to Vite, requests stay same-origin and session cookies and CSRF work as in production. Optional Vite settings go in `frontend/.env.local` (see `frontend/.env.example`). `npm --prefix frontend run preview` serves the production build on port 4173 with the same proxy.

If `frontend/dist` is missing, Flask answers `503` with the build command instead of the app.

---

## Docker Deployment

NetScope ships with a multi-stage `Dockerfile`, a `.dockerignore` and a `compose.yaml` that run the complete stack (database, broker, migrations, web application and worker) on a single machine. This is a **local Docker Compose deployment**; the repository does not describe any other deployment target.

### Why Docker

NetScope needs five cooperating pieces: a PostgreSQL database, a Valkey broker, a one-off migration step, the Flask web process and a Celery worker that must see the same uploaded files as the web process. Running them by hand means installing and starting each service, exporting the same environment variables in several terminals and building the frontend first (see [Installation and Local Development](#installation-and-local-development)). Docker Compose replaces that with one image and one command, and gives a reproducible runtime: the same Python 3.12.16 interpreter, the locked dependency set from `uv.lock`, and a pre-built Vue bundle, running as a non-root user.

### Image build architecture

The `Dockerfile` has three stages, so build tooling (Node.js, `uv`, `npm` caches) never reaches the final image.

```mermaid
flowchart LR
    subgraph S1["Stage 1: frontend-build"]
        N["node:22-bookworm-slim"] --> NB["npm ci, then npm run build"]
    end
    subgraph S2["Stage 2: python-build"]
        P["python:3.12.16-slim-bookworm plus uv"] --> PB["uv sync --frozen --no-dev --no-editable"]
    end
    subgraph S3["Stage 3: runtime"]
        R["python:3.12.16-slim-bookworm"] --> RU["non-root user netscope"]
    end
    NB -->|"frontend/dist"| R
    PB -->|".venv"| R
    BE["backend/ source"] --> R
```

| Stage | Base image | What it does |
|---|---|---|
| `frontend-build` | `node:22-bookworm-slim` | Copies `package.json` and `package-lock.json`, runs `npm ci`, copies the frontend sources and runs `npm run build` to produce `frontend/dist`. |
| `python-build` | `python:3.12.16-slim-bookworm` | Copies `uv` from `ghcr.io/astral-sh/uv:latest`, then runs `uv sync --frozen --no-dev --no-editable` against `pyproject.toml` and `uv.lock` (bytecode compiled, development dependencies excluded). `README.md` is copied too, because `pyproject.toml` declares it as the project readme. |
| `runtime` | `python:3.12.16-slim-bookworm` | Copies the virtual environment, the `backend/` sources and the compiled frontend. Creates the system user and group `netscope` and the writable `/data/uploads` directory, then runs as `netscope`. Exposes port `8000`; the default command is `gunicorn --bind 0.0.0.0:8000 wsgi:app`. |

Settings baked into the runtime image:

| Variable | Value | Effect |
|---|---|---|
| `PATH` | `/app/.venv/bin:$PATH` | Commands such as `flask`, `gunicorn` and `celery` come from the locked environment. |
| `PYTHONPATH` | `/app/backend` | Makes the `app` package and `wsgi` module importable. |
| `NETSCOPE_FRONTEND_DIST` | `/app/frontend/dist` | Flask serves the compiled Vue app from here. |
| `NETSCOPE_UPLOAD_FOLDER` | `/data/uploads` | Capture files are stored on the `uploads` volume. |

`.dockerignore` keeps the build context small and safe: it excludes `.git/`, virtual environments, caches, `node_modules/`, a local `frontend/dist/`, `.env` files (only `.env.example` is kept), the local `instance/` data folder, capture files (`*.pcap`, `*.pcapng`, `*.cap`), editor files and logs.

### Docker Compose service architecture

`compose.yaml` defines five services. `migrate`, `web` and `worker` all run the same `netscope:local` image with different commands and read their configuration from `.env`.

```mermaid
flowchart TD
    DB[("db: PostgreSQL 16")]
    VK[("redis: Valkey 8")]
    MIG["migrate: flask db upgrade"]
    WEB["web: Gunicorn on port 8000"]
    WRK["worker: Celery"]
    PGV[("volume postgres_data")]
    UPV[("volume uploads")]

    DB -->|"healthy"| MIG
    MIG -->|"completed successfully"| WEB
    MIG -->|"completed successfully"| WRK
    VK -->|"healthy"| WEB
    VK -->|"healthy"| WRK
    DB --- PGV
    WEB --- UPV
    WRK --- UPV
    Browser["Browser: http://localhost:8000"] --> WEB
```

| Service | Image | Purpose | Notable settings |
|---|---|---|---|
| `db` | `postgres:16-alpine` | PostgreSQL database. | Creates database, user and password `netscope` on first start; data on the `postgres_data` volume; health check with `pg_isready`; `restart: unless-stopped`. |
| `redis` | `valkey/valkey:8-alpine` | Valkey (Redis-compatible) broker for Celery. | Health check with `valkey-cli ping`; `restart: unless-stopped`. |
| `migrate` | `netscope:local` | Applies database migrations (`flask --app wsgi db upgrade`). | Waits for `db` to be healthy; `restart: "no"`, so it runs once and exits. |
| `web` | `netscope:local` | Flask application served by Gunicorn. | Publishes `8000:8000`; mounts `uploads` at `/data/uploads`; starts only after `migrate` completed successfully and `redis` is healthy. |
| `worker` | `netscope:local` | Celery worker that analyses uploaded captures (`celery -A wsgi:celery_app worker --loglevel=info`). | Mounts the same `uploads` volume as `web`; same start conditions as `web`. |

Design points:

- **Ordered startup.** `migrate` waits for a healthy database, and `web` and `worker` wait for `migrate` to finish with `service_completed_successfully` and for Valkey to be healthy. If a migration fails, neither starts.
- **Shared uploads.** The web process writes uploaded captures and the worker reads them, so both mount the same `uploads` volume.
- **No `build:` section.** The three application services use the image tag `netscope:local`, so the image must be built with `docker build` before `docker compose up`.
- **Only `web` is published.** The database and broker are reachable only from inside the Compose network.

### Prerequisites

- Docker Engine with the Compose plugin (the `docker compose` command).
- A clone of this repository. The build context needs `Dockerfile`, `pyproject.toml`, `uv.lock`, `README.md`, `backend/` and `frontend/`.
- Port `8000` free on the host.
- Network access on first build to pull base images and install packages.

You do not need Python, `uv`, Node.js, PostgreSQL or Valkey installed on the host.

### Configure the environment

`compose.yaml` loads `.env` (`env_file`) into `migrate`, `web` and `worker`. Create it from the template:

```bash
cp .env.example .env
```

Then edit `.env`. Inside the Compose network the services reach each other by **service name**, not `localhost`, and the database credentials must match the ones defined for `db` in `compose.yaml`:

```bash
NETSCOPE_DATABASE_URL=postgresql+psycopg://netscope:netscope@db:5432/netscope
NETSCOPE_REDIS_URL=redis://redis:6379/0
NETSCOPE_SECRET_KEY=<a long random string>
```

Generate a secret key with, for example:

```bash
openssl rand -base64 48
```

| Variable | Docker notes |
|---|---|
| `NETSCOPE_DATABASE_URL` | Host must be `db`. The user, password and database name `netscope` come from the `db` service's `POSTGRES_*` settings in `compose.yaml`. These are example credentials for local use; change them in both places for anything shared. |
| `NETSCOPE_REDIS_URL` | Host must be `redis` (the Valkey service name). |
| `NETSCOPE_SECRET_KEY` | Must be non-empty. The template line is blank, and an empty value stops the application from starting. |
| `NETSCOPE_ENV` | Defaults to `development`. With `production`, a secret key is mandatory and the session cookie is marked `Secure`, so sign-in is intended to work over HTTPS; some browsers will not send a `Secure` cookie over plain `http://localhost:8000`. |
| `NETSCOPE_UPLOAD_FOLDER`, `NETSCOPE_FRONTEND_DIST` | Already set by the image to `/data/uploads` and `/app/frontend/dist`. |

All other variables are described in the [Configuration Reference](#configuration-reference).

> **Warning: protect your secrets.** `.env` holds `NETSCOPE_SECRET_KEY` and database credentials. Never commit it (it is git-ignored) and never paste its contents into issues, logs or screenshots. Anyone who knows the secret key can forge session cookies. Only `.env.example` belongs in version control, and it must never contain a real key. `.dockerignore` keeps `.env` files out of the image build context.

### Build the image

From the repository root:

```bash
docker build -t netscope:local .
```

### Start the application

```bash
docker compose up -d
```

Compose starts `db` and `redis`, runs `migrate` to completion, then starts `web` and `worker`.

### Inspect the services

```bash
docker compose ps -a
```

Use `-a` so the finished `migrate` container is listed. Healthy output shows `db` and `redis` as healthy, `web` and `worker` as running, and `migrate` as exited with code 0; that exit is expected and means the migrations were applied.

```bash
docker compose logs -f              # follow all services (Ctrl+C stops following)
docker compose logs migrate         # migration output
docker compose logs -f web worker   # application and worker output
```

### Access the application

| What | URL |
|---|---|
| Web interface | <http://localhost:8000> |
| Health endpoint | `GET http://localhost:8000/api/v1/health` |

```bash
curl -i http://localhost:8000/api/v1/health
```

A healthy application answers `200 OK` with `{"status": "healthy"}`. Open the web interface, register an account and upload a capture as described in [Capabilities](#capabilities).

During the verification of this setup the health endpoint returned HTTP 200 with that body, the migrations completed successfully, and the Celery worker connected to Valkey and registered the `netscope.analyze_capture` task.

### Stop the services

```bash
docker compose down
```

This removes the containers and network but keeps the named volumes, so your data survives the next `docker compose up -d`.

After changing application code, rebuild the image and recreate the containers:

```bash
docker build -t netscope:local .
docker compose up -d
```

### Persistent data

| Volume | Mounted by | Contents |
|---|---|---|
| `postgres_data` | `db` at `/var/lib/postgresql/data` | The PostgreSQL database: users, captures, packets, flows and analysis results. |
| `uploads` | `web` and `worker` at `/data/uploads` | Uploaded capture files, stored as `<user_id>/<capture_id>.<format>`. |

> **Warning: `docker compose down -v` permanently deletes both volumes**, removing every account, every analysis result and every uploaded capture. Use plain `docker compose down` unless you want a clean slate.

Back up both volumes before deleting them if the data matters. Because the database and the files are stored separately, restore them together.

### Troubleshooting

| Symptom | What to check |
|---|---|
| `docker compose up` cannot find `netscope:local`, or tries to pull it | The image has not been built. Run `docker build -t netscope:local .` first. |
| `env file .env not found` | Create it with `cp .env.example .env` and edit it. |
| `db` or `redis` is `unhealthy`, or `web`/`worker` stay in `Created` | Run `docker compose ps -a` and `docker compose logs db redis`. `web` and `worker` do not start until `redis` is healthy and `migrate` has exited with code 0. Port conflicts on `8000` are reported when `web` starts. |
| `migrate` exits with a non-zero code | Read `docker compose logs migrate`. Typical causes: `NETSCOPE_DATABASE_URL` still points at `localhost` instead of `db`, the user, password or database name does not match the `db` service, or the `postgres_data` volume was initialised earlier with different credentials (the `POSTGRES_*` values apply only when the volume is first created). Fix `.env`, then run `docker compose up -d` again. |
| `web`, `worker` or `migrate` exits immediately with a secret-key or configuration error | `NETSCOPE_SECRET_KEY` is empty, or `NETSCOPE_ENV` is not one of `development`, `testing`, `production`. A malformed `NETSCOPE_ANOMALY_THRESHOLDS`, or a non-integer value in a numeric variable, also stops startup; see `docker compose logs web`. |
| Worker starts but captures stay `pending` | Check `docker compose logs -f worker` for a connection error to the broker. `NETSCOPE_REDIS_URL` must use host `redis`. The worker log should list the `netscope.analyze_capture` task. |
| Uploads fail or the worker cannot find a capture | `web` and `worker` must both mount the same `uploads` volume; do not override one of them. |

After fixing the cause, `docker compose up -d` recreates only what changed. If a service keeps restarting, `docker compose logs --tail=100 <service>` shows its most recent output.

---

## Configuration Reference

| Variable | Purpose | Required | Default | Example |
|---|---|---|---|---|
| `NETSCOPE_ENV` | `development`, `testing` or `production`. | No | `development` | `production` |
| `NETSCOPE_SECRET_KEY` | Flask secret for sessions and CSRF. | **Yes in production**; optional in development | development uses an insecure built-in key; production has none | a long random string |
| `NETSCOPE_DATABASE_URL` | SQLAlchemy database URL. | No | `postgresql+psycopg://netscope:netscope@localhost:5432/netscope` | `postgresql+psycopg://user:***@db-host:5432/netscope` |
| `NETSCOPE_REDIS_URL` | Celery broker and result-backend URL (Valkey or Redis). | No | `redis://localhost:6379/0` | `redis://localhost:6379/0` |
| `NETSCOPE_UPLOAD_FOLDER` | Where capture files are stored. | No | `backend/instance/uploads` | `/var/lib/netscope/uploads` |
| `NETSCOPE_MAX_UPLOAD_BYTES` | Maximum upload size; also sets Flask's `MAX_CONTENT_LENGTH`. | No | `209715200` (200 MiB) | `104857600` |
| `NETSCOPE_MAX_PACKETS` | Maximum packets per capture; larger captures fail analysis. | No | `2000000` | `500000` |
| `NETSCOPE_PACKET_BATCH_SIZE` | Packets written to the database per batch (also the progress-update interval). | No | `5000` | `5000` |
| `NETSCOPE_FRONTEND_DIST` | Directory of the built Vue app that Flask serves. | No | `frontend/dist` | `/srv/netscope/dist` |
| `NETSCOPE_ANOMALY_THRESHOLDS` | JSON object overriding anomaly-rule thresholds; applied when a capture is analysed and validated at startup. | No | unset (built-in thresholds) | `{"port_scan_distinct_ports": 30}` |
| `NETSCOPE_DNS_TIMEOUT_SECONDS` | Seconds a DNS query must stay unanswered, with the capture still running, to count as an inferred timeout. Must be positive. | No | `5` | `5` |

Integer variables must parse as integers and an invalid value stops the application at startup. Production sets `SESSION_COOKIE_SECURE`, so serve it over HTTPS.

**Test and frontend variables**

| Variable | Used by | Purpose |
|---|---|---|
| `NETSCOPE_CHROMIUM_PATH` | `tests/e2e` | Use an existing Chromium or Chrome executable instead of Playwright's. |
| `NETSCOPE_SHOTS` | `tests/e2e` | Directory for browser-test screenshots (default `/tmp/netscope-shots`). |
| `VITE_DEV_PROXY_TARGET` | Vite dev and preview servers | Where `/api` is proxied (default `http://127.0.0.1:5000`). |
| `VITE_API_BASE_URL` | Frontend build | API base URL (default `/api/v1`). A cross-origin value would need CORS on Flask, which the backend deliberately does not enable. |

**Anomaly threshold names** (defaults in parentheses; every value must be a positive number, and unknown names are rejected):
`non_standard_port_min_packets` (1), `non_dns_on_dns_port_min_packets` (5), `udp_on_tcp_port_min_packets` (3), `high_volume_host_bytes` (100000000), `burst_peak_to_median_ratio` (10.0), `burst_min_peak_pps` (500.0), `burst_min_intervals` (10), `connection_rate_window_seconds` (10.0), `connection_rate_threshold` (100), `repeated_attempt_threshold` (5), `repeated_attempt_min_unsuccessful_ratio` (0.8), `port_scan_distinct_ports` (20), `horizontal_scan_distinct_hosts` (20), `dns_nxdomain_min_count` (20), `dns_nxdomain_min_ratio` (0.5), `dns_long_name_length` (60), `dns_long_label_length` (40), `dns_long_name_min_queries` (5), `dns_subdomain_unique_threshold` (50), `reset_rate_threshold` (0.10), `reset_min_packets` (20), `reset_host_threshold` (50), `concentration_share` (0.90), `concentration_min_hosts` (5), `concentration_min_bytes` (100000), `icmp_share` (0.30), `icmp_min_packets` (100).

---

## API Reference

All routes are under `/api/v1`. Unless noted, routes require a signed-in session (`401` otherwise) and are scoped to the caller's own captures (`404` for anyone else's).

**Conventions**

- **CSRF.** `POST` and `DELETE` requests need the `X-CSRFToken` header; fetch the token from `GET /auth/csrf`. The token is bound to the session, so fetch a fresh one after login, registration or logout.
- **Errors** use one envelope: `{"error": {"code", "name", "message", ...}}`. Registration validation failures add an `errors` object keyed by field. Invalid filter values return `400` with the reason.
- **Lists** return `{"items", "page", "per_page", "total"}`.
- **Completed only.** Analysis, analytics, export and comparison routes return `409` until the capture is `completed`.

### Health and authentication

| Method | Route | Description |
|---|---|---|
| `GET` | `/health` | Liveness check (no authentication). |
| `GET` | `/auth/csrf` | CSRF token for session-authenticated clients. |
| `POST` | `/auth/register` | JSON `{email, password}`; creates the user and starts a session (`201`; `400` validation, `409` duplicate email). |
| `POST` | `/auth/login` | JSON `{email, password}`; starts a session (`401` on failure). |
| `POST` | `/auth/logout` | Ends the session. |
| `GET` | `/auth/me` | The current user. |

### Captures

| Method | Route | Description |
|---|---|---|
| `POST` | `/captures` | Multipart `file` (and optional `analyze=false`); validates, stores and queues analysis (`201`; `400` rejected file; `413` too large). |
| `GET` | `/captures` | Paginated list; `page`, `per_page` (max 100), `status`. |
| `GET` | `/captures/<id>` | Capture record. |
| `GET` | `/captures/<id>/status` | Status, `packet_count` (live while processing), timestamps, `error_message`. |
| `POST` | `/captures/<id>/analyze` | Queue analysis (`202`); `409` unless `uploaded` or `failed`; `503` if the broker is unavailable. |
| `DELETE` | `/captures/<id>` | Delete the file and all stored results (`204`). |

### Summary and analytics

| Method | Route | Description |
|---|---|---|
| `GET` | `/captures/<id>/summary` | Capture info, totals (packets, bytes, unique IPs, flows, malformed) and protocols. |
| `GET` | `/captures/<id>/protocols` | Packet and byte counts per transport and application protocol. |
| `GET` | `/captures/<id>/performance` | Throughput, packets per second, packet sizes, time series, TCP retransmissions, handshake RTT and jitter. Optional `link_mbps` (positive number) adds utilisation. |

### Packets

| Method | Route | Description |
|---|---|---|
| `GET` | `/captures/<id>/packets` | Paginated packets (default 50 per page, max 200). Filters: `protocol`, `src_ip`, `dst_ip`, `ip`, `src_port`, `dst_port`, `port`, `flow_id`, `min_length`, `max_length`, `tcp_flags` (letters `FSRPAUEC`), `malformed`, `retransmission`, `q` (search); `sort` (`number`, `time`, `length`), `order`. |
| `GET` | `/captures/<id>/packets/<packet_number>` | One packet with every extracted field. |

### Flows

| Method | Route | Description |
|---|---|---|
| `GET` | `/captures/<id>/flows` | Paginated flows (default 25 per page). Filters: `protocol`, `application`, `ip`, `port`; `sort` (`bytes`, `packets`, `duration`, `start`), `order`. The default (bytes, descending) is the top-flows view. |
| `GET` | `/captures/<id>/flows/<flow_id>` | One flow. |

### Advanced network intelligence

These routes return `409` with `"reason": "analytics_unavailable"` for captures analysed before Phase 4. Summary responses include the relevant `definitions` (and, for TCP, `limitations`).

| Method | Route | Description |
|---|---|---|
| `GET` | `/captures/<id>/analytics` | The complete Phase 4 document (summaries, definitions, limitations, thresholds). |
| `GET` | `/captures/<id>/tcp/summary` | Connection outcomes, success rate, handshake and lifetime distributions. |
| `GET` | `/captures/<id>/tcp/connections` | Paginated connections. Filters: `state`, `termination`, `ip`, `port`, `flow_id`, `truncated`, `has_reset`, `zero_window`, `retransmissions`; `sort` (`start`, `duration`, `handshake`, `packets`, `bytes`, `resets`, `zero_window`), `order`. |
| `GET` | `/captures/<id>/tcp/connections/<connection_id>` | One connection with its loss indicators. |
| `GET` | `/captures/<id>/tcp/resets` | Reset packet and connection rates, with evidence. |
| `GET` | `/captures/<id>/tcp/indicators` | Paginated loss indicators. Filters: `type`, `severity`, `connection_id`, `flow_id`; `sort` (`severity`, `count`, `connection`), `order`. Includes a diagnostics summary. |
| `GET` | `/captures/<id>/tcp/windows` | Window analysis and up to 50 connections with zero-window events. |
| `GET` | `/captures/<id>/dns/summary` | Latency distribution, failure rates, response codes, server statistics, unanswered counts. |
| `GET` | `/captures/<id>/dns/transactions` | Paginated transactions. Filters: `status` (`answered`, `unanswered`, `unanswered_inferred_timeout`, `unanswered_indeterminate`, `unmatched_response`), `rcode`, `transport` (`udp`, `tcp`), `client_ip`, `server_ip`, `q`, `min_latency_ms`; `sort` (`time`, `latency`, `name`, `retries`), `order`. |
| `GET` | `/captures/<id>/dns/transactions/<transaction_id>` | One transaction. |
| `GET` | `/captures/<id>/traffic/talkers` | Top talkers. Parameters: `by` (`bytes`, `packets`), `role` (`source`, `destination`, `bidirectional`), `limit` (1 to 100, default 10), `ip_version` (`4`, `6`). |
| `GET` | `/captures/<id>/traffic/direction` | Inbound, outbound, internal and unknown totals. Parameter: `local` (comma-separated addresses or CIDR networks). |
| `GET` | `/captures/<id>/anomalies` | Paginated findings. Filters: `severity`, `rule`, `ip`, `order`. Includes summary, thresholds and definitions. |
| `GET` | `/captures/<id>/anomalies/<finding_id>` | One finding. |

### Dashboard and comparison

| Method | Route | Description |
|---|---|---|
| `GET` | `/dashboard` | Totals across the caller's captures, status counts, recent sessions, recent traffic, aggregated protocol distribution. |
| `GET` | `/compare?a=<id>&b=<id>` | Metric deltas, protocol comparison and IP overlap for two different completed captures (`400` for invalid or identical IDs). |

### Reports and exports

| Method | Route | Description |
|---|---|---|
| `GET` | `/captures/<id>/report.pdf` | PDF report (extended with Phase 4 sections when available). Optional `local` for direction classification. |
| `GET` | `/captures/<id>/export/<kind>.csv` | CSV export. Base kinds: `packets`, `flows`, `protocols`, `performance`, `timeseries`. Advanced kinds (`409 analytics_unavailable` for pre-Phase-4 captures): `tcp-connections`, `tcp-windows`, `tcp-indicators`, `tcp-summary`, `dns-transactions`, `dns-summary`, `top-talkers`, `traffic-direction`, `anomalies`, `analytics-summary`. List-style exports accept the same filters as their list endpoints. An unknown kind returns `404`. |

### Frontend routes

Any non-`/api` path that is not a real file returns `index.html` so client-side routes survive a reload. Unclaimed `/api/...` paths return a JSON `404`.

---

## Testing and Validation

```bash
# Backend: unit and API tests (browser tests are skipped when unavailable)
uv run pytest

# Backend tests only
uv run pytest backend/tests

# Frontend unit and component tests (Vitest)
npm --prefix frontend test
```

The backend suite builds the application with `TestingConfig`: an **SQLite** database, Celery in eager mode (tasks run inline), and CSRF checks disabled. It therefore needs **neither PostgreSQL nor Valkey**. A migration test applies all migrations to a fresh database and fails if the result differs from the ORM models. Consequently, the repository's automated tests do not exercise a live PostgreSQL deployment or a live broker; verify those against your own environment.

**Browser tests** (Playwright, in `tests/e2e`) start a live Flask server with CSRF enforcement on, serving the production build, and drive Chromium through the interface. They are skipped when Playwright, a Chromium build, or `frontend/dist` is missing:

```bash
npm --prefix frontend run build
uv run playwright install chromium     # once; or set NETSCOPE_CHROMIUM_PATH
uv run pytest tests/e2e
```

---

## Operational Notes

- **Two process types.** The web process (Flask) and one or more Celery workers must share the database, the broker and, because the worker reads uploaded files from disk, the upload folder. If web and worker run on different machines, `NETSCOPE_UPLOAD_FOLDER` must point at storage both can reach.
- **Production-style serving.** `gunicorn` is a declared dependency (for example `uv run python -m gunicorn --chdir backend wsgi:app`), and the repository includes a local Docker Compose setup (see [Docker Deployment](#docker-deployment)). NetScope is not described here as hosted anywhere. Run it behind HTTPS with `NETSCOPE_ENV=production` and a real `NETSCOPE_SECRET_KEY`.
- **Resource use.** Analysis speed is bounded by Scapy's dissection. Memory grows with the number of distinct flows, connections, DNS transactions and addresses, not with packet count. Size `NETSCOPE_MAX_UPLOAD_BYTES` and `NETSCOPE_MAX_PACKETS` for your hardware, and give workers enough time for your largest expected capture.
- **Uploads and secrets.** Capture files are stored under the upload folder and are git-ignored (`*.pcap`, `*.pcapng`, `instance/`). `.env` files are git-ignored; never commit credentials. Treat uploaded captures as sensitive data.
- **Progress.** While a capture is `processing`, `packet_count` advances after every stored batch, so progress is a packet count, not a percentage (the total is unknown until the file has been read).

---

## Limitations and Interpretation Notes

**What the data can and cannot show**

- **Analysis is limited to the supplied capture.** Only traffic and payload visible in the uploaded file are analysed. Metrics are as good as the capture point and duration.
- **Packet-loss indicators are not loss measurements.** Retransmissions, duplicate ACKs and sequence gaps cannot independently establish whether a packet was lost in the network, lost by the capture tool, or merely reordered. NetScope reports no loss percentage.
- **Incomplete connections are not confirmed failures.** Only refused connections (SYN answered by RST-ACK) are reported as confirmed failures.
- **DNS timeouts are inferred.** An unanswered query becomes an inferred timeout only when the capture ran at least the configured timeout past its last transmission; the response may also have bypassed the capture point.
- **Direction depends on configuration.** Inbound, outbound and internal classification is meaningful only for the local networks you supply; with none, all traffic is `unknown`.
- **Anomaly findings are heuristics.** The rules are explainable thresholds, not a replacement for a dedicated intrusion detection system, and a finding is not evidence of malicious activity.
- **Retransmission counts are a lower bound** (exact repeats within a 1024-segment window per direction). RTT needs a captured handshake; jitter needs at least three packets in the flow; effective TCP window sizes need both SYN and SYN-ACK with window scaling.

**Implementation limits**

- **Captures analysed before Phase 4 have no advanced analytics.** Phase 4 endpoints return `409` with `reason: "analytics_unavailable"` for them. Analysis can only be queued from `uploaded` or `failed`, so a completed capture cannot be re-analysed in place; delete it and upload it again to obtain Phase 4 results.
- **Anomaly thresholds are applied at analysis time.** Changing `NETSCOPE_ANOMALY_THRESHOLDS` affects captures analysed afterwards.
- **DNS over TCP** is extracted only when a whole DNS message sits in a single TCP segment; messages spanning several segments are not reassembled.
- **VLAN decoding** records the 802.1Q tag Scapy exposes as the VLAN ID; stacked tags are not modelled separately.
- **Application-protocol identification** covers DNS, HTTP and the signatures and ports the detector knows; other protocols appear under their transport.
- **Interface coverage.** Anomaly findings, aggregate loss-indicator lists and window summaries are available through the API, CSV and PDF, but have no dedicated page in the Vue application.
- **Dashboard** protocol distribution uses the user's 100 most recent analysed captures.
- **Not implemented:** live capture, login rate limiting, email verification, password reset.
- **Not covered by automated tests:** a live PostgreSQL and a live broker (see [Testing and Validation](#testing-and-validation)).

---

## Contributing

There is no separate contributing policy in the repository; the following reflects how the code is organised.

1. Create a branch and keep changes focused.
2. Run `uv run pytest` and `npm --prefix frontend test` before submitting. Add tests alongside the code you change (`backend/tests/` and `frontend/tests/`).
3. A schema change needs a new Alembic migration in `backend/migrations/versions/`; the migration test fails if migrations and ORM models disagree.
4. Keep analytics definitions honest: when you add or change a metric, state its denominator and limitations next to it (see `services/analytics/engine.py`), and do not present a capture-derived indicator as proof.
5. Never commit secrets, `.env` files or capture files.

---

## License

NetScope is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE).
