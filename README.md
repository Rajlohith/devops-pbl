# NetScope

NetScope is a multi-user network traffic analysis platform. Users register, upload
PCAP/PCAPNG captures, and a background worker analyses them. The backend is Flask +
SQLAlchemy (PostgreSQL) with Celery/Redis for background jobs and Scapy for packet
parsing.

## Status

**All three phases are implemented:** the core backend (Phase 1), the network analysis
engine (Phase 2), and the dashboard, explorer, comparison and reports (Phase 3).

| Area | State |
| --- | --- |
| Flask app factory, env-based config, JSON error envelope | Done |
| PostgreSQL / SQLAlchemy models and Alembic migrations (`users`, `captures`) | Done |
| Registration, login, logout, protected routes, per-user data | Done |
| PCAP/PCAPNG upload with content validation and secure storage | Done |
| Capture list, detail, status and delete (owner-scoped) | Done |
| Celery + Redis job submission and status tracking | Done |
| Packet extraction (Ethernet, VLAN, IPv4/IPv6, TCP, UDP, ICMP/ICMPv6, ARP, DNS, HTTP) and persistence | Done |
| Packet search, filtering and pagination | Done |
| Protocol statistics, bidirectional flows, top flows | Done |
| Throughput, packets/s, packet size, traffic over time, TCP retransmissions, RTT and jitter estimates | Done |
| Malformed/truncated packet handling; failed jobs discard partial results | Done |
| Dashboard (totals, processing status, recent sessions, traffic and protocol charts) | Done |
| Upload interface with progress, capture history, live processing progress | Done |
| Packet explorer (search, filters, pagination, packet detail) | Done |
| Protocol analytics, flow analyser, performance charts | Done |
| Capture comparison | Done |
| PDF report and CSV exports (packets, flows, protocols, performance, traffic over time) | Done |
| Loading, empty and error states on every data-driven page | Done |

## Quick start

Requires Python >= 3.12, [uv](https://docs.astral.sh/uv/), Node `^20.19` or `>=22.12`, PostgreSQL and Redis.

Run everything from the repository root.

**Production-style (Flask serves the built Vue app on one port):**

```bash
uv sync
npm --prefix frontend ci && npm --prefix frontend run build   # -> frontend/dist
export NETSCOPE_DATABASE_URL=postgresql+psycopg://netscope:netscope@localhost:5432/netscope
export NETSCOPE_REDIS_URL=redis://localhost:6379/0
uv run flask --app backend/wsgi db upgrade                    # create tables
uv run flask --app backend/wsgi run                           # app + API on http://localhost:5000
uv run celery --workdir backend -A wsgi:celery_app worker --loglevel=info   # second terminal
```

For a real deployment run Flask under a WSGI server (for example
`uv run gunicorn --chdir backend wsgi:app`) behind HTTPS, with `NETSCOPE_ENV=production`.

**Development (hot reload):**

```bash
uv run flask --app backend/wsgi run      # terminal 1: Flask API on :5000
uv run celery --workdir backend -A wsgi:celery_app worker --loglevel=info   # terminal 2
npm --prefix frontend ci                 # first time only
npm --prefix frontend run dev            # terminal 3: Vue app on http://localhost:5173
```

**Tests:**

```bash
uv run pytest                            # backend tests (SQLite, no services needed); browser tests skip if unavailable
npm --prefix frontend test               # frontend unit/component tests (Vitest)
npm --prefix frontend run build && uv run pytest tests/e2e   # real-browser tests against the production build
```

The browser tests need Playwright's Chromium (`uv run playwright install chromium`) or an existing
Chromium via `NETSCOPE_CHROMIUM_PATH`, and `frontend/dist` to be built; otherwise they are skipped.

`.env.example` lists the supported environment variables. NetScope reads real environment
variables only; it does not load `.env` files itself.

Then open <http://localhost:5000> (or `:5173` in development), register, and upload a capture.

### Frontend

The interface is a Vue 3 single-page application (Composition API, Vite, Vue Router, Pinia,
Tailwind CSS 3, Chart.js 4, Axios) in `frontend/`. There are no runtime CDN dependencies.

- **Production:** `npm --prefix frontend run build` writes `frontend/dist`. Flask serves it
  (`backend/app/web/spa.py`): real files under `/assets` are cached for a year (they are
  fingerprinted), and every other non-`/api` path returns `index.html` so client-side routes work on
  reload. Set `NETSCOPE_FRONTEND_DIST` to serve a build from elsewhere. If the build is missing,
  Flask answers 503 with the build command. `npm --prefix frontend run preview` serves the build on
  `:4173` with the same `/api` proxy.
- **Development:** the Vite dev server proxies `/api` to Flask (`VITE_DEV_PROXY_TARGET`, default
  `http://127.0.0.1:5000`). The browser only talks to Vite, so requests are same-origin; session
  cookies and CSRF work exactly as in production and Flask needs no CORS settings.
- **Authentication:** the Flask session cookie (HttpOnly, SameSite=Lax) is the only credential.
  The app keeps nothing in `localStorage`/`sessionStorage`; on load it asks `GET /api/v1/auth/me`.
  The Axios client fetches a CSRF token from `GET /api/v1/auth/csrf`, sends it as `X-CSRFToken` on
  state-changing requests, refreshes it once if rejected, and drops it after login/logout. A 401
  anywhere sends the user to the sign-in page and back afterwards.

### Configuration (environment variables)

| Variable | Default | Purpose |
| --- | --- | --- |
| `NETSCOPE_ENV` | `development` | `development`, `testing` or `production` |
| `NETSCOPE_SECRET_KEY` | dev key in development only | Required in production |
| `NETSCOPE_DATABASE_URL` | local PostgreSQL | SQLAlchemy URL |
| `NETSCOPE_REDIS_URL` | `redis://localhost:6379/0` | Celery broker and backend |
| `NETSCOPE_UPLOAD_FOLDER` | `backend/instance/uploads` | Where capture files are stored |
| `NETSCOPE_MAX_UPLOAD_BYTES` | 200 MB | Upload size limit |
| `NETSCOPE_MAX_PACKETS` | 2,000,000 | Per-capture packet limit for analysis |
| `NETSCOPE_PACKET_BATCH_SIZE` | 5000 | Packets written to the database per batch |
| `NETSCOPE_FRONTEND_DIST` | `frontend/dist` | Built Vue app that Flask serves |

Production sets `SESSION_COOKIE_SECURE`, so serve it over HTTPS.

## Architecture

```
backend/
  wsgi.py            WSGI and Celery worker entry point
  app/
    __init__.py        application factory
    config.py          environment-based configuration
    extensions.py      db, migrate, login_manager, csrf
    celery_app.py      Celery bound to the Flask app context
    models/            Pydantic domain models (Capture, Packet), reused as API shapes
    orm/               SQLAlchemy tables: User, CaptureRecord, PacketRecord, FlowRecord, AnalysisResult
    services/
      capture_reader.py   validation + streaming Scapy reader
      packet_extractor.py Scapy packet -> Packet model (pure logic)
      flow_tracker.py     bidirectional flows, retransmissions, RTT, jitter (pure logic)
      traffic_stats.py    protocol/throughput/time-series statistics (pure logic)
      analysis_pipeline.py streaming reader -> extractor -> tracker/stats -> database
      analysis_queries.py packet/flow filtering, search and sorting
      dashboard_service.py cross-capture dashboard aggregates and capture comparison
      export_service.py   streaming CSV and PDF report generation
      capture_storage.py  secure file storage
      capture_service.py  upload, ownership-scoped queries, job submission, delete
      auth_service.py     registration and authentication
    api/               JSON API under /api/v1 (health, auth, captures, analysis, dashboard, reports)
    web/               serves the built Vue app (index.html fallback, caching, CSP)
    workers/tasks.py   Celery tasks
  migrations/        Alembic migrations
  tests/             unit and API tests (pytest)
frontend/
  index.html, vite.config.js, package.json, tailwind.config.js
  src/
    api/             Axios client (CSRF, error handling) and one module per API area
    router/          routes, auth guards, safe post-login redirect
    stores/          Pinia: auth, captures, dashboard, captureDetail
    composables/     polling, async state, URL-backed filters, upload, downloads, comparison
    layouts/         AppLayout (sidebar + top bar), AuthLayout
    views/           Login, Register, Dashboard, Captures, CaptureDetail (+ Overview, Protocols,
                     Flows, Packets, Performance tabs), Compare
    components/      common/, dashboard/, captures/, packets/, flows/, charts/
    utils/           formatting, chart configuration, safe redirects
  tests/             Vitest unit and component tests
tests/e2e/           real-browser end-to-end tests (Playwright) against the production build
```

Uploaded files are stored on disk at `<UPLOAD_FOLDER>/<user_id>/<capture_id>.<format>`,
never in the database; the database holds metadata and the relative path. The client's
filename is used only for display.

## Pages

| Page | Purpose |
| --- | --- |
| `/login`, `/register` | Sign in / create an account; returns you to the page you were trying to reach |
| `/dashboard` | Totals, processing status, recent sessions, traffic and protocol charts. Refreshes itself while jobs run |
| `/captures` | Drag-and-drop upload with progress, capture history, status filter, retry and delete |
| `/captures/<id>` | Processing progress, then tabs (each its own route: `/protocols`, `/flows`, `/packets`, `/performance`); report downloads. Filters and paging live in the URL, so views can be bookmarked and Back works |
| `/compare` | Pick two completed captures; shareable link via `?a=&b=` |

### Security notes

- The Vue app renders all capture-derived text through text interpolation and never uses `v-html`,
  so hostile filenames or packet contents cannot inject markup (covered by unit and browser tests).
  The app shell is served with a Content-Security-Policy (`script-src 'self'`, no inline script, no
  framing). PDF text is XML-escaped.
- The app shell is public and contains no user data; access control is enforced by the API on every
  request (401 when signed out, 404 for another user's capture). Router guards are only a convenience.
- CSV cells that could be read as spreadsheet formulas (`=`, `+`, `-`, `@`, tab, CR) are
  prefixed with an apostrophe. Reports are generated on demand, sent with `Cache-Control:
  no-store`, and never written to disk.

- Passwords are hashed with Werkzeug (scrypt); login responses do not reveal whether an email exists.
- Sessions use HttpOnly, SameSite=Lax cookies. All state-changing requests need a CSRF token:
  the Vue client (and any other JSON client) fetches it from `GET /api/v1/auth/csrf` and send `X-CSRFToken`.
- Every capture query is filtered by owner. Another user's capture returns 404.
- Uploads are validated by content (not extension), streamed to disk with a size limit,
  and error messages never include server paths.
- Not yet implemented: login rate limiting, email verification, password reset.

### Job lifecycle

`uploaded` -> `pending` (queued) -> `processing` -> `completed` | `failed`.
Packets are persisted in batches while a capture is processed; flows and the summary are
written last, and the capture only becomes `completed` after that. If processing fails,
everything stored for that capture is deleted, so partial results are never served.
A capture that fails (including when the broker is down) keeps a user-visible
`error_message` and can be retried. The worker only processes `pending` captures, so
duplicate deliveries are harmless.

## API (`/api/v1`)

| Method and path | Description |
| --- | --- |
| `GET /health` | Liveness |
| `GET /auth/csrf` | CSRF token for JSON clients |
| `POST /auth/register`, `POST /auth/login` | JSON `{email, password}`; starts a session |
| `POST /auth/logout`, `GET /auth/me` | End session; current user |
| `POST /captures` | Multipart `file` (+ optional `analyze=false`); returns 201 |
| `GET /captures` | `page`, `per_page` (max 100), `status` filter |
| `GET /captures/<id>`, `GET /captures/<id>/status` | Details; processing status |
| `POST /captures/<id>/analyze` | Queue analysis (202); 409 if not `uploaded`/`failed`; 503 if the broker is down |
| `DELETE /captures/<id>` | Delete record and file (204) |

Analysis endpoints (owner-only; `409` until the capture is `completed`):

| Method and path | Description |
| --- | --- |
| `GET /captures/<id>/summary` | Capture info, totals (packets, bytes, unique IPs, flows, malformed), protocols |
| `GET /captures/<id>/protocols` | Packet and byte counts per transport and per application protocol |
| `GET /captures/<id>/performance` | Throughput, packets/s, packet sizes, time series, TCP retransmissions, RTT/jitter. Optional `link_mbps` adds utilisation |
| `GET /captures/<id>/packets` | Paginated packets. Filters: `protocol`, `src_ip`, `dst_ip`, `ip`, `src_port`, `dst_port`, `port`, `flow_id`, `min_length`, `max_length`, `tcp_flags`, `malformed`, `retransmission`, `q` (search); `sort` (`number`/`time`/`length`), `order`, `page`, `per_page` (max 200) |
| `GET /captures/<id>/packets/<n>` | One packet with every extracted field |
| `GET /captures/<id>/flows` | Paginated flows (top flows = default sort by bytes). Filters: `protocol`, `application`, `ip`, `port`; `sort` (`bytes`/`packets`/`duration`/`start`) |
| `GET /captures/<id>/flows/<flow_id>` | One flow |

Invalid filter values return `400` with the reason.

Dashboard, comparison and reports (all owner-only):

| Method and path | Description |
| --- | --- |
| `GET /dashboard` | Totals across your captures, status counts, recent sessions, recent traffic, aggregated protocol distribution |
| `GET /compare?a=<id>&b=<id>` | Metric-by-metric deltas, protocol comparison and IP overlap for two completed captures |
| `GET /captures/<id>/export/<kind>.csv` | `kind` = `packets`, `flows`, `protocols`, `performance` or `timeseries`. `packets` and `flows` accept the same filters as their list endpoints |
| `GET /captures/<id>/report.pdf` | PDF report: summary, protocol tables and chart, performance, throughput chart, top flows |

Capture status (`GET /captures/<id>/status`) reports live progress: while a capture is
`processing`, `packet_count` grows after every stored batch.

Errors use `{"error": {"code", "name", "message"}}`.

## How metrics are defined

- **Bytes** are on-the-wire frame sizes (`original_length`), headers included, so they
  stay correct for captures cut short by a snap length.
- **Protocols**: `transport` counts by TCP/UDP/ICMP/ICMPv6 (non-IP traffic such as ARP is
  listed by name), so HTTP and DNS packets still count towards TCP/UDP. `application`
  lists DNS (Scapy-dissected, UDP and TCP) and HTTP (identified from the request or
  status line in a TCP payload). Other application protocols are not identified.
- **Flow**: a bidirectional protocol + address/port pair. Endpoint A is the side that sent
  the first packet. ICMP flows are keyed by address pair. Non-IP packets belong to no flow.
- **Retransmissions**: a TCP segment whose exact (sequence number, length) was already seen
  in the same direction (a window of 1024 segments per direction is remembered). Segments
  that are re-split or coalesced on retransmission are not detected, so the count is a
  lower bound. Pure ACKs are never counted.
- **Handshake RTT**: first SYN to its SYN-ACK as seen at the capture point. Only flows
  whose handshake was captured have one.
- **Jitter**: mean absolute change in consecutive packet inter-arrival gaps within a
  flow (arrival-time jitter; a capture has no send timestamps, so RFC 3550 jitter is not
  possible). Needs at least 3 packets in the flow.
- **Utilisation** needs a link speed, which a capture does not contain, so it is only
  computed when `link_mbps` is supplied.
- **Malformed packets** are stored, not dropped, with a reason: `truncated_ip_header`,
  `truncated_transport_header`, `unparsed_frame` or `extraction_error:<type>`.
  Later IP fragments without a transport header are expected, not malformed.

## Performance notes

Measured on a shared 2-core sandbox with PostgreSQL: a 300,000-packet / 6,000-flow capture
(38 MB) analysed in about 4 minutes with a peak process size of about 230 MB, and a deep
filtered packet page returned in under 0.4 s. Throughput is dominated by Scapy's packet
dissection (roughly 1-2k packets/s on that machine), so a capture at the default
2,000,000-packet limit can take tens of minutes on similar hardware. Run Celery workers
with enough time limits for your largest expected captures. Memory grows with the number
of distinct flows, IPs and seconds spanned, not with the number of packets.

## Testing

```bash
uv run pytest                       # unit + API tests (~250) and e2e; no external services needed
uv run pytest backend/tests         # unit + API tests only
uv run playwright install chromium  # once, to enable the browser tests
uv run pytest tests/e2e             # real-browser end-to-end tests (skipped if unavailable)
```

The end-to-end tests start a live server (CSRF enforcement on) and drive Chromium through
registration, upload, the dashboard, every capture tab, filters, downloads, comparison,
failure and retry, live progress, deletion, user isolation, hostile filenames and session
expiry, and fail on any JavaScript console error. Screenshots are written to
`/tmp/netscope-shots`.

## Known limitations

- Login rate limiting, email verification and password reset are not implemented.
- The dashboard's protocol distribution uses your 100 most recent analysed captures.
- Metrics are estimates within the definitions above (retransmissions are a lower bound; RTT
  and jitter need the handshake / at least 3 packets).
- Analysis speed is bounded by Scapy (see Performance notes). Progress shows packets
  processed, not a percentage, because the total is unknown until the file is read.
- Not verified against a live Redis broker; tests use Celery's eager mode and simulated
  broker failures.

## Capture reader

`backend/app/services/capture_reader.py` detects PCAP/PCAPNG by signature, validates structure
without loading packet bodies (truncation, bad lengths, corrupt blocks), and streams Scapy
packets one at a time through `iter_capture_packets`; `packet_extractor.py` converts each
into the `Packet` model.


## Phase 4 — Advanced network intelligence

TCP connection analytics, DNS analytics, traffic intelligence, loss indicators, window analysis and rule-based anomaly detection are documented in [docs/phase4-network-intelligence.md](docs/phase4-network-intelligence.md).
