# NetScope

NetScope is a multi-user network traffic analysis platform. Users register, upload
PCAP/PCAPNG captures, and a background worker analyses them. The backend is Flask +
SQLAlchemy (PostgreSQL) with Celery/Redis for background jobs and Scapy for packet
parsing.

## Status

**Phase 1 (core application and backend) is implemented.** Packet extraction, flows,
protocol and performance analytics, the dashboard and reports arrive in Phases 2 and 3.

| Area | State |
| --- | --- |
| Flask app factory, env-based config, JSON error envelope | Done |
| PostgreSQL / SQLAlchemy models and Alembic migrations (`users`, `captures`) | Done |
| Registration, login, logout, protected routes, per-user data | Done |
| PCAP/PCAPNG upload with content validation and secure storage | Done |
| Capture list, detail, status and delete (owner-scoped) | Done |
| Celery + Redis job submission and status tracking | Done |
| Worker analysis | **Minimal**: streams the file through the reader and records the packet count. Extraction and analytics are Phase 2 |
| Server-rendered auth and capture pages (Tailwind) | Basic; dashboard, charts and reports are Phase 3 |

## Quick start

Requires Python >= 3.12, [uv](https://docs.astral.sh/uv/), PostgreSQL and Redis.

```bash
cd netscope
uv sync
export NETSCOPE_DATABASE_URL=postgresql+psycopg://netscope:netscope@localhost:5432/netscope
export NETSCOPE_REDIS_URL=redis://localhost:6379/0
uv run flask --app wsgi db upgrade                    # create tables
uv run flask --app wsgi run                           # web app on :5000
uv run celery -A wsgi:celery_app worker --loglevel=info   # in a second terminal
uv run pytest                                         # tests (SQLite, no services needed)
```

### Configuration (environment variables)

| Variable | Default | Purpose |
| --- | --- | --- |
| `NETSCOPE_ENV` | `development` | `development`, `testing` or `production` |
| `NETSCOPE_SECRET_KEY` | dev key in development only | Required in production |
| `NETSCOPE_DATABASE_URL` | local PostgreSQL | SQLAlchemy URL |
| `NETSCOPE_REDIS_URL` | `redis://localhost:6379/0` | Celery broker and backend |
| `NETSCOPE_UPLOAD_FOLDER` | `instance/uploads` | Where capture files are stored |
| `NETSCOPE_MAX_UPLOAD_BYTES` | 200 MB | Upload size limit |
| `NETSCOPE_MAX_PACKETS` | 2,000,000 | Per-capture packet limit for analysis |

Production sets `SESSION_COOKIE_SECURE`, so serve it over HTTPS.

## Architecture

```
app/
  __init__.py        application factory
  config.py          environment-based configuration
  extensions.py      db, migrate, login_manager, csrf
  celery_app.py      Celery bound to the Flask app context
  models/            Pydantic domain models (Capture, Packet), reused as API shapes
  orm/               SQLAlchemy tables: User, CaptureRecord
  services/
    capture_reader.py   validation + streaming Scapy reader
    capture_storage.py  secure file storage
    capture_service.py  upload, ownership-scoped queries, job submission, delete
    auth_service.py     registration and authentication
  api/               JSON API under /api/v1 (health, auth, captures)
  web/, templates/   server-rendered pages calling the same services
  workers/tasks.py   Celery tasks
migrations/          Alembic migrations
```

Uploaded files are stored on disk at `<UPLOAD_FOLDER>/<user_id>/<capture_id>.<format>`,
never in the database; the database holds metadata and the relative path. The client's
filename is used only for display.

### Security notes

- Passwords are hashed with Werkzeug (scrypt); login responses do not reveal whether an email exists.
- Sessions use HttpOnly, SameSite=Lax cookies. All state-changing requests need a CSRF token:
  forms include it; JSON clients fetch it from `GET /api/v1/auth/csrf` and send `X-CSRFToken`.
- Every capture query is filtered by owner. Another user's capture returns 404.
- Uploads are validated by content (not extension), streamed to disk with a size limit,
  and error messages never include server paths.
- Not yet implemented: login rate limiting, email verification, password reset.

### Job lifecycle

`uploaded` -> `pending` (queued) -> `processing` -> `completed` | `failed`.
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

Errors use `{"error": {"code", "name", "message"}}`.

## Capture reader

`app/services/capture_reader.py` detects PCAP/PCAPNG by signature, validates structure
without loading packet bodies (truncation, bad lengths, corrupt blocks), and streams Scapy
packets one at a time through `iter_capture_packets`. Converting those into the `Packet`
model is Phase 2.
