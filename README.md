# NetScope – Network Traffic Analysis and Intelligence Platform

NetScope is a multi-user platform for understanding and investigating network
traffic captured in PCAP and PCAPNG files. It aims to make traffic analysis
more approachable by combining packet inspection, protocol analysis, flow
analysis, and traffic statistics in one accessible application.

## Project Objectives

- Analyze PCAP and PCAPNG network captures.
- Extract and inspect packet information.
- Identify and categorize network protocols.
- Understand communication between network hosts.
- Analyze network flows and traffic patterns.
- Calculate network performance statistics.
- Present analysis results in an accessible interface.

## Intended Key Features

These are intended platform capabilities; they are not all implemented yet.

- Packet inspection and filtering.
- Protocol analysis.
- Network flow analysis.
- Traffic and performance analytics.
- Capture history and reports.
- Multi-user access.

## Technology Stack

The project is being developed incrementally. The selected technologies are
listed separately from what is currently present in the repository.

### Currently implemented

| Purpose | Technologies |
| --- | --- |
| Backend API | Python, FastAPI |
| Packet capture reading | Scapy |
| Application server | Uvicorn |
| Project and dependency management | uv |
| Testing | Pytest |

### Selected for current or future components

| Purpose | Technologies |
| --- | --- |
| Data processing | Pandas |
| Database | PostgreSQL, SQLAlchemy |
| Background processing | Celery, Redis |
| Frontend | HTML, CSS, JavaScript, Tailwind CSS, Chart.js |
| Deployment and load testing | Docker, Kubernetes, Locust, Ansible |

The selected technologies are not all integrated into the current application.
In particular, persistence, background workers, frontend functionality, and
deployment automation are still future work.

## Prerequisites

- Python 3.12.16 or newer.
- [uv](https://docs.astral.sh/uv/) installed and available on `PATH`.
- A PCAP or PCAPNG file if you want to exercise the standalone capture reader.

## Installation

Clone the repository and move into the Python project directory:

```bash
git clone https://github.com/Rajlohith/devops-pbl.git
cd devops-pbl/netscope
```

Install the runtime and development dependencies with uv:

```bash
uv sync
```

The `netscope` directory is the configured Python project. Run the commands
below from that directory.

## Start the FastAPI Development Server

```bash
uv run uvicorn app.main:app --reload
```

The server listens at:

```text
http://127.0.0.1:8000
```

FastAPI's generated documentation is available at:

- Swagger UI: <http://127.0.0.1:8000/docs>
- ReDoc: <http://127.0.0.1:8000/redoc>

## Current API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | Returns a NetScope welcome message. |
| `GET` | `/health` | Returns the current application health status. |
| `POST` | `/packets/filter` | Filters the route's in-memory sample packets by optional fields. |

The packet-filter request accepts optional string fields:

```json
{
  "protocol": "TCP",
  "source_ip": "192.168.1.10"
}
```

### Packet filtering with curl

With the development server running, this command filters the sample packets
for TCP traffic originating from `192.168.1.10`:

```bash
curl -X POST http://127.0.0.1:8000/packets/filter \
  -H "Content-Type: application/json" \
  -d '{"protocol":"TCP","source_ip":"192.168.1.10"}'
```

The response contains a success message, the submitted filter values, and the
matching sample packet entries. This endpoint currently operates on data
defined in the route; it does not search uploaded or persisted captures.

## Standalone PCAP/PCAPNG Reader

The capture reader is available independently of the FastAPI routes. It
detects PCAP and PCAPNG files from their signatures, validates their structure,
and streams packets through Scapy without loading the complete capture into
memory.

From the `netscope` directory, use it from Python as follows:

```python
from app.services.capture_reader import CaptureReadError, iter_capture_packets

try:
    for packet in iter_capture_packets("path/to/capture.pcapng"):
        print(packet.summary())
except CaptureReadError as exc:
    print(f"Unable to read capture: {exc}")
```

The function accepts a filesystem path and yields Scapy packet objects one at
a time. It does not populate the NetScope Pydantic `Packet` model or perform
packet-field extraction and application-protocol analysis yet.

## Run Tests

Run the complete test suite from the `netscope` directory:

```bash
uv run pytest
```

The tests cover the current API, packet-filtering service, domain models, and
PCAP/PCAPNG reader behavior.

## Project Status and Limitations

Development is ongoing and incremental. The current foundation includes the
FastAPI backend, domain models, an in-memory packet-filtering prototype, and a
Scapy-based PCAP/PCAPNG reader.

The following capabilities are not yet implemented:

- File upload endpoints and capture management.
- Persistent storage and database integration.
- Authentication and authorization.
- Frontend functionality.
- Conversion from Scapy packets into NetScope `Packet` models.
- Complete Ethernet, IP, TCP, UDP, and application-protocol extraction.
- Flow reconstruction and protocol analytics.
- Traffic performance analytics and reporting.

## Detailed Documentation

For implementation-specific architecture, models, reader behavior, API
details, and testing guidance, see the
[NetScope Documentation](netscope/README.md).
