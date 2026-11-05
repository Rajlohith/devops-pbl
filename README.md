# devops-pbl - NetScope

**Network Traffic Analysis and Intelligence Platform**

NetScope is a Python-based web application designed to analyze network traffic captured in PCAP and PCAPNG files. It aims to provide users with insights into network communication, protocols, traffic patterns, network flows, and performance statistics.

The platform is intended to provide an accessible interface for uploading network captures, exploring packet information, and understanding network activity.

## Project Objectives

- Analyze network traffic from PCAP and PCAPNG files.
- Extract essential packet information.
- Identify and categorize network protocols.
- Analyze communication between network hosts.
- Calculate network traffic and performance statistics.
- Present network analysis results in an organized interface.

## Technology Stack

| Technology | Purpose                      |
| ---------- | ---------------------------- |
| Python     | Backend programming language |
| FastAPI    | Backend API framework        |
| Uvicorn    | ASGI application server      |

## Project Structure

```text
netscope/
├── app/
│   ├── api/
│   │   ├── routes/
│   │   │   └── health.py
│   │   └── __init__.py
│   ├── core/
│   ├── models/
│   ├── schemas/
│   ├── services/
│   ├── workers/
│   ├── __init__.py
│   └── main.py
│
├── tests/
├── uploads/
├── pyproject.toml
├── uv.lock
└── README.md
```

### Directory Overview

- **app/** – Contains the main backend application.
- **api/** – Contains API routes and endpoint definitions.
- **core/** – Reserved for core application configuration.
- **models/** – Reserved for application data models.
- **schemas/** – Reserved for request and response schemas.
- **services/** – Reserved for application business logic.
- **workers/** – Reserved for background processing components.
- **tests/** – Contains application tests.
- **uploads/** – Local directory for uploaded files during development.

## Current Implementation

The initial backend foundation has been established using FastAPI.

Currently implemented endpoints:

| Method | Endpoint  | Description                              |
| ------ | --------- | ---------------------------------------- |
| GET    | `/`       | Returns a welcome message.               |
| GET    | `/health` | Returns the application's health status. |

### API Responses

**Root endpoint (`/`)**

```json
{
  "message": "Welcome to NetScope"
}
```

**Health endpoint (`/health`)**

```json
{
  "status": "healthy"
}
```

## Development Setup

### Prerequisites

- Python 3.12.16 or later
- [uv](https://docs.astral.sh/uv/)

### Installation

Clone the repository:

```bash
git clone https://github.com/Rajlohith/devops-pbl.git
cd netscope
```

Install project dependencies:

```bash
uv sync
```

### Running the Application

Start the development server:

```bash
uv run uvicorn app.main:app --reload
```

The API will be available at:

```text
http://127.0.0.1:8000
```

### API Documentation

FastAPI automatically generates interactive API documentation.

- **Swagger UI:** http://127.0.0.1:8000/docs
- **ReDoc:** http://127.0.0.1:8000/redoc

## Project Status

The project is currently in its initial backend development stage. The FastAPI application has been initialized, and basic API routing and health-check functionality have been implemented.

The current implementation serves as the foundation for developing NetScope's backend.
