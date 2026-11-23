# --------------------------------------------------
# Stage 1: Build the Vue frontend
# --------------------------------------------------
FROM node:22-bookworm-slim AS frontend-build

WORKDIR /app/frontend

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build


# --------------------------------------------------
# Stage 2: Install Python dependencies
# --------------------------------------------------
FROM python:3.12.16-slim-bookworm AS python-build

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

COPY pyproject.toml uv.lock README.md ./
COPY backend/ ./backend/

RUN uv sync --frozen --no-dev --no-editable


# --------------------------------------------------
# Stage 3: Final runtime image
# --------------------------------------------------
FROM python:3.12.16-slim-bookworm AS runtime

WORKDIR /app

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app/backend" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NETSCOPE_FRONTEND_DIST="/app/frontend/dist" \
    NETSCOPE_UPLOAD_FOLDER="/data/uploads"

# Copy installed Python environment and application
COPY --from=python-build /app/.venv /app/.venv
COPY backend/ /app/backend/

# Copy the compiled Vue frontend
COPY --from=frontend-build /app/frontend/dist /app/frontend/dist

# Create a non-root runtime user and writable upload directory
RUN groupadd --system netscope \
    && useradd --system --gid netscope --home-dir /app netscope \
    && mkdir -p /data/uploads \
    && chown -R netscope:netscope /app /data

USER netscope

EXPOSE 8000

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "wsgi:app"]
