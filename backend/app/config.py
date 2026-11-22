"""Environment-based application configuration."""

import os
import tempfile
from pathlib import Path


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer, got {raw!r}") from exc


class Config:
    ENV_NAME = "base"
    DEBUG = False
    TESTING = False

    SECRET_KEY = os.environ.get("NETSCOPE_SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "NETSCOPE_DATABASE_URL",
        "postgresql+psycopg://netscope:netscope@localhost:5432/netscope",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Uploaded captures live outside any publicly served directory.
    UPLOAD_FOLDER = os.environ.get(
        "NETSCOPE_UPLOAD_FOLDER",
        str(Path(__file__).resolve().parent.parent / "instance" / "uploads"),
    )
    MAX_UPLOAD_BYTES = _int_env("NETSCOPE_MAX_UPLOAD_BYTES", 200 * 1024 * 1024)
    MAX_CONTENT_LENGTH = MAX_UPLOAD_BYTES
    MAX_PACKETS_PER_CAPTURE = _int_env("NETSCOPE_MAX_PACKETS", 2_000_000)
    PACKET_BATCH_SIZE = _int_env("NETSCOPE_PACKET_BATCH_SIZE", 5000)

    CELERY_BROKER_URL = os.environ.get(
        "NETSCOPE_REDIS_URL", "redis://localhost:6379/0"
    )
    CELERY_RESULT_BACKEND = os.environ.get(
        "NETSCOPE_REDIS_URL", "redis://localhost:6379/0"
    )

    # The production Vue build (`npm --prefix frontend run build`) that Flask serves.
    FRONTEND_DIST_DIR = os.environ.get(
        "NETSCOPE_FRONTEND_DIST",
        str(Path(__file__).resolve().parents[2] / "frontend" / "dist"),
    )

    ALLOWED_CAPTURE_EXTENSIONS = (".pcap", ".pcapng", ".cap")

    # Celery runs in a worker process; set CELERY_ALWAYS_EAGER to run inline.
    CELERY_ALWAYS_EAGER = False

    # CSRF tokens are tied to the session, so they do not expire on their own.
    WTF_CSRF_TIME_LIMIT = None

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = True


class DevelopmentConfig(Config):
    ENV_NAME = "development"
    DEBUG = True
    SECRET_KEY = os.environ.get("NETSCOPE_SECRET_KEY", "dev-only-insecure-key")
    SESSION_COOKIE_SECURE = False


class TestingConfig(Config):
    ENV_NAME = "testing"
    TESTING = True
    SECRET_KEY = "testing-key"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    CELERY_ALWAYS_EAGER = True
    WTF_CSRF_ENABLED = False
    SESSION_COOKIE_SECURE = False
    UPLOAD_FOLDER = os.path.join(tempfile.gettempdir(), "netscope-test-uploads")


class ProductionConfig(Config):
    ENV_NAME = "production"


CONFIGS = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}


def get_config(name: str | None = None) -> type[Config]:
    name = name or os.environ.get("NETSCOPE_ENV", "development")
    try:
        return CONFIGS[name]
    except KeyError as exc:
        raise RuntimeError(
            f"Unknown NETSCOPE_ENV {name!r}; expected one of {sorted(CONFIGS)}"
        ) from exc
