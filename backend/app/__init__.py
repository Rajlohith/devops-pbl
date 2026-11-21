"""NetScope application factory."""

from pathlib import Path

from flask import Flask

from app.config import Config, get_config

# Server-rendered templates and static assets live in the repository's frontend/ directory.
FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"


def create_app(config: str | type[Config] | None = None) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(
        __name__,
        instance_relative_config=True,
        template_folder=str(FRONTEND_DIR / "templates"),
        static_folder=str(FRONTEND_DIR / "static"),
    )

    config_class = config if isinstance(config, type) else get_config(config)
    app.config.from_object(config_class)

    if not app.config.get("SECRET_KEY"):
        raise RuntimeError(
            "NETSCOPE_SECRET_KEY must be set outside development and testing"
        )

    app.config["CELERY"] = {
        "broker_url": app.config["CELERY_BROKER_URL"],
        "result_backend": app.config["CELERY_RESULT_BACKEND"],
        # Job state is tracked in the database, not the result backend.
        "task_ignore_result": True,
        "task_always_eager": app.config["CELERY_ALWAYS_EAGER"],
        "broker_connection_retry_on_startup": True,
        "broker_transport_options": {
            "socket_connect_timeout": 2,
            "socket_timeout": 5,
        },
    }

    from app.celery_app import celery_init_app
    from app.extensions import csrf, db, login_manager, migrate

    db.init_app(app)
    _enable_sqlite_foreign_keys()
    migrate.init_app(app, db)
    csrf.init_app(app)
    login_manager.init_app(app)
    celery_init_app(app)

    from app import orm  # noqa: F401  (registers tables with SQLAlchemy metadata)
    from app.workers import tasks  # noqa: F401  (registers Celery tasks)
    from app.api import register_api
    from app.web import register_web

    register_api(app)
    register_web(app)

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        return response

    return app


def _enable_sqlite_foreign_keys() -> None:
    """SQLite ignores foreign keys unless asked; PostgreSQL always enforces them."""
    import sqlite3

    from sqlalchemy import event
    from sqlalchemy.engine import Engine

    @event.listens_for(Engine, "connect")
    def _fk_pragma(dbapi_connection, _record):
        if isinstance(dbapi_connection, sqlite3.Connection):
            dbapi_connection.execute("PRAGMA foreign_keys=ON")
