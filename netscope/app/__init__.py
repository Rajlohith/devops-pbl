"""NetScope application factory."""

from flask import Flask

from app.config import Config, get_config


def create_app(config: str | type[Config] | None = None) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__, instance_relative_config=True)

    config_class = config if isinstance(config, type) else get_config(config)
    app.config.from_object(config_class)

    if not app.config.get("SECRET_KEY"):
        raise RuntimeError(
            "NETSCOPE_SECRET_KEY must be set outside development and testing"
        )

    from app.api import register_api

    register_api(app)

    return app
