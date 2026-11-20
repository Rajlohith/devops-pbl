"""REST API blueprints, all mounted under /api/v1."""

from flask import Flask, jsonify

API_PREFIX = "/api/v1"


def register_api(app: Flask) -> None:
    from app.api.health import bp as health_bp

    app.register_blueprint(health_bp, url_prefix=API_PREFIX)
    _register_error_handlers(app)


def _register_error_handlers(app: Flask) -> None:
    from werkzeug.exceptions import HTTPException

    @app.errorhandler(HTTPException)
    def handle_http_error(error: HTTPException):
        # Consistent JSON error envelope for API paths.
        from flask import request

        if request.path.startswith(API_PREFIX):
            return (
                jsonify(
                    {
                        "error": {
                            "code": error.code,
                            "name": error.name,
                            "message": error.description,
                        }
                    }
                ),
                error.code,
            )
        return error
