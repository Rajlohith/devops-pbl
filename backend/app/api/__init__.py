"""REST API blueprints, all mounted under /api/v1."""

from flask import Flask, jsonify

API_PREFIX = "/api/v1"


def api_error(code: int, message: str, name: str | None = None, **extra):
    """Build a response in the shared JSON error envelope."""
    from werkzeug.exceptions import default_exceptions

    if name is None:
        name = default_exceptions[code]().name if code in default_exceptions else "Error"
    body = {"code": code, "name": name, "message": message, **extra}
    return jsonify({"error": body}), code


def register_api(app: Flask) -> None:
    from app.api.advanced import bp as advanced_bp
    from app.api.analysis import bp as analysis_bp
    from app.api.auth import bp as auth_bp
    from app.api.captures import bp as captures_bp
    from app.api.dashboard import bp as dashboard_bp
    from app.api.health import bp as health_bp
    from app.api.reports import bp as reports_bp
    from app.extensions import login_manager

    app.register_blueprint(health_bp, url_prefix=API_PREFIX)
    app.register_blueprint(auth_bp, url_prefix=f"{API_PREFIX}/auth")
    app.register_blueprint(captures_bp, url_prefix=f"{API_PREFIX}/captures")
    app.register_blueprint(analysis_bp, url_prefix=f"{API_PREFIX}/captures")
    app.register_blueprint(advanced_bp, url_prefix=f"{API_PREFIX}/captures")
    app.register_blueprint(dashboard_bp, url_prefix=API_PREFIX)
    app.register_blueprint(reports_bp, url_prefix=f"{API_PREFIX}/captures")
    _register_error_handlers(app)

    from urllib.parse import urlencode

    from flask import redirect, request

    @login_manager.unauthorized_handler
    def unauthorized():
        if request.path.startswith(API_PREFIX):
            return api_error(401, "Authentication required.")
        # Anything else that needs a login is a page of the single-page app.
        return redirect("/login?" + urlencode({"next": request.path}))

    from app.services.auth_service import load_user

    login_manager.user_loader(load_user)


def _register_error_handlers(app: Flask) -> None:
    from werkzeug.exceptions import HTTPException

    @app.errorhandler(HTTPException)
    def handle_http_error(error: HTTPException):
        # Consistent JSON error envelope for API paths.
        from flask import request

        if request.path.startswith(API_PREFIX):
            return api_error(error.code, error.description, name=error.name)
        return error
