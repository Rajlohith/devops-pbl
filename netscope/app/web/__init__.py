"""Server-rendered pages. They call the same service layer as the JSON API."""

from flask import Flask


def register_web(app: Flask) -> None:
    from app.web.views import bp

    app.register_blueprint(bp)
