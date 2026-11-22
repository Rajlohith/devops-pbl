"""Serves the production Vue single-page application."""

from flask import Flask


def register_web(app: Flask) -> None:
    from app.web.spa import bp

    app.register_blueprint(bp)
