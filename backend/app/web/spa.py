"""Serve the built Vue application (``frontend/dist``) and its client-side routes.

The interface is a single-page app using history-mode routing, so every GET that is not an API
call, and does not name a real file, receives ``index.html``; Vue Router then decides what to
show. Authentication is enforced by the JSON API, never by these pages: the shell carries no
user data, and each API call is checked against the session (and the owner) on the server.
"""

from pathlib import Path

from flask import Blueprint, Response, abort, current_app, make_response, send_from_directory

bp = Blueprint("web", __name__)

# `script-src 'self'` is the point: nothing a capture contains can introduce executable markup,
# and the app loads no third-party code. Styles allow inline because Vue and Chart.js set
# element styles at runtime.
CONTENT_SECURITY_POLICY = "; ".join(
    [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ]
)

_IMMUTABLE = "public, max-age=31536000, immutable"  # Vite fingerprints everything in /assets
_MISSING_BUILD = (
    "NetScope frontend build not found.\n\n"
    "Build it with:  npm --prefix frontend ci && npm --prefix frontend run build\n"
    "or use the Vite dev server (npm --prefix frontend run dev) while developing.\n"
)


def _dist_dir() -> Path:
    return Path(current_app.config["FRONTEND_DIST_DIR"])


def _index() -> Response:
    dist = _dist_dir()
    if not (dist / "index.html").is_file():
        return Response(_MISSING_BUILD, status=503, mimetype="text/plain")
    response = make_response(send_from_directory(dist, "index.html", max_age=0))
    response.headers["Cache-Control"] = "no-cache"  # always pick up a new build's asset names
    response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
    return response


@bp.get("/", defaults={"path": ""})
@bp.get("/<path:path>")
def spa(path: str):
    # Anything under /api that no API route claimed is a real 404 (JSON envelope), never HTML.
    if path == "api" or path.startswith("api/"):
        abort(404)

    if path:
        dist = _dist_dir()
        candidate = (dist / path).resolve()
        is_file = candidate.is_file() and dist.resolve() in candidate.parents
        if is_file:
            response = make_response(send_from_directory(dist, path))
            if path.startswith("assets/"):
                response.headers["Cache-Control"] = _IMMUTABLE
            return response
        # A missing asset must not turn into HTML; a client-side route has no file extension.
        if path.startswith("assets/") or "." in path.rsplit("/", 1)[-1]:
            abort(404)
    return _index()
