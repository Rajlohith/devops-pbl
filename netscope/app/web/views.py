from urllib.parse import urlparse
from uuid import UUID

from flask import Blueprint, abort, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user

from app.services import auth_service, capture_service
from app.services.auth_service import DuplicateUserError, ValidationError

bp = Blueprint("web", __name__)


def _safe_next(target: str | None) -> str | None:
    """Only allow same-site relative redirects after login."""
    if not target or not target.startswith("/") or target.startswith("//") or "\\" in target:
        return None
    parsed = urlparse(target)
    return target if not parsed.scheme and not parsed.netloc else None


@bp.get("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("web.dashboard"))
    return redirect(url_for("web.login"))


@bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("web.dashboard"))
    errors: dict[str, str] = {}
    email = ""
    if request.method == "POST":
        email = request.form.get("email", "")
        try:
            user = auth_service.register_user(email, request.form.get("password"))
        except ValidationError as exc:
            errors = exc.errors
        except DuplicateUserError:
            errors = {"email": "An account with this email already exists."}
        else:
            session.clear()
            login_user(user)
            return redirect(url_for("web.dashboard"))
        return render_template("register.html", errors=errors, email=email), 400
    return render_template("register.html", errors=errors, email=email)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("web.dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "")
        user = auth_service.authenticate(email, request.form.get("password"))
        if user is not None:
            next_url = _safe_next(request.args.get("next"))
            session.clear()
            login_user(user)
            return redirect(next_url or url_for("web.dashboard"))
        flash("Invalid email or password.", "error")
        return render_template("login.html", email=email), 401
    return render_template("login.html", email="")


@bp.post("/logout")
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("web.login"))


@bp.get("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@bp.get("/captures")
@login_required
def captures():
    return render_template("captures.html")


@bp.get("/captures/<uuid:capture_id>")
@login_required
def capture_detail(capture_id: UUID):
    # Ownership is checked here so another user's capture id is a 404, never a shell page.
    record = capture_service.get_owned_capture(current_user, capture_id)
    if record is None:
        abort(404)
    return render_template("capture_detail.html", capture=record)


@bp.get("/compare")
@login_required
def compare():
    return render_template("compare.html")
