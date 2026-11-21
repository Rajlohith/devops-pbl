from urllib.parse import urlparse
from uuid import UUID

from flask import Blueprint, abort, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user

from app.services import auth_service, capture_service
from app.services.auth_service import DuplicateUserError, ValidationError
from app.services.capture_service import AnalysisConflict, QueueUnavailable
from app.services.capture_storage import UploadRejected

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
        return redirect(url_for("web.captures"))
    return redirect(url_for("web.login"))


@bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("web.captures"))
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
            return redirect(url_for("web.captures"))
        return render_template("register.html", errors=errors, email=email), 400
    return render_template("register.html", errors=errors, email=email)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("web.captures"))
    if request.method == "POST":
        email = request.form.get("email", "")
        user = auth_service.authenticate(email, request.form.get("password"))
        if user is not None:
            next_url = _safe_next(request.args.get("next"))
            session.clear()
            login_user(user)
            return redirect(next_url or url_for("web.captures"))
        flash("Invalid email or password.", "error")
        return render_template("login.html", email=email), 401
    return render_template("login.html", email="")


@bp.post("/logout")
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("web.login"))


@bp.get("/captures")
@login_required
def captures():
    page = request.args.get("page", 1, type=int)
    result = capture_service.list_captures(current_user, max(page, 1), 20)
    return render_template("captures.html", result=result)


@bp.post("/captures/upload")
@login_required
def upload():
    analyze = request.form.get("analyze") == "on"
    try:
        record = capture_service.create_capture(
            current_user, request.files.get("file"), analyze=analyze
        )
    except UploadRejected as exc:
        flash(str(exc), "error")
        return redirect(url_for("web.captures"))
    if record.error_message:
        flash(f"Uploaded, but analysis could not start: {record.error_message}", "error")
    else:
        flash("Capture uploaded.", "success")
    return redirect(url_for("web.capture_detail", capture_id=record.id))


def _owned_or_404(capture_id: UUID):
    record = capture_service.get_owned_capture(current_user, capture_id)
    if record is None:
        abort(404)
    return record


@bp.get("/captures/<uuid:capture_id>")
@login_required
def capture_detail(capture_id: UUID):
    return render_template("capture_detail.html", capture=_owned_or_404(capture_id))


@bp.post("/captures/<uuid:capture_id>/analyze")
@login_required
def analyze(capture_id: UUID):
    record = _owned_or_404(capture_id)
    try:
        capture_service.queue_analysis(record)
        flash("Analysis queued.", "success")
    except AnalysisConflict as exc:
        flash(str(exc), "error")
    except QueueUnavailable:
        flash(record.error_message or "Job service unavailable.", "error")
    return redirect(url_for("web.capture_detail", capture_id=capture_id))


@bp.post("/captures/<uuid:capture_id>/delete")
@login_required
def delete(capture_id: UUID):
    capture_service.delete_capture(_owned_or_404(capture_id))
    flash("Capture deleted.", "success")
    return redirect(url_for("web.captures"))
