from flask import Blueprint, jsonify, request, session
from flask_login import current_user, login_required, login_user, logout_user
from flask_wtf.csrf import generate_csrf

from app.api import api_error
from app.services import auth_service
from app.services.auth_service import DuplicateUserError, ValidationError

bp = Blueprint("api_auth", __name__)


def _credentials() -> tuple[str | None, str | None]:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None, None
    return data.get("email"), data.get("password")


@bp.get("/csrf")
def csrf_token():
    """Token that session-authenticated clients send as the X-CSRFToken header."""
    return jsonify({"csrf_token": generate_csrf()})


@bp.post("/register")
def register():
    email, password = _credentials()
    try:
        user = auth_service.register_user(email, password)
    except ValidationError as exc:
        return api_error(400, "Validation failed.", errors=exc.errors)
    except DuplicateUserError:
        return api_error(409, "An account with this email already exists.")
    session.clear()
    login_user(user)
    return jsonify({"user": user.to_dict()}), 201


@bp.post("/login")
def login():
    email, password = _credentials()
    user = auth_service.authenticate(email, password)
    if user is None:
        return api_error(401, "Invalid email or password.")
    session.clear()  # drop any pre-login session state
    login_user(user)
    return jsonify({"user": user.to_dict()})


@bp.post("/logout")
def logout():
    logout_user()
    session.clear()
    return jsonify({"status": "logged_out"})


@bp.get("/me")
@login_required
def me():
    return jsonify({"user": current_user.to_dict()})
