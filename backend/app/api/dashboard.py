from uuid import UUID

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from app.api import api_error
from app.services import dashboard_service

bp = Blueprint("api_dashboard", __name__)


@bp.get("/dashboard")
@login_required
def dashboard():
    return jsonify(dashboard_service.build_dashboard(current_user))


@bp.get("/compare")
@login_required
def compare():
    try:
        a_id, b_id = UUID(request.args.get("a", "")), UUID(request.args.get("b", ""))
    except ValueError:
        return api_error(400, "Query parameters a and b must both be capture IDs.")
    if a_id == b_id:
        return api_error(400, "Choose two different captures to compare.")

    captures = []
    for capture_id in (a_id, b_id):
        record, problem = dashboard_service.completed_owned_capture(current_user, capture_id)
        if problem == "not_found":
            return api_error(404, "Capture not found.")
        if problem:
            return api_error(409, f"Capture {record_label(capture_id)} is {problem}; only completed captures can be compared.")
        captures.append(record)
    return jsonify(dashboard_service.compare_captures(*captures))


def record_label(capture_id: UUID) -> str:
    return str(capture_id)[:8]
