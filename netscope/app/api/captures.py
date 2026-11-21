from uuid import UUID

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from app.api import api_error
from app.models.capture import CaptureStatus
from app.services import capture_service
from app.services.capture_service import AnalysisConflict, QueueUnavailable
from app.services.capture_storage import UploadRejected

bp = Blueprint("api_captures", __name__)

DEFAULT_PER_PAGE = 20
MAX_PER_PAGE = 100


def _owned_or_404(capture_id: UUID):
    return capture_service.get_owned_capture(current_user, capture_id)


def _not_found():
    return api_error(404, "Capture not found.")


@bp.post("")
@login_required
def upload_capture():
    analyze = request.form.get("analyze", "true").strip().lower() not in {"false", "0", "no"}
    try:
        record = capture_service.create_capture(
            current_user, request.files.get("file"), analyze=analyze
        )
    except UploadRejected as exc:
        return api_error(exc.status_code, str(exc))
    return jsonify({"capture": record.to_dict()}), 201


@bp.get("")
@login_required
def list_captures():
    try:
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", DEFAULT_PER_PAGE))
    except ValueError:
        return api_error(400, "page and per_page must be integers.")
    if page < 1 or not 1 <= per_page <= MAX_PER_PAGE:
        return api_error(400, f"page must be >= 1 and per_page between 1 and {MAX_PER_PAGE}.")

    status = None
    if "status" in request.args:
        try:
            status = CaptureStatus(request.args["status"])
        except ValueError:
            valid = ", ".join(s.value for s in CaptureStatus)
            return api_error(400, f"status must be one of: {valid}.")

    result = capture_service.list_captures(current_user, page, per_page, status)
    return jsonify(
        {
            "items": [c.to_dict() for c in result.items],
            "page": page,
            "per_page": per_page,
            "total": result.total,
        }
    )


@bp.get("/<uuid:capture_id>")
@login_required
def get_capture(capture_id: UUID):
    record = _owned_or_404(capture_id)
    if record is None:
        return _not_found()
    return jsonify({"capture": record.to_dict()})


@bp.get("/<uuid:capture_id>/status")
@login_required
def get_status(capture_id: UUID):
    record = _owned_or_404(capture_id)
    if record is None:
        return _not_found()
    data = record.to_dict()
    return jsonify(
        {
            key: data[key]
            for key in (
                "id",
                "status",
                "packet_count",
                "processing_started_at",
                "processing_completed_at",
                "error_message",
            )
        }
    )


@bp.post("/<uuid:capture_id>/analyze")
@login_required
def analyze(capture_id: UUID):
    record = _owned_or_404(capture_id)
    if record is None:
        return _not_found()
    try:
        capture_service.queue_analysis(record)
    except AnalysisConflict as exc:
        return api_error(409, str(exc))
    except QueueUnavailable:
        return api_error(503, record.error_message or "Job service unavailable.")
    return jsonify({"capture": record.to_dict()}), 202


@bp.delete("/<uuid:capture_id>")
@login_required
def delete_capture(capture_id: UUID):
    record = _owned_or_404(capture_id)
    if record is None:
        return _not_found()
    capture_service.delete_capture(record)
    return "", 204
