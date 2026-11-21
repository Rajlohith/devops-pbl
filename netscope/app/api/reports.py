"""Report downloads. Owner-only, completed captures only, generated on demand."""

from uuid import UUID

from flask import Blueprint, request
from flask_login import current_user, login_required

from app.api import api_error
from app.extensions import db
from app.models.capture import CaptureStatus
from app.orm import FlowRecord
from app.services import analysis_queries as queries
from app.services import capture_service, export_service
from app.services.analysis_queries import FilterError, get_result

bp = Blueprint("api_reports", __name__)

KINDS = ("packets", "flows", "protocols", "performance", "timeseries")
TOP_FLOWS_IN_PDF = 15


def _completed(capture_id: UUID):
    record = capture_service.get_owned_capture(current_user, capture_id)
    if record is None:
        return None, api_error(404, "Capture not found.")
    if record.status != CaptureStatus.COMPLETED:
        return None, api_error(409, f"Reports are not available: capture is {record.status.value}.")
    return record, None


def _name(record, suffix: str) -> str:
    return f"netscope-{str(record.id)[:8]}-{suffix}"


@bp.get("/<uuid:capture_id>/export/<kind>.csv")
@login_required
def export_csv(capture_id: UUID, kind: str):
    if kind not in KINDS:
        return api_error(404, f"Unknown export. Choose one of: {', '.join(KINDS)}.")
    record, error = _completed(capture_id)
    if error:
        return error
    filename = _name(record, f"{kind}.csv")

    if kind == "packets":  # honours the explorer's filters; always in capture order
        try:
            filters = queries.parse_packet_filters(request.args)
        except FilterError as exc:
            return api_error(400, str(exc))
        rows = export_service.packet_rows(queries.packet_query(capture_id, filters))
        return export_service.csv_response(filename, export_service.PACKET_COLUMNS, rows)
    if kind == "flows":
        try:
            filters = queries.parse_flow_filters(request.args)
        except FilterError as exc:
            return api_error(400, str(exc))
        rows = export_service.flow_rows(queries.flow_query(capture_id, filters))
        return export_service.csv_response(filename, export_service.FLOW_COLUMNS, rows)

    result = get_result(capture_id)
    if kind == "protocols":
        header = ["layer", "protocol", "packets", "bytes", "packet_percent", "byte_percent"]
        rows = export_service.protocol_rows(result)
    elif kind == "performance":
        header, rows = ["section", "metric", "value"], export_service.summary_rows(result)
    else:
        header = ["time", "packets", "bytes", "packets_per_second", "bits_per_second"]
        rows = export_service.timeseries_rows(result)
    return export_service.csv_response(filename, header, rows)


@bp.get("/<uuid:capture_id>/report.pdf")
@login_required
def report_pdf(capture_id: UUID):
    record, error = _completed(capture_id)
    if error:
        return error
    top = db.session.execute(
        queries.flow_query(capture_id, queries.FlowFilters()).limit(TOP_FLOWS_IN_PDF)
    ).scalars().all()
    data = export_service.build_pdf(record, get_result(capture_id), top)
    return export_service.pdf_response(data, _name(record, "report.pdf"))
