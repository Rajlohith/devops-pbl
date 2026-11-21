"""Read-only analysis results for a completed capture. All routes are owner-scoped."""

from uuid import UUID

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from app.api import api_error
from app.extensions import db
from app.models.capture import CaptureStatus
from app.orm import FlowRecord, PacketRecord
from app.services import analysis_queries as queries
from app.services import capture_service
from app.services.analysis_queries import FilterError

bp = Blueprint("api_analysis", __name__)


def _completed(capture_id: UUID):
    """Return (capture, None), or (None, error_response) if not available."""
    record = capture_service.get_owned_capture(current_user, capture_id)
    if record is None:
        return None, api_error(404, "Capture not found.")
    if record.status != CaptureStatus.COMPLETED:
        return None, api_error(
            409, f"Analysis results are not available: capture is {record.status.value}."
        )
    return record, None


def _page_response(pagination, serialize, page, per_page):
    return jsonify(
        {
            "items": [serialize(item) for item in pagination.items],
            "page": page,
            "per_page": per_page,
            "total": pagination.total,
        }
    )


@bp.get("/<uuid:capture_id>/summary")
@login_required
def summary(capture_id: UUID):
    record, error = _completed(capture_id)
    if error:
        return error
    result = queries.get_result(capture_id)
    return jsonify(
        {
            "capture": record.to_dict(),
            "totals": result.totals(),
            "protocols": result.summary["protocols"],
        }
    )


@bp.get("/<uuid:capture_id>/protocols")
@login_required
def protocols(capture_id: UUID):
    _, error = _completed(capture_id)
    if error:
        return error
    return jsonify({"protocols": queries.get_result(capture_id).summary["protocols"]})


@bp.get("/<uuid:capture_id>/performance")
@login_required
def performance(capture_id: UUID):
    _, error = _completed(capture_id)
    if error:
        return error

    link_mbps = None
    if request.args.get("link_mbps"):
        try:
            link_mbps = float(request.args["link_mbps"])
        except ValueError:
            link_mbps = 0.0
        if not link_mbps > 0:
            return api_error(400, "link_mbps must be a positive number.")

    summary_doc = queries.get_result(capture_id).summary
    perf = dict(summary_doc["performance"])
    utilization = None
    if link_mbps is not None:  # needs a link speed, which a capture does not contain
        capacity_bps = link_mbps * 1_000_000

        def percent(bps):
            return None if bps is None else 100 * bps / capacity_bps

        utilization = {
            "link_capacity_mbps": link_mbps,
            "avg_percent": percent(perf["avg_throughput_bps"]),
            "peak_percent": percent(perf["peak_throughput_bps"]),
        }
    return jsonify(
        {
            "performance": perf,
            "utilization": utilization,
            "tcp": summary_doc["tcp"],
            "latency": summary_doc["latency"],
        }
    )


@bp.get("/<uuid:capture_id>/packets")
@login_required
def list_packets(capture_id: UUID):
    _, error = _completed(capture_id)
    if error:
        return error
    try:
        page, per_page = queries.parse_page(request.args)
        filters = queries.parse_packet_filters(request.args)
    except FilterError as exc:
        return api_error(400, str(exc))
    pagination = db.paginate(
        queries.packet_query(capture_id, filters), page=page, per_page=per_page, error_out=False
    )
    return _page_response(pagination, PacketRecord.to_dict, page, per_page)


@bp.get("/<uuid:capture_id>/packets/<int:packet_number>")
@login_required
def get_packet(capture_id: UUID, packet_number: int):
    _, error = _completed(capture_id)
    if error:
        return error
    packet = db.session.get(PacketRecord, (capture_id, packet_number))
    if packet is None:
        return api_error(404, "Packet not found.")
    return jsonify({"packet": packet.to_dict()})


@bp.get("/<uuid:capture_id>/flows")
@login_required
def list_flows(capture_id: UUID):
    _, error = _completed(capture_id)
    if error:
        return error
    try:
        page, per_page = queries.parse_page(request.args, default_per_page=25)
        filters = queries.parse_flow_filters(request.args)
    except FilterError as exc:
        return api_error(400, str(exc))
    pagination = db.paginate(
        queries.flow_query(capture_id, filters), page=page, per_page=per_page, error_out=False
    )
    return _page_response(pagination, FlowRecord.to_dict, page, per_page)


@bp.get("/<uuid:capture_id>/flows/<int:flow_id>")
@login_required
def get_flow(capture_id: UUID, flow_id: int):
    _, error = _completed(capture_id)
    if error:
        return error
    flow = db.session.get(FlowRecord, (capture_id, flow_id))
    if flow is None:
        return api_error(404, "Flow not found.")
    return jsonify({"flow": flow.to_dict()})
