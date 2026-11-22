"""Phase 4 analytics endpoints (TCP, DNS, traffic intelligence, anomalies).

Every route is authenticated and owner-scoped through the same helper as the Phase 2/3
analysis routes, so another user's capture is indistinguishable from a missing one (404).
"""

from uuid import UUID

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from app.api import api_error
from app.extensions import db
from app.models.capture import CaptureStatus
from app.orm import AnomalyFindingRecord, DnsTransactionRecord, TcpConnectionRecord, TcpIndicatorRecord
from app.services import advanced_queries as aq
from app.services import analysis_queries as queries
from app.services import capture_service
from app.services.analysis_queries import FilterError

bp = Blueprint("api_advanced", __name__)

_UNAVAILABLE = (
    "Advanced analytics are not available for this capture (it was analysed before they existed)."
)


def _context(capture_id: UUID):
    """Return (document, None) or (None, error_response)."""
    record = capture_service.get_owned_capture(current_user, capture_id)
    if record is None:
        return None, api_error(404, "Capture not found.")
    if record.status != CaptureStatus.COMPLETED:
        return None, api_error(
            409, f"Analysis results are not available: capture is {record.status.value}."
        )
    doc = aq.get_document(capture_id)
    if doc is None:
        return None, api_error(409, _UNAVAILABLE, reason="analytics_unavailable")
    return doc.document, None


def _defs(document: dict, *keys: str) -> dict:
    return {k: v for k, v in document["definitions"].items() if k.startswith(keys)}


def _page(query, serialize, page: int, per_page: int):
    pagination = db.paginate(query, page=page, per_page=per_page, error_out=False)
    return jsonify({
        "items": [serialize(i) for i in pagination.items],
        "page": page, "per_page": per_page, "total": pagination.total,
    })


def _page_with(query, serialize, page, per_page, **extra):
    pagination = db.paginate(query, page=page, per_page=per_page, error_out=False)
    return jsonify({
        "items": [serialize(i) for i in pagination.items],
        "page": page, "per_page": per_page, "total": pagination.total, **extra,
    })


@bp.get("/<uuid:capture_id>/analytics")
@login_required
def analytics(capture_id: UUID):
    doc, error = _context(capture_id)
    if error:
        return error
    return jsonify({"analytics": doc})


# ------------------------------------------------------------------------- TCP


@bp.get("/<uuid:capture_id>/tcp/summary")
@login_required
def tcp_summary(capture_id: UUID):
    doc, error = _context(capture_id)
    if error:
        return error
    return jsonify({"tcp": doc["tcp"], "definitions": _defs(doc, "tcp_success", "tcp_incomplete",
                                                          "tcp_refused", "tcp_handshake", "tcp_observed"),
                    "limitations": doc["limitations"]})


@bp.get("/<uuid:capture_id>/tcp/connections")
@login_required
def tcp_connections(capture_id: UUID):
    _, error = _context(capture_id)
    if error:
        return error
    try:
        page, per_page = queries.parse_page(request.args, default_per_page=25)
        filters = aq.parse_connection_filters(request.args)
    except FilterError as exc:
        return api_error(400, str(exc))
    return _page(aq.connection_query(capture_id, filters), TcpConnectionRecord.to_dict, page, per_page)


@bp.get("/<uuid:capture_id>/tcp/connections/<int:connection_id>")
@login_required
def tcp_connection(capture_id: UUID, connection_id: int):
    _, error = _context(capture_id)
    if error:
        return error
    conn = db.session.get(TcpConnectionRecord, (capture_id, connection_id))
    if conn is None:
        return api_error(404, "Connection not found.")
    indicators = db.session.execute(
        aq.indicator_query(capture_id, aq.IndicatorFilters(connection_id=connection_id))
    ).scalars().all()
    return jsonify({"connection": conn.to_dict(detail=True),
                    "indicators": [i.to_dict() for i in indicators]})


@bp.get("/<uuid:capture_id>/tcp/resets")
@login_required
def tcp_resets(capture_id: UUID):
    doc, error = _context(capture_id)
    if error:
        return error
    return jsonify({"resets": doc["resets"], "definitions": _defs(doc, "tcp_reset")})


@bp.get("/<uuid:capture_id>/tcp/indicators")
@login_required
def tcp_indicators(capture_id: UUID):
    doc, error = _context(capture_id)
    if error:
        return error
    try:
        page, per_page = queries.parse_page(request.args, default_per_page=25)
        filters = aq.parse_indicator_filters(request.args)
    except FilterError as exc:
        return api_error(400, str(exc))
    return _page_with(
        aq.indicator_query(capture_id, filters), TcpIndicatorRecord.to_dict, page, per_page,
        summary=doc["diagnostics"], definitions=_defs(doc, "packet_loss"),
    )


@bp.get("/<uuid:capture_id>/tcp/windows")
@login_required
def tcp_windows(capture_id: UUID):
    doc, error = _context(capture_id)
    if error:
        return error
    zero = db.session.execute(
        aq.connection_query(
            capture_id,
            aq.ConnectionFilters(zero_window=True, sort="zero_window", order="desc"),
        ).limit(50)
    ).scalars().all()
    return jsonify({
        "windows": doc["windows"],
        "zero_window_connections": [c.to_dict(detail=True) for c in zero],
        "definitions": _defs(doc, "tcp_window"),
    })


# ------------------------------------------------------------------------- DNS


@bp.get("/<uuid:capture_id>/dns/summary")
@login_required
def dns_summary(capture_id: UUID):
    doc, error = _context(capture_id)
    if error:
        return error
    return jsonify({"dns": doc["dns"], "definitions": _defs(doc, "dns")})


@bp.get("/<uuid:capture_id>/dns/transactions")
@login_required
def dns_transactions(capture_id: UUID):
    _, error = _context(capture_id)
    if error:
        return error
    try:
        page, per_page = queries.parse_page(request.args, default_per_page=25)
        filters = aq.parse_dns_filters(request.args)
    except FilterError as exc:
        return api_error(400, str(exc))
    return _page(aq.dns_query(capture_id, filters), DnsTransactionRecord.to_dict, page, per_page)


@bp.get("/<uuid:capture_id>/dns/transactions/<int:transaction_id>")
@login_required
def dns_transaction(capture_id: UUID, transaction_id: int):
    _, error = _context(capture_id)
    if error:
        return error
    txn = db.session.get(DnsTransactionRecord, (capture_id, transaction_id))
    if txn is None:
        return api_error(404, "DNS transaction not found.")
    return jsonify({"transaction": txn.to_dict()})


# ---------------------------------------------------------------------- traffic


@bp.get("/<uuid:capture_id>/traffic/talkers")
@login_required
def traffic_talkers(capture_id: UUID):
    doc, error = _context(capture_id)
    if error:
        return error
    try:
        result = aq.top_talkers(capture_id, request.args, doc)
    except FilterError as exc:
        return api_error(400, str(exc))
    return jsonify({**result, "definitions": _defs(doc, "top_talkers")})


@bp.get("/<uuid:capture_id>/traffic/direction")
@login_required
def traffic_direction(capture_id: UUID):
    doc, error = _context(capture_id)
    if error:
        return error
    try:
        result = aq.direction(capture_id, request.args, doc)
    except FilterError as exc:
        return api_error(400, str(exc))
    return jsonify({**result, "definitions": _defs(doc, "direction")})


# -------------------------------------------------------------------- anomalies


@bp.get("/<uuid:capture_id>/anomalies")
@login_required
def anomalies(capture_id: UUID):
    doc, error = _context(capture_id)
    if error:
        return error
    try:
        page, per_page = queries.parse_page(request.args, default_per_page=25)
        filters = aq.parse_anomaly_filters(request.args)
    except FilterError as exc:
        return api_error(400, str(exc))
    return _page_with(
        aq.anomaly_query(capture_id, filters), AnomalyFindingRecord.to_dict, page, per_page,
        summary=doc["anomalies"], thresholds=doc["thresholds"], definitions=_defs(doc, "anomalies"),
    )


@bp.get("/<uuid:capture_id>/anomalies/<int:finding_id>")
@login_required
def anomaly(capture_id: UUID, finding_id: int):
    _, error = _context(capture_id)
    if error:
        return error
    finding = db.session.get(AnomalyFindingRecord, (capture_id, finding_id))
    if finding is None:
        return api_error(404, "Finding not found.")
    return jsonify({"finding": finding.to_dict()})
