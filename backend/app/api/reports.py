"""Report downloads. Owner-only, completed captures only, generated on demand."""

from uuid import UUID

from flask import Blueprint, request
from flask_login import current_user, login_required

from app.api import api_error
from app.extensions import db
from app.models.capture import CaptureStatus
from app.orm import AnomalyFindingRecord, FlowRecord
from app.services import advanced_queries as aq
from app.services import analysis_queries as queries
from app.services import capture_service, export_service
from app.services.analysis_queries import FilterError, get_result

bp = Blueprint("api_reports", __name__)

BASE_KINDS = ("packets", "flows", "protocols", "performance", "timeseries")
ADVANCED_KINDS = (
    "tcp-connections", "tcp-windows", "tcp-indicators", "tcp-summary", "dns-transactions",
    "dns-summary", "top-talkers", "traffic-direction", "anomalies", "analytics-summary",
)
KINDS = BASE_KINDS + ADVANCED_KINDS
TOP_FLOWS_IN_PDF = 15
TOP_FINDINGS_IN_PDF = 15


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

    if kind in ADVANCED_KINDS:
        return _advanced_csv(capture_id, kind, filename)

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
    stored = aq.get_document(capture_id)
    advanced = stored.document if stored else None
    findings = direction = None
    if advanced is not None:
        try:
            direction = aq.direction(capture_id, request.args, advanced)  # optional ?local=...
        except FilterError as exc:
            return api_error(400, str(exc))
        findings = db.session.execute(
            aq.anomaly_query(capture_id, aq.AnomalyFilters()).limit(TOP_FINDINGS_IN_PDF)
        ).scalars().all()
    data = export_service.build_pdf(
        record, get_result(capture_id), top, advanced=advanced, findings=findings,
        direction=direction,
    )
    return export_service.pdf_response(data, _name(record, "report.pdf"))


def _advanced_csv(capture_id: UUID, kind: str, filename: str):
    stored = aq.get_document(capture_id)
    if stored is None:
        return api_error(409, "Advanced analytics are not available for this capture.",
                         reason="analytics_unavailable")
    doc = stored.document
    es = export_service
    try:
        if kind == "tcp-connections":
            q = aq.connection_query(capture_id, aq.parse_connection_filters(request.args))
            return es.csv_response(filename, es.TCP_CONNECTION_COLUMNS, es.tcp_connection_rows(q))
        if kind == "tcp-windows":
            q = aq.connection_query(capture_id, aq.parse_connection_filters(request.args))
            return es.csv_response(filename, es.TCP_WINDOW_COLUMNS, es.tcp_window_rows(q))
        if kind == "tcp-indicators":
            q = aq.indicator_query(capture_id, aq.parse_indicator_filters(request.args))
            return es.csv_response(filename, es.TCP_INDICATOR_COLUMNS, es.tcp_indicator_rows(q))
        if kind == "dns-transactions":
            q = aq.dns_query(capture_id, aq.parse_dns_filters(request.args))
            return es.csv_response(filename, es.DNS_COLUMNS, es.dns_rows(q))
        if kind == "anomalies":
            q = aq.anomaly_query(capture_id, aq.parse_anomaly_filters(request.args))
            return es.csv_response(filename, es.ANOMALY_COLUMNS, es.anomaly_rows(q))
        if kind == "top-talkers":
            talkers = aq.top_talkers(capture_id, request.args, doc)
            return es.csv_response(filename, es.TALKER_COLUMNS, es.talker_rows(talkers["items"]))
        if kind == "traffic-direction":
            stats = aq.direction(capture_id, request.args, doc)
            return es.csv_response(filename, es.DIRECTION_COLUMNS, es.direction_rows(stats))
    except FilterError as exc:
        return api_error(400, str(exc))

    header = ["section", "metric", "value"]
    if kind == "tcp-summary":
        rows = list(es.flatten_rows("tcp", {k: v for k, v in doc["tcp"].items() if k != "charts"}))
        rows += es.flatten_rows("resets", doc["resets"])
        rows += es.flatten_rows("diagnostics", doc["diagnostics"])
        rows += es.flatten_rows("windows", doc["windows"])
        return es.csv_response(filename, header, rows)
    if kind == "dns-summary":
        dns = {k: v for k, v in doc["dns"].items() if k not in ("charts", "servers")}
        return es.csv_response(filename, header, es.flatten_rows("dns", dns))
    return es.csv_response(filename, header, es.analytics_summary_rows(doc))
