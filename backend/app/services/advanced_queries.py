"""Filtering, sorting and ranking over persisted Phase 4 analytics (owner scoping is the caller's job)."""

import re
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import or_

from app.extensions import db
from app.orm import (
    AdvancedAnalysis, AnomalyFindingRecord, DnsTransactionRecord, IpPairRecord, IpTrafficRecord,
    TcpConnectionRecord, TcpIndicatorRecord,
)
from app.services.analysis_queries import FilterError, _bool, _choice, _int, _ip
from app.services.analytics.traffic_intel import (
    TALKER_METRICS, TALKER_ROLES, direction_stats, parse_local_networks, rank_talkers,
)

MAX_TALKERS = 100
DEFAULT_TALKERS = 10
STATES = ("established", "incomplete", "refused", "unclassified")
TERMINATIONS = ("fin", "reset", "half_closed", "none")
INDICATOR_TYPES = ("retransmission", "duplicate_ack", "sequence_gap", "out_of_order", "partial_overlap")
SEVERITIES = ("info", "low", "medium", "high")
DNS_STATUSES = ("answered", "unanswered", "unanswered_inferred_timeout",
                "unanswered_indeterminate", "unmatched_response")
_RULE = re.compile(r"^[a-z_]{1,40}$")
_RCODE = re.compile(r"^[A-Za-z0-9]{1,12}$")


def get_document(capture_id: UUID) -> AdvancedAnalysis | None:
    return db.session.get(AdvancedAnalysis, capture_id)


def _float(args, name: str) -> float | None:
    raw = args.get(name)
    if raw in (None, ""):
        return None
    try:
        value = float(raw)
    except ValueError:
        raise FilterError(f"{name} must be a number.") from None
    if value != value or value < 0:  # NaN or negative
        raise FilterError(f"{name} must be a non-negative number.")
    return value


def _order(column, order: str):
    return column.desc().nulls_last() if order == "desc" else column.asc().nulls_last()


# ------------------------------------------------------------------ TCP connections


@dataclass
class ConnectionFilters:
    state: str | None = None
    ip: str | None = None
    port: int | None = None
    flow_id: int | None = None
    termination: str | None = None
    truncated: bool | None = None
    has_reset: bool | None = None
    zero_window: bool | None = None
    retransmissions: bool | None = None
    sort: str = "start"
    order: str = "asc"


def parse_connection_filters(args) -> ConnectionFilters:
    state = args.get("state") or None
    if state is not None and state not in STATES:
        raise FilterError(f"state must be one of: {', '.join(STATES)}.")
    term = args.get("termination") or None
    if term is not None and term not in TERMINATIONS:
        raise FilterError(f"termination must be one of: {', '.join(TERMINATIONS)}.")
    return ConnectionFilters(
        state=state, ip=_ip(args, "ip"), port=_int(args, "port", 0, 65535),
        flow_id=_int(args, "flow_id", 1), termination=term,
        truncated=_bool(args, "truncated"), has_reset=_bool(args, "has_reset"),
        zero_window=_bool(args, "zero_window"), retransmissions=_bool(args, "retransmissions"),
        sort=_choice(args, "sort", ("start", "duration", "handshake", "packets", "bytes", "resets",
                                    "zero_window"), "start"),
        order=_choice(args, "order", ("asc", "desc"), "asc"),
    )


_CONN_SORT = {
    "start": TcpConnectionRecord.first_seen,
    "duration": TcpConnectionRecord.duration_seconds,
    "handshake": TcpConnectionRecord.handshake_ms,
    "packets": TcpConnectionRecord.packets,
    "bytes": TcpConnectionRecord.bytes,
    "resets": TcpConnectionRecord.rst_packets,
    "zero_window": TcpConnectionRecord.zero_window_events,
}


def connection_query(capture_id: UUID, f: ConnectionFilters):
    C = TcpConnectionRecord
    q = db.select(C).where(C.capture_id == capture_id)
    if f.state:
        q = q.where(C.state == f.state)
    if f.ip:
        q = q.where(or_(C.endpoint_a_ip == f.ip, C.endpoint_b_ip == f.ip))
    if f.port is not None:
        q = q.where(or_(C.endpoint_a_port == f.port, C.endpoint_b_port == f.port))
    if f.flow_id is not None:
        q = q.where(C.flow_id == f.flow_id)
    if f.termination:
        q = q.where(C.termination == f.termination)
    if f.truncated is not None:
        q = q.where(C.capture_truncated.is_(f.truncated))
    if f.has_reset is not None:
        q = q.where(C.rst_packets > 0 if f.has_reset else C.rst_packets == 0)
    if f.zero_window is not None:
        q = q.where(C.zero_window_events > 0 if f.zero_window else C.zero_window_events == 0)
    if f.retransmissions is not None:
        q = q.where(C.retransmissions > 0 if f.retransmissions else C.retransmissions == 0)
    return q.order_by(_order(_CONN_SORT[f.sort], f.order), C.connection_id)


# --------------------------------------------------------------------- indicators


@dataclass
class IndicatorFilters:
    type: str | None = None
    severity: str | None = None
    connection_id: int | None = None
    flow_id: int | None = None
    sort: str = "severity"
    order: str = "desc"


def parse_indicator_filters(args) -> IndicatorFilters:
    kind = args.get("type") or None
    if kind is not None and kind not in INDICATOR_TYPES:
        raise FilterError(f"type must be one of: {', '.join(INDICATOR_TYPES)}.")
    sev = args.get("severity") or None
    if sev is not None and sev not in SEVERITIES:
        raise FilterError(f"severity must be one of: {', '.join(SEVERITIES)}.")
    return IndicatorFilters(
        type=kind, severity=sev, connection_id=_int(args, "connection_id", 1),
        flow_id=_int(args, "flow_id", 1),
        sort=_choice(args, "sort", ("severity", "count", "connection"), "severity"),
        order=_choice(args, "order", ("asc", "desc"), "desc"),
    )


def indicator_query(capture_id: UUID, f: IndicatorFilters):
    I = TcpIndicatorRecord
    q = db.select(I).where(I.capture_id == capture_id)
    if f.type:
        q = q.where(I.type == f.type)
    if f.severity:
        q = q.where(I.severity == f.severity)
    if f.connection_id is not None:
        q = q.where(I.connection_id == f.connection_id)
    if f.flow_id is not None:
        q = q.where(I.flow_id == f.flow_id)
    column = {"severity": I.severity_rank, "count": I.count, "connection": I.connection_id}[f.sort]
    primary = column.desc() if f.order == "desc" else column.asc()
    return q.order_by(primary, I.count.desc(), I.indicator_id)


# -------------------------------------------------------------------------- DNS


@dataclass
class DnsFilters:
    status: str | None = None
    rcode: str | None = None
    transport: str | None = None
    client_ip: str | None = None
    server_ip: str | None = None
    q: str | None = None
    min_latency_ms: float | None = None
    sort: str = "time"
    order: str = "asc"


def parse_dns_filters(args) -> DnsFilters:
    status = args.get("status") or None
    if status is not None and status not in DNS_STATUSES:
        raise FilterError(f"status must be one of: {', '.join(DNS_STATUSES)}.")
    rcode = (args.get("rcode") or "").strip().upper() or None
    if rcode is not None and not _RCODE.match(rcode):
        raise FilterError("rcode must be a response-code name such as NXDOMAIN, or a number.")
    transport = (args.get("transport") or "").lower() or None
    if transport not in (None, "udp", "tcp"):
        raise FilterError("transport must be udp or tcp.")
    return DnsFilters(
        status=status, rcode=rcode, transport=transport,
        client_ip=_ip(args, "client_ip"), server_ip=_ip(args, "server_ip"),
        q=(args.get("q") or "").strip()[:100] or None,
        min_latency_ms=_float(args, "min_latency_ms"),
        sort=_choice(args, "sort", ("time", "latency", "name", "retries"), "time"),
        order=_choice(args, "order", ("asc", "desc"), "asc"),
    )


def dns_query(capture_id: UUID, f: DnsFilters):
    D = DnsTransactionRecord
    q = db.select(D).where(D.capture_id == capture_id)
    if f.status == "unanswered":
        q = q.where(D.status.in_(("unanswered_inferred_timeout", "unanswered_indeterminate")))
    elif f.status:
        q = q.where(D.status == f.status)
    if f.rcode:
        if f.rcode.isdigit():
            q = q.where(D.rcode == int(f.rcode))
        else:
            q = q.where(D.rcode_name == f.rcode)
    if f.transport:
        q = q.where(D.transport == f.transport)
    if f.client_ip:
        q = q.where(D.client_ip == f.client_ip)
    if f.server_ip:
        q = q.where(D.server_ip == f.server_ip)
    if f.q:
        q = q.where(D.qname.icontains(f.q, autoescape=True))
    if f.min_latency_ms is not None:
        q = q.where(D.latency_ms >= f.min_latency_ms)
    column = {"time": D.transaction_id, "latency": D.latency_ms, "name": D.qname,
              "retries": D.query_count}[f.sort]
    return q.order_by(_order(column, f.order), D.transaction_id)


# ---------------------------------------------------------------------- anomalies


@dataclass
class AnomalyFilters:
    severity: str | None = None
    rule: str | None = None
    ip: str | None = None
    order: str = "desc"


def parse_anomaly_filters(args) -> AnomalyFilters:
    sev = args.get("severity") or None
    if sev is not None and sev not in SEVERITIES:
        raise FilterError(f"severity must be one of: {', '.join(SEVERITIES)}.")
    rule = args.get("rule") or None
    if rule is not None and not _RULE.match(rule):
        raise FilterError("rule must be a rule name such as port_scan_vertical.")
    return AnomalyFilters(severity=sev, rule=rule, ip=_ip(args, "ip"),
                          order=_choice(args, "order", ("asc", "desc"), "desc"))


def anomaly_query(capture_id: UUID, f: AnomalyFilters):
    A = AnomalyFindingRecord
    q = db.select(A).where(A.capture_id == capture_id)
    if f.severity:
        q = q.where(A.severity == f.severity)
    if f.rule:
        q = q.where(A.rule == f.rule)
    if f.ip:  # the address is validated, so matching its quoted form in the JSON text is exact
        q = q.where(A.affected_ips.cast(db.Text).contains(f'"{f.ip}"', autoescape=True))
    primary = A.severity_rank.desc() if f.order == "desc" else A.severity_rank.asc()
    return q.order_by(primary, A.rule, A.finding_id)


# ----------------------------------------------------------------- traffic intel


def top_talkers(capture_id: UUID, args, document: dict) -> dict:
    metric = _choice(args, "by", TALKER_METRICS, "bytes")
    role = _choice(args, "role", TALKER_ROLES, "bidirectional")
    limit = _int(args, "limit", 1, MAX_TALKERS) or DEFAULT_TALKERS
    version = _int(args, "ip_version", 4, 6)
    if version not in (None, 4, 6):
        raise FilterError("ip_version must be 4 or 6.")
    rows = (
        row.as_row()
        for row in db.session.execute(
            db.select(IpTrafficRecord)
            .where(IpTrafficRecord.capture_id == capture_id)
            .execution_options(yield_per=5000)
        ).scalars()
    )
    traffic = document["traffic"]
    return {
        "by": metric, "role": role, "limit": limit, "ip_version": version,
        "total_ip_packets": traffic["total_ip_packets"],
        "total_ip_bytes": traffic["total_ip_bytes"],
        "unique_addresses": traffic["unique_addresses"],
        "ip_versions": traffic["ip_versions"],
        "items": rank_talkers(rows, metric, role, limit, traffic["total_ip_packets"],
                              traffic["total_ip_bytes"], ip_version=version),
    }


def direction(capture_id: UUID, args, document: dict) -> dict:
    try:
        networks = parse_local_networks(args.get("local"))
    except ValueError as exc:
        raise FilterError(str(exc)) from None
    pairs = (
        {"source_ip": r.source_ip, "destination_ip": r.destination_ip,
         "packets": r.packets, "bytes": r.bytes}
        for r in db.session.execute(
            db.select(IpPairRecord)
            .where(IpPairRecord.capture_id == capture_id)
            .execution_options(yield_per=5000)
        ).scalars()
    )
    traffic = document["traffic"]
    return direction_stats(pairs, networks, traffic["total_ip_packets"], traffic["total_ip_bytes"])
