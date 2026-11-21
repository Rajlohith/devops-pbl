"""Filtering, searching and sorting of persisted packets and flows."""

import ipaddress
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import func, or_

from app.extensions import db
from app.orm import AnalysisResult, FlowRecord, PacketRecord

MAX_PER_PAGE = 200
DEFAULT_PER_PAGE = 50
_TCP_FLAG_LETTERS = set("FSRPAUEC")


class FilterError(ValueError):
    """An invalid query parameter; the message is safe to return to the client."""


def _int(args, name: str, minimum: int = 0, maximum: int | None = None) -> int | None:
    raw = args.get(name)
    if raw in (None, ""):
        return None
    try:
        value = int(raw)
    except ValueError:
        raise FilterError(f"{name} must be an integer.") from None
    if value < minimum or (maximum is not None and value > maximum):
        bound = f"between {minimum} and {maximum}" if maximum is not None else f">= {minimum}"
        raise FilterError(f"{name} must be {bound}.")
    return value


def _ip(args, name: str) -> str | None:
    raw = args.get(name)
    if not raw:
        return None
    try:
        return str(ipaddress.ip_address(raw.strip()))  # normalised, e.g. IPv6 compression
    except ValueError:
        raise FilterError(f"{name} must be a valid IPv4 or IPv6 address.") from None


def _bool(args, name: str) -> bool | None:
    raw = args.get(name)
    if raw in (None, ""):
        return None
    if raw.lower() in {"true", "1", "yes"}:
        return True
    if raw.lower() in {"false", "0", "no"}:
        return False
    raise FilterError(f"{name} must be true or false.")


def _choice(args, name: str, allowed: tuple[str, ...], default: str) -> str:
    value = args.get(name, default)
    if value not in allowed:
        raise FilterError(f"{name} must be one of: {', '.join(allowed)}.")
    return value


def parse_page(args, default_per_page: int = DEFAULT_PER_PAGE) -> tuple[int, int]:
    page = _int(args, "page", minimum=1) or 1
    per_page = _int(args, "per_page", minimum=1, maximum=MAX_PER_PAGE) or default_per_page
    return page, per_page


@dataclass
class PacketFilters:
    protocol: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    port: int | None = None
    flow_id: int | None = None
    min_length: int | None = None
    max_length: int | None = None
    tcp_flags: str | None = None
    malformed: bool | None = None
    retransmission: bool | None = None
    q: str | None = None
    sort: str = "number"
    order: str = "asc"


def parse_packet_filters(args) -> PacketFilters:
    flags = (args.get("tcp_flags") or "").upper()
    if flags and not set(flags) <= _TCP_FLAG_LETTERS:
        raise FilterError("tcp_flags may only contain the letters F S R P A U E C.")
    q = (args.get("q") or "").strip()[:100]
    return PacketFilters(
        protocol=(args.get("protocol") or "").strip() or None,
        src_ip=_ip(args, "src_ip"),
        dst_ip=_ip(args, "dst_ip"),
        ip=_ip(args, "ip"),
        src_port=_int(args, "src_port", 0, 65535),
        dst_port=_int(args, "dst_port", 0, 65535),
        port=_int(args, "port", 0, 65535),
        flow_id=_int(args, "flow_id", 1),
        min_length=_int(args, "min_length"),
        max_length=_int(args, "max_length"),
        tcp_flags=flags or None,
        malformed=_bool(args, "malformed"),
        retransmission=_bool(args, "retransmission"),
        q=q or None,
        sort=_choice(args, "sort", ("number", "time", "length"), "number"),
        order=_choice(args, "order", ("asc", "desc"), "asc"),
    )


_PACKET_SORT = {
    "number": PacketRecord.packet_number,
    "time": PacketRecord.timestamp,
    "length": PacketRecord.original_length,
}


def packet_query(capture_id: UUID, f: PacketFilters):
    P = PacketRecord
    query = db.select(P).where(P.capture_id == capture_id)

    if f.protocol:
        value = f.protocol.lower()
        query = query.where(
            or_(
                func.lower(P.protocol) == value,
                func.lower(P.transport_protocol) == value,
                func.lower(P.application_protocol) == value,
            )
        )
    if f.src_ip:
        query = query.where(P.source_ip == f.src_ip)
    if f.dst_ip:
        query = query.where(P.destination_ip == f.dst_ip)
    if f.ip:
        query = query.where(or_(P.source_ip == f.ip, P.destination_ip == f.ip))
    if f.src_port is not None:
        query = query.where(P.source_port == f.src_port)
    if f.dst_port is not None:
        query = query.where(P.destination_port == f.dst_port)
    if f.port is not None:
        query = query.where(or_(P.source_port == f.port, P.destination_port == f.port))
    if f.flow_id is not None:
        query = query.where(P.flow_id == f.flow_id)
    if f.min_length is not None:
        query = query.where(P.original_length >= f.min_length)
    if f.max_length is not None:
        query = query.where(P.original_length <= f.max_length)
    for letter in f.tcp_flags or "":  # every requested flag must be set
        query = query.where(P.tcp_flags.contains(letter, autoescape=True))
    if f.malformed is not None:
        query = query.where(
            P.malformed_reason.is_not(None) if f.malformed else P.malformed_reason.is_(None)
        )
    if f.retransmission is not None:
        query = query.where(P.is_retransmission.is_(f.retransmission))
    if f.q:
        clauses = [
            P.source_ip.icontains(f.q, autoescape=True),
            P.destination_ip.icontains(f.q, autoescape=True),
            P.protocol.icontains(f.q, autoescape=True),
            P.source_mac.icontains(f.q, autoescape=True),
            P.destination_mac.icontains(f.q, autoescape=True),
        ]
        if f.q.isdigit():
            number = int(f.q)
            clauses += [
                P.packet_number == number,
                P.source_port == number,
                P.destination_port == number,
            ]
        query = query.where(or_(*clauses))

    column = _PACKET_SORT[f.sort]
    primary = column.desc() if f.order == "desc" else column.asc()
    secondary = P.packet_number.desc() if f.order == "desc" else P.packet_number.asc()
    return query.order_by(primary, secondary)


@dataclass
class FlowFilters:
    protocol: str | None = None
    application: str | None = None
    ip: str | None = None
    port: int | None = None
    sort: str = "bytes"
    order: str = "desc"


def parse_flow_filters(args) -> FlowFilters:
    return FlowFilters(
        protocol=(args.get("protocol") or "").strip() or None,
        application=(args.get("application") or "").strip() or None,
        ip=_ip(args, "ip"),
        port=_int(args, "port", 0, 65535),
        sort=_choice(args, "sort", ("bytes", "packets", "duration", "start"), "bytes"),
        order=_choice(args, "order", ("asc", "desc"), "desc"),
    )


_FLOW_SORT = {
    "bytes": FlowRecord.bytes_total,
    "packets": FlowRecord.packets_total,
    "duration": FlowRecord.duration_seconds,
    "start": FlowRecord.first_seen,
}


def flow_query(capture_id: UUID, f: FlowFilters):
    F = FlowRecord
    query = db.select(F).where(F.capture_id == capture_id)
    if f.protocol:
        query = query.where(func.lower(F.protocol) == f.protocol.lower())
    if f.application:
        query = query.where(func.lower(F.application_protocol) == f.application.lower())
    if f.ip:
        query = query.where(or_(F.endpoint_a_ip == f.ip, F.endpoint_b_ip == f.ip))
    if f.port is not None:
        query = query.where(or_(F.endpoint_a_port == f.port, F.endpoint_b_port == f.port))
    column = _FLOW_SORT[f.sort]
    primary = column.desc() if f.order == "desc" else column.asc()
    return query.order_by(primary, F.flow_id)


def get_result(capture_id: UUID) -> AnalysisResult | None:
    return db.session.get(AnalysisResult, capture_id)
