"""Shared types and helpers for the analytics modules."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

SEQ_MASK = 0xFFFFFFFF
SEQ_HALF = 0x80000000

RCODE_NAMES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
    6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE",
}
QTYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
    33: "SRV", 35: "NAPTR", 43: "DS", 46: "RRSIG", 48: "DNSKEY", 65: "HTTPS", 255: "ANY",
}

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


def rcode_name(code: int | None) -> str | None:
    if code is None:
        return None
    return RCODE_NAMES.get(code, f"RCODE{code}")


def qtype_name(code: int | None) -> str | None:
    if code is None:
        return None
    return QTYPE_NAMES.get(code, f"TYPE{code}")


@dataclass(slots=True)
class PacketView:
    """The fields the analytics need from one packet, independent of Scapy/ORM types."""

    number: int
    ts: float  # seconds since the epoch (capture timestamp)
    flow_id: int | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    ip_version: int | None = None
    transport: str | None = None  # "TCP", "UDP", "ICMP", ...
    app: str | None = None  # "DNS", "HTTP" or None
    length: int = 0  # on-the-wire frame size (original_length)
    tcp_flags: str | None = None
    seq: int | None = None
    ack: int | None = None
    window: int | None = None  # raw (unscaled) advertised window
    wscale: int | None = None  # window-scale shift announced in a SYN / SYN-ACK
    payload_len: int = 0  # transport payload bytes
    is_retx: bool = False  # exact duplicate TCP segment, as flagged by FlowTracker
    dns: dict[str, Any] | None = None
    malformed: bool = False

    @classmethod
    def from_extracted(cls, ex, flow_id: int | None, is_retx: bool) -> "PacketView":
        """Build a view from the extractor's ExtractedPacket (duck-typed)."""
        p = ex.packet
        transport = p.transport_protocol.name if p.transport_protocol else None
        payload = ex.payload_length or 0
        if transport == "UDP" and p.udp_length:
            payload = max(int(p.udp_length) - 8, 0)
        return cls(
            number=p.packet_number,
            ts=p.timestamp.timestamp(),
            flow_id=flow_id,
            src_ip=str(p.source_ip) if p.source_ip is not None else None,
            dst_ip=str(p.destination_ip) if p.destination_ip is not None else None,
            src_port=p.source_port,
            dst_port=p.destination_port,
            ip_version=p.ip_version,
            transport=transport,
            app=p.application_protocol,
            length=p.original_length,
            tcp_flags=p.tcp_flags,
            seq=p.tcp_sequence_number,
            ack=p.tcp_acknowledgement_number,
            window=getattr(ex, "tcp_window", None),
            wscale=getattr(ex, "tcp_window_scale", None),
            payload_len=payload,
            is_retx=is_retx,
            dns=getattr(ex, "dns", None) if p.application_protocol == "DNS" else None,
            malformed=bool(ex.malformed_reason),
        )


# ----------------------------------------------------------------------- arithmetic


def seq_diff(a: int, b: int) -> int:
    """Signed distance a - b in 32-bit sequence space (handles wraparound)."""
    d = (a - b) & SEQ_MASK
    return d - (1 << 32) if d >= SEQ_HALF else d


def ratio(numerator: int | float, denominator: int | float) -> float | None:
    """numerator / denominator, or None when the denominator is zero (never 0.0 or NaN)."""
    return numerator / denominator if denominator else None


def percentile(sorted_values: list[float], q: float) -> float:
    """Linear-interpolated percentile (same convention as pandas.Series.quantile)."""
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    pos = (len(sorted_values) - 1) * q
    lo = math.floor(pos)
    hi = math.ceil(pos)
    frac = pos - lo
    return float(sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * frac)


def distribution(values: list[float]) -> dict | None:
    """count/min/mean/median/p95/max, or None when there are no measurements."""
    if not values:
        return None
    ordered = sorted(values)
    return {
        "count": len(ordered),
        "min": float(ordered[0]),
        "mean": float(sum(ordered) / len(ordered)),
        "median": percentile(ordered, 0.5),
        "p95": percentile(ordered, 0.95),
        "max": float(ordered[-1]),
    }


def histogram(values: list[float], edges: list[float], unit: str) -> list[dict]:
    """Counts per half-open bucket [edge_i, edge_i+1), last bucket open-ended."""
    counts = [0] * len(edges)
    for v in values:
        index = 0
        for i, edge in enumerate(edges):
            if v >= edge:
                index = i
        counts[index] += 1
    rows = []
    for i, edge in enumerate(edges):
        label = (
            f"{edge:g}-{edges[i + 1]:g} {unit}" if i + 1 < len(edges) else f">= {edge:g} {unit}"
        )
        rows.append({"label": label, "min": edge, "count": counts[i]})
    return rows


def iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    from datetime import datetime, timezone

    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def ms(delta_seconds: float | None) -> float | None:
    """Seconds -> milliseconds; negative deltas (clock disorder) are not measurements."""
    if delta_seconds is None or delta_seconds < 0:
        return None
    return delta_seconds * 1000.0
