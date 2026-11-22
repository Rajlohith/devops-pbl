"""TCP connection tracking: handshake success, durations, termination and resets.

Connections are identified per FlowTracker flow (the bidirectional 5-tuple), but a flow can
contain several connections when a port pair is reused, so a new SYN with a different
initial sequence number starts a new connection record.

Classification (``state``), decided only from what was captured:

``established``
    SYN, a matching SYN-ACK (ack == client ISN + 1) and a client ACK acknowledging the
    server's ISN + 1 were all seen: a completed three-way handshake.
``refused``
    SYN followed by an RST-ACK from the server that acknowledges the SYN, before any SYN-ACK.
    This is the only *confirmed* connection failure a passive capture can show.
``incomplete``
    SYN seen but the handshake was not completed in the capture. ``incomplete_reason`` is
    ``no_synack`` (no answer observed) or ``no_final_ack``. This is NOT a confirmed failure:
    the packets may have been dropped, filtered, answered on a path the capture did not see,
    or the capture may have ended first.
``unclassified``
    No initial SYN was captured (the capture started mid-connection, or only a SYN-ACK was
    seen), so the connection cannot be judged either way.

Connection success rate = established / (established + incomplete + refused), i.e. over
*observable attempts* (connections whose initial SYN was captured). Unclassified connections
are excluded from the denominator. The confirmed failure rate uses the same denominator.

Timing (seconds in the model, milliseconds in API output):
- ``syn_to_synack_ms``: first SYN to first matching SYN-ACK (the handshake RTT at the capture point).
- ``handshake_ms``: first SYN to the completing client ACK. Includes SYN retransmission delay
  because it starts at the first SYN. Only established connections have it.
- ``duration_seconds``: first to last captured packet of the connection (*observed* lifetime;
  not the true lifetime when the capture is truncated).

Termination: ``reset`` (an RST before the connection closed gracefully), ``fin`` (FIN seen from
both sides), ``half_closed`` (FIN from one side only) or ``none`` (neither). Established
connections with termination ``none``/``half_closed`` and connections with no SYN are flagged
``capture_truncated`` because the capture does not show how they ended / began.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import tcp_diagnostics as diag
from .common import SEQ_MASK, distribution, histogram, ms, ratio

RST_EVIDENCE_CAP = 10
LIFETIME_EDGES = [0, 1, 10, 60, 600]  # seconds
HANDSHAKE_EDGES = [0, 1, 10, 50, 100, 250, 500, 1000]  # milliseconds


@dataclass(slots=True)
class Conn:
    id: int
    flow_id: int
    a_ip: str
    a_port: int | None
    b_ip: str
    b_port: int | None
    initiator_known: bool
    ip_version: int | None
    first_ts: float
    last_ts: float
    first_pkt: int
    last_pkt: int
    syn_ts: float | None = None
    syn_pkt: int | None = None
    syn_count: int = 0
    isn_a: int | None = None
    synack_ts: float | None = None
    synack_pkt: int | None = None
    isn_b: int | None = None
    ack_ts: float | None = None
    ack_pkt: int | None = None
    established: bool = False
    refused: bool = False
    fin_a_ts: float | None = None
    fin_b_ts: float | None = None
    rst_a: int = 0
    rst_b: int = 0
    rst_first_ts: float | None = None
    rst_packets: list = field(default_factory=list)
    packets: int = 0
    bytes: int = 0
    packets_a: int = 0
    packets_b: int = 0
    bytes_a: int = 0
    bytes_b: int = 0
    dirs: tuple = field(default_factory=lambda: (diag.DirDiag(), diag.DirDiag()))
    indicators: dict = field(default_factory=dict)

    # ---- derived (valid once all packets were observed)
    @property
    def state(self) -> str:
        if self.syn_pkt is None:
            return "unclassified"
        if self.established:
            return "established"
        if self.refused:
            return "refused"
        return "incomplete"

    @property
    def incomplete_reason(self) -> str | None:
        if self.state != "incomplete":
            return None
        return "no_final_ack" if self.synack_pkt is not None else "no_synack"

    @property
    def termination(self) -> str:
        fins = self.fin_a_ts is not None, self.fin_b_ts is not None
        if self.rst_first_ts is not None:
            closed_at = max(self.fin_a_ts or 0, self.fin_b_ts or 0)
            if all(fins) and self.rst_first_ts >= closed_at:
                return "fin"  # graceful close first; the RST only followed it
            return "reset"
        if all(fins):
            return "fin"
        if any(fins):
            return "half_closed"
        return "none"

    @property
    def terminated_by(self) -> str | None:
        term = self.termination
        if term == "reset":
            if self.rst_a and self.rst_b:
                return "both"
            return "a" if self.rst_a else "b"
        if term == "fin":
            return "both"
        if term == "half_closed":
            return "a" if self.fin_a_ts is not None else "b"
        return None

    @property
    def truncation_reasons(self) -> list[str]:
        reasons = []
        if self.syn_pkt is None:
            reasons.append("start_not_observed")
        if self.established and self.termination in ("none", "half_closed"):
            reasons.append("end_not_observed")
        return reasons

    @property
    def rst_total(self) -> int:
        return self.rst_a + self.rst_b

    @property
    def duration_seconds(self) -> float:
        return max(self.last_ts - self.first_ts, 0.0)

    def times(self) -> dict:
        syn_to_synack = (
            ms(self.synack_ts - self.syn_ts) if self.synack_ts is not None and self.syn_ts is not None else None
        )
        handshake = (
            ms(self.ack_ts - self.syn_ts) if self.established and self.syn_ts is not None else None
        )
        synack_to_ack = (
            ms(self.ack_ts - self.synack_ts) if self.established and self.synack_ts is not None else None
        )
        return {
            "syn_to_synack_ms": syn_to_synack,
            "synack_to_ack_ms": synack_to_ack,
            "handshake_ms": handshake,
        }


class TcpConnectionTracker:
    def __init__(self) -> None:
        self._active: dict[int, Conn] = {}
        self._all: list[Conn] = []
        self.rst_packets = 0
        self.tcp_packets = 0
        self.rst_by_sender: dict[str, int] = {}

    @property
    def connections(self) -> list[Conn]:
        return self._all

    # ------------------------------------------------------------------ observe
    def observe(self, v) -> Conn | None:
        if v.transport != "TCP" or v.tcp_flags is None or v.flow_id is None:
            return None
        if v.src_ip is None or v.dst_ip is None:
            return None
        flags = v.tcp_flags
        self.tcp_packets += 1
        syn = "S" in flags and "A" not in flags
        synack = "S" in flags and "A" in flags

        conn = self._active.get(v.flow_id)
        if syn:
            if conn is None or not self._is_syn_retransmit(conn, v):
                conn = self._start(v, initiator=True)
        elif conn is None:
            conn = self._start(v, initiator=False)

        side = "a" if (v.src_ip, v.src_port) == (conn.a_ip, conn.a_port) else "b"
        self._count(conn, side, v)
        if "R" in flags:
            self._reset(conn, side, v)
        if "F" in flags:
            if side == "a" and conn.fin_a_ts is None:
                conn.fin_a_ts = v.ts
            elif side == "b" and conn.fin_b_ts is None:
                conn.fin_b_ts = v.ts

        self._handshake(conn, side, v, syn, synack)
        diag.observe_segment(conn, side, v)
        return conn

    @staticmethod
    def _is_syn_retransmit(conn: Conn, v) -> bool:
        same_sender = (v.src_ip, v.src_port) == (conn.a_ip, conn.a_port)
        return conn.initiator_known and same_sender and conn.isn_a == v.seq

    def _start(self, v, *, initiator: bool) -> Conn:
        flags = v.tcp_flags
        # Without an initial SYN, a SYN-ACK still tells us who the server is.
        if not initiator and "S" in flags and "A" in flags:
            a_ip, a_port, b_ip, b_port = v.dst_ip, v.dst_port, v.src_ip, v.src_port
        else:
            a_ip, a_port, b_ip, b_port = v.src_ip, v.src_port, v.dst_ip, v.dst_port
        conn = Conn(
            id=len(self._all) + 1,
            flow_id=v.flow_id,
            a_ip=a_ip, a_port=a_port, b_ip=b_ip, b_port=b_port,
            initiator_known=initiator,
            ip_version=v.ip_version,
            first_ts=v.ts, last_ts=v.ts, first_pkt=v.number, last_pkt=v.number,
        )
        self._all.append(conn)
        self._active[v.flow_id] = conn
        return conn

    @staticmethod
    def _count(conn: Conn, side: str, v) -> None:
        conn.packets += 1
        conn.bytes += v.length
        if side == "a":
            conn.packets_a += 1
            conn.bytes_a += v.length
        else:
            conn.packets_b += 1
            conn.bytes_b += v.length
        if v.ts < conn.first_ts:
            conn.first_ts, conn.first_pkt = v.ts, v.number
        if v.ts >= conn.last_ts:
            conn.last_ts, conn.last_pkt = v.ts, v.number

    def _reset(self, conn: Conn, side: str, v) -> None:
        self.rst_packets += 1
        self.rst_by_sender[v.src_ip] = self.rst_by_sender.get(v.src_ip, 0) + 1
        if side == "a":
            conn.rst_a += 1
        else:
            conn.rst_b += 1
        if conn.rst_first_ts is None or v.ts < conn.rst_first_ts:
            conn.rst_first_ts = v.ts
        if len(conn.rst_packets) < RST_EVIDENCE_CAP:
            conn.rst_packets.append({"packet": v.number, "side": side})

    @staticmethod
    def _handshake(conn: Conn, side: str, v, syn: bool, synack: bool) -> None:
        flags = v.tcp_flags
        if syn and side == "a" and conn.initiator_known:
            if conn.syn_pkt is None:
                conn.syn_ts, conn.syn_pkt, conn.isn_a = v.ts, v.number, v.seq
            conn.syn_count += 1
            return
        if conn.syn_pkt is None or v.ack is None or conn.isn_a is None:
            # Missing SYN: remember a SYN-ACK's ISN but never claim a completed handshake.
            if synack and side == "b" and conn.isn_b is None:
                conn.isn_b = v.seq
            return
        expect_synack_ack = (conn.isn_a + 1) & SEQ_MASK
        if synack and side == "b" and v.ack == expect_synack_ack and conn.synack_pkt is None:
            conn.synack_ts, conn.synack_pkt, conn.isn_b = v.ts, v.number, v.seq
            return
        if "R" in flags and side == "b" and "A" in flags and v.ack == expect_synack_ack:
            if conn.synack_pkt is None and not conn.established:
                conn.refused = True
            return
        if (
            side == "a" and not conn.established and conn.synack_pkt is not None
            and "A" in flags and "S" not in flags and "R" not in flags
            and v.ack == (conn.isn_b + 1) & SEQ_MASK
        ):
            conn.established = True
            conn.ack_ts, conn.ack_pkt = v.ts, v.number

    # ----------------------------------------------------------------- summary
    def connection_rows(self) -> list[dict]:
        return [connection_row(c) for c in self._all]

    def summary(self) -> dict:
        return summarize_connections(self._all, self.tcp_packets, self.rst_packets, self.rst_by_sender)


def connection_row(c: Conn) -> dict:
    t = c.times()
    w = diag.window_summary(c)
    return {
        "connection_id": c.id,
        "flow_id": c.flow_id,
        "ip_version": c.ip_version,
        "endpoint_a_ip": c.a_ip, "endpoint_a_port": c.a_port,
        "endpoint_b_ip": c.b_ip, "endpoint_b_port": c.b_port,
        "initiator_known": c.initiator_known,
        "state": c.state,
        "incomplete_reason": c.incomplete_reason,
        "first_ts": c.first_ts, "last_ts": c.last_ts,
        "first_packet": c.first_pkt, "last_packet": c.last_pkt,
        "duration_seconds": c.duration_seconds,
        "syn_packet": c.syn_pkt, "syn_retransmissions": max(c.syn_count - 1, 0),
        "syn_to_synack_ms": t["syn_to_synack_ms"],
        "synack_to_ack_ms": t["synack_to_ack_ms"],
        "handshake_ms": t["handshake_ms"],
        "termination": c.termination,
        "terminated_by": c.terminated_by,
        "capture_truncated": bool(c.truncation_reasons),
        "truncation_reasons": c.truncation_reasons,
        "packets": c.packets, "bytes": c.bytes,
        "packets_a_to_b": c.packets_a, "packets_b_to_a": c.packets_b,
        "bytes_a_to_b": c.bytes_a, "bytes_b_to_a": c.bytes_b,
        "rst_packets": c.rst_total, "rst_from_a": c.rst_a, "rst_from_b": c.rst_b,
        "rst_evidence": list(c.rst_packets),
        "retransmissions": _count(c, "retransmission"),
        "duplicate_acks": _count(c, "duplicate_ack"),
        "zero_window_events": w["a"]["zero_window_events"] + w["b"]["zero_window_events"],
        "window_scaling": w["scaling"],
        "window": w,
    }


def _count(c: Conn, kind: str) -> int:
    return sum(i.count for (k, _), i in c.indicators.items() if k == kind)


def summarize_connections(conns, tcp_packets: int, rst_packets: int, rst_by_sender: dict) -> dict:
    counts = {"established": 0, "incomplete": 0, "refused": 0, "unclassified": 0}
    reasons = {"no_synack": 0, "no_final_ack": 0}
    terminations = {"fin": 0, "reset": 0, "half_closed": 0, "none": 0}
    handshake, synack, lifetimes = [], [], []
    truncated = 0
    reset_conns = reset_before = reset_after = reset_unclassified = 0
    for c in conns:
        counts[c.state] += 1
        if c.incomplete_reason:
            reasons[c.incomplete_reason] += 1
        terminations[c.termination] += 1
        if c.truncation_reasons:
            truncated += 1
        t = c.times()
        if t["handshake_ms"] is not None:
            handshake.append(t["handshake_ms"])
        if t["syn_to_synack_ms"] is not None:
            synack.append(t["syn_to_synack_ms"])
        lifetimes.append(c.duration_seconds)
        if c.rst_total:
            reset_conns += 1
            if c.state == "unclassified":
                reset_unclassified += 1  # handshake never captured: cannot say when it was reset
            elif c.established:
                reset_after += 1
            else:
                reset_before += 1

    attempts = counts["established"] + counts["incomplete"] + counts["refused"]
    total = len(conns)
    top_senders = sorted(rst_by_sender.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
    return {
        "total_connections": total,
        "states": counts,
        "observable_attempts": attempts,
        "success_rate": ratio(counts["established"], attempts),
        "confirmed_failure_rate": ratio(counts["refused"], attempts),
        "incomplete_rate": ratio(counts["incomplete"], attempts),
        "incomplete_reasons": reasons,
        "terminations": terminations,
        "capture_truncated_connections": truncated,
        "handshake_ms": distribution(handshake),
        "syn_to_synack_ms": distribution(synack),
        "lifetime_seconds": distribution(lifetimes),
        "charts": {
            "handshake_histogram": histogram(handshake, HANDSHAKE_EDGES, "ms"),
            "lifetime_histogram": histogram(lifetimes, LIFETIME_EDGES, "s"),
        },
        "resets": {
            "rst_packets": rst_packets,
            "tcp_packets": tcp_packets,
            "packet_rate": ratio(rst_packets, tcp_packets),
            "connections_with_reset": reset_conns,
            "tcp_connections": total,
            "connection_rate": ratio(reset_conns, total),
            "reset_before_established": reset_before,
            "reset_after_established": reset_after,
            "reset_unclassified": reset_unclassified,
            "top_senders": [{"ip": ip, "rst_packets": n} for ip, n in top_senders],
        },
    }
