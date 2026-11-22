"""Per-connection TCP diagnostics: loss indicators and advertised-window analysis.

IMPORTANT - what these are. A capture taken at one point cannot show whether a packet was
lost in the network. Everything reported as an *indicator* is evidence that is commonly
associated with loss or reordering; none of it is a measurement of packet loss and NetScope
never converts it into a loss percentage.

Indicator definitions (all per connection and per sender direction):

``retransmission``
    A segment whose exact (sequence number, length) was already seen in the same direction
    (the flag comes from FlowTracker, so it is counted once there and never again here).
    Lower bound: re-segmented retransmissions appear as ``partial_overlap`` instead.
``duplicate_ack``
    A pure ACK (no payload, no SYN/FIN/RST) repeating the previous ACK number and window from
    the same sender while the peer still has unacknowledged data in flight (RFC 5681 sense).
    A run of three or more is the classic fast-retransmit trigger.
``sequence_gap``
    A segment arrived whose sequence number is ahead of the next expected one, leaving a
    byte range that was not seen. The range may be lost in the network, lost by the capture
    tool, or simply delayed (reordering). Only gaps still unfilled at the end are "potentially
    missing".
``out_of_order``
    A non-duplicate segment arrived behind the highest sequence seen and landed inside an
    earlier gap: reordering, or a retransmission of data lost before the capture point.
``partial_overlap``
    A segment overlapping already-seen data without being an exact duplicate (typically a
    re-segmented retransmission).

Sequence arithmetic is modulo 2**32. Tracking starts at the SYN when it was captured;
otherwise at the first data segment, so nothing before it can be judged. Keep-alive and
zero-window probes (one byte just behind the next expected sequence) are ignored.

Window analysis: the advertised window is the receive window the *sender of the packet*
announces. A raw value is multiplied by 2**shift only when both SYN and SYN-ACK were
captured and both carried a window-scale option (RFC 7323). If either is missing the
scale is unknown and effective window sizes are reported as null, never guessed.
"""

from __future__ import annotations

from .common import SEQ_MASK, seq_diff

EVIDENCE_CAP = 10
MAX_GAPS = 32
MAX_WSCALE = 14  # RFC 7323: larger announced shifts are treated as 14

INDICATOR_DESCRIPTIONS = {
    "retransmission": "Exact duplicate TCP segments seen in the same direction.",
    "duplicate_ack": "Repeated identical ACKs while the peer had unacknowledged data in flight.",
    "sequence_gap": "Segments arrived ahead of the expected sequence number, leaving unseen byte ranges.",
    "out_of_order": "Segments arrived behind the highest sequence seen and filled an earlier gap.",
    "partial_overlap": "Segments overlapped data already seen without being exact duplicates.",
}


class Indicator:
    __slots__ = ("type", "side", "count", "first_packet", "last_packet", "evidence", "detail")

    def __init__(self, type_: str, side: str) -> None:
        self.type = type_
        self.side = side
        self.count = 0
        self.first_packet: int | None = None
        self.last_packet: int | None = None
        self.evidence: list[dict] = []
        self.detail: dict = {}

    def add(self, packet: int, evidence: dict | None = None) -> None:
        self.count += 1
        if self.first_packet is None:
            self.first_packet = packet
        self.last_packet = packet
        if evidence is not None and len(self.evidence) < EVIDENCE_CAP:
            self.evidence.append({"packet": packet, **evidence})


class DirDiag:
    """State for the segments sent by one side of a connection."""

    __slots__ = (
        "next_seq", "gaps", "gaps_dropped", "last_ack", "last_win", "dup_run", "max_dup_run",
        "syn_seen", "wscale_offered", "wscale", "syn_window", "win_min", "win_max", "win_last",
        "win_changes", "win_samples", "zero_events", "zero_packets", "zero_evidence",
    )

    def __init__(self) -> None:
        self.next_seq: int | None = None
        self.gaps: list[list[int]] = []  # [start, end, packet_number], oldest first
        self.gaps_dropped = 0
        self.last_ack: int | None = None
        self.last_win: int | None = None
        self.dup_run = 0
        self.max_dup_run = 0
        self.syn_seen = False
        self.wscale_offered = False
        self.wscale: int | None = None
        self.syn_window: int | None = None
        self.win_min: int | None = None
        self.win_max: int | None = None
        self.win_last: int | None = None
        self.win_changes = 0
        self.win_samples = 0
        self.zero_events = 0
        self.zero_packets = 0
        self.zero_evidence: list[int] = []


def _indicator(conn, kind: str, side: str) -> Indicator:
    key = (kind, side)
    ind = conn.indicators.get(key)
    if ind is None:
        ind = conn.indicators[key] = Indicator(kind, side)
    return ind


def observe_segment(conn, side: str, v) -> None:
    """Update diagnostics for one TCP packet sent by ``side`` ('a' or 'b') of ``conn``."""
    d = conn.dirs[0 if side == "a" else 1]
    peer = conn.dirs[1 if side == "a" else 0]
    flags = v.tcp_flags or ""
    _window(d, v, flags)
    _duplicate_ack(conn, side, d, peer, v, flags)
    _sequence(conn, side, d, v, flags)


# ------------------------------------------------------------------------- window


def _window(d: DirDiag, v, flags: str) -> None:
    if v.window is None or "R" in flags:
        return
    if "S" in flags:
        d.syn_seen = True
        d.syn_window = v.window  # the window in a SYN is never scaled
        if v.wscale is not None:
            d.wscale_offered = True
            d.wscale = min(int(v.wscale), MAX_WSCALE)
        return
    w = v.window
    d.win_samples += 1
    if d.win_last is not None and w != d.win_last:
        d.win_changes += 1
    d.win_min = w if d.win_min is None else min(d.win_min, w)
    d.win_max = w if d.win_max is None else max(d.win_max, w)
    if w == 0:
        d.zero_packets += 1
        if d.win_last != 0:  # a new zero-window episode
            d.zero_events += 1
            if len(d.zero_evidence) < EVIDENCE_CAP:
                d.zero_evidence.append(v.number)
    d.win_last = w


def window_summary(conn) -> dict:
    """Advertised-window facts for a connection, with scaling status stated explicitly."""
    a, b = conn.dirs
    if a.syn_seen and b.syn_seen:
        negotiated = a.wscale_offered and b.wscale_offered
        status = "negotiated" if negotiated else "not_negotiated"
    elif a.syn_seen or b.syn_seen:
        status, negotiated = "unknown_handshake_incomplete", None
    else:
        status, negotiated = "unknown_handshake_not_observed", None

    def side(d: DirDiag, announced: str) -> dict:
        if negotiated:
            shift = d.wscale if d.wscale is not None else 0
        elif status == "not_negotiated":
            shift = 0
        else:
            shift = None  # unknown: do not guess

        def eff(raw):
            if raw is None or shift is None:
                return None
            return raw << shift

        return {
            "advertised_by": announced,
            "samples": d.win_samples,
            "scale_shift": shift,
            "scale_option_seen": d.wscale if d.wscale_offered else None,
            "syn_window": d.syn_window,
            "raw": {"min": d.win_min, "max": d.win_max, "last": d.win_last},
            "effective": (
                None if shift is None
                else {"min": eff(d.win_min), "max": eff(d.win_max), "last": eff(d.win_last)}
            ),
            "changes": d.win_changes,
            "zero_window_events": d.zero_events,
            "zero_window_packets": d.zero_packets,
            "zero_window_evidence": list(d.zero_evidence),
        }

    return {"scaling": status, "a": side(a, "a"), "b": side(b, "b")}


# ------------------------------------------------------------------ duplicate ACKs


def _duplicate_ack(conn, side: str, d: DirDiag, peer: DirDiag, v, flags: str) -> None:
    pure_ack = (
        "A" in flags
        and not any(f in flags for f in "SFR")
        and v.payload_len == 0
        and v.ack is not None
    )
    if not pure_ack:
        d.dup_run = 0
        d.last_ack = d.last_win = None  # data/control segments never count as duplicates
        return
    outstanding = peer.next_seq is not None and seq_diff(peer.next_seq, v.ack) > 0
    if outstanding and d.last_ack == v.ack and d.last_win == v.window:
        d.dup_run += 1
        d.max_dup_run = max(d.max_dup_run, d.dup_run)
        _indicator(conn, "duplicate_ack", side).add(v.number, {"ack": v.ack, "run": d.dup_run})
    else:
        d.dup_run = 0
    d.last_ack, d.last_win = v.ack, v.window


# ----------------------------------------------------------------- sequence space


def _sequence(conn, side: str, d: DirDiag, v, flags: str) -> None:
    if v.seq is None or "R" in flags:
        return
    syn, fin = "S" in flags, "F" in flags
    seg_len = v.payload_len + (1 if syn else 0) + (1 if fin else 0)
    if seg_len == 0:
        return
    if v.is_retx:  # already identified exactly once by FlowTracker; never double-count
        _indicator(conn, "retransmission", side).add(v.number, {"seq": v.seq, "length": seg_len})
        return
    end = (v.seq + seg_len) & SEQ_MASK
    if syn:
        d.next_seq = end
        return
    if d.next_seq is None:  # capture began mid-connection: nothing earlier can be judged
        d.next_seq = end
        return

    delta = seq_diff(v.seq, d.next_seq)
    if delta == 0:
        d.next_seq = end
    elif delta > 0:
        _record_gap(conn, side, d, d.next_seq, v.seq, delta, v.number)
        d.next_seq = end
    else:
        if _fill_gaps(d, v.seq, end):
            _indicator(conn, "out_of_order", side).add(v.number, {"seq": v.seq, "length": seg_len})
        elif delta == -1 and seg_len == 1:
            return  # keep-alive / zero-window probe, not an anomaly
        else:
            _indicator(conn, "partial_overlap", side).add(
                v.number, {"seq": v.seq, "length": seg_len}
            )


def _record_gap(conn, side, d: DirDiag, start: int, end: int, size: int, packet: int) -> None:
    ind = _indicator(conn, "sequence_gap", side)
    ind.add(packet, {"start": start, "end": end, "bytes": size})
    ind.detail["observed_gap_bytes"] = ind.detail.get("observed_gap_bytes", 0) + size
    d.gaps.append([start, end, packet])
    if len(d.gaps) > MAX_GAPS:
        d.gaps.pop(0)
        d.gaps_dropped += 1


def _fill_gaps(d: DirDiag, seq: int, end: int) -> bool:
    """Remove [seq, end) from pending gaps. Returns True if it overlapped any gap."""
    hit = False
    remaining = []
    for start, gap_end, packet in d.gaps:
        size = seq_diff(gap_end, start)
        lo = max(seq_diff(seq, start), 0)
        hi = min(seq_diff(end, start), size)
        if lo >= hi:
            remaining.append([start, gap_end, packet])
            continue
        hit = True
        if lo > 0:
            remaining.append([start, (start + lo) & SEQ_MASK, packet])
        if hi < size:
            remaining.append([(start + hi) & SEQ_MASK, gap_end, packet])
    d.gaps = remaining
    return hit


# ------------------------------------------------------------------- finalisation


def indicator_rows(conn) -> list[dict]:
    """Serialisable indicators for a connection with severity and confidence."""
    has_dup = any(k[0] == "duplicate_ack" for k in conn.indicators)
    has_retx = any(k[0] == "retransmission" for k in conn.indicators)
    rows = []
    for (kind, side), ind in sorted(conn.indicators.items()):
        detail = dict(ind.detail)
        severity, confidence = _grade(kind, ind, conn, side, has_dup, has_retx, detail)
        rows.append(
            {
                "type": kind,
                "side": side,
                "count": ind.count,
                "first_packet": ind.first_packet,
                "last_packet": ind.last_packet,
                "severity": severity,
                "confidence": confidence,
                "evidence": list(ind.evidence),
                "detail": detail,
            }
        )
    return rows


def _grade(kind, ind, conn, side, has_dup, has_retx, detail) -> tuple[str, str]:
    if kind == "retransmission":
        severity = "medium" if ind.count >= 10 else "low"
        return severity, "high" if has_dup else "medium"
    if kind == "duplicate_ack":
        detail["max_run"] = conn.dirs[0 if side == "a" else 1].max_dup_run
        triple = detail["max_run"] >= 3
        return ("medium" if triple else "low"), ("medium" if triple else "low")
    if kind == "sequence_gap":
        d = conn.dirs[0 if side == "a" else 1]
        detail["unfilled_gaps"] = len(d.gaps)
        detail["unfilled_gap_bytes"] = sum(seq_diff(e, s) for s, e, _ in d.gaps)
        if d.gaps_dropped:
            detail["gaps_not_tracked"] = d.gaps_dropped
        corroborated = has_dup or has_retx
        if detail["unfilled_gaps"] and corroborated:
            return "medium", "medium"
        return "low", "medium" if corroborated else "low"
    return "info", "low"  # out_of_order, partial_overlap
