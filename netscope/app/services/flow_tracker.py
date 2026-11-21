"""Bidirectional flow reconstruction with TCP retransmission, RTT and jitter estimates.

Pure logic over ExtractedPacket objects; the pipeline persists the results.

Definitions
- A flow is the 5-tuple (protocol, ip, port, ip, port) treated bidirectionally.
  Endpoint A is whichever side sent the flow's first packet.
- Bytes are on-the-wire frame sizes (original_length), headers included.
- Retransmission: a TCP segment carrying payload (or SYN/FIN) whose exact
  (sequence number, length) was already seen in the same direction. Re-segmented or
  coalesced retransmissions are not detected, so counts are a lower bound.
- Handshake RTT: time from the first SYN to the matching SYN-ACK as seen at the
  capture point. Only flows whose handshake was captured have one.
- Jitter: mean absolute difference between consecutive packet inter-arrival gaps
  within a flow (arrival-time jitter, not RFC 3550 transit-time jitter, because send
  timestamps are not available in a capture). Needs at least 3 packets.
"""

from dataclasses import dataclass, field
from datetime import datetime

from app.services.packet_extractor import ExtractedPacket

_SEEN_WINDOW = 1024  # remembered TCP segments per direction, bounds memory


@dataclass(slots=True)
class Flow:
    flow_id: int
    protocol_number: int
    protocol_name: str
    a_ip: str
    a_port: int | None
    b_ip: str
    b_port: int | None
    first_seen: datetime
    last_seen: datetime
    application_protocol: str | None = None
    packets_ab: int = 0
    packets_ba: int = 0
    bytes_ab: int = 0
    bytes_ba: int = 0
    retransmissions: int = 0
    handshake_rtt_ms: float | None = None
    _syn_time: float | None = None
    _syn_from_a: bool | None = None
    _last_time: float | None = None
    _last_gap: float | None = None
    _jitter_sum: float = 0.0
    _jitter_n: int = 0
    _seen: tuple[dict, dict] = field(default_factory=lambda: ({}, {}))

    @property
    def packets_total(self) -> int:
        return self.packets_ab + self.packets_ba

    @property
    def bytes_total(self) -> int:
        return self.bytes_ab + self.bytes_ba

    @property
    def duration_seconds(self) -> float:
        return (self.last_seen - self.first_seen).total_seconds()

    @property
    def jitter_ms(self) -> float | None:
        if self._jitter_n == 0:
            return None
        return self._jitter_sum / self._jitter_n * 1000.0


class FlowTracker:
    def __init__(self) -> None:
        self._flows: dict[tuple, Flow] = {}

    def __len__(self) -> int:
        return len(self._flows)

    @property
    def flows(self) -> list[Flow]:
        return list(self._flows.values())

    def observe(self, ex: ExtractedPacket) -> tuple[int | None, bool]:
        """Record a packet. Returns (flow_id, is_retransmission); flow_id is None for
        packets that are not IP (e.g. ARP) and so belong to no flow."""
        p = ex.packet
        if p.source_ip is None or p.destination_ip is None or p.transport_protocol is None:
            return None, False

        src = (str(p.source_ip), p.source_port or 0)
        dst = (str(p.destination_ip), p.destination_port or 0)
        number = p.transport_protocol.number
        key = (number, *sorted((src, dst)))
        flow = self._flows.get(key)
        if flow is None:
            flow = Flow(
                flow_id=len(self._flows) + 1,
                protocol_number=number,
                protocol_name=p.transport_protocol.name or f"Proto {number}",
                a_ip=src[0],
                a_port=p.source_port,
                b_ip=dst[0],
                b_port=p.destination_port,
                first_seen=p.timestamp,
                last_seen=p.timestamp,
            )
            self._flows[key] = flow

        from_a = src == (flow.a_ip, flow.a_port or 0)
        if from_a:
            flow.packets_ab += 1
            flow.bytes_ab += p.original_length
        else:
            flow.packets_ba += 1
            flow.bytes_ba += p.original_length

        if p.timestamp < flow.first_seen:
            flow.first_seen = p.timestamp
        if p.timestamp > flow.last_seen:
            flow.last_seen = p.timestamp
        if flow.application_protocol is None and p.application_protocol:
            flow.application_protocol = p.application_protocol

        now = p.timestamp.timestamp()
        self._update_jitter(flow, now)

        is_retx = False
        if p.tcp_flags is not None:
            is_retx = self._observe_tcp(flow, p, ex.payload_length or 0, from_a, now)
        return flow.flow_id, is_retx

    @staticmethod
    def _update_jitter(flow: Flow, now: float) -> None:
        if flow._last_time is not None:
            gap = now - flow._last_time
            if gap >= 0:  # ignore out-of-order timestamps
                if flow._last_gap is not None:
                    flow._jitter_sum += abs(gap - flow._last_gap)
                    flow._jitter_n += 1
                flow._last_gap = gap
                flow._last_time = now
        else:
            flow._last_time = now

    @staticmethod
    def _observe_tcp(flow: Flow, p, payload: int, from_a: bool, now: float) -> bool:
        flags = p.tcp_flags
        syn, ack = "S" in flags, "A" in flags

        if syn and not ack and flow._syn_time is None:
            flow._syn_time = now
            flow._syn_from_a = from_a
        elif syn and ack and flow._syn_time is not None and flow.handshake_rtt_ms is None:
            if from_a != flow._syn_from_a and now >= flow._syn_time:
                flow.handshake_rtt_ms = (now - flow._syn_time) * 1000.0

        length = payload or (1 if syn or "F" in flags else 0)
        if length == 0 or p.tcp_sequence_number is None:
            return False  # pure ACK/RST segments are never counted as retransmissions
        seen = flow._seen[0 if from_a else 1]
        segment = (p.tcp_sequence_number, length)
        if segment in seen:
            flow.retransmissions += 1
            return True
        seen[segment] = None
        if len(seen) > _SEEN_WINDOW:
            del seen[next(iter(seen))]
        return False
