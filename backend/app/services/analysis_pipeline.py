"""Streaming capture analysis: reader -> extractor -> flows/stats -> database.

Packets are persisted in batches so memory stays bounded for large captures. Results
that need the whole capture (flows, summary) are written last, and a capture is only
marked completed after that, so readers never see half-finished results.
"""

import logging
from pathlib import Path
from uuid import UUID

from flask import current_app

from app.extensions import db
from app.orm import AnalysisResult, CaptureRecord, FlowRecord, PacketRecord
from app.services.capture_reader import iter_capture_packets
from app.services.flow_tracker import Flow, FlowTracker
from app.services.packet_extractor import ExtractedPacket, extract_packet
from app.services.traffic_stats import StatsAccumulator

logger = logging.getLogger(__name__)


class AnalysisError(Exception):
    """A failure whose message is safe to show to the capture's owner."""


def clear_results(capture_id: UUID) -> None:
    """Delete any stored analysis for a capture (retry, or cleanup after a failure)."""
    for model in (PacketRecord, FlowRecord, AnalysisResult):
        db.session.execute(db.delete(model).where(model.capture_id == capture_id))
    db.session.commit()


def analyze_file(capture_id: UUID, path: Path) -> int:
    """Analyse the stored capture and persist results. Returns the packet count."""
    batch_size = current_app.config["PACKET_BATCH_SIZE"]
    max_packets = current_app.config["MAX_PACKETS_PER_CAPTURE"]

    clear_results(capture_id)
    tracker = FlowTracker()
    stats = StatsAccumulator()
    batch: list[dict] = []
    count = 0

    for count, scapy_packet in enumerate(iter_capture_packets(path), start=1):
        if count > max_packets:
            raise AnalysisError(f"Capture exceeds the limit of {max_packets} packets.")
        extracted = extract_packet(scapy_packet, count, capture_id)
        flow_id, is_retransmission = tracker.observe(extracted)
        stats.observe(extracted, is_retransmission)
        batch.append(_packet_row(extracted, flow_id, is_retransmission))
        if len(batch) >= batch_size:
            _insert(PacketRecord, batch)
            _report_progress(capture_id, count)
            batch = []
    if batch:
        _insert(PacketRecord, batch)

    flows = tracker.flows
    for start in range(0, len(flows), batch_size):
        _insert(FlowRecord, [_flow_row(capture_id, f) for f in flows[start : start + batch_size]])

    result = stats.finalize(flows)
    db.session.add(
        AnalysisResult(capture_id=capture_id, summary=result["summary"], **result["columns"])
    )
    db.session.commit()
    logger.info("Analysed capture %s: %d packets, %d flows", capture_id, count, len(flows))
    return count


def _report_progress(capture_id: UUID, packets_so_far: int) -> None:
    """Expose live progress: clients polling the status endpoint see this count grow."""
    db.session.execute(
        db.update(CaptureRecord)
        .where(CaptureRecord.id == capture_id)
        .values(packet_count=packets_so_far)
    )
    db.session.commit()


def _insert(model, rows: list[dict]) -> None:
    db.session.execute(db.insert(model), rows)
    db.session.commit()


def _packet_row(ex: ExtractedPacket, flow_id: int | None, is_retransmission: bool) -> dict:
    p = ex.packet
    return {
        "capture_id": p.capture_id,
        "packet_number": p.packet_number,
        "timestamp": p.timestamp,
        "captured_length": p.captured_length,
        "original_length": p.original_length,
        "source_mac": p.source_mac,
        "destination_mac": p.destination_mac,
        "ether_type": p.ether_type,
        "vlan_id": p.vlan_id,
        "source_ip": str(p.source_ip) if p.source_ip is not None else None,
        "destination_ip": str(p.destination_ip) if p.destination_ip is not None else None,
        "ip_version": p.ip_version,
        "ttl_or_hop_limit": p.ttl_or_hop_limit,
        "protocol_number": p.transport_protocol.number if p.transport_protocol else None,
        "transport_protocol": p.transport_protocol.name if p.transport_protocol else None,
        "application_protocol": p.application_protocol,
        "protocol": ex.label,
        "source_port": p.source_port,
        "destination_port": p.destination_port,
        "tcp_flags": p.tcp_flags,
        "tcp_sequence_number": p.tcp_sequence_number,
        "tcp_acknowledgement_number": p.tcp_acknowledgement_number,
        "udp_length": p.udp_length,
        "payload_length": ex.payload_length,
        "flow_id": flow_id,
        "is_retransmission": is_retransmission,
        "malformed_reason": ex.malformed_reason,
        "application_metadata": p.application_metadata,
    }


def _flow_row(capture_id: UUID, f: Flow) -> dict:
    return {
        "capture_id": capture_id,
        "flow_id": f.flow_id,
        "protocol_number": f.protocol_number,
        "protocol": f.protocol_name,
        "application_protocol": f.application_protocol,
        "endpoint_a_ip": f.a_ip,
        "endpoint_a_port": f.a_port,
        "endpoint_b_ip": f.b_ip,
        "endpoint_b_port": f.b_port,
        "first_seen": f.first_seen,
        "last_seen": f.last_seen,
        "duration_seconds": f.duration_seconds,
        "packets_total": f.packets_total,
        "packets_a_to_b": f.packets_ab,
        "packets_b_to_a": f.packets_ba,
        "bytes_total": f.bytes_total,
        "bytes_a_to_b": f.bytes_ab,
        "bytes_b_to_a": f.bytes_ba,
        "retransmissions": f.retransmissions,
        "handshake_rtt_ms": f.handshake_rtt_ms,
        "jitter_ms": f.jitter_ms,
    }
