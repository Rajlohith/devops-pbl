"""Persisted analysis output: packets, flows and the per-capture summary."""

import uuid
from datetime import datetime

from sqlalchemy.orm import Mapped, mapped_column

from app.extensions import db
from app.orm.capture import _aware
from app.orm.user import iso_utc, utcnow


def _capture_fk():
    return db.ForeignKey("captures.id", ondelete="CASCADE")


class PacketRecord(db.Model):
    __tablename__ = "packets"
    __table_args__ = (
        db.Index("ix_packets_capture_timestamp", "capture_id", "timestamp"),
        db.Index("ix_packets_capture_src", "capture_id", "source_ip"),
        db.Index("ix_packets_capture_dst", "capture_id", "destination_ip"),
        db.Index("ix_packets_capture_protocol", "capture_id", "protocol"),
        db.Index("ix_packets_capture_flow", "capture_id", "flow_id"),
    )

    capture_id: Mapped[uuid.UUID] = mapped_column(db.Uuid, _capture_fk(), primary_key=True)
    packet_number: Mapped[int] = mapped_column(db.Integer, primary_key=True, autoincrement=False)
    timestamp: Mapped[datetime] = mapped_column(db.DateTime(timezone=True))
    captured_length: Mapped[int] = mapped_column(db.Integer)
    original_length: Mapped[int] = mapped_column(db.Integer)

    source_mac: Mapped[str | None] = mapped_column(db.String(17))
    destination_mac: Mapped[str | None] = mapped_column(db.String(17))
    ether_type: Mapped[int | None] = mapped_column(db.Integer)
    vlan_id: Mapped[int | None] = mapped_column(db.Integer)

    source_ip: Mapped[str | None] = mapped_column(db.String(45))
    destination_ip: Mapped[str | None] = mapped_column(db.String(45))
    ip_version: Mapped[int | None] = mapped_column(db.SmallInteger)
    ttl_or_hop_limit: Mapped[int | None] = mapped_column(db.SmallInteger)

    protocol_number: Mapped[int | None] = mapped_column(db.SmallInteger)
    transport_protocol: Mapped[str | None] = mapped_column(db.String(16))
    application_protocol: Mapped[str | None] = mapped_column(db.String(16))
    protocol: Mapped[str] = mapped_column(db.String(24))  # highest identified layer

    source_port: Mapped[int | None] = mapped_column(db.Integer)
    destination_port: Mapped[int | None] = mapped_column(db.Integer)
    tcp_flags: Mapped[str | None] = mapped_column(db.String(12))
    tcp_sequence_number: Mapped[int | None] = mapped_column(db.BigInteger)
    tcp_acknowledgement_number: Mapped[int | None] = mapped_column(db.BigInteger)
    tcp_window: Mapped[int | None] = mapped_column(db.Integer)
    tcp_window_scale: Mapped[int | None] = mapped_column(db.SmallInteger)
    udp_length: Mapped[int | None] = mapped_column(db.Integer)
    payload_length: Mapped[int | None] = mapped_column(db.Integer)

    flow_id: Mapped[int | None] = mapped_column(db.Integer)
    is_retransmission: Mapped[bool] = mapped_column(db.Boolean, default=False)
    malformed_reason: Mapped[str | None] = mapped_column(db.String(64))
    application_metadata: Mapped[dict | None] = mapped_column(db.JSON)

    def to_dict(self) -> dict:
        return {
            "packet_number": self.packet_number,
            "timestamp": iso_utc(self.timestamp),
            "captured_length": self.captured_length,
            "original_length": self.original_length,
            "protocol": self.protocol,
            "transport_protocol": self.transport_protocol,
            "application_protocol": self.application_protocol,
            "source_mac": self.source_mac,
            "destination_mac": self.destination_mac,
            "ether_type": self.ether_type,
            "vlan_id": self.vlan_id,
            "ip_version": self.ip_version,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "ttl_or_hop_limit": self.ttl_or_hop_limit,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "tcp_flags": self.tcp_flags,
            "tcp_sequence_number": self.tcp_sequence_number,
            "tcp_acknowledgement_number": self.tcp_acknowledgement_number,
            "tcp_window": self.tcp_window,
            "tcp_window_scale": self.tcp_window_scale,
            "udp_length": self.udp_length,
            "payload_length": self.payload_length,
            "flow_id": self.flow_id,
            "is_retransmission": bool(self.is_retransmission),
            "malformed_reason": self.malformed_reason,
            "application_metadata": self.application_metadata,
        }


class FlowRecord(db.Model):
    __tablename__ = "flows"
    __table_args__ = (
        db.Index("ix_flows_capture_bytes", "capture_id", "bytes_total"),
        db.Index("ix_flows_capture_packets", "capture_id", "packets_total"),
    )

    capture_id: Mapped[uuid.UUID] = mapped_column(db.Uuid, _capture_fk(), primary_key=True)
    flow_id: Mapped[int] = mapped_column(db.Integer, primary_key=True, autoincrement=False)
    protocol_number: Mapped[int] = mapped_column(db.SmallInteger)
    protocol: Mapped[str] = mapped_column(db.String(16))
    application_protocol: Mapped[str | None] = mapped_column(db.String(16))
    endpoint_a_ip: Mapped[str] = mapped_column(db.String(45))
    endpoint_a_port: Mapped[int | None] = mapped_column(db.Integer)
    endpoint_b_ip: Mapped[str] = mapped_column(db.String(45))
    endpoint_b_port: Mapped[int | None] = mapped_column(db.Integer)
    first_seen: Mapped[datetime] = mapped_column(db.DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(db.DateTime(timezone=True))
    duration_seconds: Mapped[float] = mapped_column(db.Float)
    packets_total: Mapped[int] = mapped_column(db.Integer)
    packets_a_to_b: Mapped[int] = mapped_column(db.Integer)
    packets_b_to_a: Mapped[int] = mapped_column(db.Integer)
    bytes_total: Mapped[int] = mapped_column(db.BigInteger)
    bytes_a_to_b: Mapped[int] = mapped_column(db.BigInteger)
    bytes_b_to_a: Mapped[int] = mapped_column(db.BigInteger)
    retransmissions: Mapped[int] = mapped_column(db.Integer, default=0)
    handshake_rtt_ms: Mapped[float | None] = mapped_column(db.Float)
    jitter_ms: Mapped[float | None] = mapped_column(db.Float)

    def to_dict(self) -> dict:
        return {
            "flow_id": self.flow_id,
            "protocol": self.protocol,
            "application_protocol": self.application_protocol,
            "endpoint_a": {"ip": self.endpoint_a_ip, "port": self.endpoint_a_port},
            "endpoint_b": {"ip": self.endpoint_b_ip, "port": self.endpoint_b_port},
            "first_seen": iso_utc(self.first_seen),
            "last_seen": iso_utc(self.last_seen),
            "duration_seconds": self.duration_seconds,
            "packets": {
                "total": self.packets_total,
                "a_to_b": self.packets_a_to_b,
                "b_to_a": self.packets_b_to_a,
            },
            "bytes": {
                "total": self.bytes_total,
                "a_to_b": self.bytes_a_to_b,
                "b_to_a": self.bytes_b_to_a,
            },
            "retransmissions": self.retransmissions,
            "handshake_rtt_ms": self.handshake_rtt_ms,
            "jitter_ms": self.jitter_ms,
        }


class AnalysisResult(db.Model):
    """One row per analysed capture. Scalars are columns so the dashboard can
    aggregate across captures in SQL; the rest is a JSON document."""

    __tablename__ = "analysis_results"

    capture_id: Mapped[uuid.UUID] = mapped_column(db.Uuid, _capture_fk(), primary_key=True)
    total_packets: Mapped[int] = mapped_column(db.Integer)
    total_bytes: Mapped[int] = mapped_column(db.BigInteger)
    unique_ips: Mapped[int] = mapped_column(db.Integer)
    flow_count: Mapped[int] = mapped_column(db.Integer)
    malformed_packets: Mapped[int] = mapped_column(db.Integer)
    first_timestamp: Mapped[datetime | None] = mapped_column(db.DateTime(timezone=True))
    last_timestamp: Mapped[datetime | None] = mapped_column(db.DateTime(timezone=True))
    duration_seconds: Mapped[float | None] = mapped_column(db.Float)
    summary: Mapped[dict] = mapped_column(db.JSON)
    created_at: Mapped[datetime] = mapped_column(db.DateTime(timezone=True), default=utcnow)

    def totals(self) -> dict:
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "unique_ips": self.unique_ips,
            "flow_count": self.flow_count,
            "malformed_packets": self.malformed_packets,
            "first_timestamp": iso_utc(self.first_timestamp),
            "last_timestamp": iso_utc(self.last_timestamp),
            "duration_seconds": self.duration_seconds,
        }
