"""Persisted Phase 4 analytics: TCP connections, indicators, DNS, addresses and findings."""

import uuid
from datetime import datetime

from sqlalchemy.orm import Mapped, mapped_column

from app.extensions import db
from app.orm.analysis import _capture_fk
from app.orm.user import iso_utc, utcnow
from app.services.analytics.common import SEVERITY_ORDER


class AdvancedAnalysis(db.Model):
    """Aggregate document (KPIs, distributions, definitions, thresholds) per capture."""

    __tablename__ = "advanced_analyses"

    capture_id: Mapped[uuid.UUID] = mapped_column(db.Uuid, _capture_fk(), primary_key=True)
    schema_version: Mapped[int] = mapped_column(db.Integer)
    document: Mapped[dict] = mapped_column(db.JSON)
    created_at: Mapped[datetime] = mapped_column(db.DateTime(timezone=True), default=utcnow)


class TcpConnectionRecord(db.Model):
    __tablename__ = "tcp_connections"
    __table_args__ = (
        db.Index("ix_tcpconn_capture_state", "capture_id", "state"),
        db.Index("ix_tcpconn_capture_duration", "capture_id", "duration_seconds"),
        db.Index("ix_tcpconn_capture_zerowin", "capture_id", "zero_window_events"),
        db.Index("ix_tcpconn_capture_flow", "capture_id", "flow_id"),
    )

    capture_id: Mapped[uuid.UUID] = mapped_column(db.Uuid, _capture_fk(), primary_key=True)
    connection_id: Mapped[int] = mapped_column(db.Integer, primary_key=True, autoincrement=False)
    flow_id: Mapped[int] = mapped_column(db.Integer)
    ip_version: Mapped[int | None] = mapped_column(db.SmallInteger)
    endpoint_a_ip: Mapped[str] = mapped_column(db.String(45))
    endpoint_a_port: Mapped[int | None] = mapped_column(db.Integer)
    endpoint_b_ip: Mapped[str] = mapped_column(db.String(45))
    endpoint_b_port: Mapped[int | None] = mapped_column(db.Integer)
    initiator_known: Mapped[bool] = mapped_column(db.Boolean)
    state: Mapped[str] = mapped_column(db.String(16))
    incomplete_reason: Mapped[str | None] = mapped_column(db.String(16))
    first_seen: Mapped[datetime] = mapped_column(db.DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(db.DateTime(timezone=True))
    first_packet: Mapped[int] = mapped_column(db.Integer)
    last_packet: Mapped[int] = mapped_column(db.Integer)
    duration_seconds: Mapped[float] = mapped_column(db.Float)
    syn_packet: Mapped[int | None] = mapped_column(db.Integer)
    syn_retransmissions: Mapped[int] = mapped_column(db.Integer)
    syn_to_synack_ms: Mapped[float | None] = mapped_column(db.Float)
    synack_to_ack_ms: Mapped[float | None] = mapped_column(db.Float)
    handshake_ms: Mapped[float | None] = mapped_column(db.Float)
    termination: Mapped[str] = mapped_column(db.String(16))
    terminated_by: Mapped[str | None] = mapped_column(db.String(4))
    capture_truncated: Mapped[bool] = mapped_column(db.Boolean)
    truncation_reasons: Mapped[list] = mapped_column(db.JSON)
    packets: Mapped[int] = mapped_column(db.Integer)
    bytes: Mapped[int] = mapped_column(db.BigInteger)
    packets_a_to_b: Mapped[int] = mapped_column(db.Integer)
    packets_b_to_a: Mapped[int] = mapped_column(db.Integer)
    bytes_a_to_b: Mapped[int] = mapped_column(db.BigInteger)
    bytes_b_to_a: Mapped[int] = mapped_column(db.BigInteger)
    rst_packets: Mapped[int] = mapped_column(db.Integer)
    rst_from_a: Mapped[int] = mapped_column(db.Integer)
    rst_from_b: Mapped[int] = mapped_column(db.Integer)
    rst_evidence: Mapped[list] = mapped_column(db.JSON)
    retransmissions: Mapped[int] = mapped_column(db.Integer)
    duplicate_acks: Mapped[int] = mapped_column(db.Integer)
    zero_window_events: Mapped[int] = mapped_column(db.Integer)
    window_scaling: Mapped[str] = mapped_column(db.String(40))
    window: Mapped[dict] = mapped_column(db.JSON)

    def to_dict(self, detail: bool = False) -> dict:
        data = {
            "connection_id": self.connection_id,
            "flow_id": self.flow_id,
            "ip_version": self.ip_version,
            "endpoint_a": {"ip": self.endpoint_a_ip, "port": self.endpoint_a_port},
            "endpoint_b": {"ip": self.endpoint_b_ip, "port": self.endpoint_b_port},
            "initiator_known": self.initiator_known,
            "state": self.state,
            "incomplete_reason": self.incomplete_reason,
            "first_seen": iso_utc(self.first_seen),
            "last_seen": iso_utc(self.last_seen),
            "first_packet": self.first_packet,
            "last_packet": self.last_packet,
            "duration_seconds": self.duration_seconds,
            "syn_packet": self.syn_packet,
            "syn_retransmissions": self.syn_retransmissions,
            "syn_to_synack_ms": self.syn_to_synack_ms,
            "synack_to_ack_ms": self.synack_to_ack_ms,
            "handshake_ms": self.handshake_ms,
            "termination": self.termination,
            "terminated_by": self.terminated_by,
            "capture_truncated": self.capture_truncated,
            "truncation_reasons": self.truncation_reasons,
            "packets": self.packets,
            "bytes": self.bytes,
            "packets_a_to_b": self.packets_a_to_b,
            "packets_b_to_a": self.packets_b_to_a,
            "bytes_a_to_b": self.bytes_a_to_b,
            "bytes_b_to_a": self.bytes_b_to_a,
            "rst_packets": self.rst_packets,
            "retransmissions": self.retransmissions,
            "duplicate_acks": self.duplicate_acks,
            "zero_window_events": self.zero_window_events,
            "window_scaling": self.window_scaling,
        }
        if detail:
            data["rst_from_a"] = self.rst_from_a
            data["rst_from_b"] = self.rst_from_b
            data["rst_evidence"] = self.rst_evidence
            data["window"] = self.window
        return data


class TcpIndicatorRecord(db.Model):
    __tablename__ = "tcp_indicators"
    __table_args__ = (
        db.Index("ix_tcpind_capture_type", "capture_id", "type"),
        db.Index("ix_tcpind_capture_severity", "capture_id", "severity_rank"),
        db.Index("ix_tcpind_capture_conn", "capture_id", "connection_id"),
    )

    capture_id: Mapped[uuid.UUID] = mapped_column(db.Uuid, _capture_fk(), primary_key=True)
    indicator_id: Mapped[int] = mapped_column(db.Integer, primary_key=True, autoincrement=False)
    connection_id: Mapped[int] = mapped_column(db.Integer)
    flow_id: Mapped[int] = mapped_column(db.Integer)
    endpoint_a: Mapped[str] = mapped_column(db.String(60))
    endpoint_b: Mapped[str] = mapped_column(db.String(60))
    type: Mapped[str] = mapped_column(db.String(24))
    side: Mapped[str] = mapped_column(db.String(1))
    count: Mapped[int] = mapped_column(db.Integer)
    first_packet: Mapped[int | None] = mapped_column(db.Integer)
    last_packet: Mapped[int | None] = mapped_column(db.Integer)
    severity: Mapped[str] = mapped_column(db.String(8))
    severity_rank: Mapped[int] = mapped_column(db.SmallInteger)
    confidence: Mapped[str] = mapped_column(db.String(8))
    evidence: Mapped[list] = mapped_column(db.JSON)
    detail: Mapped[dict] = mapped_column(db.JSON)

    def to_dict(self) -> dict:
        return {
            "indicator_id": self.indicator_id,
            "connection_id": self.connection_id,
            "flow_id": self.flow_id,
            "endpoint_a": self.endpoint_a,
            "endpoint_b": self.endpoint_b,
            "type": self.type,
            "sender": self.side,
            "packet_count": self.count,
            "first_packet": self.first_packet,
            "last_packet": self.last_packet,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "detail": self.detail,
        }


class DnsTransactionRecord(db.Model):
    __tablename__ = "dns_transactions"
    __table_args__ = (
        db.Index("ix_dns_capture_latency", "capture_id", "latency_ms"),
        db.Index("ix_dns_capture_status", "capture_id", "status"),
        db.Index("ix_dns_capture_rcode", "capture_id", "rcode"),
        db.Index("ix_dns_capture_server", "capture_id", "server_ip"),
        db.Index("ix_dns_capture_client", "capture_id", "client_ip"),
    )

    capture_id: Mapped[uuid.UUID] = mapped_column(db.Uuid, _capture_fk(), primary_key=True)
    transaction_id: Mapped[int] = mapped_column(db.Integer, primary_key=True, autoincrement=False)
    transport: Mapped[str] = mapped_column(db.String(3))
    client_ip: Mapped[str] = mapped_column(db.String(45))
    client_port: Mapped[int | None] = mapped_column(db.Integer)
    server_ip: Mapped[str] = mapped_column(db.String(45))
    server_port: Mapped[int | None] = mapped_column(db.Integer)
    dns_id: Mapped[int] = mapped_column(db.Integer)
    qname: Mapped[str | None] = mapped_column(db.String(255))
    qtype: Mapped[str | None] = mapped_column(db.String(12))
    question_count: Mapped[int] = mapped_column(db.Integer)
    questions: Mapped[list] = mapped_column(db.JSON)
    query_packet: Mapped[int | None] = mapped_column(db.Integer)
    response_packet: Mapped[int | None] = mapped_column(db.Integer)
    query_time: Mapped[datetime | None] = mapped_column(db.DateTime(timezone=True))
    response_time: Mapped[datetime | None] = mapped_column(db.DateTime(timezone=True))
    query_count: Mapped[int] = mapped_column(db.Integer)
    latency_ms: Mapped[float | None] = mapped_column(db.Float)
    latency_from_last_query_ms: Mapped[float | None] = mapped_column(db.Float)
    rcode: Mapped[int | None] = mapped_column(db.Integer)
    rcode_name: Mapped[str | None] = mapped_column(db.String(12))
    truncated: Mapped[bool] = mapped_column(db.Boolean)
    answer_count: Mapped[int | None] = mapped_column(db.Integer)
    status: Mapped[str] = mapped_column(db.String(32))
    note: Mapped[str | None] = mapped_column(db.String(120))

    def to_dict(self) -> dict:
        return {
            "transaction_id": self.transaction_id,
            "transport": self.transport,
            "client": {"ip": self.client_ip, "port": self.client_port},
            "server": {"ip": self.server_ip, "port": self.server_port},
            "dns_id": self.dns_id,
            "qname": self.qname,
            "qtype": self.qtype,
            "question_count": self.question_count,
            "questions": self.questions,
            "query_packet": self.query_packet,
            "response_packet": self.response_packet,
            "query_time": iso_utc(self.query_time),
            "response_time": iso_utc(self.response_time),
            "query_count": self.query_count,
            "latency_ms": self.latency_ms,
            "latency_from_last_query_ms": self.latency_from_last_query_ms,
            "rcode": self.rcode,
            "rcode_name": self.rcode_name,
            "truncated": self.truncated,
            "answer_count": self.answer_count,
            "status": self.status,
            "note": self.note,
        }


class IpTrafficRecord(db.Model):
    __tablename__ = "ip_traffic"
    __table_args__ = (
        db.Index("ix_iptraffic_capture_sent", "capture_id", "sent_bytes"),
        db.Index("ix_iptraffic_capture_recv", "capture_id", "received_bytes"),
    )

    capture_id: Mapped[uuid.UUID] = mapped_column(db.Uuid, _capture_fk(), primary_key=True)
    ip: Mapped[str] = mapped_column(db.String(45), primary_key=True)
    ip_version: Mapped[int | None] = mapped_column(db.SmallInteger)
    sent_packets: Mapped[int] = mapped_column(db.Integer)
    sent_bytes: Mapped[int] = mapped_column(db.BigInteger)
    received_packets: Mapped[int] = mapped_column(db.Integer)
    received_bytes: Mapped[int] = mapped_column(db.BigInteger)

    def as_row(self) -> dict:
        return {
            "ip": self.ip, "ip_version": self.ip_version,
            "sent_packets": self.sent_packets, "sent_bytes": self.sent_bytes,
            "received_packets": self.received_packets, "received_bytes": self.received_bytes,
        }


class IpPairRecord(db.Model):
    """Directional address-pair totals; lets direction be re-classified for any local config."""

    __tablename__ = "ip_pairs"

    capture_id: Mapped[uuid.UUID] = mapped_column(db.Uuid, _capture_fk(), primary_key=True)
    source_ip: Mapped[str] = mapped_column(db.String(45), primary_key=True)
    destination_ip: Mapped[str] = mapped_column(db.String(45), primary_key=True)
    packets: Mapped[int] = mapped_column(db.Integer)
    bytes: Mapped[int] = mapped_column(db.BigInteger)


class AnomalyFindingRecord(db.Model):
    __tablename__ = "anomaly_findings"
    __table_args__ = (
        db.Index("ix_anomaly_capture_severity", "capture_id", "severity_rank"),
        db.Index("ix_anomaly_capture_rule", "capture_id", "rule"),
    )

    capture_id: Mapped[uuid.UUID] = mapped_column(db.Uuid, _capture_fk(), primary_key=True)
    finding_id: Mapped[int] = mapped_column(db.Integer, primary_key=True, autoincrement=False)
    rule: Mapped[str] = mapped_column(db.String(40))
    name: Mapped[str] = mapped_column(db.String(120))
    severity: Mapped[str] = mapped_column(db.String(8))
    severity_rank: Mapped[int] = mapped_column(db.SmallInteger)
    description: Mapped[str] = mapped_column(db.Text)
    reason: Mapped[str] = mapped_column(db.Text)
    evidence: Mapped[dict] = mapped_column(db.JSON)
    affected_ips: Mapped[list] = mapped_column(db.JSON)
    affected_flows: Mapped[list] = mapped_column(db.JSON)
    packet_refs: Mapped[list] = mapped_column(db.JSON)
    thresholds: Mapped[dict] = mapped_column(db.JSON)
    note: Mapped[str] = mapped_column(db.String(200))

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "rule": self.rule,
            "name": self.name,
            "severity": self.severity,
            "description": self.description,
            "reason": self.reason,
            "evidence": self.evidence,
            "affected_ips": self.affected_ips,
            "affected_flows": self.affected_flows,
            "packet_refs": self.packet_refs,
            "thresholds": self.thresholds,
            "note": self.note,
        }


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER[severity]
