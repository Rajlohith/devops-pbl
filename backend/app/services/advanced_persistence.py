"""Persist Phase 4 analytics produced by AdvancedAnalyzer (batched inserts)."""

from datetime import datetime, timezone
from uuid import UUID

from app.extensions import db
from app.orm import (
    AdvancedAnalysis, AnomalyFindingRecord, DnsTransactionRecord, IpPairRecord, IpTrafficRecord,
    TcpConnectionRecord, TcpIndicatorRecord,
)
from app.services.analytics.common import SEVERITY_ORDER
from app.services.analytics.engine import SCHEMA_VERSION, AdvancedResult

ADVANCED_MODELS = (
    TcpConnectionRecord, TcpIndicatorRecord, DnsTransactionRecord, IpTrafficRecord, IpPairRecord,
    AnomalyFindingRecord, AdvancedAnalysis,
)


def _dt(ts: float | None) -> datetime | None:
    return None if ts is None else datetime.fromtimestamp(ts, tz=timezone.utc)


def _insert(model, rows: list[dict], batch_size: int) -> None:
    for start in range(0, len(rows), batch_size):
        db.session.execute(db.insert(model), rows[start : start + batch_size])
        db.session.commit()


_CONN_COPY = (
    "connection_id flow_id ip_version endpoint_a_ip endpoint_a_port endpoint_b_ip endpoint_b_port "
    "initiator_known state incomplete_reason first_packet last_packet duration_seconds syn_packet "
    "syn_retransmissions syn_to_synack_ms synack_to_ack_ms handshake_ms termination terminated_by "
    "capture_truncated truncation_reasons packets bytes packets_a_to_b packets_b_to_a bytes_a_to_b "
    "bytes_b_to_a rst_packets rst_from_a rst_from_b rst_evidence retransmissions duplicate_acks "
    "zero_window_events window_scaling window"
).split()


def persist_advanced(capture_id: UUID, result: AdvancedResult, batch_size: int) -> None:
    cid = capture_id
    _insert(TcpConnectionRecord, [
        {"capture_id": cid, **{k: c[k] for k in _CONN_COPY},
         "first_seen": _dt(c["first_ts"]), "last_seen": _dt(c["last_ts"])}
        for c in result.connections
    ], batch_size)

    _insert(TcpIndicatorRecord, [
        {
            "capture_id": cid, "indicator_id": i, "connection_id": r["connection_id"],
            "flow_id": r["flow_id"], "endpoint_a": r["endpoint_a"][:60],
            "endpoint_b": r["endpoint_b"][:60], "type": r["type"], "side": r["side"],
            "count": r["count"], "first_packet": r["first_packet"], "last_packet": r["last_packet"],
            "severity": r["severity"], "severity_rank": SEVERITY_ORDER[r["severity"]],
            "confidence": r["confidence"], "evidence": r["evidence"], "detail": r["detail"],
        }
        for i, r in enumerate(result.indicators, start=1)
    ], batch_size)

    _insert(DnsTransactionRecord, [
        {
            "capture_id": cid, "transaction_id": t["transaction_id"], "transport": t["transport"],
            "client_ip": t["client_ip"], "client_port": t["client_port"],
            "server_ip": t["server_ip"], "server_port": t["server_port"], "dns_id": t["dns_id"],
            "qname": (t["qname"] or None) and t["qname"][:255], "qtype": t["qtype"],
            "question_count": t["question_count"], "questions": t["questions"],
            "query_packet": t["query_packet"], "response_packet": t["response_packet"],
            "query_time": _dt(t["query_ts"]), "response_time": _dt(t["response_ts"]),
            "query_count": t["query_count"], "latency_ms": t["latency_ms"],
            "latency_from_last_query_ms": t["latency_from_last_query_ms"],
            "rcode": t["rcode"], "rcode_name": t["rcode_name"], "truncated": t["truncated"],
            "answer_count": t["answer_count"], "status": t["status"],
            "note": (t["note"] or None) and t["note"][:120],
        }
        for t in result.dns_transactions
    ], batch_size)

    _insert(IpTrafficRecord, [{"capture_id": cid, **r} for r in result.ip_rows], batch_size)
    _insert(IpPairRecord, [{"capture_id": cid, **r} for r in result.pair_rows], batch_size)

    _insert(AnomalyFindingRecord, [
        {
            "capture_id": cid, "finding_id": f["finding_id"], "rule": f["rule"],
            "name": f["name"][:120], "severity": f["severity"],
            "severity_rank": SEVERITY_ORDER[f["severity"]], "description": f["description"],
            "reason": f["reason"], "evidence": f["evidence"], "affected_ips": f["affected_ips"],
            "affected_flows": f["affected_flows"], "packet_refs": f["packet_refs"],
            "thresholds": f["thresholds"], "note": f["note"][:200],
        }
        for f in result.findings
    ], batch_size)

    db.session.add(
        AdvancedAnalysis(capture_id=cid, schema_version=SCHEMA_VERSION, document=result.document)
    )
    db.session.commit()
