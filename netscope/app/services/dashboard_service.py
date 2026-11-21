"""Cross-capture aggregates for the dashboard and for capture comparison.

Everything is computed from the user's own persisted analysis; nothing is cached or
hard-coded, so the numbers always reflect the captures that currently exist.
"""

from uuid import UUID

from sqlalchemy import func

from app.extensions import db
from app.models.capture import CaptureStatus
from app.orm import AnalysisResult, CaptureRecord, PacketRecord, User
from app.orm.user import iso_utc

RECENT_SESSIONS = 8
RECENT_TRAFFIC = 10
PROTOCOL_CAPTURE_LIMIT = 100  # most recent analysed captures that feed the distribution


def unique_ips_for_captures(*conditions) -> set[str]:
    """Distinct source/destination addresses across the packets matching conditions."""
    sources = db.select(PacketRecord.source_ip.label("ip")).where(
        PacketRecord.source_ip.is_not(None), *conditions
    )
    destinations = db.select(PacketRecord.destination_ip.label("ip")).where(
        PacketRecord.destination_ip.is_not(None), *conditions
    )
    union = sources.union(destinations).subquery()
    return {row[0] for row in db.session.execute(db.select(union.c.ip))}


def build_dashboard(user: User) -> dict:
    owned = CaptureRecord.owner_id == user.id

    status_counts = {s.value: 0 for s in CaptureStatus}
    for status, count in db.session.execute(
        db.select(CaptureRecord.status, func.count()).where(owned).group_by(CaptureRecord.status)
    ):
        status_counts[status.value] = count

    packets, data_bytes, flows = db.session.execute(
        db.select(
            func.coalesce(func.sum(AnalysisResult.total_packets), 0),
            func.coalesce(func.sum(AnalysisResult.total_bytes), 0),
            func.coalesce(func.sum(AnalysisResult.flow_count), 0),
        )
        .join(CaptureRecord, CaptureRecord.id == AnalysisResult.capture_id)
        .where(owned)
    ).one()

    # Distinct across all of the user's captures (an IP seen in two captures counts once).
    owned_ids = db.select(CaptureRecord.id).where(owned)
    unique_ips = len(unique_ips_for_captures(PacketRecord.capture_id.in_(owned_ids)))

    recent = db.session.execute(
        db.select(CaptureRecord, AnalysisResult)
        .outerjoin(AnalysisResult, AnalysisResult.capture_id == CaptureRecord.id)
        .where(owned)
        .order_by(CaptureRecord.uploaded_at.desc(), CaptureRecord.id)
        .limit(RECENT_SESSIONS)
    ).all()

    traffic_rows = db.session.execute(
        db.select(CaptureRecord, AnalysisResult)
        .join(AnalysisResult, AnalysisResult.capture_id == CaptureRecord.id)
        .where(owned)
        .order_by(CaptureRecord.uploaded_at.desc(), CaptureRecord.id)
        .limit(RECENT_TRAFFIC)
    ).all()

    summaries = db.session.execute(
        db.select(AnalysisResult.summary)
        .join(CaptureRecord, CaptureRecord.id == AnalysisResult.capture_id)
        .where(owned)
        .order_by(CaptureRecord.uploaded_at.desc())
        .limit(PROTOCOL_CAPTURE_LIMIT)
    ).scalars().all()

    return {
        "totals": {
            "captures": sum(status_counts.values()),
            "packets": int(packets),
            "bytes": int(data_bytes),
            "unique_ips": unique_ips,
            "flows": int(flows),
        },
        "status_counts": status_counts,
        "in_progress": status_counts["pending"] + status_counts["processing"],
        "recent_sessions": [_session_row(c, r) for c, r in recent],
        # Oldest first, so charts read left to right in time.
        "recent_traffic": [_session_row(c, r) for c, r in reversed(traffic_rows)],
        "protocols": {
            "transport": _merge_protocols(s["protocols"]["transport"] for s in summaries),
            "application": _merge_protocols(s["protocols"]["application"] for s in summaries),
            "captures_included": len(summaries),
        },
    }


def _session_row(capture: CaptureRecord, result: AnalysisResult | None) -> dict:
    return {
        "id": str(capture.id),
        "filename": capture.original_filename,
        "status": capture.status.value,
        "uploaded_at": iso_utc(capture.uploaded_at),
        "file_size_bytes": capture.file_size_bytes,
        "packets": result.total_packets if result else None,
        "bytes": result.total_bytes if result else None,
        "flows": result.flow_count if result else None,
        "error_message": capture.error_message,
    }


def _merge_protocols(per_capture) -> list[dict]:
    merged: dict[str, list[int]] = {}
    for rows in per_capture:
        for row in rows:
            entry = merged.setdefault(row["protocol"], [0, 0])
            entry[0] += row["packets"]
            entry[1] += row["bytes"]
    total_packets = sum(p for p, _ in merged.values())
    total_bytes = sum(b for _, b in merged.values())
    result = [
        {
            "protocol": name,
            "packets": packets,
            "bytes": nbytes,
            "packet_percent": 100 * packets / total_packets if total_packets else 0.0,
            "byte_percent": 100 * nbytes / total_bytes if total_bytes else 0.0,
        }
        for name, (packets, nbytes) in merged.items()
    ]
    return sorted(result, key=lambda r: (-r["bytes"], r["protocol"]))


# ---------------------------------------------------------------------------- comparison

_METRICS = (
    # key, label, unit, getter(totals, summary) -> value
    ("total_packets", "Packets", "count", lambda t, s: t["total_packets"]),
    ("total_bytes", "Data transferred", "bytes", lambda t, s: t["total_bytes"]),
    ("duration_seconds", "Duration", "seconds", lambda t, s: t["duration_seconds"]),
    ("unique_ips", "Unique IP addresses", "count", lambda t, s: t["unique_ips"]),
    ("flow_count", "Flows", "count", lambda t, s: t["flow_count"]),
    ("malformed_packets", "Malformed packets", "count", lambda t, s: t["malformed_packets"]),
    ("avg_packet_size", "Average packet size", "bytes", lambda t, s: s["performance"]["avg_packet_size_bytes"]),
    ("avg_pps", "Average packets/s", "pps", lambda t, s: s["performance"]["avg_packets_per_second"]),
    ("avg_bps", "Average throughput", "bps", lambda t, s: s["performance"]["avg_throughput_bps"]),
    ("peak_bps", "Peak throughput", "bps", lambda t, s: s["performance"]["peak_throughput_bps"]),
    ("retransmission_rate", "TCP retransmission rate", "ratio", lambda t, s: s["tcp"]["retransmission_rate"]),
    ("rtt_mean_ms", "Mean handshake RTT", "ms", lambda t, s: (s["latency"]["handshake_rtt_ms"] or {}).get("mean")),
)
_IP_SAMPLE = 25


def compare_captures(a: CaptureRecord, b: CaptureRecord) -> dict:
    results = {
        r.capture_id: r
        for r in db.session.execute(
            db.select(AnalysisResult).where(AnalysisResult.capture_id.in_([a.id, b.id]))
        ).scalars()
    }
    ra, rb = results[a.id], results[b.id]
    ta, tb = ra.totals(), rb.totals()

    metrics = []
    for key, label, unit, getter in _METRICS:
        va, vb = getter(ta, ra.summary), getter(tb, rb.summary)
        delta = vb - va if va is not None and vb is not None else None
        metrics.append(
            {
                "key": key,
                "label": label,
                "unit": unit,
                "a": va,
                "b": vb,
                "delta": delta,
                "delta_percent": 100 * delta / va if delta is not None and va else None,
            }
        )

    protocols: dict[str, dict] = {}
    for side, result in (("a", ra), ("b", rb)):
        for row in result.summary["protocols"]["transport"]:
            entry = protocols.setdefault(
                row["protocol"], {"protocol": row["protocol"], "a": None, "b": None}
            )
            entry[side] = {"packets": row["packets"], "bytes": row["bytes"]}

    ips_a = unique_ips_for_captures(PacketRecord.capture_id == a.id)
    ips_b = unique_ips_for_captures(PacketRecord.capture_id == b.id)
    shared, only_a, only_b = ips_a & ips_b, ips_a - ips_b, ips_b - ips_a

    def side(capture: CaptureRecord, totals: dict) -> dict:
        return {
            "id": str(capture.id),
            "filename": capture.original_filename,
            "uploaded_at": iso_utc(capture.uploaded_at),
            "first_timestamp": totals["first_timestamp"],
        }

    return {
        "a": side(a, ta),
        "b": side(b, tb),
        "metrics": metrics,
        "protocols": sorted(
            protocols.values(),
            key=lambda p: -((p["a"] or {}).get("bytes", 0) + (p["b"] or {}).get("bytes", 0)),
        ),
        "ips": {
            "shared": len(shared),
            "only_a": len(only_a),
            "only_b": len(only_b),
            "sample": {
                "shared": sorted(shared)[:_IP_SAMPLE],
                "only_a": sorted(only_a)[:_IP_SAMPLE],
                "only_b": sorted(only_b)[:_IP_SAMPLE],
            },
        },
    }


def completed_owned_capture(user: User, capture_id: UUID):
    """(capture, error) where error is 'not_found' or the capture's non-completed status."""
    record = db.session.execute(
        db.select(CaptureRecord).filter_by(id=capture_id, owner_id=user.id)
    ).scalar_one_or_none()
    if record is None:
        return None, "not_found"
    if record.status != CaptureStatus.COMPLETED:
        return None, record.status.value
    return record, None
