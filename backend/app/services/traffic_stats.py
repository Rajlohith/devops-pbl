"""Capture-level statistics accumulated packet by packet (constant memory per packet).

Pure logic. Memory grows with the number of distinct IPs, protocols and seconds spanned,
not with the number of packets.
"""

import math
from datetime import datetime, timezone

import pandas as pd

from app.services.flow_tracker import Flow
from app.services.packet_extractor import ExtractedPacket

# Candidate chart bucket widths in seconds; the smallest giving <= MAX_POINTS is used.
_BUCKETS = (1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 21600, 43200, 86400)
MAX_POINTS = 300


class StatsAccumulator:
    def __init__(self) -> None:
        self.packets = 0
        self.bytes = 0
        self.malformed = 0
        self.min_size: int | None = None
        self.max_size: int | None = None
        self.first: datetime | None = None
        self.last: datetime | None = None
        self.ips: set[str] = set()
        self.transport: dict[str, list[int]] = {}
        self.application: dict[str, list[int]] = {}
        self.tcp_packets = 0
        self.retransmissions = 0
        self._bins: dict[int, list[int]] = {}

    def observe(self, ex: ExtractedPacket, is_retransmission: bool) -> None:
        p = ex.packet
        size = p.original_length
        self.packets += 1
        self.bytes += size
        self.min_size = size if self.min_size is None else min(self.min_size, size)
        self.max_size = size if self.max_size is None else max(self.max_size, size)
        if ex.malformed_reason:
            self.malformed += 1
        if self.first is None or p.timestamp < self.first:
            self.first = p.timestamp
        if self.last is None or p.timestamp > self.last:
            self.last = p.timestamp
        if p.source_ip is not None:
            self.ips.add(str(p.source_ip))
        if p.destination_ip is not None:
            self.ips.add(str(p.destination_ip))

        if p.transport_protocol is not None:
            name = p.transport_protocol.name or f"Proto {p.transport_protocol.number}"
        else:
            name = ex.label  # non-IP traffic, e.g. ARP
        _add(self.transport, name, size)
        if p.application_protocol:
            _add(self.application, p.application_protocol, size)
        if p.tcp_flags is not None:
            self.tcp_packets += 1
            if is_retransmission:
                self.retransmissions += 1

        _add(self._bins, int(p.timestamp.timestamp()), size)

    def finalize(self, flows: list[Flow]) -> dict:
        """Return {"columns": scalar fields, "summary": JSON-serialisable detail}."""
        duration = (self.last - self.first).total_seconds() if self.first else None
        rate_ok = bool(duration and duration > 0)
        peak_pps = max((b[0] for b in self._bins.values()), default=None)
        peak_bps = max((b[1] * 8 for b in self._bins.values()), default=None)

        performance = {
            "duration_seconds": duration,
            "avg_packet_size_bytes": self.bytes / self.packets if self.packets else None,
            "min_packet_size_bytes": self.min_size,
            "max_packet_size_bytes": self.max_size,
            "avg_packets_per_second": self.packets / duration if rate_ok else None,
            "avg_throughput_bps": self.bytes * 8 / duration if rate_ok else None,
            "peak_packets_per_second": peak_pps,
            "peak_throughput_bps": peak_bps,
            "timeseries": self._timeseries(),
        }
        return {
            "columns": {
                "total_packets": self.packets,
                "total_bytes": self.bytes,
                "unique_ips": len(self.ips),
                "flow_count": len(flows),
                "malformed_packets": self.malformed,
                "first_timestamp": self.first,
                "last_timestamp": self.last,
                "duration_seconds": duration,
            },
            "summary": {
                "protocols": {
                    "transport": self._protocol_rows(self.transport),
                    "application": self._protocol_rows(self.application),
                },
                "performance": performance,
                "tcp": {
                    "packets": self.tcp_packets,
                    "retransmissions": self.retransmissions,
                    "retransmission_rate": (
                        self.retransmissions / self.tcp_packets if self.tcp_packets else None
                    ),
                },
                "latency": {
                    "handshake_rtt_ms": _distribution(
                        [f.handshake_rtt_ms for f in flows if f.handshake_rtt_ms is not None]
                    ),
                    "flow_jitter_ms": _distribution(
                        [f.jitter_ms for f in flows if f.jitter_ms is not None]
                    ),
                },
            },
        }

    def _protocol_rows(self, counters: dict[str, list[int]]) -> list[dict]:
        rows = [
            {
                "protocol": name,
                "packets": pk,
                "bytes": by,
                "packet_percent": 100 * pk / self.packets,
                "byte_percent": 100 * by / self.bytes if self.bytes else 0.0,
            }
            for name, (pk, by) in counters.items()
        ]
        return sorted(rows, key=lambda r: (-r["bytes"], r["protocol"]))

    def _timeseries(self) -> dict:
        if not self._bins:
            return {"bucket_seconds": None, "points": []}
        start, end = min(self._bins), max(self._bins)
        span = end - start + 1
        bucket = next((b for b in _BUCKETS if math.ceil(span / b) <= MAX_POINTS), _BUCKETS[-1])
        count = (end - start) // bucket + 1

        frame = pd.DataFrame.from_dict(self._bins, orient="index", columns=["packets", "bytes"])
        frame["bucket"] = (frame.index - start) // bucket
        grouped = frame.groupby("bucket")[["packets", "bytes"]].sum()
        grouped = grouped.reindex(range(count), fill_value=0).astype(int)  # keep idle gaps as zeros

        points = []
        for index, row in enumerate(grouped.itertuples()):
            points.append(
                {
                    "time": datetime.fromtimestamp(start + index * bucket, tz=timezone.utc).isoformat(),
                    "packets": int(row.packets),
                    "bytes": int(row.bytes),
                    "packets_per_second": row.packets / bucket,
                    "bits_per_second": row.bytes * 8 / bucket,
                }
            )
        return {"bucket_seconds": bucket, "points": points}


def _add(counters: dict, key, size: int) -> None:
    entry = counters.get(key)
    if entry is None:
        counters[key] = [1, size]
    else:
        entry[0] += 1
        entry[1] += size


def _distribution(values: list[float]) -> dict | None:
    if not values:
        return None
    series = pd.Series(values, dtype="float64")
    return {
        "count": int(series.size),
        "min": float(series.min()),
        "mean": float(series.mean()),
        "median": float(series.median()),
        "p95": float(series.quantile(0.95)),
        "max": float(series.max()),
    }
