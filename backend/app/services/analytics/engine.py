"""Orchestrates the Phase 4 trackers alongside the existing flow/stat accumulators.

The analysis pipeline calls :meth:`AdvancedAnalyzer.observe` for each packet with the flow id
and retransmission flag FlowTracker already produced, then :meth:`finalize` once. Nothing here
re-reads the capture or duplicates flow reconstruction: connection tracking is keyed by the
existing flow ids and retransmissions are taken from FlowTracker, not recounted.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import tcp_diagnostics as diag
from .anomalies import (
    AnomalyInputs, AnomalyThresholds, ProtocolPortObserver, detect, findings_summary,
    thresholds_dict,
)
from .common import PacketView, ratio
from .dns_analytics import DnsConfig, DnsTracker
from .tcp_connections import TcpConnectionTracker, connection_row
from .traffic_intel import TrafficIntel

SCHEMA_VERSION = 1

DEFINITIONS = {
    "tcp_success_rate": (
        "Established connections / observable attempts. Observable attempts are connections whose "
        "initial SYN was captured (established + incomplete + refused). Connections seen only "
        "mid-stream are 'unclassified' and excluded. Null when there are no observable attempts."
    ),
    "tcp_incomplete": (
        "SYN seen but no completed handshake in the capture. NOT a confirmed failure: the "
        "packets may be filtered, answered elsewhere, or the capture may have ended."
    ),
    "tcp_refused": "SYN answered by an RST-ACK before any SYN-ACK: the only confirmed failure.",
    "tcp_handshake_ms": "First SYN to the completing client ACK (established connections only).",
    "tcp_observed_duration": "First to last captured packet of the connection; the true lifetime is "
                             "longer when the capture starts or ends mid-connection.",
    "dns_latency": "First query transmission to its response, matched on addresses, ports, "
                   "transaction id and transport. Only matched transactions are measured.",
    "dns_failure_rate": "Responses with a non-NOERROR RCODE / responses observed. Unanswered "
                        "queries are not part of this rate.",
    "dns_inferred_timeout": "An unanswered query is an inferred timeout only when the capture "
                            "continued past the timeout after its last transmission.",
    "tcp_reset_packet_rate": "RST packets / TCP packets.",
    "tcp_reset_connection_rate": "Connections with at least one RST / all tracked TCP connections.",
    "top_talkers": "Addresses ranked by bytes or packets sent, received or both. Percentages use "
                   "total IP bytes/packets as the denominator; bidirectional shares sum to ~200%.",
    "direction": "Relative to the configured local networks only; private ranges are not assumed "
                 "to be local. Without local networks every packet is 'unknown'.",
    "packet_loss_indicators": "Retransmissions, duplicate ACKs and sequence gaps are INDICATORS "
                              "that are often associated with loss. A single capture cannot "
                              "measure packet loss and NetScope reports no loss percentage.",
    "tcp_window": "Advertised receive window per direction. Scaling is applied only when both "
                  "SYN and SYN-ACK were captured with the window-scale option; otherwise "
                  "effective sizes are null.",
    "anomalies": "Threshold rules over measured metrics. Findings are heuristics, not proof of "
                 "malicious activity; no machine learning or threat intelligence is used.",
}

LIMITATIONS = [
    "A passive capture shows only what crossed the capture point; asymmetric routing can hide one direction.",
    "Connections and DNS transactions are tracked in memory per capture; DNS over TCP is only parsed when the whole message is in one segment.",
    "Retransmission detection matches exact (sequence, length) repeats within a window of 1024 segments per direction (a lower bound).",
    "Sequence-gap indicators cannot distinguish network loss, capture loss and reordering.",
    "Top talkers and direction use IP-layer traffic only; non-IP frames (e.g. ARP) are excluded.",
]


@dataclass
class AdvancedResult:
    document: dict
    connections: list[dict] = field(default_factory=list)
    indicators: list[dict] = field(default_factory=list)
    dns_transactions: list[dict] = field(default_factory=list)
    ip_rows: list[dict] = field(default_factory=list)
    pair_rows: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)


class AdvancedAnalyzer:
    def __init__(self, thresholds: AnomalyThresholds | None = None,
                 dns_config: DnsConfig | None = None) -> None:
        self.thresholds = thresholds or AnomalyThresholds()
        self.tcp = TcpConnectionTracker()
        self.dns = DnsTracker(dns_config)
        self.traffic = TrafficIntel()
        self.observer = ProtocolPortObserver()

    def observe(self, ex, flow_id: int | None, is_retransmission: bool) -> None:
        self.observe_view(PacketView.from_extracted(ex, flow_id, is_retransmission))

    def observe_view(self, v: PacketView) -> None:
        self.tcp.observe(v)
        self.dns.observe(v)
        self.traffic.observe(v)
        self.observer.observe(v)

    def finalize(self, *, last_ts: float | None, total_packets: int,
                 transport_rows: list[dict], timeseries: dict) -> AdvancedResult:
        self.dns.finalize(last_ts)
        conns = self.tcp.connections
        conn_rows = [connection_row(c) for c in conns]
        indicator_rows = []
        for c in conns:
            for ind in diag.indicator_rows(c):
                indicator_rows.append({"connection_id": c.id, "flow_id": c.flow_id,
                                       "endpoint_a": f"{c.a_ip}:{c.a_port}",
                                       "endpoint_b": f"{c.b_ip}:{c.b_port}", **ind})

        ip_rows = self.traffic.ip_rows()
        findings = detect(
            AnomalyInputs(
                connections=conns, tcp_packets=self.tcp.tcp_packets,
                rst_packets=self.tcp.rst_packets, rst_by_sender=self.tcp.rst_by_sender,
                dns_transactions=self.dns.transactions, ip_rows=ip_rows,
                total_ip_bytes=self.traffic.total_bytes, transport_rows=transport_rows,
                total_packets=total_packets, timeseries=timeseries, observer=self.observer,
            ),
            self.thresholds,
        )

        tcp_summary = self.tcp.summary()
        document = {
            "schema_version": SCHEMA_VERSION,
            "tcp": {k: v for k, v in tcp_summary.items() if k != "resets"},
            "resets": tcp_summary["resets"],
            "diagnostics": _diagnostics_summary(indicator_rows, conn_rows, self.tcp.tcp_packets),
            "windows": _window_summary(conn_rows),
            "dns": self.dns.summary(),
            "traffic": self.traffic.summary(limit=10),
            "anomalies": findings_summary(findings),
            "thresholds": thresholds_dict(self.thresholds),
            "definitions": DEFINITIONS,
            "limitations": LIMITATIONS,
        }
        return AdvancedResult(
            document=document, connections=conn_rows, indicators=indicator_rows,
            dns_transactions=self.dns.rows(), ip_rows=ip_rows,
            pair_rows=self.traffic.pair_rows(), findings=findings,
        )


def _diagnostics_summary(indicators: list[dict], conns: list[dict], tcp_packets: int) -> dict:
    by_type: dict[str, dict] = {}
    for ind in indicators:
        t = by_type.setdefault(ind["type"], {"events": 0, "connections": set()})
        t["events"] += ind["count"]
        t["connections"].add(ind["connection_id"])
    types = {
        k: {"events": v["events"], "connections": len(v["connections"])} for k, v in by_type.items()
    }
    retx = types.get("retransmission", {"events": 0})["events"]
    return {
        "indicator_types": types,
        "connections_with_indicators": len({i["connection_id"] for i in indicators}),
        "tcp_connections": len(conns),
        "tcp_packets": tcp_packets,
        "retransmission_packets": retx,
        "retransmission_rate": ratio(retx, tcp_packets),  # share of TCP packets; an indicator only
        "packet_loss_percent": None,
        "packet_loss_status": "not_measurable_from_a_single_capture",
    }


def _window_summary(conns: list[dict]) -> dict:
    scaling: dict[str, int] = {}
    zero_conns = zero_events = 0
    max_effective = []
    for c in conns:
        w = c["window"]
        scaling[w["scaling"]] = scaling.get(w["scaling"], 0) + 1
        if c["zero_window_events"]:
            zero_conns += 1
            zero_events += c["zero_window_events"]
        for side in ("a", "b"):
            eff = w[side]["effective"]
            if eff and eff["max"] is not None:
                max_effective.append(eff["max"])
    return {
        "connections": len(conns),
        "scaling_status": scaling,
        "connections_with_zero_window": zero_conns,
        "zero_window_events": zero_events,
        "max_effective_window_bytes": max(max_effective) if max_effective else None,
        "effective_window_available_for": len(max_effective),
    }
