"""Explainable, rule-based protocol anomaly detection.

Every finding states which rule fired, why (the measured value against the configured
threshold), what was affected and which packets support it. There is no machine learning and
no external threat intelligence: rules are plain thresholds over metrics NetScope already
measured. **A finding is a heuristic indicator, not proof of malicious activity** - busy
servers, scanners run by administrators, misconfigured clients and legitimate bursts all
trigger these rules. Thresholds are configurable (NETSCOPE_ANOMALY_THRESHOLDS, a JSON object of
overrides, applied when a capture is analysed) and each finding records the thresholds it used.

Rules
- http_on_nonstandard_port      cleartext HTTP on ports other than the usual HTTP ports
                                (the lower of the two ports is reported as the service port)
- non_dns_on_dns_port           payload on port 53 that did not parse as DNS
- udp_on_tcp_service_port       UDP payload to ports normally used only by TCP services
- high_volume_host              one address sent more than ``high_volume_host_bytes``
- traffic_burst                 peak packet rate far above the median interval rate
- high_connection_rate          one source opened many TCP connections within a short window
- repeated_connection_attempts  many attempts to one destination service that mostly never completed
- port_scan_vertical            one source tried many destination ports on one host
- port_scan_horizontal          one source tried one port on many hosts
- dns_nxdomain_burst            a client received many NXDOMAIN answers
- dns_long_names                a client queried unusually long DNS names or labels
- dns_many_subdomains           a client queried many distinct subdomains of one domain
- high_reset_rate               an unusually large share of TCP packets were resets
- reset_source_host             one address sent many TCP resets
- host_traffic_concentration    a single address sent almost all bytes among many hosts
- icmp_heavy                    ICMP made up a large share of packets
"""

from __future__ import annotations

import statistics
from dataclasses import asdict, dataclass, fields

from .common import SEVERITY_ORDER, iso

DISCLAIMER = (
    "Heuristic indicator from threshold rules; it does not prove malicious activity."
)
HTTP_PORTS = frozenset({80, 8000, 8008, 8080, 8888, 3128})
UDP_ON_TCP_PORTS = frozenset({20, 21, 22, 23, 25, 110, 143, 993, 995, 3389})
SAMPLE = 10  # packet references / examples kept per finding


@dataclass
class AnomalyThresholds:
    non_standard_port_min_packets: int = 1
    non_dns_on_dns_port_min_packets: int = 5
    udp_on_tcp_port_min_packets: int = 3
    high_volume_host_bytes: int = 100_000_000
    burst_peak_to_median_ratio: float = 10.0
    burst_min_peak_pps: float = 500.0
    burst_min_intervals: int = 10
    connection_rate_window_seconds: float = 10.0
    connection_rate_threshold: int = 100
    repeated_attempt_threshold: int = 5
    repeated_attempt_min_unsuccessful_ratio: float = 0.8
    port_scan_distinct_ports: int = 20
    horizontal_scan_distinct_hosts: int = 20
    dns_nxdomain_min_count: int = 20
    dns_nxdomain_min_ratio: float = 0.5
    dns_long_name_length: int = 60
    dns_long_label_length: int = 40
    dns_long_name_min_queries: int = 5
    dns_subdomain_unique_threshold: int = 50
    reset_rate_threshold: float = 0.10
    reset_min_packets: int = 20
    reset_host_threshold: int = 50
    concentration_share: float = 0.90
    concentration_min_hosts: int = 5
    concentration_min_bytes: int = 100_000
    icmp_share: float = 0.30
    icmp_min_packets: int = 100

    @classmethod
    def from_overrides(cls, overrides: dict | None) -> "AnomalyThresholds":
        """Apply user overrides; unknown names or non-positive numbers are errors."""
        base = cls()
        if not overrides:
            return base
        known = {f.name: f.type for f in fields(cls)}
        for name, value in overrides.items():
            if name not in known:
                raise ValueError(f"Unknown anomaly threshold {name!r}.")
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
                raise ValueError(f"Anomaly threshold {name!r} must be a positive number.")
            default = getattr(base, name)
            setattr(base, name, type(default)(value))
        return base


class ProtocolPortObserver:
    """Per-packet observations for the protocol/port rules (bounded memory)."""

    def __init__(self) -> None:
        self.http_nonstandard: dict = {}
        self.non_dns_dns_port: dict = {}
        self.udp_tcp_port: dict = {}

    @staticmethod
    def _add(table: dict, key, v) -> None:
        rec = table.get(key)
        if rec is None:
            rec = table[key] = {"count": 0, "bytes": 0, "packets": [], "ips": set(), "flows": set()}
        rec["count"] += 1
        rec["bytes"] += v.length
        if len(rec["packets"]) < SAMPLE:
            rec["packets"].append(v.number)
        if len(rec["ips"]) < 20:
            rec["ips"].update(x for x in (v.src_ip, v.dst_ip) if x)
        if v.flow_id is not None and len(rec["flows"]) < 20:
            rec["flows"].add(v.flow_id)

    def observe(self, v) -> None:
        if v.transport not in ("TCP", "UDP") or v.src_port is None or v.dst_port is None:
            return
        ports = (v.src_port, v.dst_port)
        if v.app == "HTTP" and v.transport == "TCP" and not (set(ports) & HTTP_PORTS):
            self._add(self.http_nonstandard, min(ports), v)
        if 53 in ports and v.app != "DNS" and v.payload_len > 0 and not v.malformed:
            self._add(self.non_dns_dns_port, v.transport, v)
        if v.transport == "UDP" and v.dst_port in UDP_ON_TCP_PORTS and v.payload_len > 0:
            self._add(self.udp_tcp_port, v.dst_port, v)


@dataclass
class AnomalyInputs:
    connections: list
    tcp_packets: int
    rst_packets: int
    rst_by_sender: dict
    dns_transactions: list
    ip_rows: list
    total_ip_bytes: int
    transport_rows: list  # [{"protocol", "packets", ...}]
    total_packets: int
    timeseries: dict  # {"bucket_seconds", "points": [...]}
    observer: ProtocolPortObserver


def _finding(rule, name, severity, description, reason, evidence, thresholds, ips=(), flows=(), packets=()):
    return {
        "rule": rule,
        "name": name,
        "severity": severity,
        "description": description,
        "reason": reason,
        "evidence": evidence,
        "affected_ips": sorted(set(ips))[:20],
        "affected_flows": sorted(set(flows))[:20],
        "packet_refs": sorted(set(packets))[:SAMPLE],
        "thresholds": thresholds,
        "note": DISCLAIMER,
    }


def detect(inp: AnomalyInputs, th: AnomalyThresholds) -> list[dict]:
    findings: list[dict] = []
    for rule in (
        _protocol_port, _volume, _burst, _connection_rate, _repeated, _scans, _dns, _resets,
        _distribution,
    ):
        findings.extend(rule(inp, th))
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f["severity"]], f["rule"], f["reason"]))
    for i, f in enumerate(findings, start=1):
        f["finding_id"] = i
    return findings


# ----------------------------------------------------------------- protocol / port


def _protocol_port(inp, th):
    obs = inp.observer
    out = []
    for port, rec in sorted(obs.http_nonstandard.items()):
        if rec["count"] >= th.non_standard_port_min_packets:
            out.append(_finding(
                "http_on_nonstandard_port", "Cleartext HTTP on a non-standard port", "low",
                "HTTP request/response lines were seen on a port that is not normally used for HTTP.",
                f"{rec['count']} HTTP packets on port {port} (minimum {th.non_standard_port_min_packets}; "
                f"usual HTTP ports: {sorted(HTTP_PORTS)})",
                {"port": port, "packets": rec["count"], "bytes": rec["bytes"]},
                {"non_standard_port_min_packets": th.non_standard_port_min_packets},
                rec["ips"], rec["flows"], rec["packets"]))
    for transport, rec in sorted(obs.non_dns_dns_port.items()):
        if rec["count"] >= th.non_dns_on_dns_port_min_packets:
            out.append(_finding(
                "non_dns_on_dns_port", "Non-DNS payload on port 53", "medium",
                "Payload on port 53 did not parse as DNS. This can be malformed DNS, a different "
                "protocol using the port, or tunnelling.",
                f"{rec['count']} {transport} packets with a payload on port 53 that is not valid DNS "
                f"(minimum {th.non_dns_on_dns_port_min_packets})",
                {"transport": transport, "packets": rec["count"], "bytes": rec["bytes"]},
                {"non_dns_on_dns_port_min_packets": th.non_dns_on_dns_port_min_packets},
                rec["ips"], rec["flows"], rec["packets"]))
    for port, rec in sorted(obs.udp_tcp_port.items()):
        if rec["count"] >= th.udp_on_tcp_port_min_packets:
            out.append(_finding(
                "udp_on_tcp_service_port", "UDP to a TCP-only service port", "low",
                "UDP payload was sent to a port normally used only by a TCP service.",
                f"{rec['count']} UDP packets with payload to port {port} (minimum {th.udp_on_tcp_port_min_packets})",
                {"port": port, "packets": rec["count"], "bytes": rec["bytes"]},
                {"udp_on_tcp_port_min_packets": th.udp_on_tcp_port_min_packets},
                rec["ips"], rec["flows"], rec["packets"]))
    return out


# ----------------------------------------------------------------- volume / bursts


def _volume(inp, th):
    out = []
    for r in inp.ip_rows:
        if r["sent_bytes"] >= th.high_volume_host_bytes:
            share = 100 * r["sent_bytes"] / inp.total_ip_bytes if inp.total_ip_bytes else None
            severity = "high" if r["sent_bytes"] >= 10 * th.high_volume_host_bytes else "medium"
            out.append(_finding(
                "high_volume_host", "Unusually high traffic volume from one address", severity,
                "One address sent a large amount of data during the capture.",
                f"{r['ip']} sent {r['sent_bytes']:,} bytes (threshold {th.high_volume_host_bytes:,})",
                {"sent_bytes": r["sent_bytes"], "sent_packets": r["sent_packets"],
                 "share_of_ip_bytes_percent": share},
                {"high_volume_host_bytes": th.high_volume_host_bytes}, [r["ip"]]))
    return out


def _burst(inp, th):
    points = (inp.timeseries or {}).get("points") or []
    if len(points) < th.burst_min_intervals:
        return []
    rates = [p["packets_per_second"] for p in points]
    median = statistics.median(rates)
    if median <= 0:
        return []
    peak = max(rates)
    ratio = peak / median
    if ratio < th.burst_peak_to_median_ratio or peak < th.burst_min_peak_pps:
        return []
    when = points[rates.index(peak)]["time"]
    return [_finding(
        "traffic_burst", "Traffic burst far above the typical rate", "medium",
        "The peak packet rate in one interval greatly exceeded the median interval rate.",
        f"peak {peak:,.0f} packets/s is {ratio:.1f}x the median {median:,.1f} packets/s "
        f"(thresholds: ratio {th.burst_peak_to_median_ratio:g}, peak >= {th.burst_min_peak_pps:g} packets/s)",
        {"peak_pps": peak, "median_pps": median, "ratio": ratio, "interval_start": when,
         "bucket_seconds": inp.timeseries.get("bucket_seconds")},
        {"burst_peak_to_median_ratio": th.burst_peak_to_median_ratio,
         "burst_min_peak_pps": th.burst_min_peak_pps, "burst_min_intervals": th.burst_min_intervals})]


# ------------------------------------------------------------- connection patterns


def _initiated(inp):
    return [c for c in inp.connections if c.initiator_known and c.syn_pkt is not None]


def _connection_rate(inp, th):
    by_src: dict[str, list] = {}
    for c in _initiated(inp):
        by_src.setdefault(c.a_ip, []).append(c)
    out = []
    for src, conns in sorted(by_src.items()):
        conns.sort(key=lambda c: c.syn_ts)
        lo, best, best_lo = 0, 0, 0
        for hi, c in enumerate(conns):
            while c.syn_ts - conns[lo].syn_ts > th.connection_rate_window_seconds:
                lo += 1
            if hi - lo + 1 > best:
                best, best_lo = hi - lo + 1, lo
        if best >= th.connection_rate_threshold:
            window = conns[best_lo: best_lo + best]
            severity = "high" if best >= 10 * th.connection_rate_threshold else "medium"
            out.append(_finding(
                "high_connection_rate", "Unusual TCP connection frequency", severity,
                "One source opened many TCP connections within a short window.",
                f"{src} opened {best} TCP connections within {th.connection_rate_window_seconds:g}s "
                f"(threshold {th.connection_rate_threshold})",
                {"connections_in_window": best, "window_start": iso(window[0].syn_ts),
                 "distinct_destinations": len({(c.b_ip, c.b_port) for c in window})},
                {"connection_rate_threshold": th.connection_rate_threshold,
                 "connection_rate_window_seconds": th.connection_rate_window_seconds},
                [src], [c.flow_id for c in window], [c.syn_pkt for c in window]))
    return out


def _repeated(inp, th):
    groups: dict[tuple, list] = {}
    for c in _initiated(inp):
        groups.setdefault((c.a_ip, c.b_ip, c.b_port), []).append(c)
    out = []
    for (src, dst, port), conns in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][2] or 0)):
        attempts = len(conns)
        if attempts < th.repeated_attempt_threshold:
            continue
        unsuccessful = sum(1 for c in conns if c.state in ("incomplete", "refused"))
        refused = sum(1 for c in conns if c.state == "refused")
        ratio = unsuccessful / attempts
        if ratio < th.repeated_attempt_min_unsuccessful_ratio:
            continue
        out.append(_finding(
            "repeated_connection_attempts", "Repeated connection attempts to one service", "medium",
            "Many connection attempts to the same destination port did not complete in the capture. "
            "Incomplete attempts are not confirmed failures; only refused ones are.",
            f"{src} made {attempts} attempts to {dst}:{port}, {unsuccessful} not completed "
            f"({ratio:.0%}; thresholds: {th.repeated_attempt_threshold} attempts, "
            f"{th.repeated_attempt_min_unsuccessful_ratio:.0%} unsuccessful)",
            {"attempts": attempts, "not_completed": unsuccessful, "confirmed_refused": refused,
             "syn_retransmissions": sum(max(c.syn_count - 1, 0) for c in conns)},
            {"repeated_attempt_threshold": th.repeated_attempt_threshold,
             "repeated_attempt_min_unsuccessful_ratio": th.repeated_attempt_min_unsuccessful_ratio},
            [src, dst], [c.flow_id for c in conns], [c.syn_pkt for c in conns]))
    return out


def _scans(inp, th):
    vertical: dict[tuple, list] = {}
    horizontal: dict[tuple, list] = {}
    for c in _initiated(inp):
        vertical.setdefault((c.a_ip, c.b_ip), []).append(c)
        horizontal.setdefault((c.a_ip, c.b_port), []).append(c)
    out = []
    for (src, dst), conns in sorted(vertical.items()):
        ports = sorted({c.b_port for c in conns if c.b_port is not None})
        if len(ports) >= th.port_scan_distinct_ports:
            out.append(_finding(
                "port_scan_vertical", "Many destination ports contacted on one host", "medium",
                "One source attempted connections to many different ports on a single destination. "
                "This pattern is typical of port scanning but also of some legitimate tools.",
                f"{src} contacted {len(ports)} distinct TCP ports on {dst} "
                f"(threshold {th.port_scan_distinct_ports})",
                {"distinct_ports": len(ports), "sample_ports": ports[:20], "attempts": len(conns)},
                {"port_scan_distinct_ports": th.port_scan_distinct_ports},
                [src, dst], [c.flow_id for c in conns], [c.syn_pkt for c in conns]))
    for (src, port), conns in sorted(horizontal.items(), key=lambda kv: (kv[0][0], kv[0][1] or 0)):
        hosts = sorted({c.b_ip for c in conns})
        if len(hosts) >= th.horizontal_scan_distinct_hosts:
            out.append(_finding(
                "port_scan_horizontal", "One port contacted on many hosts", "medium",
                "One source attempted connections to the same port on many different hosts.",
                f"{src} contacted TCP port {port} on {len(hosts)} distinct hosts "
                f"(threshold {th.horizontal_scan_distinct_hosts})",
                {"port": port, "distinct_hosts": len(hosts), "sample_hosts": hosts[:20],
                 "attempts": len(conns)},
                {"horizontal_scan_distinct_hosts": th.horizontal_scan_distinct_hosts},
                [src], [c.flow_id for c in conns], [c.syn_pkt for c in conns]))
    return out


# -------------------------------------------------------------------------- DNS


def _parent(name: str) -> tuple[str, str] | None:
    labels = [l for l in name.split(".") if l]
    if len(labels) < 3:
        return None
    return ".".join(labels[-2:]), labels[0]


def _dns(inp, th):
    per_client: dict[str, dict] = {}
    for t in inp.dns_transactions:
        c = per_client.setdefault(t.client_ip, {
            "responses": 0, "nx": 0, "nx_pkts": [], "long": 0, "long_pkts": [], "long_names": [],
            "subs": {}, "sub_pkts": {},
        })
        pkt = t.query_packet if t.query_packet is not None else t.response_packet
        if t.status in ("answered", "unmatched_response"):
            c["responses"] += 1
            if t.rcode == 3:
                c["nx"] += 1
                if len(c["nx_pkts"]) < SAMPLE:
                    c["nx_pkts"].append(t.response_packet)
        name = t.qname
        if not name:
            continue
        labels = name.split(".")
        if len(name) >= th.dns_long_name_length or max(len(l) for l in labels) >= th.dns_long_label_length:
            c["long"] += 1
            if len(c["long_pkts"]) < SAMPLE:
                c["long_pkts"].append(pkt)
            if len(c["long_names"]) < 3:
                c["long_names"].append(name[:120])
        parts = _parent(name)
        if parts is not None:
            domain, sub = parts
            subs = c["subs"].setdefault(domain, set())
            if len(subs) < 1000:
                subs.add(sub)
            c["sub_pkts"].setdefault(domain, [])
            if len(c["sub_pkts"][domain]) < SAMPLE:
                c["sub_pkts"][domain].append(pkt)

    out = []
    for client, c in sorted(per_client.items()):
        ratio = c["nx"] / c["responses"] if c["responses"] else 0
        if c["nx"] >= th.dns_nxdomain_min_count and ratio >= th.dns_nxdomain_min_ratio:
            out.append(_finding(
                "dns_nxdomain_burst", "Many NXDOMAIN responses to one client", "medium",
                "A client received many 'no such domain' answers, which can indicate generated "
                "domain names, misconfiguration or stale lookups.",
                f"{client} received {c['nx']} NXDOMAIN responses ({ratio:.0%} of its {c['responses']} "
                f"responses; thresholds {th.dns_nxdomain_min_count} and {th.dns_nxdomain_min_ratio:.0%})",
                {"nxdomain": c["nx"], "responses": c["responses"], "ratio": ratio},
                {"dns_nxdomain_min_count": th.dns_nxdomain_min_count,
                 "dns_nxdomain_min_ratio": th.dns_nxdomain_min_ratio},
                [client], (), c["nx_pkts"]))
        if c["long"] >= th.dns_long_name_min_queries:
            out.append(_finding(
                "dns_long_names", "Unusually long DNS names", "low",
                "A client queried unusually long DNS names or labels. Long labels are sometimes "
                "used to carry data in DNS, but also appear in some CDN and tracking names.",
                f"{client} sent {c['long']} queries with names >= {th.dns_long_name_length} characters "
                f"or labels >= {th.dns_long_label_length} (minimum {th.dns_long_name_min_queries})",
                {"queries": c["long"], "examples": c["long_names"]},
                {"dns_long_name_length": th.dns_long_name_length,
                 "dns_long_label_length": th.dns_long_label_length,
                 "dns_long_name_min_queries": th.dns_long_name_min_queries},
                [client], (), c["long_pkts"]))
        for domain, subs in sorted(c["subs"].items()):
            if len(subs) >= th.dns_subdomain_unique_threshold:
                out.append(_finding(
                    "dns_many_subdomains", "Many distinct subdomains of one domain", "medium",
                    "A client queried many different subdomains of the same domain, a pattern "
                    "seen in DNS tunnelling and domain-generation activity, and also in some "
                    "CDNs and service discovery.",
                    f"{client} queried {len(subs)} distinct subdomains of {domain} "
                    f"(threshold {th.dns_subdomain_unique_threshold})",
                    {"domain": domain, "distinct_subdomains": len(subs),
                     "examples": sorted(subs)[:5]},
                    {"dns_subdomain_unique_threshold": th.dns_subdomain_unique_threshold},
                    [client], (), c["sub_pkts"][domain]))
    return out


# ---------------------------------------------------------------------- resets


def _resets(inp, th):
    out = []
    rate = inp.rst_packets / inp.tcp_packets if inp.tcp_packets else None
    ref_pkts = [e["packet"] for c in inp.connections for e in c.rst_packets][:SAMPLE]
    ref_flows = [c.flow_id for c in inp.connections if c.rst_total][:20]
    if rate is not None and inp.rst_packets >= th.reset_min_packets and rate >= th.reset_rate_threshold:
        out.append(_finding(
            "high_reset_rate", "Abnormal share of TCP resets", "medium",
            "A large share of TCP packets were RST segments. Resets are normal for refused or "
            "aborted connections but unusual in large proportions.",
            f"{inp.rst_packets} of {inp.tcp_packets} TCP packets are resets ({rate:.1%}; thresholds "
            f"{th.reset_rate_threshold:.0%} and at least {th.reset_min_packets} resets)",
            {"rst_packets": inp.rst_packets, "tcp_packets": inp.tcp_packets, "rate": rate},
            {"reset_rate_threshold": th.reset_rate_threshold, "reset_min_packets": th.reset_min_packets},
            [ip for ip, _ in sorted(inp.rst_by_sender.items(), key=lambda kv: -kv[1])[:5]],
            ref_flows, ref_pkts))
    for ip, n in sorted(inp.rst_by_sender.items(), key=lambda kv: (-kv[1], kv[0])):
        if n >= th.reset_host_threshold:
            pkts = [e["packet"] for c in inp.connections for e in c.rst_packets
                    if (c.a_ip if e["side"] == "a" else c.b_ip) == ip][:SAMPLE]
            out.append(_finding(
                "reset_source_host", "One address sent many TCP resets", "medium",
                "A single address sent many RST segments, for example a host or firewall "
                "rejecting many connections.",
                f"{ip} sent {n} TCP resets (threshold {th.reset_host_threshold})",
                {"rst_packets": n},
                {"reset_host_threshold": th.reset_host_threshold}, [ip],
                [c.flow_id for c in inp.connections if c.rst_total][:20], pkts))
    return out


# ---------------------------------------------------------------- distribution


def _distribution(inp, th):
    out = []
    senders = sorted(inp.ip_rows, key=lambda r: (-r["sent_bytes"], r["ip"]))
    active = [r for r in senders if r["sent_bytes"] > 0]
    if (
        len(active) >= th.concentration_min_hosts
        and inp.total_ip_bytes >= th.concentration_min_bytes
    ):
        top = active[0]
        share = top["sent_bytes"] / inp.total_ip_bytes
        if share >= th.concentration_share:
            out.append(_finding(
                "host_traffic_concentration", "Traffic concentrated on one address", "low",
                "Almost all bytes were sent by a single address even though many addresses sent traffic.",
                f"{top['ip']} sent {share:.1%} of IP bytes among {len(active)} sending addresses "
                f"(thresholds {th.concentration_share:.0%}, at least {th.concentration_min_hosts} senders)",
                {"share": share, "sent_bytes": top["sent_bytes"], "sending_addresses": len(active)},
                {"concentration_share": th.concentration_share,
                 "concentration_min_hosts": th.concentration_min_hosts,
                 "concentration_min_bytes": th.concentration_min_bytes}, [top["ip"]]))
    icmp = sum(r["packets"] for r in inp.transport_rows if r["protocol"] in ("ICMP", "ICMPv6"))
    if inp.total_packets and icmp >= th.icmp_min_packets and icmp / inp.total_packets >= th.icmp_share:
        out.append(_finding(
            "icmp_heavy", "ICMP makes up a large share of traffic", "low",
            "ICMP packets formed an unusually large share of the capture (ping sweeps, "
            "monitoring or error storms are typical causes).",
            f"{icmp} of {inp.total_packets} packets are ICMP/ICMPv6 ({icmp / inp.total_packets:.1%}; "
            f"thresholds {th.icmp_share:.0%} and at least {th.icmp_min_packets})",
            {"icmp_packets": icmp, "total_packets": inp.total_packets,
             "share": icmp / inp.total_packets},
            {"icmp_share": th.icmp_share, "icmp_min_packets": th.icmp_min_packets}))
    return out


def findings_summary(findings: list[dict]) -> dict:
    by_sev = {s: 0 for s in SEVERITY_ORDER}
    by_rule: dict[str, int] = {}
    for f in findings:
        by_sev[f["severity"]] += 1
        by_rule[f["rule"]] = by_rule.get(f["rule"], 0) + 1
    return {"total": len(findings), "by_severity": by_sev, "by_rule": by_rule, "disclaimer": DISCLAIMER}


def thresholds_dict(th: AnomalyThresholds) -> dict:
    return asdict(th)
