"""CSV and PDF report generation.

Reports are generated on demand from persisted analysis and streamed to the requester;
nothing is written to disk, so there are no report files to leak or clean up.
"""

import csv
import io
import json
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from flask import Response, stream_with_context

from app.extensions import db
from app.orm import AnalysisResult, CaptureRecord, FlowRecord, PacketRecord
from app.orm.user import iso_utc

_CHUNK = 2000
# Characters that make Excel/Sheets treat a cell as a formula (CSV injection).
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def safe_cell(value):
    """Render a value for CSV. Untrusted strings (e.g. HTTP start lines) that could be
    read as a spreadsheet formula are neutralised with a leading apostrophe."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        value = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def csv_response(filename: str, header: list[str], rows) -> Response:
    """Stream rows (an iterable of sequences) as a CSV download."""

    def generate():
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\r\n")
        writer.writerow(header)
        yield buffer.getvalue()
        for row in rows:
            buffer.seek(0)
            buffer.truncate()
            writer.writerow([safe_cell(v) for v in row])
            yield buffer.getvalue()

    response = Response(stream_with_context(generate()), mimetype="text/csv")
    _download_headers(response, filename)
    return response


def _download_headers(response: Response, filename: str) -> None:
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    response.headers["Cache-Control"] = "no-store"  # reports contain private traffic data


PACKET_COLUMNS = [
    "packet_number", "timestamp", "source_ip", "destination_ip", "source_port",
    "destination_port", "protocol", "transport_protocol", "application_protocol",
    "original_length", "captured_length", "tcp_flags", "tcp_sequence_number",
    "tcp_acknowledgement_number", "ttl_or_hop_limit", "ip_version", "vlan_id",
    "source_mac", "destination_mac", "payload_length", "flow_id", "is_retransmission",
    "malformed_reason", "application_metadata",
]


def packet_rows(base_query):
    """Packets in capture order, fetched in keyset-paginated chunks so memory stays flat."""
    last = 0
    while True:
        chunk = db.session.execute(
            base_query.order_by(None)
            .where(PacketRecord.packet_number > last)
            .order_by(PacketRecord.packet_number)
            .limit(_CHUNK)
        ).scalars().all()
        if not chunk:
            return
        for packet in chunk:
            data = packet.to_dict()
            yield [data[c] for c in PACKET_COLUMNS]
        last = chunk[-1].packet_number
        db.session.expunge_all()


FLOW_COLUMNS = [
    "flow_id", "protocol", "application_protocol", "endpoint_a_ip", "endpoint_a_port",
    "endpoint_b_ip", "endpoint_b_port", "first_seen", "last_seen", "duration_seconds",
    "packets_total", "packets_a_to_b", "packets_b_to_a", "bytes_total", "bytes_a_to_b",
    "bytes_b_to_a", "retransmissions", "handshake_rtt_ms", "jitter_ms",
]


def flow_rows(query):
    for flow in db.session.execute(query).scalars():
        row = flow.to_dict()
        yield [
            row["flow_id"], row["protocol"], row["application_protocol"],
            row["endpoint_a"]["ip"], row["endpoint_a"]["port"],
            row["endpoint_b"]["ip"], row["endpoint_b"]["port"],
            row["first_seen"], row["last_seen"], row["duration_seconds"],
            row["packets"]["total"], row["packets"]["a_to_b"], row["packets"]["b_to_a"],
            row["bytes"]["total"], row["bytes"]["a_to_b"], row["bytes"]["b_to_a"],
            row["retransmissions"], row["handshake_rtt_ms"], row["jitter_ms"],
        ]


def protocol_rows(result: AnalysisResult):
    for layer in ("transport", "application"):
        for r in result.summary["protocols"][layer]:
            yield [layer, r["protocol"], r["packets"], r["bytes"], r["packet_percent"], r["byte_percent"]]


def summary_rows(result: AnalysisResult):
    summary = result.summary
    perf = {k: v for k, v in summary["performance"].items() if k != "timeseries"}
    for section, values in (("totals", result.totals()), ("performance", perf), ("tcp", summary["tcp"])):
        for key, value in values.items():
            yield [section, key, value]
    for name, dist in summary["latency"].items():
        for stat, value in (dist or {}).items():
            yield ["latency", f"{name}.{stat}", value]


def timeseries_rows(result: AnalysisResult):
    for p in result.summary["performance"]["timeseries"]["points"]:
        yield [p["time"], p["packets"], p["bytes"], p["packets_per_second"], p["bits_per_second"]]


# ------------------------------------------------------------- Phase 4 analytics (CSV)


def _stream(query):
    """Rows fetched in server-side chunks so memory stays flat for large captures."""
    return db.session.execute(query.execution_options(yield_per=_CHUNK)).scalars()


TCP_CONNECTION_COLUMNS = [
    "connection_id", "flow_id", "endpoint_a_ip", "endpoint_a_port", "endpoint_b_ip",
    "endpoint_b_port", "initiator_known", "state", "incomplete_reason", "first_seen", "last_seen",
    "duration_seconds", "syn_retransmissions", "syn_to_synack_ms", "synack_to_ack_ms",
    "handshake_ms", "termination", "terminated_by", "capture_truncated", "truncation_reasons",
    "packets", "bytes", "rst_packets", "retransmissions", "duplicate_acks", "zero_window_events",
    "window_scaling",
]


def tcp_connection_rows(query):
    for c in _stream(query):
        d = c.to_dict()
        yield [
            d["connection_id"], d["flow_id"], d["endpoint_a"]["ip"], d["endpoint_a"]["port"],
            d["endpoint_b"]["ip"], d["endpoint_b"]["port"], d["initiator_known"], d["state"],
            d["incomplete_reason"], d["first_seen"], d["last_seen"], d["duration_seconds"],
            d["syn_retransmissions"], d["syn_to_synack_ms"], d["synack_to_ack_ms"],
            d["handshake_ms"], d["termination"], d["terminated_by"], d["capture_truncated"],
            d["truncation_reasons"], d["packets"], d["bytes"], d["rst_packets"],
            d["retransmissions"], d["duplicate_acks"], d["zero_window_events"], d["window_scaling"],
        ]


TCP_WINDOW_COLUMNS = [
    "connection_id", "endpoint_a", "endpoint_b", "window_scaling", "side", "scale_shift",
    "samples", "raw_min", "raw_max", "raw_last", "effective_min", "effective_max",
    "effective_last", "window_changes", "zero_window_events", "zero_window_packets",
    "zero_window_evidence_packets",
]


def tcp_window_rows(query):
    for c in _stream(query):
        d = c.to_dict(detail=True)
        for side in ("a", "b"):
            w = d["window"][side]
            eff = w["effective"] or {}
            yield [
                d["connection_id"], f"{c.endpoint_a_ip}:{c.endpoint_a_port}",
                f"{c.endpoint_b_ip}:{c.endpoint_b_port}", d["window_scaling"], side,
                w["scale_shift"], w["samples"], w["raw"]["min"], w["raw"]["max"], w["raw"]["last"],
                eff.get("min"), eff.get("max"), eff.get("last"), w["changes"],
                w["zero_window_events"], w["zero_window_packets"], w["zero_window_evidence"],
            ]


TCP_INDICATOR_COLUMNS = [
    "indicator_id", "connection_id", "flow_id", "endpoint_a", "endpoint_b", "type", "sender",
    "packet_count", "first_packet", "last_packet", "severity", "confidence", "evidence", "detail",
]


def tcp_indicator_rows(query):
    for i in _stream(query):
        d = i.to_dict()
        yield [d[c] for c in TCP_INDICATOR_COLUMNS]


DNS_COLUMNS = [
    "transaction_id", "transport", "client_ip", "client_port", "server_ip", "server_port",
    "dns_id", "qname", "qtype", "question_count", "query_packet", "response_packet", "query_time",
    "response_time", "query_count", "latency_ms", "latency_from_last_query_ms", "rcode",
    "rcode_name", "truncated", "answer_count", "status", "note",
]


def dns_rows(query):
    for t in _stream(query):
        d = t.to_dict()
        yield [
            d["transaction_id"], d["transport"], d["client"]["ip"], d["client"]["port"],
            d["server"]["ip"], d["server"]["port"], d["dns_id"], d["qname"], d["qtype"],
            d["question_count"], d["query_packet"], d["response_packet"], d["query_time"],
            d["response_time"], d["query_count"], d["latency_ms"], d["latency_from_last_query_ms"],
            d["rcode"], d["rcode_name"], d["truncated"], d["answer_count"], d["status"], d["note"],
        ]


ANOMALY_COLUMNS = [
    "finding_id", "rule", "name", "severity", "description", "reason", "affected_ips",
    "affected_flows", "packet_refs", "evidence", "thresholds", "note",
]


def anomaly_rows(query):
    for f in _stream(query):
        d = f.to_dict()
        yield [d[c] for c in ANOMALY_COLUMNS]


TALKER_COLUMNS = [
    "rank", "ip", "ip_version", "packets", "bytes", "sent_packets", "sent_bytes",
    "received_packets", "received_bytes", "percent_of_packets", "percent_of_bytes",
]


def talker_rows(items):
    for r in items:
        yield [r[c] for c in TALKER_COLUMNS]


DIRECTION_COLUMNS = ["direction", "packets", "bytes", "percent_of_packets", "percent_of_bytes",
                     "local_networks", "explanation"]


def direction_rows(stats: dict):
    local = ",".join(stats["local_networks"]) or "(none configured)"
    for name, d in stats["directions"].items():
        yield [name, d["packets"], d["bytes"], d["percent_of_packets"], d["percent_of_bytes"],
               local, d["explanation"]]


def flatten_rows(section: str, value, prefix: str = ""):
    """Flatten a nested summary dict into (section, metric, value) rows; lists become JSON cells."""
    if isinstance(value, dict):
        for key, inner in value.items():
            yield from flatten_rows(section, inner, f"{prefix}.{key}" if prefix else str(key))
    else:
        yield [section, prefix, value]


def analytics_summary_rows(document: dict):
    for section in ("tcp", "resets", "diagnostics", "windows", "dns", "traffic", "anomalies"):
        value = document[section]
        if section == "tcp":
            value = {k: v for k, v in value.items() if k != "charts"}
        if section == "dns":
            value = {k: v for k, v in value.items() if k not in ("charts", "servers")}
        yield from flatten_rows(section, value)
    for key, text in document["definitions"].items():
        yield ["definition", key, text]
    for i, text in enumerate(document["limitations"], start=1):
        yield ["limitation", str(i), text]


# ------------------------------------------------------------------------------- PDF


def human_bytes(n) -> str:
    if n is None:
        return "-"
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1000 or unit == "TB":
            return f"{int(value)} B" if unit == "B" else f"{value:.2f} {unit}"
        value /= 1000
    return f"{n} B"


def human_bps(n) -> str:
    if n is None:
        return "-"
    value = float(n)
    for unit in ("bit/s", "Kbit/s", "Mbit/s", "Gbit/s"):
        if value < 1000 or unit == "Gbit/s":
            return f"{value:.0f} {unit}" if unit == "bit/s" else f"{value:.2f} {unit}"
        value /= 1000
    return f"{n} bit/s"


def _num(value, digits=2, suffix="") -> str:
    return "-" if value is None else f"{value:,.{digits}f}{suffix}"


def build_pdf(capture: CaptureRecord, result: AnalysisResult, top_flows: list[FlowRecord],
              compress: bool = True, advanced: dict | None = None, findings: list | None = None,
              direction: dict | None = None) -> bytes:
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.charts.lineplots import LinePlot
    from reportlab.graphics.shapes import Drawing, String
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = getSampleStyleSheet()
    h1, h2, body = styles["Title"], styles["Heading2"], styles["BodyText"]
    small = styles["BodyText"].clone("small", fontSize=8, leading=10)
    summary = result.summary
    perf, tcp, latency = summary["performance"], summary["tcp"], summary["latency"]
    totals = result.totals()

    def para(text, style=body):
        return Paragraph(escape(str(text)), style)  # user-controlled text must be escaped

    def table(rows, widths, header=True):
        t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
        style = [
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]
        if header:
            style += [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ]
        t.setStyle(TableStyle(style))
        return t

    story = [
        Paragraph("NetScope analysis report", h1),
        para(f"Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC", small),
        Spacer(1, 6 * mm),
        Paragraph("Capture", h2),
        table(
            [
                ["File", para(capture.original_filename, small)],
                ["Capture ID", str(capture.id)],
                ["Format", capture.file_format.value],
                ["File size", human_bytes(capture.file_size_bytes)],
                ["SHA-256", para(capture.sha256, small)],
                ["Uploaded", iso_utc(capture.uploaded_at)],
                ["Capture period", f"{totals['first_timestamp'] or '-'}  to  {totals['last_timestamp'] or '-'}"],
            ],
            [35 * mm, 135 * mm], header=False,
        ),
        Paragraph("Summary", h2),
        table(
            [
                ["Metric", "Value"],
                ["Packets analysed", f"{totals['total_packets']:,}"],
                ["Data (frame bytes)", human_bytes(totals["total_bytes"])],
                ["Unique IP addresses", f"{totals['unique_ips']:,}"],
                ["Flows", f"{totals['flow_count']:,}"],
                ["Malformed packets", f"{totals['malformed_packets']:,}"],
                ["Duration", _num(totals["duration_seconds"], 3, " s")],
            ],
            [70 * mm, 100 * mm],
        ),
    ]

    for layer, title in (("transport", "Protocol distribution (transport)"), ("application", "Application protocols")):
        rows = summary["protocols"][layer]
        story.append(Paragraph(title, h2))
        if rows:
            story.append(table(
                [["Protocol", "Packets", "Bytes", "% packets", "% bytes"]]
                + [[r["protocol"], f"{r['packets']:,}", human_bytes(r["bytes"]),
                    _num(r["packet_percent"], 1), _num(r["byte_percent"], 1)] for r in rows],
                [40 * mm, 30 * mm, 40 * mm, 30 * mm, 30 * mm],
            ))
        else:
            story.append(para("None identified.", small))

    transport = summary["protocols"]["transport"][:8]
    if transport:
        drawing = Drawing(170 * mm, 60 * mm)
        chart = VerticalBarChart()
        chart.x, chart.y, chart.width, chart.height = 12 * mm, 10 * mm, 150 * mm, 42 * mm
        chart.data = [[r["bytes"] for r in transport]]
        chart.categoryAxis.categoryNames = [r["protocol"][:12] for r in transport]
        chart.categoryAxis.labels.fontSize = 7
        chart.valueAxis.labels.fontSize = 7
        chart.valueAxis.valueMin = 0
        chart.bars[0].fillColor = colors.HexColor("#2563eb")
        drawing.add(chart)
        drawing.add(String(2, 55 * mm, "Bytes by protocol", fontName="Helvetica", fontSize=8))
        story += [Spacer(1, 3 * mm), drawing]

    story += [
        Paragraph("Performance", h2),
        table(
            [
                ["Metric", "Value"],
                ["Average packet size", _num(perf["avg_packet_size_bytes"], 1, " B")],
                ["Average packets/s", _num(perf["avg_packets_per_second"], 2)],
                ["Average throughput", human_bps(perf["avg_throughput_bps"])],
                ["Peak packets/s (1 s)", _num(perf["peak_packets_per_second"], 0)],
                ["Peak throughput (1 s)", human_bps(perf["peak_throughput_bps"])],
                ["TCP packets", f"{tcp['packets']:,}"],
                ["TCP retransmissions", f"{tcp['retransmissions']:,}  ({_num(100 * tcp['retransmission_rate'], 2, '%') if tcp['retransmission_rate'] is not None else '-'})"],
                ["Handshake RTT (mean / p95)", _latency_text(latency["handshake_rtt_ms"])],
                ["Flow jitter (mean / p95)", _latency_text(latency["flow_jitter_ms"])],
            ],
            [70 * mm, 100 * mm],
        ),
    ]

    points = perf["timeseries"]["points"]
    if len(points) >= 2:
        drawing = Drawing(170 * mm, 60 * mm)
        plot = LinePlot()
        plot.x, plot.y, plot.width, plot.height = 14 * mm, 10 * mm, 148 * mm, 42 * mm
        plot.data = [[(i, p["bits_per_second"]) for i, p in enumerate(points)]]
        plot.lines[0].strokeColor = colors.HexColor("#2563eb")
        plot.xValueAxis.labels.fontSize = 7
        plot.yValueAxis.labels.fontSize = 7
        plot.yValueAxis.valueMin = 0
        drawing.add(plot)
        drawing.add(String(
            2, 55 * mm,
            f"Throughput (bit/s) by {perf['timeseries']['bucket_seconds']} s interval (x axis: interval number)",
            fontName="Helvetica", fontSize=8,
        ))
        story += [Spacer(1, 3 * mm), drawing]
    story.append(para(
        "Bytes are on-the-wire frame sizes. Retransmissions count exact duplicate TCP segments "
        "(a lower bound). RTT is SYN to SYN-ACK at the capture point. Jitter is arrival-time jitter per flow.",
        small,
    ))

    story.append(Paragraph("Top flows by bytes", h2))
    if top_flows:
        story.append(table(
            [["#", "Protocol", "Endpoint A", "Endpoint B", "Packets", "Bytes", "Duration"]]
            + [[str(f.flow_id), f.protocol, _endpoint(f.endpoint_a_ip, f.endpoint_a_port),
                _endpoint(f.endpoint_b_ip, f.endpoint_b_port), f"{f.packets_total:,}",
                human_bytes(f.bytes_total), _num(f.duration_seconds, 2, " s")] for f in top_flows],
            [8 * mm, 16 * mm, 50 * mm, 50 * mm, 18 * mm, 20 * mm, 18 * mm],
        ))
    else:
        story.append(para("No flows.", small))

    story += _advanced_story(advanced, findings or [], direction, para, table, h2, small, body, mm)

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.drawString(20 * mm, 10 * mm, f"NetScope - {str(capture.id)[:8]}")
        canvas.drawRightString(190 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm, topMargin=18 * mm,
        bottomMargin=18 * mm, title="NetScope analysis report", author="NetScope",
        pageCompression=1 if compress else 0,
    )
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()


def _pct(value, digits=2) -> str:
    return "n/a" if value is None else f"{100 * value:.{digits}f}%"


def _dist(d, unit) -> str:
    if not d:
        return "not available (no measurements)"
    return (f"min {d['min']:.2f} / mean {d['mean']:.2f} / median {d['median']:.2f} / "
            f"p95 {d['p95']:.2f} / max {d['max']:.2f} {unit}  (n={d['count']})")


def _advanced_story(doc, findings, direction, para, table, h2, small, body, mm):
    """Phase 4 sections. Every metric is shown with its definition and measurement limits."""
    from reportlab.platypus import PageBreak, Paragraph, Spacer

    if doc is None:
        return [Paragraph("Advanced network analytics", h2),
                para("Not available: this capture was analysed before advanced analytics existed.", small)]

    tcp, resets, diag, win, dns = doc["tcp"], doc["resets"], doc["diagnostics"], doc["windows"], doc["dns"]
    states = tcp["states"]
    out = [PageBreak(), Paragraph("Advanced network analytics", h2),
           para("Values marked n/a could not be measured from this capture and are never estimated.", small),
           Paragraph("TCP connections", h2),
           table([
               ["Metric", "Value"],
               ["Connections tracked", f"{tcp['total_connections']:,}"],
               ["Established / incomplete / refused / unclassified",
                f"{states['established']:,} / {states['incomplete']:,} / {states['refused']:,} / {states['unclassified']:,}"],
               ["Observable attempts (initial SYN captured)", f"{tcp['observable_attempts']:,}"],
               ["Connection success rate", _pct(tcp["success_rate"])],
               ["Confirmed failure rate (refused)", _pct(tcp["confirmed_failure_rate"])],
               ["Incomplete (not confirmed failures)", _pct(tcp["incomplete_rate"])],
               ["Handshake time (ms)", _dist(tcp["handshake_ms"], "ms")],
               ["Observed lifetime (s)", _dist(tcp["lifetime_seconds"], "s")],
               ["Terminated by FIN / RST / half-closed / not observed",
                " / ".join(f"{tcp['terminations'][k]:,}" for k in ("fin", "reset", "half_closed", "none"))],
               ["Capture-truncated connections", f"{tcp['capture_truncated_connections']:,}"],
           ], [75 * mm, 95 * mm]),
           Paragraph("TCP resets", h2),
           table([
               ["Metric", "Value"],
               ["RST packets / TCP packets", f"{resets['rst_packets']:,} / {resets['tcp_packets']:,}  ({_pct(resets['packet_rate'])})"],
               ["Connections with a reset / tracked connections",
                f"{resets['connections_with_reset']:,} / {resets['tcp_connections']:,}  ({_pct(resets['connection_rate'])})"],
               ["Reset before / after establishment / unclassified",
                f"{resets['reset_before_established']:,} / {resets['reset_after_established']:,} / {resets['reset_unclassified']:,}"],
           ], [75 * mm, 95 * mm]),
           Paragraph("Packet-loss indicators and TCP window", h2),
           para("Retransmissions, duplicate ACKs and sequence gaps are indicators only. A single "
                "capture cannot measure packet loss, so no loss percentage is reported.", small),
           table([["Indicator", "Events", "Connections"]] + [
               [k.replace("_", " "), f"{v['events']:,}", f"{v['connections']:,}"]
               for k, v in sorted(diag["indicator_types"].items())
           ] or [["none observed", "0", "0"]], [70 * mm, 40 * mm, 40 * mm]),
           Spacer(1, 2 * mm),
           table([
               ["Window metric", "Value"],
               ["Connections with zero-window advertisements", f"{win['connections_with_zero_window']:,}"],
               ["Zero-window events", f"{win['zero_window_events']:,}"],
               ["Window scaling status", ", ".join(f"{k}: {v}" for k, v in win["scaling_status"].items()) or "n/a"],
               ["Largest effective window (bytes)",
                "n/a (scale unknown)" if win["max_effective_window_bytes"] is None else f"{win['max_effective_window_bytes']:,}"],
           ], [75 * mm, 95 * mm]),
           Paragraph("DNS", h2)]
    if not dns["available"]:
        out.append(para("No DNS traffic was identified in this capture.", small))
    else:
        out += [table([
            ["Metric", "Value"],
            ["Queries / answered", f"{dns['queries']:,} / {dns['answered']:,}"],
            ["Unanswered: inferred timeout / indeterminate",
             f"{dns['unanswered']['inferred_timeout']:,} / {dns['unanswered']['indeterminate']:,}"],
            ["Unmatched responses", f"{dns['unmatched_responses']:,}"],
            ["Response time", _dist(dns["latency_ms"], "ms")],
            ["Responses observed", f"{dns['responses_observed']:,}"],
            ["Error response rate (RCODE != NOERROR)", _pct(dns["error_response_rate"])],
            ["Server failure rate (excl. NXDOMAIN)", _pct(dns["server_failure_rate"])],
            ["NXDOMAIN rate", _pct(dns["nxdomain_rate"])],
            ["Response codes", ", ".join(f"{k}: {v}" for k, v in dns["rcodes"].items()) or "n/a"],
        ], [75 * mm, 95 * mm])]
    top = doc["traffic"]["top_by_bytes"]
    out.append(Paragraph("Top talkers (sent + received bytes)", h2))
    out.append(table([["#", "Address", "Packets", "Bytes", "% of IP bytes"]] + [
        [str(r["rank"]), r["ip"], f"{r['packets']:,}", human_bytes(r["bytes"]),
         "n/a" if r["percent_of_bytes"] is None else f"{r['percent_of_bytes']:.1f}"] for r in top
    ], [10 * mm, 70 * mm, 28 * mm, 32 * mm, 30 * mm]) if top else para("No IP traffic.", small))
    out.append(para("Percentages use total IP bytes as the denominator; each packet has two endpoints, "
                    "so bidirectional shares add up to about 200%.", small))
    out.append(Paragraph("Inbound / outbound traffic", h2))
    if direction is None or not direction["configured"]:
        out.append(para("Direction is not classified: no local networks were configured for this report "
                        "(private address ranges are not assumed to be local). All traffic is 'unknown'.", small))
    else:
        out.append(para("Local networks: " + ", ".join(direction["local_networks"]), small))
        out.append(table([["Direction", "Packets", "Bytes", "% of bytes"]] + [
            [k, f"{v['packets']:,}", human_bytes(v["bytes"]),
             "n/a" if v["percent_of_bytes"] is None else f"{v['percent_of_bytes']:.1f}"]
            for k, v in direction["directions"].items()
        ], [40 * mm, 40 * mm, 45 * mm, 45 * mm]))
    out.append(Paragraph("Anomaly findings", h2))
    out.append(para("Rule-based heuristics. A finding is not proof of malicious activity.", small))
    if findings:
        out.append(table([["Severity", "Rule", "Reason"]] + [
            [f.severity, f.rule, para(f.reason, small)] for f in findings
        ], [20 * mm, 45 * mm, 105 * mm]))
        total = doc["anomalies"]["total"]
        if total > len(findings):
            out.append(para(f"Showing the {len(findings)} highest-severity of {total} findings; see the CSV export for all.", small))
    else:
        out.append(para("No findings.", small))
    out += [Paragraph("Metric definitions", h2)]
    out += [para(f"{k.replace('_', ' ')}: {v}", small) for k, v in doc["definitions"].items()]
    out += [Paragraph("Measurement limitations", h2)]
    out += [para(f"- {t}", small) for t in doc["limitations"]]
    return out


def _endpoint(ip: str, port) -> str:
    return f"[{ip}]:{port}" if port is not None and ":" in ip else (f"{ip}:{port}" if port is not None else ip)


def _latency_text(dist) -> str:
    if not dist:
        return "not available"
    return f"{dist['mean']:.2f} ms / {dist['p95']:.2f} ms  (n={dist['count']})"


def pdf_response(data: bytes, filename: str) -> Response:
    response = Response(data, mimetype="application/pdf")
    _download_headers(response, filename)
    return response
