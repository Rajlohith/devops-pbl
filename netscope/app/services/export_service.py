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
              compress: bool = True) -> bytes:
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
