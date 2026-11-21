import csv
import io
import shutil
import subprocess

import pytest
from scapy.all import wrpcap

from app.services import analysis_pipeline, export_service
from tests.conftest import register, upload
from tests.scenario import build_packets


@pytest.fixture
def capture_id(auth_client, tmp_path):
    path = tmp_path / "scenario.pcap"
    wrpcap(str(path), build_packets())
    return upload(auth_client, path.read_bytes(), "scenario.pcap").get_json()["capture"]["id"]


def export(client, capture_id, kind, **params):
    return client.get(f"/api/v1/captures/{capture_id}/export/{kind}.csv", query_string=params)


def parse(response):
    assert response.status_code == 200, response.get_data(as_text=True)
    return list(csv.reader(io.StringIO(response.get_data(as_text=True))))


# ------------------------------------------------------------------------------- CSV


def test_packets_csv_has_every_packet_in_order(auth_client, capture_id):
    response = export(auth_client, capture_id, "packets")
    rows = parse(response)
    header, data = rows[0], rows[1:]

    assert response.mimetype == "text/csv"
    assert response.headers["Content-Disposition"] == f'attachment; filename="netscope-{capture_id[:8]}-packets.csv"'
    assert response.headers["Cache-Control"] == "no-store"
    assert header[:3] == ["packet_number", "timestamp", "source_ip"]
    assert [int(r[0]) for r in data] == list(range(1, 16))

    row = dict(zip(header, data[3]))  # packet 4: the HTTP request
    assert (row["source_ip"], row["destination_ip"], row["destination_port"]) == ("10.0.0.1", "10.0.0.2", "80")
    assert row["protocol"] == "HTTP" and row["tcp_flags"] == "PA"
    assert row["timestamp"].startswith("2023-11-14T22:13:20.1")
    assert "GET /index.html" in row["application_metadata"]
    retx = dict(zip(header, data[8]))
    assert retx["is_retransmission"] == "true" and dict(zip(header, data[0]))["is_retransmission"] == "false"
    assert dict(zip(header, data[14]))["malformed_reason"] == "truncated_ip_header"


def test_packets_csv_honours_explorer_filters(auth_client, capture_id):
    dns = parse(export(auth_client, capture_id, "packets", protocol="dns"))
    assert [r[0] for r in dns[1:]] == ["7", "8"]
    flow = parse(export(auth_client, capture_id, "packets", flow_id=1, tcp_flags="P"))
    assert [r[0] for r in flow[1:]] == ["4", "6", "9"]
    assert len(parse(export(auth_client, capture_id, "packets", q="no-such-thing"))) == 1  # header only
    # sort/order params from the explorer do not reorder an export
    assert [r[0] for r in parse(export(auth_client, capture_id, "packets", order="desc"))[1:3]] == ["1", "2"]


def test_packets_csv_streams_across_chunks_without_loss_or_duplicates(auth_client, capture_id, monkeypatch):
    monkeypatch.setattr(export_service, "_CHUNK", 4)
    rows = parse(export(auth_client, capture_id, "packets"))
    assert [int(r[0]) for r in rows[1:]] == list(range(1, 16))


def test_flows_protocols_performance_timeseries_csv(auth_client, capture_id):
    flows = parse(export(auth_client, capture_id, "flows"))
    head = flows[0]
    assert len(flows) == 5 and flows[1][0] == "1"  # bytes-descending: the HTTP flow first
    first = dict(zip(head, flows[1]))
    assert (first["endpoint_a_ip"], first["endpoint_a_port"], first["packets_total"]) == ("10.0.0.1", "40000", "8")
    assert first["retransmissions"] == "1"
    assert len(parse(export(auth_client, capture_id, "flows", protocol="udp"))) == 2

    protocols = parse(export(auth_client, capture_id, "protocols"))
    layers = [(r[0], r[1], r[2]) for r in protocols[1:]]
    assert ("transport", "TCP", "9") in layers and ("application", "DNS", "2") in layers
    assert len(layers) == 7

    perf = {(r[0], r[1]): r[2] for r in parse(export(auth_client, capture_id, "performance"))[1:]}
    assert perf[("totals", "total_packets")] == "15" and perf[("tcp", "retransmissions")] == "1"
    assert float(perf[("latency", "handshake_rtt_ms.mean")]) == pytest.approx(50.0, abs=0.01)
    assert float(perf[("performance", "duration_seconds")]) == pytest.approx(5.0)

    series = parse(export(auth_client, capture_id, "timeseries"))
    assert [r[1] for r in series[1:]] == ["8", "2", "2", "1", "1", "1"]


def test_csv_cells_cannot_become_spreadsheet_formulas():
    for dangerous in ("=SUM(A1)", "+1+1", "-2+3", "@cmd", "\tcmd", "\rcmd"):
        assert export_service.safe_cell(dangerous) == "'" + dangerous
    assert export_service.safe_cell("10.0.0.1") == "10.0.0.1"
    assert export_service.safe_cell(-5) == -5  # real numbers are not text
    assert export_service.safe_cell(None) == "" and export_service.safe_cell(True) == "true"
    assert export_service.safe_cell({"q": "=x"}) == '{"q":"=x"}'


def test_csv_response_neutralises_and_quotes_untrusted_values(app):
    with app.test_request_context():
        response = export_service.csv_response("t.csv", ["a", "b"], [["=HYPERLINK(1)", 'say "hi", ok']])
        rows = list(csv.reader(io.StringIO(response.get_data(as_text=True))))
    assert rows[1] == ["'=HYPERLINK(1)", 'say "hi", ok']


def test_export_validation_and_access_control(auth_client, capture_id, make_client, tmp_path):
    assert export(auth_client, capture_id, "bogus").status_code == 404
    assert export(auth_client, capture_id, "packets", ip="nope").status_code == 400
    assert export(auth_client, capture_id, "flows", sort="bad").status_code == 400

    anonymous = make_client()
    other = make_client()
    register(other, "mallory@example.com")
    for kind in ("packets", "flows", "protocols", "performance", "timeseries"):
        assert export(anonymous, capture_id, kind).status_code == 401
        assert export(other, capture_id, kind).status_code == 404
    assert anonymous.get(f"/api/v1/captures/{capture_id}/report.pdf").status_code == 401
    assert other.get(f"/api/v1/captures/{capture_id}/report.pdf").status_code == 404

    path = tmp_path / "p.pcap"
    wrpcap(str(path), build_packets())
    pending = upload(auth_client, path.read_bytes(), analyze="false").get_json()["capture"]["id"]
    assert export(auth_client, pending, "packets").status_code == 409
    assert auth_client.get(f"/api/v1/captures/{pending}/report.pdf").status_code == 409


# ------------------------------------------------------------------------------- PDF


def pdf_text(data: bytes, tmp_path) -> str:
    path = tmp_path / "report.pdf"
    path.write_bytes(data)
    return subprocess.run(
        ["pdftotext", "-layout", str(path), "-"], capture_output=True, text=True, check=True
    ).stdout


needs_pdftotext = pytest.mark.skipif(shutil.which("pdftotext") is None, reason="pdftotext not installed")


def test_pdf_report_download_headers(auth_client, capture_id):
    response = auth_client.get(f"/api/v1/captures/{capture_id}/report.pdf")
    assert response.status_code == 200 and response.mimetype == "application/pdf"
    assert response.data.startswith(b"%PDF") and response.data.rstrip().endswith(b"%%EOF")
    assert response.headers["Content-Disposition"] == f'attachment; filename="netscope-{capture_id[:8]}-report.pdf"'
    assert response.headers["Cache-Control"] == "no-store"


@needs_pdftotext
def test_pdf_report_contains_the_real_results(auth_client, capture_id, tmp_path):
    text = pdf_text(auth_client.get(f"/api/v1/captures/{capture_id}/report.pdf").data, tmp_path)

    assert "NetScope analysis report" in text and "scenario.pcap" in text and capture_id in text
    assert "Packets analysed" in text and "15" in text
    for protocol in ("TCP", "UDP", "ICMP", "ARP", "HTTP", "DNS"):
        assert protocol in text
    assert "Top flows by bytes" in text and "10.0.0.1:40000" in text and "10.0.0.2:80" in text
    assert "(11.11%)" in text  # 1 retransmission of 9 TCP packets
    assert "50.00 ms" in text  # handshake RTT


@needs_pdftotext
def test_pdf_for_empty_and_single_packet_captures(auth_client, tmp_path):
    empty = tmp_path / "e.pcap"
    wrpcap(str(empty), [])
    one = tmp_path / "o.pcap"
    wrpcap(str(one), build_packets()[:1])
    for path, expected in ((empty, "None identified."), (one, "Top flows by bytes")):
        cid = upload(auth_client, path.read_bytes(), path.name).get_json()["capture"]["id"]
        response = auth_client.get(f"/api/v1/captures/{cid}/report.pdf")
        assert response.status_code == 200
        assert expected in pdf_text(response.data, tmp_path)


@needs_pdftotext
def test_pdf_treats_filenames_as_text_not_markup(auth_client, tmp_path, app):
    from app.extensions import db
    from app.orm import CaptureRecord
    import uuid

    path = tmp_path / "x.pcap"
    wrpcap(str(path), build_packets()[:3])
    cid = upload(auth_client, path.read_bytes(), "x.pcap").get_json()["capture"]["id"]
    record = db.session.get(CaptureRecord, uuid.UUID(cid))
    record.original_filename = "<b>bold</b> & <i>x</i>.pcap"  # as if a hostile name had been stored
    db.session.commit()

    text = pdf_text(auth_client.get(f"/api/v1/captures/{cid}/report.pdf").data, tmp_path)
    assert "<b>bold</b> & <i>x</i>.pcap" in text


# ---------------------------------------------------------------------------- progress


def test_progress_is_reported_after_each_batch(auth_client, tmp_path, app, monkeypatch):
    seen = []
    original = analysis_pipeline._report_progress

    def spy(capture_id, count):
        original(capture_id, count)
        seen.append(count)

    monkeypatch.setattr(analysis_pipeline, "_report_progress", spy)
    app.config["PACKET_BATCH_SIZE"] = 4
    path = tmp_path / "p.pcap"
    wrpcap(str(path), build_packets())
    capture = upload(auth_client, path.read_bytes()).get_json()["capture"]

    assert seen == [4, 8, 12]  # the final partial batch is covered by the completion update
    assert capture["status"] == "completed" and capture["packet_count"] == 15
