"""End to end: upload a synthetic capture, run the Celery task, query every Phase 4 endpoint.

The expected numbers are derived by hand in tests/synthetic.py.
"""

import csv
import io

import pytest
from scapy.all import wrpcap

from app.extensions import db
from app.orm import (
    AdvancedAnalysis, AnomalyFindingRecord, DnsTransactionRecord, IpPairRecord, IpTrafficRecord,
    PacketRecord, TcpConnectionRecord, TcpIndicatorRecord,
)
from tests.conftest import register, upload
from tests.synthetic import build_packets

BASE = "/api/v1/captures"
ENDPOINTS = [
    "/analytics", "/tcp/summary", "/tcp/connections", "/tcp/connections/1", "/tcp/resets",
    "/tcp/indicators", "/tcp/windows", "/dns/summary", "/dns/transactions", "/dns/transactions/1",
    "/traffic/talkers", "/traffic/direction", "/anomalies", "/anomalies/1",
]


@pytest.fixture
def capture_id(auth_client, tmp_path):
    path = tmp_path / "phase4.pcap"
    wrpcap(str(path), build_packets())
    response = upload(auth_client, path.read_bytes(), "phase4.pcap")
    assert response.get_json()["capture"]["status"] == "completed"
    return response.get_json()["capture"]["id"]


def api(client, capture_id, path, **params):
    return client.get(f"{BASE}/{capture_id}{path}", query_string=params)


def body(client, capture_id, path, **params):
    response = api(client, capture_id, path, **params)
    assert response.status_code == 200, response.get_json()
    return response.get_json()


# ------------------------------------------------------------------ persistence


def test_pipeline_persists_derived_metrics_and_packet_windows(app, capture_id):
    import uuid

    cid = uuid.UUID(capture_id)
    assert db.session.get(AdvancedAnalysis, cid).schema_version == 1
    assert db.session.query(TcpConnectionRecord).filter_by(capture_id=cid).count() == 29
    assert db.session.query(DnsTransactionRecord).filter_by(capture_id=cid).count() == 7
    assert db.session.query(IpTrafficRecord).filter_by(capture_id=cid).count() >= 6
    assert db.session.query(IpPairRecord).filter_by(capture_id=cid).count() >= 6
    assert db.session.query(TcpIndicatorRecord).filter_by(capture_id=cid).count() > 0
    # Existing packet analysis still ran, and now also records the advertised window.
    syn = db.session.get(PacketRecord, (cid, 1))
    assert (syn.tcp_window, syn.tcp_window_scale) == (64240, 7)
    synack = db.session.get(PacketRecord, (cid, 2))
    assert (synack.tcp_window, synack.tcp_window_scale) == (65160, 8)


def test_phase_one_to_three_results_are_unchanged(auth_client, capture_id):
    summary = body(auth_client, capture_id, "/summary")
    assert summary["totals"]["total_packets"] == len(build_packets())


# --------------------------------------------------------------------- TCP


def test_tcp_summary_separates_incomplete_from_confirmed_failure(auth_client, capture_id):
    tcp = body(auth_client, capture_id, "/tcp/summary")["tcp"]
    assert tcp["states"] == {"established": 2, "incomplete": 26, "refused": 1, "unclassified": 0}
    assert tcp["observable_attempts"] == 29
    assert tcp["success_rate"] == pytest.approx(2 / 29)
    assert tcp["confirmed_failure_rate"] == pytest.approx(1 / 29)
    assert tcp["incomplete_reasons"]["no_synack"] == 26
    assert tcp["handshake_ms"]["count"] == 2


def test_connection_timings_and_termination(auth_client, capture_id):
    items = body(auth_client, capture_id, "/tcp/connections", state="established", ip="10.0.0.2")["items"]
    (c,) = items
    assert c["endpoint_a"] == {"ip": "10.0.0.1", "port": 40000}
    assert c["syn_to_synack_ms"] == pytest.approx(50, abs=1)
    assert c["handshake_ms"] == pytest.approx(60, abs=1)
    assert c["duration_seconds"] == pytest.approx(0.82, abs=0.01)
    assert (c["termination"], c["capture_truncated"]) == ("fin", False)
    assert c["window_scaling"] == "negotiated"


def test_connection_listing_filters_sorting_and_pagination(auth_client, capture_id):
    page = body(auth_client, capture_id, "/tcp/connections", state="incomplete", per_page=10, page=2)
    assert (page["total"], page["page"], len(page["items"])) == (26, 2, 10)
    ipv6 = body(auth_client, capture_id, "/tcp/connections", ip="2001:db8::1")["items"]
    assert [c["state"] for c in ipv6] == ["established"] and ipv6[0]["ip_version"] == 6
    refused = body(auth_client, capture_id, "/tcp/connections", state="refused")["items"]
    assert refused[0]["rst_packets"] == 1
    by_handshake = body(auth_client, capture_id, "/tcp/connections", sort="handshake", order="desc")["items"]
    assert by_handshake[0]["handshake_ms"] is not None  # NULLs sort last


def test_connection_detail_includes_window_and_indicators(auth_client, capture_id):
    first = body(auth_client, capture_id, "/tcp/connections", state="established", ip="10.0.0.2")["items"][0]
    detail = body(auth_client, capture_id, f"/tcp/connections/{first['connection_id']}")
    window = detail["connection"]["window"]
    assert window["scaling"] == "negotiated"
    assert (window["a"]["scale_shift"], window["b"]["scale_shift"]) == (7, 8)
    assert window["b"]["zero_window_events"] == 1
    assert window["b"]["raw"]["max"] == 8192  # the closing FIN-ACK uses Scapy's default window
    assert window["b"]["effective"]["max"] == 8192 << 8  # scaled by endpoint B's shift of 8
    kinds = {i["type"] for i in detail["indicators"]}
    assert {"retransmission", "duplicate_ack"} <= kinds
    assert api(auth_client, capture_id, "/tcp/connections/99999").status_code == 404


def test_resets_report_both_rates_and_denominators(auth_client, capture_id):
    resets = body(auth_client, capture_id, "/tcp/resets")["resets"]
    assert (resets["rst_packets"], resets["tcp_packets"]) == (1, 47)
    assert resets["packet_rate"] == pytest.approx(1 / 47)
    assert resets["connections_with_reset"] == 1 and resets["tcp_connections"] == 29
    assert resets["connection_rate"] == pytest.approx(1 / 29)


def test_loss_indicators_are_not_reported_as_packet_loss(auth_client, capture_id):
    data = body(auth_client, capture_id, "/tcp/indicators")
    summary = data["summary"]
    assert summary["packet_loss_percent"] is None
    assert summary["packet_loss_status"] == "not_measurable_from_a_single_capture"
    assert summary["retransmission_packets"] == 1
    assert summary["indicator_types"]["duplicate_ack"]["events"] == 3
    dup = body(auth_client, capture_id, "/tcp/indicators", type="duplicate_ack")["items"][0]
    assert dup["severity"] == "medium" and dup["detail"]["max_run"] == 3 and dup["evidence"]
    # a retransmission is counted once: no gap/overlap indicator was invented for it
    assert body(auth_client, capture_id, "/tcp/indicators", type="partial_overlap")["total"] == 0


def test_window_summary_reports_zero_window_connection(auth_client, capture_id):
    data = body(auth_client, capture_id, "/tcp/windows")
    assert data["windows"]["connections_with_zero_window"] == 1
    assert data["windows"]["scaling_status"]["negotiated"] == 1
    (conn,) = data["zero_window_connections"]
    assert conn["window"]["b"]["zero_window_evidence"]


# --------------------------------------------------------------------- DNS


def test_dns_summary_matches_hand_computed_values(auth_client, capture_id):
    dns = body(auth_client, capture_id, "/dns/summary")["dns"]
    assert dns["queries"] == 6 and dns["answered"] == 3
    assert dns["unanswered"] == {"inferred_timeout": 2, "indeterminate": 1}
    assert dns["unmatched_responses"] == 1
    assert dns["rcodes"] == {"NOERROR": 2, "NXDOMAIN": 1, "SERVFAIL": 1}
    assert dns["responses_observed"] == 4
    assert dns["error_response_rate"] == pytest.approx(0.5)
    assert dns["server_failure_rate"] == pytest.approx(0.25)
    assert dns["latency_ms"]["count"] == 3
    assert dns["latency_ms"]["median"] == pytest.approx(30, abs=2)


def test_dns_transactions_filters(auth_client, capture_id):
    nx = body(auth_client, capture_id, "/dns/transactions", rcode="NXDOMAIN")["items"]
    assert [t["qname"] for t in nx] == ["nx.test"]
    unanswered = body(auth_client, capture_id, "/dns/transactions", status="unanswered")
    assert unanswered["total"] == 3
    timeouts = body(auth_client, capture_id, "/dns/transactions", status="unanswered_inferred_timeout")
    assert {t["qname"] for t in timeouts["items"]} == {"lost.test", "=cmd.test"}
    late = body(auth_client, capture_id, "/dns/transactions", status="unanswered_indeterminate")["items"]
    assert [t["qname"] for t in late] == ["late.test"] and late[0]["latency_ms"] is None
    unmatched = body(auth_client, capture_id, "/dns/transactions", status="unmatched_response")["items"]
    assert unmatched[0]["query_packet"] is None
    by_latency = body(auth_client, capture_id, "/dns/transactions", status="answered", sort="latency", order="desc")["items"]
    assert [t["qname"] for t in by_latency][0] == "fail.test"
    assert body(auth_client, capture_id, "/dns/transactions", q="NX.")["total"] == 1


# ---------------------------------------------------------------- traffic intel


def test_top_talkers_totals_and_limits(auth_client, capture_id):
    data = body(auth_client, capture_id, "/traffic/talkers", by="bytes", role="source", limit=3)
    assert len(data["items"]) == 3 and data["limit"] == 3
    assert data["items"] == sorted(data["items"], key=lambda r: (-r["bytes"], r["ip"]))
    assert all(r["percent_of_bytes"] <= 100 for r in data["items"])
    everyone = body(auth_client, capture_id, "/traffic/talkers", role="source", limit=100)
    assert sum(r["bytes"] for r in everyone["items"]) == data["total_ip_bytes"]
    v6 = body(auth_client, capture_id, "/traffic/talkers", ip_version=6)["items"]
    assert {r["ip"] for r in v6} == {"2001:db8::1", "2001:db8::2"}


def test_direction_is_unknown_until_local_networks_are_configured(auth_client, capture_id):
    unconfigured = body(auth_client, capture_id, "/traffic/direction")
    assert unconfigured["configured"] is False
    assert unconfigured["directions"]["unknown"]["packets"] == unconfigured["total_ip_packets"]

    configured = body(auth_client, capture_id, "/traffic/direction", local="10.0.0.0/24")
    d = configured["directions"]
    assert d["outbound"]["packets"] > 0 and d["inbound"]["packets"] > 0 and d["internal"]["packets"] > 0
    assert d["unknown"]["packets"] == 4  # exactly the IPv6 conversation: neither end is in 10.0.0.0/24
    assert sum(x["packets"] for x in d.values()) == configured["total_ip_packets"]


# -------------------------------------------------------------------- anomalies


def test_anomaly_findings_are_explained_and_filterable(auth_client, capture_id):
    data = body(auth_client, capture_id, "/anomalies")
    rules = {f["rule"] for f in data["items"]}
    assert {"port_scan_vertical", "udp_on_tcp_service_port"} <= rules
    scan = body(auth_client, capture_id, "/anomalies", rule="port_scan_vertical")["items"][0]
    assert scan["severity"] == "medium"
    assert "25 distinct TCP ports" in scan["reason"]
    assert set(scan["affected_ips"]) == {"10.0.0.9", "10.0.0.2"}
    assert scan["packet_refs"] and scan["affected_flows"] and scan["thresholds"]
    assert "not prove" in scan["note"]
    assert body(auth_client, capture_id, "/anomalies", ip="10.0.0.9")["total"] >= 1
    assert body(auth_client, capture_id, "/anomalies", severity="high")["total"] == 0
    severities = [f["severity"] for f in data["items"]]
    order = {"info": 0, "low": 1, "medium": 2, "high": 3}
    assert [order[s] for s in severities] == sorted((order[s] for s in severities), reverse=True)
    detail = body(auth_client, capture_id, f"/anomalies/{scan['finding_id']}")["finding"]
    assert detail["rule"] == "port_scan_vertical"
    assert data["thresholds"]["port_scan_distinct_ports"] == 20


# -------------------------------------------------------------------- security


@pytest.mark.parametrize("path", ENDPOINTS)
def test_endpoints_require_authentication(make_client, capture_id, path):
    # `capture_id` logs the shared `client` in, so use a brand-new client with no session.
    assert api(make_client(), capture_id, path).status_code == 401


@pytest.mark.parametrize("path", ENDPOINTS)
def test_other_users_cannot_read_a_capture_they_do_not_own(make_client, auth_client, capture_id, path):
    mallory = make_client()
    register(mallory, "mallory@example.com")
    response = api(mallory, capture_id, path)
    assert response.status_code == 404  # indistinguishable from a capture that does not exist


@pytest.mark.parametrize("path,params", [
    ("/tcp/connections", {"state": "bogus"}),
    ("/tcp/connections", {"ip": "999.1.1.1"}),
    ("/tcp/connections", {"port": "70000"}),
    ("/tcp/connections", {"sort": "password"}),
    ("/tcp/indicators", {"type": "x"}),
    ("/dns/transactions", {"status": "nope"}),
    ("/dns/transactions", {"rcode": "NX DOMAIN;--"}),
    ("/dns/transactions", {"min_latency_ms": "-5"}),
    ("/dns/transactions", {"min_latency_ms": "abc"}),
    ("/traffic/talkers", {"limit": "0"}),
    ("/traffic/talkers", {"limit": "101"}),
    ("/traffic/talkers", {"role": "everyone"}),
    ("/traffic/talkers", {"ip_version": "5"}),
    ("/traffic/direction", {"local": "10.0.0.0/33"}),
    ("/traffic/direction", {"local": "not-an-ip"}),
    ("/anomalies", {"rule": "Robert'); DROP TABLE"}),
    ("/anomalies", {"severity": "critical"}),
])
def test_invalid_input_is_rejected_with_400(auth_client, capture_id, path, params):
    response = api(auth_client, capture_id, path, **params)
    assert response.status_code == 400
    assert "error" in response.get_json()


def test_sql_metacharacters_in_text_filters_are_inert(auth_client, capture_id):
    data = body(auth_client, capture_id, "/dns/transactions", q="%' OR 1=1 --")
    assert data["total"] == 0
    assert body(auth_client, capture_id, "/dns/transactions", q="%")["total"] == 0  # % is literal


def test_unknown_capture_is_404(auth_client):
    missing = "00000000-0000-0000-0000-000000000001"
    assert api(auth_client, missing, "/tcp/summary").status_code == 404


def test_capture_analysed_before_phase4_reports_unavailable(auth_client, capture_id):
    import uuid

    db.session.delete(db.session.get(AdvancedAnalysis, uuid.UUID(capture_id)))
    db.session.commit()
    response = api(auth_client, capture_id, "/tcp/summary")
    assert response.status_code == 409
    assert response.get_json()["error"]["reason"] == "analytics_unavailable"


# ---------------------------------------------------------------------- exports

CSV_KINDS = [
    "tcp-connections", "tcp-windows", "tcp-indicators", "tcp-summary", "dns-transactions",
    "dns-summary", "top-talkers", "traffic-direction", "anomalies", "analytics-summary",
]


@pytest.mark.parametrize("kind", CSV_KINDS)
def test_csv_exports_download(auth_client, capture_id, kind):
    response = api(auth_client, capture_id, f"/export/{kind}.csv")
    assert response.status_code == 200
    assert response.mimetype == "text/csv"
    assert "attachment" in response.headers["Content-Disposition"]
    rows = list(csv.reader(io.StringIO(response.get_data(as_text=True))))
    assert len(rows) >= 2


def test_csv_export_respects_filters(auth_client, capture_id):
    text = api(auth_client, capture_id, "/export/tcp-connections.csv", state="refused").get_data(as_text=True)
    rows = list(csv.DictReader(io.StringIO(text)))
    assert [r["state"] for r in rows] == ["refused"]
    unfiltered = api(auth_client, capture_id, "/export/tcp-connections.csv").get_data(as_text=True)
    assert len(list(csv.DictReader(io.StringIO(unfiltered)))) == 29


def test_csv_export_neutralises_formula_injection(auth_client, capture_id):
    text = api(auth_client, capture_id, "/export/dns-transactions.csv").get_data(as_text=True)
    cells = [cell for row in csv.reader(io.StringIO(text)) for cell in row]
    assert "'=cmd.test" in cells
    assert not any(c.startswith(("=", "+", "@")) for c in cells)


def test_csv_export_of_bad_filter_is_400_and_other_user_is_404(make_client, auth_client, capture_id):
    assert api(auth_client, capture_id, "/export/dns-transactions.csv", status="x").status_code == 400
    mallory = make_client()
    register(mallory, "mallory@example.com")
    assert api(mallory, capture_id, "/export/tcp-connections.csv").status_code == 404
    assert api(mallory, capture_id, "/report.pdf").status_code == 404


def test_direction_csv_uses_local_networks(auth_client, capture_id):
    text = api(auth_client, capture_id, "/export/traffic-direction.csv", local="10.0.0.0/24").get_data(as_text=True)
    rows = {r["direction"]: r for r in csv.DictReader(io.StringIO(text))}
    assert rows["outbound"]["local_networks"] == "10.0.0.0/24"


def test_pdf_report_still_builds_with_advanced_sections(auth_client, capture_id):
    response = api(auth_client, capture_id, "/report.pdf", local="10.0.0.0/24")
    assert response.status_code == 200
    assert response.data.startswith(b"%PDF")
    assert api(auth_client, capture_id, "/report.pdf", local="garbage").status_code == 400


def test_dashboard_pools_network_intelligence(auth_client, capture_id):
    data = auth_client.get("/api/v1/dashboard").get_json()["network_intelligence"]
    assert data["captures_included"] == 1
    assert data["tcp"]["success_rate"] == pytest.approx(2 / 29)
    assert data["dns"]["error_rate"] == pytest.approx(0.5)
    assert data["anomalies"]["total"] >= 2
