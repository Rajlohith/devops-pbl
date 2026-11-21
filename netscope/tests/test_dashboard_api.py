import uuid
from pathlib import Path

import pytest
from scapy.all import wrpcap

from app.extensions import db
from app.orm import CaptureRecord
from tests.conftest import register, upload
from tests.scenario import build_packets


def pcap_of(tmp_path, packets, name):
    path = tmp_path / name
    wrpcap(str(path), packets)
    return path.read_bytes()


def frame_total(packets):
    return sum(len(bytes(p)) for p in packets)


@pytest.fixture
def two_captures(auth_client, tmp_path):
    full, head = build_packets(), build_packets()[:3]
    a = upload(auth_client, pcap_of(tmp_path, full, "a.pcap"), "full.pcap").get_json()["capture"]
    b = upload(auth_client, pcap_of(tmp_path, head, "b.pcap"), "head.pcap").get_json()["capture"]
    return a, b, full, head


def test_empty_dashboard_has_zeros_not_errors(auth_client):
    body = auth_client.get("/api/v1/dashboard").get_json()
    assert body["totals"] == {"captures": 0, "packets": 0, "bytes": 0, "unique_ips": 0, "flows": 0}
    assert body["recent_sessions"] == [] and body["recent_traffic"] == []
    assert body["protocols"] == {"transport": [], "application": [], "captures_included": 0}
    assert body["in_progress"] == 0


def test_dashboard_requires_login(client):
    assert client.get("/api/v1/dashboard").status_code == 401
    assert client.get("/api/v1/compare").status_code == 401


def test_dashboard_aggregates_real_analysis(auth_client, two_captures):
    a, b, full, head = two_captures
    # An upload that is rejected outright must not be counted.
    assert upload(auth_client, b"x", "x.pcap").status_code == 400

    body = auth_client.get("/api/v1/dashboard").get_json()
    assert body["totals"] == {
        "captures": 2,
        "packets": 15 + 3,
        "bytes": frame_total(full) + frame_total(head),
        "unique_ips": 6,  # the 3-packet capture only repeats addresses seen in the big one
        "flows": 4 + 1,
    }
    assert body["status_counts"]["completed"] == 2 and body["in_progress"] == 0

    sessions = body["recent_sessions"]
    assert [s["filename"] for s in sessions] == ["head.pcap", "full.pcap"]  # newest first
    assert sessions[1]["packets"] == 15 and sessions[1]["flows"] == 4
    assert [t["filename"] for t in body["recent_traffic"]] == ["full.pcap", "head.pcap"]  # oldest first

    transport = {p["protocol"]: p["packets"] for p in body["protocols"]["transport"]}
    assert transport == {"TCP": 9 + 3, "UDP": 2, "ICMP": 2, "ARP": 1, "Other": 1}
    application = {p["protocol"]: p["packets"] for p in body["protocols"]["application"]}
    assert application == {"HTTP": 3, "DNS": 2}
    assert body["protocols"]["captures_included"] == 2
    assert sum(p["packet_percent"] for p in body["protocols"]["transport"]) == pytest.approx(100)


def test_dashboard_counts_failed_and_pending_by_status(auth_client, tmp_path, app):
    cid = upload(auth_client, pcap_of(tmp_path, build_packets(), "a.pcap"), analyze="false").get_json()["capture"]["id"]
    path = next(Path(app.config["UPLOAD_FOLDER"]).rglob(f"{cid}.pcap"))
    path.write_bytes(path.read_bytes()[:-5])  # corrupt after the upload-time validation
    auth_client.post(f"/api/v1/captures/{cid}/analyze")

    body = auth_client.get("/api/v1/dashboard").get_json()
    assert body["status_counts"]["failed"] == 1 and body["totals"]["captures"] == 1
    assert body["totals"]["packets"] == 0 and body["totals"]["unique_ips"] == 0
    failed = body["recent_sessions"][0]
    assert failed["status"] == "failed" and failed["error_message"] and failed["packets"] is None


def test_dashboard_is_scoped_to_the_user(auth_client, two_captures, make_client, tmp_path):
    other = make_client()
    register(other, "other@example.com")
    assert other.get("/api/v1/dashboard").get_json()["totals"]["captures"] == 0
    upload(other, pcap_of(tmp_path, build_packets()[:2], "o.pcap"), "o.pcap")
    mine = auth_client.get("/api/v1/dashboard").get_json()["totals"]
    theirs = other.get("/api/v1/dashboard").get_json()["totals"]
    assert (mine["captures"], mine["packets"]) == (2, 18)
    assert (theirs["captures"], theirs["packets"], theirs["unique_ips"]) == (1, 2, 2)


def test_dashboard_shows_in_progress_jobs(auth_client, tmp_path):
    cid = upload(auth_client, pcap_of(tmp_path, build_packets(), "a.pcap"), analyze="false").get_json()["capture"]["id"]
    record = db.session.get(CaptureRecord, uuid.UUID(cid))
    from app.models.capture import CaptureStatus

    record.status = CaptureStatus.PROCESSING
    db.session.commit()
    body = auth_client.get("/api/v1/dashboard").get_json()
    assert body["in_progress"] == 1 and body["status_counts"]["processing"] == 1


# ------------------------------------------------------------------------- comparison


def compare(client, a, b):
    return client.get("/api/v1/compare", query_string={"a": a, "b": b})


def test_compare_metrics_and_deltas(auth_client, two_captures):
    a, b, full, head = two_captures
    body = compare(auth_client, a["id"], b["id"]).get_json()
    metrics = {m["key"]: m for m in body["metrics"]}

    assert body["a"]["filename"] == "full.pcap" and body["b"]["filename"] == "head.pcap"
    assert (metrics["total_packets"]["a"], metrics["total_packets"]["b"]) == (15, 3)
    assert metrics["total_packets"]["delta"] == -12
    assert metrics["total_packets"]["delta_percent"] == pytest.approx(-80.0)
    assert metrics["total_bytes"]["a"] == frame_total(full) and metrics["total_bytes"]["b"] == frame_total(head)
    assert metrics["flow_count"]["delta"] == -3
    assert metrics["duration_seconds"]["b"] == pytest.approx(0.06, abs=1e-6)
    assert metrics["avg_packet_size"]["b"] == pytest.approx(frame_total(head) / 3)
    assert metrics["retransmission_rate"]["a"] == pytest.approx(1 / 9)
    assert metrics["retransmission_rate"]["b"] == 0
    assert metrics["rtt_mean_ms"]["a"] == pytest.approx(50.0, abs=0.01)


def test_compare_handles_missing_values_without_errors(auth_client, tmp_path, two_captures):
    a, _, _, _ = two_captures
    single = upload(auth_client, pcap_of(tmp_path, build_packets()[:1], "s.pcap"), "one.pcap").get_json()["capture"]
    metrics = {m["key"]: m for m in compare(auth_client, a["id"], single["id"]).get_json()["metrics"]}
    assert metrics["avg_bps"]["b"] is None and metrics["avg_bps"]["delta"] is None
    assert metrics["avg_bps"]["delta_percent"] is None
    assert metrics["rtt_mean_ms"]["b"] is None


def test_compare_protocols_and_ip_overlap(auth_client, two_captures):
    a, b, _, _ = two_captures
    body = compare(auth_client, a["id"], b["id"]).get_json()
    protocols = {p["protocol"]: p for p in body["protocols"]}

    assert protocols["TCP"]["a"]["packets"] == 9 and protocols["TCP"]["b"]["packets"] == 3
    assert protocols["UDP"]["a"]["packets"] == 2 and protocols["UDP"]["b"] is None
    assert body["protocols"][0]["protocol"] == "TCP"  # largest combined bytes first

    ips = body["ips"]
    assert (ips["shared"], ips["only_a"], ips["only_b"]) == (2, 4, 0)
    assert ips["sample"]["shared"] == ["10.0.0.1", "10.0.0.2"]
    assert "8.8.8.8" in ips["sample"]["only_a"] and ips["sample"]["only_b"] == []


def test_compare_rejects_bad_requests(auth_client, two_captures, make_client, tmp_path):
    a, b, _, _ = two_captures
    assert compare(auth_client, a["id"], a["id"]).status_code == 400
    assert compare(auth_client, "nope", b["id"]).status_code == 400
    assert auth_client.get("/api/v1/compare").status_code == 400
    assert compare(auth_client, a["id"], str(uuid.uuid4())).status_code == 404

    pending = upload(auth_client, pcap_of(tmp_path, build_packets(), "p.pcap"), analyze="false").get_json()["capture"]
    response = compare(auth_client, a["id"], pending["id"])
    assert response.status_code == 409 and "uploaded" in response.get_json()["error"]["message"]

    other = make_client()
    register(other, "mallory@example.com")
    assert compare(other, a["id"], b["id"]).status_code == 404
    own = upload(other, pcap_of(tmp_path, build_packets()[:2], "m.pcap"), "m.pcap").get_json()["capture"]
    assert compare(other, own["id"], a["id"]).status_code == 404  # cannot pair with someone else's
