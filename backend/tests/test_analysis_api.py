import io
import uuid

import pytest
from scapy.all import wrpcap
from scapy.utils import PcapNgWriter

from app.extensions import db
from app.models.capture import CaptureStatus
from app.orm import AnalysisResult, CaptureRecord, FlowRecord, PacketRecord
from app.workers.tasks import analyze_capture
from tests.conftest import register, upload
from tests.scenario import FLOW1_PACKETS, GET, build_packets


@pytest.fixture
def packets():
    return build_packets()


@pytest.fixture
def pcap(tmp_path, packets):
    path = tmp_path / "scenario.pcap"
    wrpcap(str(path), packets)
    return path.read_bytes()


@pytest.fixture
def capture_id(auth_client, pcap):
    response = upload(auth_client, pcap, "scenario.pcap")
    assert response.get_json()["capture"]["status"] == "completed"
    return response.get_json()["capture"]["id"]


def frame_len(packets, number):
    return len(bytes(packets[number - 1]))


def get(client, capture_id, path="", **params):
    return client.get(f"/api/v1/captures/{capture_id}{path}", query_string=params)


def numbers(response):
    return [item["packet_number"] for item in response.get_json()["items"]]


# ---------------------------------------------------------------- summary & protocols


def test_summary_totals_match_the_constructed_capture(auth_client, capture_id, packets):
    body = get(auth_client, capture_id, "/summary").get_json()
    totals = body["totals"]

    assert body["capture"]["status"] == "completed" and body["capture"]["packet_count"] == 15
    assert totals["total_packets"] == 15
    assert totals["total_bytes"] == sum(len(bytes(p)) for p in packets)
    assert totals["unique_ips"] == 6
    assert totals["flow_count"] == 4  # HTTP, DNS, ICMP, IPv6; ARP and the malformed frame have none
    assert totals["malformed_packets"] == 1
    assert totals["duration_seconds"] == pytest.approx(5.0)
    assert totals["first_timestamp"].startswith("2023-11-14T22:13:20")


def test_protocol_statistics(auth_client, capture_id, packets):
    protocols = get(auth_client, capture_id, "/protocols").get_json()["protocols"]
    transport = {r["protocol"]: r for r in protocols["transport"]}
    application = {r["protocol"]: r for r in protocols["application"]}

    assert {k: v["packets"] for k, v in transport.items()} == {
        "TCP": 9, "UDP": 2, "ICMP": 2, "ARP": 1, "Other": 1,
    }
    tcp_numbers = (1, 2, 3, 4, 5, 6, 9, 10, 13)
    assert transport["TCP"]["bytes"] == sum(frame_len(packets, n) for n in tcp_numbers)
    assert {k: v["packets"] for k, v in application.items()} == {"HTTP": 3, "DNS": 2}
    assert application["DNS"]["bytes"] == frame_len(packets, 7) + frame_len(packets, 8)
    assert sum(r["packet_percent"] for r in transport.values()) == pytest.approx(100)
    # Sorted by bytes, largest first
    assert [r["bytes"] for r in protocols["transport"]] == sorted(
        (r["bytes"] for r in protocols["transport"]), reverse=True
    )


# ---------------------------------------------------------------- performance


def test_performance_metrics(auth_client, capture_id, packets):
    body = get(auth_client, capture_id, "/performance").get_json()
    perf, total = body["performance"], sum(len(bytes(p)) for p in packets)

    assert body["utilization"] is None  # needs a link speed
    assert perf["avg_packet_size_bytes"] == pytest.approx(total / 15)
    assert perf["avg_packets_per_second"] == pytest.approx(15 / 5.0)
    assert perf["avg_throughput_bps"] == pytest.approx(total * 8 / 5.0)
    assert perf["min_packet_size_bytes"] == min(len(bytes(p)) for p in packets)
    assert perf["max_packet_size_bytes"] == max(len(bytes(p)) for p in packets)

    # Busiest second is the first one: packets 1-8 (t = 0.0 .. 0.6).
    assert perf["peak_packets_per_second"] == 8
    assert perf["peak_throughput_bps"] == sum(frame_len(packets, n) for n in range(1, 9)) * 8

    series = perf["timeseries"]
    assert series["bucket_seconds"] == 1
    assert [p["packets"] for p in series["points"]] == [8, 2, 2, 1, 1, 1]
    assert sum(p["bytes"] for p in series["points"]) == total
    assert series["points"][0]["time"].startswith("2023-11-14T22:13:20")


def test_tcp_retransmissions_and_latency(auth_client, capture_id):
    body = get(auth_client, capture_id, "/performance").get_json()
    assert body["tcp"] == {"packets": 9, "retransmissions": 1, "retransmission_rate": pytest.approx(1 / 9)}
    rtt = body["latency"]["handshake_rtt_ms"]
    assert rtt["count"] == 1 and rtt["mean"] == pytest.approx(50.0, abs=0.01)
    jitter = body["latency"]["flow_jitter_ms"]
    assert jitter["count"] >= 1 and jitter["min"] > 0


def test_utilization_requires_and_validates_link_speed(auth_client, capture_id):
    body = get(auth_client, capture_id, "/performance", link_mbps="0.001").get_json()
    perf = body["performance"]
    capacity = 0.001 * 1_000_000
    assert body["utilization"]["link_capacity_mbps"] == 0.001
    assert body["utilization"]["avg_percent"] == pytest.approx(100 * perf["avg_throughput_bps"] / capacity)
    assert body["utilization"]["peak_percent"] == pytest.approx(100 * perf["peak_throughput_bps"] / capacity)
    for bad in ("0", "-5", "fast"):
        assert get(auth_client, capture_id, "/performance", link_mbps=bad).status_code == 400


# ---------------------------------------------------------------- flows


def test_http_flow_reconstruction(auth_client, capture_id, packets):
    items = get(auth_client, capture_id, "/flows").get_json()["items"]
    top = items[0]  # default sort: bytes descending

    assert top["protocol"] == "TCP" and top["application_protocol"] == "HTTP"
    assert top["endpoint_a"] == {"ip": "10.0.0.1", "port": 40000}  # initiator
    assert top["endpoint_b"] == {"ip": "10.0.0.2", "port": 80}
    assert top["packets"] == {"total": 8, "a_to_b": 4, "b_to_a": 4}
    assert top["bytes"]["total"] == sum(frame_len(packets, n) for n in FLOW1_PACKETS)
    assert top["bytes"]["a_to_b"] == sum(frame_len(packets, n) for n in (1, 3, 4, 10))
    assert top["duration_seconds"] == pytest.approx(1.25, abs=1e-6)
    assert top["retransmissions"] == 1
    assert top["handshake_rtt_ms"] == pytest.approx(50.0, abs=0.01)
    assert top["flow_id"] == 1
    assert [f["bytes"]["total"] for f in items] == sorted((f["bytes"]["total"] for f in items), reverse=True)


def test_flow_filters_sorting_and_detail(auth_client, capture_id):
    def flows(**params):
        return get(auth_client, capture_id, "/flows", **params).get_json()

    assert flows(protocol="udp")["total"] == 1
    assert flows(protocol="UDP")["items"][0]["application_protocol"] == "DNS"
    assert flows(application="http")["total"] == 1
    assert flows(ip="2001:0db8:0:0:0:0:0:1")["total"] == 1  # uncompressed IPv6 is normalised
    assert flows(port="53")["total"] == 1
    assert flows(ip="10.0.0.1")["total"] == 3
    by_start = flows(sort="start", order="asc")["items"]
    assert [f["flow_id"] for f in by_start] == [1, 2, 3, 4]
    assert flows(sort="packets")["items"][0]["packets"]["total"] == 8
    assert flows(per_page=2)["total"] == 4 and len(flows(per_page=2)["items"]) == 2

    one = get(auth_client, capture_id, "/flows/3").get_json()["flow"]
    assert one["protocol"] == "ICMP" and one["endpoint_a"]["port"] is None
    assert get(auth_client, capture_id, "/flows/99").status_code == 404


# ---------------------------------------------------------------- packets


def test_packet_pagination_and_ordering(auth_client, capture_id):
    page1 = get(auth_client, capture_id, "/packets", per_page=4).get_json()
    assert page1["total"] == 15 and page1["page"] == 1 and page1["per_page"] == 4
    assert numbers(get(auth_client, capture_id, "/packets", per_page=4)) == [1, 2, 3, 4]
    assert numbers(get(auth_client, capture_id, "/packets", per_page=4, page=4)) == [13, 14, 15]
    assert numbers(get(auth_client, capture_id, "/packets", per_page=4, page=5)) == []
    assert numbers(get(auth_client, capture_id, "/packets", per_page=3, order="desc")) == [15, 14, 13]
    biggest = get(auth_client, capture_id, "/packets", sort="length", order="desc", per_page=1)
    assert numbers(biggest) == [9] or numbers(biggest) == [6]  # the two equal-size 80-byte responses


@pytest.mark.parametrize(
    "params, expected",
    [
        ({"protocol": "tcp"}, [1, 2, 3, 4, 5, 6, 9, 10, 13]),
        ({"protocol": "HTTP"}, [4, 6, 9]),
        ({"protocol": "dns"}, [7, 8]),
        ({"protocol": "arp"}, [14]),
        ({"src_ip": "8.8.8.8"}, [8]),
        ({"dst_ip": "8.8.8.8"}, [7]),
        ({"ip": "10.0.0.3"}, [11, 12]),
        ({"ip": "2001:db8::2"}, [13]),
        ({"src_port": 80}, [2, 5, 6, 9]),
        ({"dst_port": 53}, [7]),
        ({"port": 53}, [7, 8]),
        ({"flow_id": 1}, [1, 2, 3, 4, 5, 6, 9, 10]),
        ({"tcp_flags": "SA"}, [2]),
        ({"tcp_flags": "S"}, [1, 2, 13]),
        ({"tcp_flags": "FA"}, [10]),
        ({"retransmission": "true"}, [9]),
        ({"malformed": "true"}, [15]),
        ({"malformed": "false", "protocol": "other"}, []),
        ({"q": "8.8.8.8"}, [7, 8]),
        ({"q": "40000"}, [1, 2, 3, 4, 5, 6, 9, 10]),
        ({"q": "15"}, [15]),
        ({"q": "arp"}, [14]),
        ({"protocol": "tcp", "tcp_flags": "P", "src_port": 80}, [6, 9]),
    ],
)
def test_packet_filters(auth_client, capture_id, params, expected):
    assert numbers(get(auth_client, capture_id, "/packets", **params)) == expected


def test_packet_length_filters(auth_client, capture_id, packets):
    threshold = frame_len(packets, 6)
    expected = [n for n in range(1, 16) if frame_len(packets, n) >= threshold]
    assert numbers(get(auth_client, capture_id, "/packets", min_length=threshold)) == expected
    small = [n for n in range(1, 16) if frame_len(packets, n) <= 42]
    assert numbers(get(auth_client, capture_id, "/packets", max_length=42)) == small


@pytest.mark.parametrize(
    "params",
    [
        {"ip": "not-an-ip"}, {"src_port": 70000}, {"port": "abc"}, {"per_page": 1000},
        {"per_page": 0}, {"page": 0}, {"tcp_flags": "Z"}, {"sort": "bogus"},
        {"order": "sideways"}, {"retransmission": "maybe"}, {"flow_id": 0},
    ],
)
def test_invalid_filters_are_rejected(auth_client, capture_id, params):
    response = get(auth_client, capture_id, "/packets", **params)
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == 400


def test_like_wildcards_in_search_are_literal(auth_client, capture_id):
    assert get(auth_client, capture_id, "/packets", q="%").get_json()["total"] == 0
    assert get(auth_client, capture_id, "/packets", q="_").get_json()["total"] == 0


def test_packet_detail_exposes_extracted_fields(auth_client, capture_id):
    http = get(auth_client, capture_id, "/packets/4").get_json()["packet"]
    assert http["timestamp"].startswith("2023-11-14T22:13:20.1")
    assert (http["source_ip"], http["destination_ip"], http["ip_version"]) == ("10.0.0.1", "10.0.0.2", 4)
    assert (http["source_port"], http["destination_port"]) == (40000, 80)
    assert http["tcp_flags"] == "PA" and http["tcp_sequence_number"] == 101
    assert http["protocol"] == "HTTP" and http["transport_protocol"] == "TCP"
    assert http["application_metadata"] == {"start_line": "GET /index.html HTTP/1.1"}
    assert http["payload_length"] == len(GET) and http["flow_id"] == 1

    assert get(auth_client, capture_id, "/packets/9").get_json()["packet"]["is_retransmission"] is True
    v6 = get(auth_client, capture_id, "/packets/13").get_json()["packet"]
    assert v6["ip_version"] == 6 and v6["source_ip"] == "2001:db8::1"
    bad = get(auth_client, capture_id, "/packets/15").get_json()["packet"]
    assert bad["malformed_reason"] == "truncated_ip_header" and bad["source_ip"] is None
    assert get(auth_client, capture_id, "/packets/16").status_code == 404
    assert get(auth_client, capture_id, "/packets/0").status_code == 404


# ---------------------------------------------------------------- access control & state


ANALYSIS_PATHS = ["/summary", "/protocols", "/performance", "/packets", "/packets/1", "/flows", "/flows/1"]


def test_other_users_cannot_read_analysis(capture_id, make_client):
    other = make_client()
    register(other, "mallory@example.com")
    for path in ANALYSIS_PATHS:
        assert get(other, capture_id, path).status_code == 404, path


def test_analysis_requires_login(capture_id, make_client):
    for path in ANALYSIS_PATHS:
        assert get(make_client(), capture_id, path).status_code == 401, path


def test_results_unavailable_until_completed(auth_client, pcap):
    capture_id = upload(auth_client, pcap, analyze="false").get_json()["capture"]["id"]
    for path in ANALYSIS_PATHS:
        response = get(auth_client, capture_id, path)
        assert response.status_code == 409, path
        assert "uploaded" in response.get_json()["error"]["message"]


def test_delete_removes_all_analysis_rows(auth_client, capture_id):
    assert db.session.scalar(db.select(db.func.count()).select_from(PacketRecord)) == 15
    assert auth_client.delete(f"/api/v1/captures/{capture_id}").status_code == 204
    db.session.expire_all()
    for model in (PacketRecord, FlowRecord, AnalysisResult):
        assert db.session.scalar(db.select(db.func.count()).select_from(model)) == 0, model


# ---------------------------------------------------------------- pipeline behaviour


def test_small_batches_give_identical_results(auth_client, pcap, app):
    app.config["PACKET_BATCH_SIZE"] = 4
    capture_id = upload(auth_client, pcap).get_json()["capture"]["id"]
    totals = get(auth_client, capture_id, "/summary").get_json()["totals"]
    assert (totals["total_packets"], totals["flow_count"]) == (15, 4)
    assert get(auth_client, capture_id, "/packets").get_json()["total"] == 15
    assert get(auth_client, capture_id, "/flows").get_json()["total"] == 4


def test_pcapng_capture_gives_same_analysis(auth_client, tmp_path, packets):
    path = tmp_path / "scenario.pcapng"
    writer = PcapNgWriter(str(path))
    writer.write(packets)
    writer.close()
    response = upload(auth_client, path.read_bytes(), "scenario.pcapng")

    capture = response.get_json()["capture"]
    assert capture["file_format"] == "pcapng" and capture["status"] == "completed"
    summary = get(auth_client, capture["id"], "/summary").get_json()["totals"]
    assert (summary["total_packets"], summary["flow_count"], summary["unique_ips"]) == (15, 4, 6)
    assert summary["total_bytes"] == sum(len(bytes(p)) for p in packets)


def test_capture_with_no_packets_completes_with_zero_results(auth_client, tmp_path):
    path = tmp_path / "empty.pcap"
    wrpcap(str(path), [])
    capture = upload(auth_client, path.read_bytes(), "empty.pcap").get_json()["capture"]

    assert capture["status"] == "completed" and capture["packet_count"] == 0
    totals = get(auth_client, capture["id"], "/summary").get_json()["totals"]
    assert totals["total_packets"] == 0 and totals["first_timestamp"] is None
    perf = get(auth_client, capture["id"], "/performance").get_json()["performance"]
    assert perf["avg_throughput_bps"] is None and perf["timeseries"]["points"] == []
    assert get(auth_client, capture["id"], "/packets").get_json()["items"] == []
    assert get(auth_client, capture["id"], "/flows").get_json()["items"] == []


def test_reanalysis_replaces_results_instead_of_duplicating(auth_client, capture_id):
    cid = uuid.UUID(capture_id)
    record = db.session.get(CaptureRecord, cid)
    record.status = CaptureStatus.PENDING
    db.session.commit()

    analyze_capture(capture_id)

    assert db.session.scalar(db.select(db.func.count()).select_from(PacketRecord)) == 15
    assert db.session.scalar(db.select(db.func.count()).select_from(FlowRecord)) == 4
    assert db.session.scalar(db.select(db.func.count()).select_from(AnalysisResult)) == 1


def test_failure_midway_discards_partial_results(auth_client, pcap, app, monkeypatch):
    app.config["PACKET_BATCH_SIZE"] = 4  # several batches are already stored when it fails
    calls = {"n": 0}
    from app.services.flow_tracker import FlowTracker

    original = FlowTracker.observe

    def flaky(self, ex):
        calls["n"] += 1
        if calls["n"] == 10:
            raise RuntimeError("simulated crash")
        return original(self, ex)

    monkeypatch.setattr(FlowTracker, "observe", flaky)
    capture = upload(auth_client, pcap).get_json()["capture"]

    assert capture["status"] == "failed" and "unexpectedly" in capture["error_message"]
    db.session.expire_all()
    for model in (PacketRecord, FlowRecord, AnalysisResult):
        assert db.session.scalar(db.select(db.func.count()).select_from(model)) == 0, model
    assert get(auth_client, capture["id"], "/packets").status_code == 409

    monkeypatch.undo()  # retry succeeds and serves complete results
    assert auth_client.post(f"/api/v1/captures/{capture['id']}/analyze").status_code == 202
    assert get(auth_client, capture["id"], "/packets").get_json()["total"] == 15


def test_packet_limit_failure_discards_partial_results(auth_client, pcap, app):
    app.config["MAX_PACKETS_PER_CAPTURE"] = 10
    app.config["PACKET_BATCH_SIZE"] = 4
    capture = upload(auth_client, pcap).get_json()["capture"]

    assert capture["status"] == "failed" and "limit of 10 packets" in capture["error_message"]
    db.session.expire_all()
    assert db.session.scalar(db.select(db.func.count()).select_from(PacketRecord)) == 0


def test_analysis_does_not_mix_data_between_captures(auth_client, make_client, pcap, tmp_path):
    first = upload(auth_client, pcap, "a.pcap").get_json()["capture"]["id"]
    other = make_client()
    register(other, "bob@example.com")
    path = tmp_path / "tiny.pcap"
    wrpcap(str(path), build_packets()[:3])
    second = upload(other, path.read_bytes(), "b.pcap").get_json()["capture"]["id"]

    assert get(auth_client, first, "/packets").get_json()["total"] == 15
    assert get(other, second, "/packets").get_json()["total"] == 3
    assert get(other, second, "/flows").get_json()["total"] == 1
