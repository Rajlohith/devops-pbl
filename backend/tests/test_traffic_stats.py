import pytest
from scapy.all import ARP, DNS, DNSQR, Ether, IP, UDP

from app.services.flow_tracker import FlowTracker
from app.services.traffic_stats import MAX_POINTS, StatsAccumulator
from tests.helpers import T0, extract, tcp


def run(packets):
    tracker, stats = FlowTracker(), StatsAccumulator()
    for p in packets:
        _, retx = tracker.observe(p)
        stats.observe(p, retx)
    return stats.finalize(tracker.flows)


def test_empty_capture_finalizes_without_errors():
    result = run([])
    cols, summary = result["columns"], result["summary"]
    assert cols["total_packets"] == 0 and cols["total_bytes"] == 0 and cols["flow_count"] == 0
    assert cols["first_timestamp"] is None
    perf = summary["performance"]
    assert perf["avg_packet_size_bytes"] is None and perf["avg_throughput_bps"] is None
    assert perf["timeseries"] == {"bucket_seconds": None, "points": []}
    assert summary["latency"] == {"handshake_rtt_ms": None, "flow_jitter_ms": None}


def test_single_packet_has_no_rates():
    result = run([tcp("10.0.0.1", "10.0.0.2", 1, 2, "S")])
    perf = result["summary"]["performance"]
    assert result["columns"]["duration_seconds"] == 0
    assert perf["avg_packets_per_second"] is None and perf["avg_throughput_bps"] is None
    assert perf["peak_packets_per_second"] == 1  # still observable within its second


def test_totals_protocols_and_rates():
    packets = [
        tcp("10.0.0.1", "10.0.0.2", 5000, 80, "S", ts=T0),
        tcp("10.0.0.2", "10.0.0.1", 80, 5000, "SA", ts=T0 + 0.5),
        extract(Ether() / IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=1, dport=53) / DNS(qd=DNSQR(qname="a.io")), ts=T0 + 1),
        extract(Ether() / ARP(), ts=T0 + 4),
    ]
    result = run(packets)
    cols, summary = result["columns"], result["summary"]
    total_bytes = sum(p.packet.original_length for p in packets)

    assert cols["total_packets"] == 4 and cols["total_bytes"] == total_bytes
    assert cols["unique_ips"] == 3 and cols["flow_count"] == 2
    assert cols["duration_seconds"] == pytest.approx(4.0)

    transport = {r["protocol"]: r for r in summary["protocols"]["transport"]}
    assert {k: v["packets"] for k, v in transport.items()} == {"TCP": 2, "UDP": 1, "ARP": 1}
    assert sum(r["packet_percent"] for r in transport.values()) == pytest.approx(100)
    assert sum(r["byte_percent"] for r in transport.values()) == pytest.approx(100)
    assert [r["protocol"] for r in summary["protocols"]["application"]] == ["DNS"]

    perf = summary["performance"]
    assert perf["avg_packet_size_bytes"] == pytest.approx(total_bytes / 4)
    assert perf["avg_packets_per_second"] == pytest.approx(1.0)
    assert perf["avg_throughput_bps"] == pytest.approx(total_bytes * 8 / 4)
    # Packets at +0 and +0.5 share the first second; that is the peak.
    assert perf["peak_packets_per_second"] == 2
    first_second = packets[0].packet.original_length + packets[1].packet.original_length
    assert perf["peak_throughput_bps"] == first_second * 8
    assert summary["latency"]["handshake_rtt_ms"]["count"] == 1


def test_timeseries_fills_idle_gaps_and_conserves_totals():
    packets = [tcp("10.0.0.1", "10.0.0.2", 1, 2, "A", ts=T0 + t, seq=t) for t in (0, 1, 7)]
    series = run(packets)["summary"]["performance"]["timeseries"]
    assert series["bucket_seconds"] == 1
    assert [p["packets"] for p in series["points"]] == [1, 1, 0, 0, 0, 0, 0, 1]
    assert sum(p["bytes"] for p in series["points"]) == sum(p.packet.original_length for p in packets)


def test_timeseries_bucket_widens_for_long_captures():
    packets = [tcp("10.0.0.1", "10.0.0.2", 1, 2, "A", ts=T0 + t, seq=t) for t in (0, 3600)]
    series = run(packets)["summary"]["performance"]["timeseries"]
    assert series["bucket_seconds"] > 1
    assert len(series["points"]) <= MAX_POINTS
    assert sum(p["packets"] for p in series["points"]) == 2


def test_retransmission_rate_counts_tcp_packets_only():
    packets = [
        tcp("10.0.0.1", "10.0.0.2", 1, 2, "PA", seq=5, payload=b"x", ts=T0),
        tcp("10.0.0.1", "10.0.0.2", 1, 2, "PA", seq=5, payload=b"x", ts=T0 + 1),
        extract(Ether() / ARP()),
    ]
    tcp_stats = run(packets)["summary"]["tcp"]
    assert tcp_stats == {"packets": 2, "retransmissions": 1, "retransmission_rate": 0.5}
