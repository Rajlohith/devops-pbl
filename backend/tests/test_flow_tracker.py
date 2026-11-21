import pytest

from app.services.flow_tracker import FlowTracker
from tests.helpers import ARP, ICMP, IP, TCP, UDP, Ether, T0, extract, tcp


def observe_all(packets):
    tracker = FlowTracker()
    results = [tracker.observe(p) for p in packets]
    return tracker, results


def test_both_directions_form_one_flow_with_initiator_as_endpoint_a():
    packets = [
        tcp("10.0.0.1", "10.0.0.2", 5000, 80, "S", seq=1, ts=T0),
        tcp("10.0.0.2", "10.0.0.1", 80, 5000, "SA", seq=9, ack=2, ts=T0 + 0.02),
        tcp("10.0.0.1", "10.0.0.2", 5000, 80, "A", seq=2, ack=10, ts=T0 + 0.03),
    ]
    tracker, results = observe_all(packets)

    assert [r[0] for r in results] == [1, 1, 1]
    (flow,) = tracker.flows
    assert (flow.a_ip, flow.a_port, flow.b_ip, flow.b_port) == ("10.0.0.1", 5000, "10.0.0.2", 80)
    assert (flow.packets_ab, flow.packets_ba, flow.packets_total) == (2, 1, 3)
    assert flow.bytes_total == sum(p.packet.original_length for p in packets)
    assert flow.bytes_ab == packets[0].packet.original_length + packets[2].packet.original_length
    assert flow.duration_seconds == pytest.approx(0.03, abs=1e-6)
    assert flow.protocol_name == "TCP"


def test_different_ports_or_protocols_are_different_flows():
    packets = [
        tcp("10.0.0.1", "10.0.0.2", 5000, 80, "S"),
        tcp("10.0.0.1", "10.0.0.2", 5001, 80, "S"),
        extract(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=80)),
    ]
    tracker, results = observe_all(packets)
    assert [r[0] for r in results] == [1, 2, 3]
    assert len(tracker) == 3


def test_icmp_flow_and_non_ip_packets():
    packets = [
        extract(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / ICMP(type=8), ts=T0),
        extract(Ether() / IP(src="2.2.2.2", dst="1.1.1.1") / ICMP(type=0), ts=T0 + 0.5),
        extract(Ether() / ARP()),
    ]
    tracker, results = observe_all(packets)
    assert [r[0] for r in results] == [1, 1, None]  # ARP belongs to no flow
    assert tracker.flows[0].protocol_name == "ICMP" and tracker.flows[0].packets_total == 2


def test_exact_duplicate_segment_is_a_retransmission_but_pure_acks_are_not():
    data = dict(seq=1000, payload=b"x" * 50)
    packets = [
        tcp("10.0.0.1", "10.0.0.2", 5000, 80, "PA", ts=T0, **data),
        tcp("10.0.0.1", "10.0.0.2", 5000, 80, "PA", ts=T0 + 0.2, **data),  # duplicate
        tcp("10.0.0.2", "10.0.0.1", 80, 5000, "A", seq=7, ack=1050, ts=T0 + 0.3),
        tcp("10.0.0.2", "10.0.0.1", 80, 5000, "A", seq=7, ack=1050, ts=T0 + 0.4),  # dup ACK
        tcp("10.0.0.1", "10.0.0.2", 5000, 80, "PA", seq=1050, payload=b"y" * 50, ts=T0 + 0.5),
    ]
    tracker, results = observe_all(packets)
    assert [r[1] for r in results] == [False, True, False, False, False]
    assert tracker.flows[0].retransmissions == 1


def test_same_sequence_in_opposite_directions_is_not_a_retransmission():
    packets = [
        tcp("10.0.0.1", "10.0.0.2", 5000, 80, "PA", seq=1, payload=b"abc"),
        tcp("10.0.0.2", "10.0.0.1", 80, 5000, "PA", seq=1, payload=b"abc"),
    ]
    _, results = observe_all(packets)
    assert [r[1] for r in results] == [False, False]


def test_retransmitted_syn_is_detected_and_rtt_uses_first_syn():
    packets = [
        tcp("10.0.0.1", "10.0.0.2", 5000, 80, "S", seq=1, ts=T0),
        tcp("10.0.0.1", "10.0.0.2", 5000, 80, "S", seq=1, ts=T0 + 1.0),  # SYN retransmit
        tcp("10.0.0.2", "10.0.0.1", 80, 5000, "SA", seq=5, ack=2, ts=T0 + 1.04),
    ]
    tracker, results = observe_all(packets)
    assert results[1][1] is True
    assert tracker.flows[0].retransmissions == 1
    assert tracker.flows[0].handshake_rtt_ms == pytest.approx(1040, abs=0.01)


def test_handshake_rtt_is_syn_to_synack():
    packets = [
        tcp("10.0.0.1", "10.0.0.2", 5000, 80, "S", seq=1, ts=T0),
        tcp("10.0.0.2", "10.0.0.1", 80, 5000, "SA", seq=5, ack=2, ts=T0 + 0.042),
    ]
    (flow,) = observe_all(packets)[0].flows
    assert flow.handshake_rtt_ms == pytest.approx(42.0, abs=0.01)


def test_no_rtt_without_captured_handshake():
    packets = [tcp("10.0.0.1", "10.0.0.2", 5000, 80, "PA", seq=1, payload=b"a")]
    assert observe_all(packets)[0].flows[0].handshake_rtt_ms is None


def test_jitter_is_mean_absolute_change_in_interarrival_gap():
    # gaps: 0.10, 0.30, 0.10  ->  |0.30-0.10| and |0.10-0.30| -> mean 0.20 s
    times = [0.0, 0.10, 0.40, 0.50]
    packets = [tcp("10.0.0.1", "10.0.0.2", 5000, 80, "A", seq=i, ts=T0 + t) for i, t in enumerate(times)]
    (flow,) = observe_all(packets)[0].flows
    assert flow.jitter_ms == pytest.approx(200.0, abs=0.01)


def test_jitter_needs_three_packets():
    packets = [tcp("10.0.0.1", "10.0.0.2", 5000, 80, "A", ts=T0 + t) for t in (0, 1)]
    assert observe_all(packets)[0].flows[0].jitter_ms is None


def test_out_of_order_timestamps_extend_flow_bounds_without_negative_gaps():
    packets = [
        tcp("10.0.0.1", "10.0.0.2", 5000, 80, "A", seq=1, ts=T0 + 5),
        tcp("10.0.0.1", "10.0.0.2", 5000, 80, "A", seq=2, ts=T0),
    ]
    (flow,) = observe_all(packets)[0].flows
    assert flow.duration_seconds == pytest.approx(5.0)
    assert flow.jitter_ms is None


def test_retransmission_memory_is_bounded():
    from app.services import flow_tracker

    tracker = FlowTracker()
    for i in range(flow_tracker._SEEN_WINDOW + 50):
        tracker.observe(tcp("10.0.0.1", "10.0.0.2", 5000, 80, "PA", seq=i * 10, payload=b"x"))
    seen = tracker.flows[0]._seen[0]
    assert len(seen) <= flow_tracker._SEEN_WINDOW + 1
