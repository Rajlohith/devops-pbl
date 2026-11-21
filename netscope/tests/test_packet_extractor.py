from datetime import datetime, timezone

from scapy.all import (
    ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Dot1Q, Ether, IPv6, IPv6ExtHdrHopByHop,
    Raw,
)
from scapy.layers.inet6 import ICMPv6EchoRequest

from app.services.packet_extractor import extract_packet
from tests.helpers import CAPTURE_ID, T0, extract, roundtrip


def test_tcp_over_ipv4_fields():
    ex = extract(
        Ether(src="AA:BB:CC:00:00:01", dst="aa:bb:cc:00:00:02")
        / IP(src="10.1.1.1", dst="10.1.1.2", ttl=33)
        / TCP(sport=4000, dport=22, flags="SA", seq=1000, ack=2000),
        ts=T0 + 0.123456,
    )
    p = ex.packet
    assert ex.malformed_reason is None and ex.label == "TCP"
    assert (str(p.source_ip), str(p.destination_ip), p.ip_version) == ("10.1.1.1", "10.1.1.2", 4)
    assert (p.source_port, p.destination_port) == (4000, 22)
    assert p.tcp_flags == "SA"
    assert (p.tcp_sequence_number, p.tcp_acknowledgement_number) == (1000, 2000)
    assert p.ttl_or_hop_limit == 33
    assert p.transport_protocol.number == 6 and p.transport_protocol.name == "TCP"
    assert (p.source_mac, p.destination_mac) == ("aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02")
    assert p.ether_type == 0x0800
    assert p.timestamp == datetime.fromtimestamp(int(T0), tz=timezone.utc).replace(microsecond=123456)


def test_tcp_payload_length_comes_from_ip_header():
    ex = extract(Ether() / IP() / TCP() / Raw(b"x" * 37))
    assert ex.payload_length == 37


def test_snaplen_truncated_packet_keeps_wire_length_and_payload_length():
    layers = Ether() / IP() / TCP() / Raw(b"x" * 1000)
    ex = extract(layers)
    # Simulate a capture cut at 100 bytes: the file stores only the first 100.
    cut = Ether(bytes(roundtrip(layers))[:100])
    cut.time = T0
    cut.wirelen = len(bytes(layers))
    ex = extract_packet(cut, 1, CAPTURE_ID)
    assert ex.packet.captured_length == 100
    assert ex.packet.original_length == len(bytes(layers))
    assert ex.payload_length == 1000  # taken from the IP total length, not the cut bytes


def test_udp_dns_query_and_response():
    q = extract(Ether() / IP() / UDP(sport=5000, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com")))
    assert q.label == "DNS" and q.packet.transport_protocol.name == "UDP"
    assert q.packet.application_metadata == {"query": "example.com", "is_response": False, "rcode": 0}
    assert q.packet.udp_length is not None

    r = extract(
        Ether() / IP() / UDP(sport=53, dport=5000)
        / DNS(qr=1, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com", rdata="1.2.3.4"))
    )
    assert r.packet.application_protocol == "DNS"
    assert r.packet.application_metadata["is_response"] is True


def test_dns_over_tcp_is_identified():
    dns = bytes(DNS(rd=1, qd=DNSQR(qname="tcp.example.org")))
    ex = extract(Ether() / IP() / TCP(sport=4000, dport=53, flags="PA") / Raw(len(dns).to_bytes(2, "big") + dns))
    assert ex.packet.application_protocol == "DNS"
    assert ex.packet.application_metadata["query"] == "tcp.example.org"


def test_http_request_and_response_identified_by_payload():
    req = extract(Ether() / IP() / TCP(dport=8080, flags="PA") / Raw(b"POST /x HTTP/1.1\r\nHost: a\r\n\r\n"))
    assert req.label == "HTTP"
    assert req.packet.application_metadata == {"start_line": "POST /x HTTP/1.1"}
    resp = extract(Ether() / IP() / TCP(sport=9999, flags="PA") / Raw(b"HTTP/1.1 404 Not Found\r\n\r\n"))
    assert resp.packet.application_protocol == "HTTP"


def test_non_http_payload_on_port_80_is_not_labelled_http():
    ex = extract(Ether() / IP() / TCP(dport=80, flags="PA") / Raw(b"\x16\x03\x01 binary"))
    assert ex.packet.application_protocol is None and ex.label == "TCP"


def test_icmp_and_metadata():
    ex = extract(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / ICMP(type=8, code=0))
    assert ex.label == "ICMP"
    assert ex.packet.transport_protocol.number == 1
    assert ex.packet.application_metadata == {"icmp_type": 8, "icmp_code": 0}
    assert ex.packet.source_port is None


def test_ipv6_tcp_with_extension_header_and_vlan():
    ex = extract(
        Ether() / Dot1Q(vlan=42) / IPv6(src="2001:db8::1", dst="2001:db8::2", hlim=7)
        / IPv6ExtHdrHopByHop() / TCP(sport=1000, dport=443, flags="S")
    )
    p = ex.packet
    assert p.ip_version == 6 and str(p.source_ip) == "2001:db8::1"
    assert p.vlan_id == 42
    assert p.transport_protocol.number == 6  # final protocol, not the hop-by-hop header
    assert (p.source_port, p.destination_port) == (1000, 443)
    assert p.ttl_or_hop_limit == 7
    assert ex.malformed_reason is None


def test_icmpv6():
    ex = extract(Ether() / IPv6(src="fe80::1", dst="fe80::2") / ICMPv6EchoRequest())
    assert ex.label == "ICMPv6" and ex.packet.transport_protocol.number == 58


def test_arp_is_recognised_without_ip_fields():
    ex = extract(Ether() / ARP())
    assert ex.label == "ARP" and ex.packet.source_ip is None and ex.malformed_reason is None


def test_unknown_ip_protocol_is_kept_with_number_only():
    ex = extract(Ether() / IP(proto=99) / Raw(b"abc"))
    assert ex.packet.transport_protocol.number == 99
    assert ex.packet.transport_protocol.name is None
    assert ex.label == "Proto 99" and ex.malformed_reason is None


def test_truncated_ip_header_is_malformed_but_kept():
    ex = extract(Ether(type=0x0800) / Raw(b"\x45\x00\x00"))
    assert ex.malformed_reason == "truncated_ip_header"
    assert ex.packet.captured_length == 17


def test_truncated_transport_header_is_malformed_but_ip_fields_kept():
    ex = extract(Ether() / IP(src="10.0.0.1", dst="10.0.0.2", proto=6) / Raw(b"abcd"))
    assert ex.malformed_reason == "truncated_transport_header"
    assert str(ex.packet.source_ip) == "10.0.0.1" and ex.packet.source_port is None


def test_later_ip_fragment_without_transport_header_is_not_malformed():
    ex = extract(Ether() / IP(proto=6, frag=5) / Raw(b"abcd"))
    assert ex.malformed_reason is None and ex.packet.transport_protocol.name == "TCP"


def test_undissectable_frame_is_malformed():
    pkt = Raw(b"\x01\x02\x03")
    pkt.time = T0
    ex = extract_packet(pkt, 9, CAPTURE_ID)
    assert ex.malformed_reason == "unparsed_frame" and ex.packet.packet_number == 9


def test_unexpected_exception_yields_fallback_packet(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("decoder bug")

    monkeypatch.setattr("app.services.packet_extractor._extract", boom)
    pkt = roundtrip(Ether() / IP() / TCP())
    ex = extract_packet(pkt, 4, CAPTURE_ID)
    assert ex.malformed_reason == "extraction_error:RuntimeError"
    assert ex.packet.packet_number == 4 and ex.packet.captured_length > 0


def test_tcp_port_53_payload_that_is_not_valid_dns_is_not_labelled_dns():
    ex = extract(Ether() / IP() / TCP(dport=53, flags="PA") / Raw(b"\x00\x63not a dns message at all"))
    assert ex.packet.application_protocol is None and ex.label == "TCP"
