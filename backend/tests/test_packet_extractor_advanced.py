"""Phase 4 extractor additions: TCP window / window scale and full DNS details."""

from tests.helpers import DNS, DNSQR, IP, TCP, UDP, Ether, extract

from scapy.all import IPv6


def _tcp(flags, window=8192, options=None, ip=None):
    return extract(Ether() / (ip or IP(src="10.0.0.1", dst="10.0.0.2"))
                   / TCP(sport=1, dport=2, flags=flags, window=window, options=options or []))


def test_tcp_window_is_captured_raw_and_unscaled():
    assert _tcp("A", window=1234).tcp_window == 1234
    assert _tcp("A", window=0).tcp_window == 0


def test_window_scale_option_is_read_from_syn_only_when_present():
    assert _tcp("S", options=[("WScale", 7)]).tcp_window_scale == 7
    assert _tcp("S", options=[("MSS", 1460)]).tcp_window_scale is None
    assert _tcp("S").tcp_window_scale is None


def test_window_fields_are_ipv6_aware_and_absent_for_udp():
    v6 = _tcp("S", window=500, options=[("WScale", 3)], ip=IPv6(src="2001:db8::1", dst="2001:db8::2"))
    assert (v6.tcp_window, v6.tcp_window_scale) == (500, 3)
    udp = extract(Ether() / IP() / UDP(sport=1, dport=9))
    assert (udp.tcp_window, udp.tcp_window_scale) == (None, None)


def test_dns_details_support_matching_and_multiple_questions():
    query = extract(Ether() / IP() / UDP(sport=5000, dport=53)
                    / DNS(id=77, rd=1, qd=DNSQR(qname="a.test") / DNSQR(qname="b.test", qtype="AAAA")))
    assert query.dns["id"] == 77 and query.dns["is_response"] is False
    assert [q["name"] for q in query.dns["questions"]] == ["a.test", "b.test"]
    assert [q["type"] for q in query.dns["questions"]] == [1, 28]

    response = extract(Ether() / IP() / UDP(sport=53, dport=5000)
                       / DNS(id=77, qr=1, rcode=3, tc=1, qd=DNSQR(qname="a.test")))
    assert response.dns["is_response"] is True and response.dns["rcode"] == 3
    assert response.dns["tc"] is True


def test_existing_dns_metadata_is_unchanged():
    ex = extract(Ether() / IP() / UDP(sport=5000, dport=53) / DNS(id=1, qd=DNSQR(qname="example.com")))
    assert ex.packet.application_metadata == {"query": "example.com", "is_response": False, "rcode": 0}


def test_non_dns_packets_carry_no_dns_details():
    assert _tcp("A").dns is None
