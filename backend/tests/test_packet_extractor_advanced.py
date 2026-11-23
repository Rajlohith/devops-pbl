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
                    / DNS(id=77, rd=1, qd=[DNSQR(qname="a.test"), DNSQR(qname="b.test", qtype="AAAA")]))
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


# ---- wider application-protocol identification (rules themselves: test_protocol_detector.py)
from scapy.all import Raw  # noqa: E402

from tests.test_protocol_detector import client_hello  # noqa: E402


def test_tls_is_identified_with_sni_on_any_port():
    ex = extract(Ether() / IP() / TCP(sport=50000, dport=8443, flags="PA") / Raw(client_hello(b"example.org")))
    assert ex.packet.application_protocol == "TLS" and ex.label == "TLS"
    assert ex.packet.application_metadata["sni"] == "example.org"


def test_ssh_banner_and_port_only_services():
    ssh = extract(Ether() / IP() / TCP(dport=2222, flags="PA") / Raw(b"SSH-2.0-OpenSSH_9.6\r\n"))
    assert ssh.packet.application_protocol == "SSH"
    mysql = extract(Ether() / IP() / TCP(dport=3306, flags="PA") / Raw(b"\x01\x02\x03"))
    assert mysql.packet.application_protocol == "MySQL"
    assert mysql.packet.application_metadata == {"detected_by": "port"}


def test_bare_handshake_packets_are_not_labelled_from_the_port():
    ex = extract(Ether() / IP() / TCP(dport=22, flags="S"))
    assert ex.packet.application_protocol is None and ex.label == "TCP"


def test_udp_protocols():
    quic = extract(Ether() / IP() / UDP(sport=50000, dport=443) / Raw(b"\xc3\x00\x00\x00\x01\x08" + b"\x00" * 30))
    assert quic.packet.application_protocol == "QUIC"
    ntp = extract(Ether() / IP() / UDP(sport=40000, dport=123) / Raw(b"\x1b" + b"\x00" * 47))
    assert ntp.packet.application_protocol == "NTP"


def test_more_ip_protocols_and_layer2_protocols_get_names():
    assert extract(Ether() / IP(proto=89)).label == "OSPF"
    assert extract(Ether() / IP(proto=2)).label == "IGMP"
    assert extract(Ether(type=0x88CC) / Raw(b"\x02\x07lldp")).label == "LLDP"
    assert extract(Ether(type=0x888E) / Raw(b"\x01\x00\x00\x00")).label == "EAPOL"
