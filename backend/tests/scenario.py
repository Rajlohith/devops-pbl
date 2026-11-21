"""A small capture with a known, hand-built conversation for end-to-end tests.

Packet numbers are file order. Times are offsets (seconds) from T0.
"""

from scapy.all import ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether, IPv6, Raw

T0 = 1_700_000_000  # 2023-11-14T22:13:20Z

GET = b"GET /index.html HTTP/1.1\r\nHost: example.test\r\n\r\n"
RESPONSE = b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 80

CLIENT, SERVER, DNS_SERVER, PING_TARGET = "10.0.0.1", "10.0.0.2", "8.8.8.8", "10.0.0.3"
V6_A, V6_B = "2001:db8::1", "2001:db8::2"


def _tcp(src, dst, sport, dport, flags, seq, ack, payload=b""):
    layers = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
    return layers / Raw(payload) if payload else layers


def build_packets():
    spec = [
        (0.000, _tcp(CLIENT, SERVER, 40000, 80, "S", 100, 0)),                       # 1
        (0.050, _tcp(SERVER, CLIENT, 80, 40000, "SA", 500, 101)),                    # 2  RTT 50 ms
        (0.060, _tcp(CLIENT, SERVER, 40000, 80, "A", 101, 501)),                     # 3
        (0.100, _tcp(CLIENT, SERVER, 40000, 80, "PA", 101, 501, GET)),               # 4  HTTP request
        (0.150, _tcp(SERVER, CLIENT, 80, 40000, "A", 501, 101 + len(GET))),          # 5
        (0.200, _tcp(SERVER, CLIENT, 80, 40000, "PA", 501, 101 + len(GET), RESPONSE)),  # 6  HTTP response
        (0.500, Ether() / IP(src=CLIENT, dst=DNS_SERVER) / UDP(sport=5000, dport=53)
                / DNS(id=7, rd=1, qd=DNSQR(qname="example.test"))),                  # 7
        (0.600, Ether() / IP(src=DNS_SERVER, dst=CLIENT) / UDP(sport=53, dport=5000)
                / DNS(id=7, qr=1, qd=DNSQR(qname="example.test"),
                      an=DNSRR(rrname="example.test", rdata="10.0.0.2"))),           # 8
        (1.200, _tcp(SERVER, CLIENT, 80, 40000, "PA", 501, 101 + len(GET), RESPONSE)),  # 9  retransmission of 6
        (1.250, _tcp(CLIENT, SERVER, 40000, 80, "FA", 101 + len(GET), 501 + len(RESPONSE))),  # 10
        (2.000, Ether() / IP(src=CLIENT, dst=PING_TARGET) / ICMP(type=8)),           # 11
        (2.010, Ether() / IP(src=PING_TARGET, dst=CLIENT) / ICMP(type=0)),           # 12
        (3.000, Ether() / IPv6(src=V6_A, dst=V6_B) / TCP(sport=1000, dport=443, flags="S")),  # 13
        (4.000, Ether() / ARP()),                                                    # 14
        (5.000, Ether(type=0x0800) / Raw(b"\x45\x00\x00")),                          # 15 malformed
    ]
    packets = []
    for offset, layers in spec:
        packet = Ether(bytes(layers))
        packet.time = T0 + offset
        packets.append(packet)
    return packets


FLOW1_PACKETS = (1, 2, 3, 4, 5, 6, 9, 10)  # the HTTP connection
