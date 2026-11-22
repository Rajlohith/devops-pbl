"""A controlled capture exercising every Phase 4 metric. Offsets are seconds from T0.

Hand-computed expectations (kept next to the packets so tests and capture stay in sync):

TCP connections (29): 10.0.0.1:40000->10.0.0.2:80 established (SYN->SYN-ACK 50 ms, handshake 60 ms,
  window scale 7/8, 1 retransmission, 3 duplicate ACKs, 1 zero-window episode, closed by FIN);
  :40001 incomplete (unanswered SYN); :40002 refused (RST-ACK); an IPv6 connection established;
  25 SYN-only probes from 10.0.0.9 to ports 2000-2024 (incomplete).  Success 2/29.
TCP packets: 15 + 1 + 2 + 4 + 25 = 47; RST packets: 1.
DNS: 6 queries (3 answered: 30/20/50 ms; 2 inferred timeouts; 1 indeterminate, asked 1 s before the
  capture ended), 1 unmatched response; responses observed 4 with RCODEs NOERROR 2, NXDOMAIN 1, SERVFAIL 1.
"""

from scapy.all import DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether, IPv6, Raw

T0 = 1_700_000_000
C, S, SCANNER, DNSS = "10.0.0.1", "10.0.0.2", "10.0.0.9", "8.8.8.8"
V6A, V6B = "2001:db8::1", "2001:db8::2"
END = 20.0


def _tcp(src, dst, sport, dport, flags, seq=0, ack=0, payload=b"", window=8192, options=None):
    layer = TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=window,
                options=options or [])
    pkt = Ether() / IP(src=src, dst=dst) / layer
    return pkt / Raw(payload) if payload else pkt


def _dns_query(t, port, qid, name):
    return (t, Ether() / IP(src=C, dst=DNSS) / UDP(sport=port, dport=53)
            / DNS(id=qid, rd=1, qd=DNSQR(qname=name)))


def _dns_response(t, port, qid, name, rcode=0):
    answer = DNSRR(rrname=name, rdata="10.0.0.2") if rcode == 0 else None
    dns = DNS(id=qid, qr=1, rcode=rcode, qd=DNSQR(qname=name), an=answer)
    return (t, Ether() / IP(src=DNSS, dst=C) / UDP(sport=53, dport=port) / dns)


def build_packets():
    data = b"x" * 100
    spec = [
        # --- connection 1: handshake with window scaling, then loss indicators and a zero window
        (0.000, _tcp(C, S, 40000, 80, "S", 100, 0, window=64240, options=[("WScale", 7)])),
        (0.050, _tcp(S, C, 80, 40000, "SA", 500, 101, window=65160, options=[("WScale", 8)])),
        (0.060, _tcp(C, S, 40000, 80, "A", 101, 501)),
        (0.100, _tcp(C, S, 40000, 80, "PA", 101, 501, data)),
        (0.110, _tcp(C, S, 40000, 80, "PA", 201, 501, data)),
        (0.150, _tcp(S, C, 80, 40000, "A", 501, 201, window=1000)),   # baseline ACK
        (0.160, _tcp(S, C, 80, 40000, "A", 501, 201, window=1000)),   # duplicate ACK 1
        (0.170, _tcp(S, C, 80, 40000, "A", 501, 201, window=1000)),   # duplicate ACK 2
        (0.180, _tcp(S, C, 80, 40000, "A", 501, 201, window=1000)),   # duplicate ACK 3
        (0.500, _tcp(C, S, 40000, 80, "PA", 201, 501, data)),         # retransmission
        (0.600, _tcp(S, C, 80, 40000, "A", 501, 301, window=0)),      # zero window
        (0.700, _tcp(S, C, 80, 40000, "A", 501, 301, window=5000)),   # window update
        (0.800, _tcp(C, S, 40000, 80, "FA", 301, 501)),
        (0.810, _tcp(S, C, 80, 40000, "FA", 501, 302)),
        (0.820, _tcp(C, S, 40000, 80, "A", 302, 502)),
        # --- connection 2: unanswered SYN (incomplete, not a confirmed failure)
        (1.000, _tcp(C, S, 40001, 81, "S", 700, 0)),
        # --- connection 3: refused (RST-ACK straight after the SYN)
        (1.100, _tcp(C, S, 40002, 82, "S", 1000, 0)),
        (1.110, _tcp(S, C, 82, 40002, "RA", 0, 1001)),
        # --- DNS
        _dns_query(2.000, 5001, 1, "example.test"),
        _dns_response(2.030, 5001, 1, "example.test"),
        _dns_query(2.100, 5002, 2, "nx.test"),
        _dns_response(2.120, 5002, 2, "nx.test", rcode=3),
        _dns_query(2.200, 5003, 3, "fail.test"),
        _dns_response(2.250, 5003, 3, "fail.test", rcode=2),
        _dns_query(2.300, 5004, 4, "lost.test"),                       # unanswered, long before the end
        _dns_query(2.400, 5007, 7, "=cmd.test"),                       # formula-like name for CSV safety
        _dns_response(3.000, 5006, 6, "ghost.test"),                   # response with no query
        _dns_query(19.000, 5005, 5, "late.test"),                      # unanswered, capture ends 1 s later
        # --- unusual protocol/port: UDP payload to the SSH port
        *[(4.0 + i * 0.01, Ether() / IP(src=C, dst="8.8.4.4") / UDP(sport=6000 + i, dport=22) / Raw(b"hello"))
          for i in range(3)],
        # --- vertical scan: one source, 25 ports on one host
        *[(5.0 + i * 0.01, _tcp(SCANNER, S, 50000 + i, 2000 + i, "S", 1)) for i in range(25)],
        # --- IPv6 connection
        (10.000, Ether() / IPv6(src=V6A, dst=V6B) / TCP(sport=1000, dport=443, flags="S", seq=10)),
        (10.020, Ether() / IPv6(src=V6B, dst=V6A) / TCP(sport=443, dport=1000, flags="SA", seq=20, ack=11)),
        (10.030, Ether() / IPv6(src=V6A, dst=V6B) / TCP(sport=1000, dport=443, flags="A", seq=11, ack=21)),
        (10.040, Ether() / IPv6(src=V6A, dst=V6B) / TCP(sport=1000, dport=443, flags="PA", seq=11, ack=21) / Raw(b"hi")),
        # --- ends the capture so unanswered queries can be judged
        (END, Ether() / IP(src=C, dst="10.0.0.3") / ICMP(type=8)),
    ]
    packets = []
    for offset, layers in sorted(spec, key=lambda item: item[0]):
        packet = Ether(bytes(layers))
        packet.time = T0 + offset
        packets.append(packet)
    return packets
