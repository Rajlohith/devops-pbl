"""Builders for PacketView-based analytics tests (no Scapy or database needed)."""

from app.services.analytics.common import PacketView

T0 = 1_700_000_000.0


class Trace:
    """Builds PacketViews with FlowTracker-like flow ids and exact-duplicate detection."""

    def __init__(self):
        self.views = []
        self._flows = {}
        self._seen = set()

    def _flow(self, proto, src, sport, dst, dport):
        key = (proto, *sorted(((src, sport), (dst, dport))))
        return self._flows.setdefault(key, len(self._flows) + 1)

    def tcp(self, t, src, sport, dst, dport, flags, seq=0, ack=0, payload=0, window=65535,
            wscale=None, ipv=4):
        number = len(self.views) + 1
        length = payload + (1 if "S" in flags else 0) + (1 if "F" in flags else 0)
        seg = (src, sport, seq, length)
        is_retx = length > 0 and seg in self._seen
        if length > 0:
            self._seen.add(seg)
        v = PacketView(
            number=number, ts=T0 + t, flow_id=self._flow(6, src, sport, dst, dport),
            src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport, ip_version=ipv,
            transport="TCP", length=54 + payload, tcp_flags=flags, seq=seq, ack=ack,
            window=window, wscale=wscale, payload_len=payload, is_retx=is_retx,
        )
        self.views.append(v)
        return v

    def udp(self, t, src, sport, dst, dport, payload=20, app=None, dns=None, ipv=4):
        number = len(self.views) + 1
        v = PacketView(
            number=number, ts=T0 + t, flow_id=self._flow(17, src, sport, dst, dport),
            src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport, ip_version=ipv,
            transport="UDP", app=app, length=42 + payload, payload_len=payload, dns=dns,
        )
        self.views.append(v)
        return v

    def dns_query(self, t, client, cport, server, qid, name="example.test", qtype=1,
                  transport="UDP", extra=None, sport_fixed=None):
        meta = {"id": qid, "is_response": False, "rcode": 0,
                "questions": [{"name": name, "type": qtype}] + (extra or []), "query": name}
        if transport == "UDP":
            return self.udp(t, client, cport, server, 53, app="DNS", dns=meta)
        v = self.tcp(t, client, cport, server, 53, "PA", seq=1000 + qid, payload=40)
        v.app, v.dns = "DNS", meta
        return v

    def dns_response(self, t, client, cport, server, qid, name="example.test", qtype=1, rcode=0,
                     transport="UDP", tc=False, questions=True):
        meta = {"id": qid, "is_response": True, "rcode": rcode, "tc": tc, "ancount": 1,
                "questions": [{"name": name, "type": qtype}] if questions else [], "query": name}
        if transport == "UDP":
            return self.udp(t, server, 53, client, cport, app="DNS", dns=meta)
        v = self.tcp(t, server, 53, client, cport, "PA", seq=5000 + qid, payload=60)
        v.app, v.dns = "DNS", meta
        return v

    def handshake(self, t, client="10.0.0.1", cport=40000, server="10.0.0.2", sport=80,
                  rtt=0.05, isn_c=100, isn_s=500, wsc_c=None, wsc_s=None, ipv=4):
        self.tcp(t, client, cport, server, sport, "S", seq=isn_c, window=64240, wscale=wsc_c, ipv=ipv)
        self.tcp(t + rtt, server, sport, client, cport, "SA", seq=isn_s, ack=isn_c + 1,
                 window=65160, wscale=wsc_s, ipv=ipv)
        self.tcp(t + rtt + 0.01, client, cport, server, sport, "A", seq=isn_c + 1, ack=isn_s + 1, ipv=ipv)
