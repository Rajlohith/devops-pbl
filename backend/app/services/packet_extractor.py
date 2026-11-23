"""Convert Scapy packets into NetScope Packet models.

Pure logic: no Flask or database access. Anything that cannot be decoded cleanly is
still returned (with whatever fields were recovered) and tagged with a
``malformed_reason`` instead of being dropped, so counts stay accurate.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import (
    IPv6,
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrFragment,
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrRouting,
)
from scapy.layers.l2 import ARP, Dot1Q, Ether
from scapy.packet import Raw

from app.models.packet import _RECOGNIZED_TRANSPORT_PROTOCOLS, Packet, TransportProtocol
from app.services.protocol_detector import L2_ETHERTYPES, detect_tcp, detect_udp

_IPV6_EXT_HEADERS = (
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrRouting,
    IPv6ExtHdrFragment,
    IPv6ExtHdrDestOpt,
)
_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_IPV6 = 0x86DD
_ETHERTYPE_ARP = 0x0806
_HTTP_PREFIXES = (
    b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ",
    b"CONNECT ", b"HTTP/1.",
)


@dataclass(frozen=True, slots=True)
class ExtractedPacket:
    packet: Packet
    label: str  # highest identified layer, e.g. DNS, TCP, ARP, Other
    payload_length: int | None  # TCP payload bytes, used for retransmission detection
    malformed_reason: str | None
    # Phase 4 additions. Defaults keep every existing construction site valid, and the
    # Packet model / application_metadata are unchanged so existing consumers see no difference.
    tcp_window: int | None = None  # raw advertised receive window (never scaled)
    tcp_window_scale: int | None = None  # shift count from a WScale option (SYN / SYN-ACK only)
    dns: dict | None = None  # full DNS header/question details for transaction matching


def extract_packet(scapy_packet, packet_number: int, capture_id: UUID) -> ExtractedPacket:
    try:
        return _extract(scapy_packet, packet_number, capture_id)
    except Exception as exc:  # noqa: BLE001 - a bad packet must never abort the capture
        return _fallback(scapy_packet, packet_number, capture_id, f"extraction_error:{type(exc).__name__}")


def _timestamp(scapy_packet) -> datetime:
    t = scapy_packet.time  # EDecimal: keep sub-microsecond digits out of float rounding
    seconds = int(t)
    micros = int(round((t - seconds) * 1_000_000))
    return datetime.fromtimestamp(seconds, tz=timezone.utc) + timedelta(microseconds=micros)


def _lengths(scapy_packet) -> tuple[int, int]:
    raw = getattr(scapy_packet, "original", None)
    captured = len(raw) if raw else len(bytes(scapy_packet))
    wire = getattr(scapy_packet, "wirelen", None) or captured
    return captured, max(int(wire), captured)


def _fallback(scapy_packet, number, capture_id, reason) -> ExtractedPacket:
    try:
        timestamp = _timestamp(scapy_packet)
    except Exception:  # noqa: BLE001
        timestamp = datetime.fromtimestamp(0, tz=timezone.utc)
    try:
        captured, original = _lengths(scapy_packet)
    except Exception:  # noqa: BLE001
        captured = original = 0
    packet = Packet(
        capture_id=capture_id,
        packet_number=number,
        timestamp=timestamp,
        captured_length=captured,
        original_length=original,
    )
    return ExtractedPacket(packet, "Other", None, reason)


def _transport_layer(ip_layer):
    """First layer after the IP header, skipping IPv6 extension headers."""
    layer = ip_layer.payload
    while isinstance(layer, _IPV6_EXT_HEADERS):
        layer = layer.payload
    return layer


def _ipv6_final_protocol(ip6) -> int:
    number = ip6.nh
    layer = ip6.payload
    while isinstance(layer, _IPV6_EXT_HEADERS):
        number = layer.nh
        layer = layer.payload
    return int(number)


def _is_later_fragment(ip_layer) -> bool:
    if isinstance(ip_layer, IP):
        return int(ip_layer.frag) > 0
    layer = ip_layer.payload
    while isinstance(layer, _IPV6_EXT_HEADERS):
        if isinstance(layer, IPv6ExtHdrFragment) and layer.offset > 0:
            return True
        layer = layer.payload
    return False


def _extract(pkt, number: int, capture_id: UUID) -> ExtractedPacket:
    captured, original = _lengths(pkt)
    fields: dict = {
        "capture_id": capture_id,
        "packet_number": number,
        "timestamp": _timestamp(pkt),
        "captured_length": captured,
        "original_length": original,
    }
    malformed: str | None = None

    eth = pkt.getlayer(Ether)
    if eth is not None:
        fields["source_mac"] = eth.src.lower()
        fields["destination_mac"] = eth.dst.lower()
        fields["ether_type"] = int(eth.type)
    dot1q = pkt.getlayer(Dot1Q)
    if dot1q is not None:
        fields["vlan_id"] = int(dot1q.vlan)
        fields["ether_type"] = int(dot1q.type)

    ip = pkt.getlayer(IP)
    ip6 = pkt.getlayer(IPv6) if ip is None else None
    ip_layer = ip if ip is not None else ip6
    ether_type = fields.get("ether_type")

    label = "Other"
    payload_length = None
    metadata: dict | None = None
    tcp_window: int | None = None
    tcp_window_scale: int | None = None
    dns_details: dict | None = None

    if ip_layer is None:
        if ether_type == _ETHERTYPE_ARP and pkt.haslayer(ARP):
            label = "ARP"
        elif ether_type in L2_ETHERTYPES:
            label = L2_ETHERTYPES[ether_type]  # LLDP, EAPOL, PPPoE, MPLS, ...
        elif ether_type in (_ETHERTYPE_IPV4, _ETHERTYPE_IPV6):
            malformed = "truncated_ip_header"
        elif isinstance(pkt, Raw):  # the reader's fallback when a frame cannot be dissected
            malformed = "unparsed_frame"
        return ExtractedPacket(Packet(**fields), label, None, malformed)

    if ip is not None:
        fields.update(
            ip_version=4,
            source_ip=ip.src,
            destination_ip=ip.dst,
            ttl_or_hop_limit=int(ip.ttl),
        )
        protocol_number = int(ip.proto)
    else:
        fields.update(
            ip_version=6,
            source_ip=ip6.src,
            destination_ip=ip6.dst,
            ttl_or_hop_limit=int(ip6.hlim),
        )
        protocol_number = _ipv6_final_protocol(ip6)
    fields["transport_protocol"] = TransportProtocol(
        number=protocol_number, name=_RECOGNIZED_TRANSPORT_PROTOCOLS.get(protocol_number)
    )
    transport_name = fields["transport_protocol"].name
    label = transport_name or f"Proto {protocol_number}"

    transport = _transport_layer(ip_layer)
    later_fragment = _is_later_fragment(ip_layer)
    expected = {6: TCP, 17: UDP, 1: ICMP}.get(protocol_number)
    if expected is not None and not isinstance(transport, expected) and not later_fragment:
        malformed = "truncated_transport_header"
    elif protocol_number == 58 and transport_name == "ICMPv6" and not later_fragment:
        if not type(transport).__name__.startswith("ICMPv6"):
            malformed = "truncated_transport_header"

    if isinstance(transport, TCP):
        fields.update(
            source_port=int(transport.sport),
            destination_port=int(transport.dport),
            tcp_flags=str(transport.flags),
            tcp_sequence_number=int(transport.seq),
            tcp_acknowledgement_number=int(transport.ack),
        )
        payload_length = _tcp_payload_length(ip_layer, transport)
        tcp_window = int(transport.window)
        tcp_window_scale = _window_scale(transport)
        app, metadata = _tcp_application(transport, payload_length)
    elif isinstance(transport, UDP):
        fields.update(
            source_port=int(transport.sport),
            destination_port=int(transport.dport),
            udp_length=int(transport.len) if transport.len is not None else None,
        )
        app, metadata = _udp_application(transport)
    elif isinstance(transport, ICMP) or type(transport).__name__.startswith("ICMPv6"):
        app = None
        metadata = {"icmp_type": int(transport.type), "icmp_code": int(getattr(transport, "code", 0))}
    else:
        app = None

    if app == "DNS":
        dns_details = _dns_details(transport.payload)

    if app is not None:
        fields["application_protocol"] = app
        label = app
    if metadata:
        fields["application_metadata"] = metadata

    return ExtractedPacket(
        Packet(**fields), label, payload_length, malformed,
        tcp_window=tcp_window, tcp_window_scale=tcp_window_scale, dns=dns_details,
    )


def _window_scale(tcp) -> int | None:
    """Shift count of a TCP window-scale option, if the segment carries one."""
    try:
        for option in tcp.options or ():
            if isinstance(option, tuple) and len(option) == 2 and option[0] == "WScale":
                return int(option[1])
    except Exception:  # noqa: BLE001 - malformed options must never fail the packet
        return None
    return None


_MAX_DNS_QUESTIONS = 8


def _dns_details(dns) -> dict | None:
    """Header fields and questions needed to pair queries with responses."""
    try:
        qd = dns.qd
        try:
            items = list(qd) if qd is not None else []
        except TypeError:
            items = [qd]
        questions = []
        for question in items[:_MAX_DNS_QUESTIONS]:
            raw = getattr(question, "qname", None)
            if raw is None:
                continue
            name = (raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)).rstrip(".")
            questions.append({"name": name, "type": int(question.qtype)})
        return {
            "id": int(dns.id),
            "is_response": bool(dns.qr),
            "opcode": int(dns.opcode),
            "rcode": int(dns.rcode),
            "tc": bool(dns.tc),
            "qdcount": int(dns.qdcount if dns.qdcount is not None else len(questions)),
            "ancount": int(dns.ancount if dns.ancount is not None else 0),
            "questions": questions,
            "query": questions[0]["name"] if questions else None,
        }
    except Exception:  # noqa: BLE001 - keep the packet; it just cannot be matched
        return None


def _tcp_payload_length(ip_layer, tcp) -> int:
    """TCP payload size from the IP header, so snaplen-truncated captures stay correct."""
    header = int(tcp.dataofs or 5) * 4
    if isinstance(ip_layer, IP) and ip_layer.len:
        return max(int(ip_layer.len) - int(ip_layer.ihl) * 4 - header, 0)
    if isinstance(ip_layer, IPv6) and isinstance(ip_layer.payload, TCP) and ip_layer.plen:
        return max(int(ip_layer.plen) - header, 0)
    return len(tcp.payload)


def _udp_application(udp) -> tuple[str | None, dict | None]:
    if isinstance(udp.payload, DNS):
        return "DNS", _dns_metadata(udp.payload)
    try:
        data = bytes(udp.payload)
        if udp.len is not None:  # drop Ethernet padding after the UDP datagram
            data = data[: max(int(udp.len) - 8, 0)]
        return detect_udp(int(udp.sport), int(udp.dport), data) or (None, None)
    except Exception:  # noqa: BLE001 - identification is best effort
        return None, None


def _tcp_application(tcp, payload_length: int | None = None) -> tuple[str | None, dict | None]:
    payload = tcp.payload
    if isinstance(payload, DNS):  # Scapy handles the 2-byte length prefix and checks it
        return "DNS", _dns_metadata(payload)
    try:
        data = bytes(payload)
        if payload_length is not None:  # never classify Ethernet padding as payload
            data = data[:payload_length]
        if not data:
            return None, None
        if isinstance(payload, Raw) and data.startswith(_HTTP_PREFIXES):
            line = data.split(b"\r\n", 1)[0][:200].decode("latin-1")
            return "HTTP", {"start_line": line}
        return detect_tcp(int(tcp.sport), int(tcp.dport), data) or (None, None)
    except Exception:  # noqa: BLE001 - identification is best effort
        return None, None


def _dns_metadata(dns) -> dict:
    name = None
    questions = dns.qd  # a list of DNSQR in current Scapy; empty for some responses
    if questions is not None and len(questions) > 0 and getattr(questions[0], "qname", None):
        raw = questions[0].qname
        name = (raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)).rstrip(".")
    return {"query": name, "is_response": bool(dns.qr), "rcode": int(dns.rcode)}
