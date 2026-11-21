"""Builders for Scapy packets and ExtractedPackets used across analysis tests."""

import uuid

from scapy.all import ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether, Raw

from app.services.packet_extractor import extract_packet

CAPTURE_ID = uuid.UUID("00000000-0000-0000-0000-00000000c0de")
T0 = 1_700_000_000.0


def roundtrip(layers, ts=T0, wirelen=None):
    """Serialise and re-dissect, exactly as the capture reader would."""
    pkt = Ether(bytes(layers))
    pkt.time = ts
    if wirelen is not None:
        pkt.wirelen = wirelen
    return pkt


def extract(layers, ts=T0, number=1, wirelen=None):
    return extract_packet(roundtrip(layers, ts, wirelen), number, CAPTURE_ID)


def tcp(src, dst, sport, dport, flags, seq=0, ack=0, payload=b"", ts=T0, number=1):
    layers = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
    if payload:
        layers = layers / Raw(payload)
    return extract(layers, ts, number)


__all__ = [
    "ARP", "CAPTURE_ID", "DNS", "DNSQR", "DNSRR", "ICMP", "IP", "Raw", "T0", "TCP", "UDP",
    "Ether", "extract", "roundtrip", "tcp",
]
