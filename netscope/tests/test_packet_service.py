import pytest
from app.schemas.packet import PacketFilter
from app.services.packet_service import filter_packets


@pytest.fixture
def sample_packets():
    return [
        {
            "protocol": "TCP",
            "source_ip": "192.168.1.10",
            "destination_ip": "192.168.1.20",
        },
        {
            "protocol": "UDP",
            "source_ip": "192.168.1.15",
            "destination_ip": "192.168.1.30",
        },
        {
            "protocol": "TCP",
            "source_ip": "192.168.1.10",
            "destination_ip": "192.168.1.30",
        },
        {
            "protocol": "ICMP",
            "source_ip": "192.168.1.20",
            "destination_ip": "192.168.1.10",
        },
    ]


def test_filter_tcp_packets(sample_packets):
    packet_filter = PacketFilter(protocol="TCP")

    result = filter_packets(sample_packets, packet_filter)

    assert len(result) == 2
    assert all(packet["protocol"] == "TCP" for packet in result)


def test_filter_udp_packets(sample_packets):
    packet_filter = PacketFilter(protocol="UDP")

    result = filter_packets(sample_packets, packet_filter)

    assert len(result) == 1
    assert result[0]["protocol"] == "UDP"


def test_filter_by_source_ip(sample_packets):
    packet_filter = PacketFilter(source_ip="192.168.1.10")

    result = filter_packets(sample_packets, packet_filter)

    assert len(result) == 2


def test_filter_by_protocol_and_source_ip(sample_packets):
    packet_filter = PacketFilter(protocol="TCP", source_ip="192.168.1.10")

    result = filter_packets(sample_packets, packet_filter)

    assert len(result) == 2


def test_empty_filter_returns_all_packets(sample_packets):
    packet_filter = PacketFilter()

    result = filter_packets(sample_packets, packet_filter)

    assert len(result) == 4


def test_no_matching_packets(sample_packets):
    packet_filter = PacketFilter(protocol="HTTP")

    result = filter_packets(sample_packets, packet_filter)

    assert len(result) == 0
