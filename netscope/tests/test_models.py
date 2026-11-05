from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.models import (
    Capture,
    CaptureFormat,
    CaptureStatus,
    Packet,
    TransportProtocol,
)


def test_capture_constructs_with_generated_identity_and_timestamp():
    capture = Capture(
        original_filename="traffic.pcap",
        file_format=CaptureFormat.PCAP,
        file_size_bytes=1024,
        status=CaptureStatus.UPLOADED,
    )

    assert capture.id
    assert capture.uploaded_at.tzinfo == timezone.utc
    assert capture.owner_user_id is None


def test_capture_accepts_processing_and_error_fields():
    started_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    completed_at = datetime(2026, 1, 2, tzinfo=timezone.utc)
    capture = Capture(
        owner_user_id=uuid4(),
        original_filename="traffic.pcapng",
        file_format="pcapng",
        file_size_bytes=2048,
        status="failed",
        processing_started_at=started_at,
        processing_completed_at=completed_at,
        error_message="Unsupported link type",
    )

    assert capture.file_format is CaptureFormat.PCAPNG
    assert capture.status is CaptureStatus.FAILED
    assert capture.error_message == "Unsupported link type"


def test_capture_strips_filename_whitespace():
    capture = Capture(
        original_filename="  traffic.pcap  ",
        file_format="pcap",
        file_size_bytes=100,
        status="uploaded",
    )

    assert capture.original_filename == "traffic.pcap"


@pytest.mark.parametrize(
    "field, value",
    [
        ("original_filename", " "),
        ("file_size_bytes", 0),
        ("status", "unknown"),
        ("file_format", "pcap2"),
    ],
)
def test_capture_rejects_invalid_values(field, value):
    values = {
        "original_filename": "traffic.pcap",
        "file_format": "pcap",
        "file_size_bytes": 100,
        "status": "uploaded",
        field: value,
    }

    with pytest.raises(ValidationError):
        Capture(**values)


def test_transport_protocol_accepts_consistent_known_pair():
    protocol = TransportProtocol(number=6, name="tcp")

    assert protocol.model_dump() == {"number": 6, "name": "tcp"}


@pytest.mark.parametrize(
    "protocol",
    [
        {"number": 99, "name": "CUSTOM"},
        {"name": "CUSTOM"},
        {"number": 99},
    ],
)
def test_transport_protocol_accepts_unknown_values(protocol):
    assert TransportProtocol(**protocol)


@pytest.mark.parametrize(
    "protocol",
    [
        {"number": 6, "name": "UDP"},
        {"number": 17, "name": "TCP"},
        {"number": 6, "name": ""},
        {},
    ],
)
def test_transport_protocol_rejects_invalid_values(protocol):
    with pytest.raises(ValidationError):
        TransportProtocol(**protocol)


def test_packet_constructs_with_all_available_protocol_fields():
    packet = Packet(
        capture_id=uuid4(),
        packet_number=1,
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        captured_length=100,
        original_length=120,
        source_mac="00:11:22:33:44:55",
        destination_mac="66:77:88:99:aa:bb",
        ether_type=2048,
        vlan_id=100,
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
        ip_version=4,
        ttl_or_hop_limit=64,
        transport_protocol={"number": 6, "name": "TCP"},
        source_port=1234,
        destination_port=443,
        tcp_flags="SYN",
        tcp_sequence_number=10,
        tcp_acknowledgement_number=0,
        application_protocol="HTTP",
        application_metadata={"method": "GET"},
    )

    serialized = packet.model_dump(mode="json")

    assert serialized["source_ip"] == "192.168.1.10"
    assert serialized["transport_protocol"] == {"number": 6, "name": "TCP"}
    assert serialized["application_metadata"] == {"method": "GET"}


@pytest.mark.parametrize(
    "source_ip, destination_ip, ip_version",
    [
        ("192.168.1.10", None, 4),
        (None, "2001:db8::2", 6),
        ("192.168.1.10", "192.168.1.20", None),
        ("2001:db8::1", "2001:db8::2", 6),
    ],
)
def test_packet_accepts_optional_consistent_ip_version(
    source_ip, destination_ip, ip_version
):
    packet = Packet(
        capture_id=uuid4(),
        packet_number=1,
        timestamp=datetime.now(timezone.utc),
        captured_length=0,
        original_length=0,
        source_ip=source_ip,
        destination_ip=destination_ip,
        ip_version=ip_version,
    )

    assert packet.ip_version == ip_version


@pytest.mark.parametrize(
    "source_ip, destination_ip, ip_version",
    [
        ("192.168.1.10", None, 6),
        (None, "2001:db8::2", 4),
        ("192.168.1.10", "2001:db8::2", 4),
    ],
)
def test_packet_rejects_inconsistent_ip_version(
    source_ip, destination_ip, ip_version
):
    with pytest.raises(ValidationError):
        Packet(
            capture_id=uuid4(),
            packet_number=1,
            timestamp=datetime.now(timezone.utc),
            captured_length=0,
            original_length=0,
            source_ip=source_ip,
            destination_ip=destination_ip,
            ip_version=ip_version,
        )


def test_packet_rejects_naive_timestamp():
    with pytest.raises(ValidationError):
        Packet(
            capture_id=uuid4(),
            packet_number=1,
            timestamp=datetime(2026, 1, 1),
            captured_length=0,
            original_length=0,
        )


@pytest.mark.parametrize(
    "source_mac, destination_mac",
    [
        ("00:11:22:33:44:55", None),
        (None, "66:77:88:99:aa:bb"),
        ("00:11:22:33:44:55", "66:77:88:99:AA:BB"),
    ],
)
def test_packet_accepts_valid_mac_addresses(source_mac, destination_mac):
    packet = Packet(
        capture_id=uuid4(),
        packet_number=1,
        timestamp=datetime.now(timezone.utc),
        captured_length=0,
        original_length=0,
        source_mac=source_mac,
        destination_mac=destination_mac,
    )

    assert packet.source_mac == source_mac
    assert packet.destination_mac == destination_mac


def test_packet_accepts_vlan_id_zero():
    packet = Packet(
        capture_id=uuid4(),
        packet_number=1,
        timestamp=datetime.now(timezone.utc),
        captured_length=0,
        original_length=0,
        vlan_id=0,
    )

    assert packet.vlan_id == 0


@pytest.mark.parametrize(
    "field, value",
    [
        ("source_mac", "00:11:22:33:44"),
        ("destination_mac", "not-a-mac"),
        ("source_mac", "00:11:22:33:44:GG"),
    ],
)
def test_packet_rejects_invalid_mac_addresses(field, value):
    with pytest.raises(ValidationError):
        Packet(
            capture_id=uuid4(),
            packet_number=1,
            timestamp=datetime.now(timezone.utc),
            captured_length=0,
            original_length=0,
            **{field: value},
        )


def test_packet_accepts_missing_network_and_transport_layers():
    packet = Packet(
        capture_id=uuid4(),
        packet_number=1,
        timestamp=datetime.now(timezone.utc),
        captured_length=0,
        original_length=0,
    )

    assert packet.source_ip is None
    assert packet.destination_ip is None
    assert packet.transport_protocol is None
    assert packet.source_port is None
    assert packet.udp_length is None


@pytest.mark.parametrize(
    "field, value",
    [
        ("packet_number", 0),
        ("captured_length", -1),
        ("original_length", -1),
        ("ether_type", 65536),
        ("vlan_id", 4095),
        ("ip_version", 5),
        ("ttl_or_hop_limit", 256),
        ("source_port", 65536),
        ("tcp_sequence_number", -1),
        ("udp_length", -1),
    ],
)
def test_packet_rejects_invalid_values(field, value):
    values = {
        "capture_id": uuid4(),
        "packet_number": 1,
        "timestamp": datetime.now(timezone.utc),
        "captured_length": 100,
        "original_length": 100,
        field: value,
    }

    with pytest.raises(ValidationError):
        Packet(**values)


def test_packet_rejects_captured_length_greater_than_original_length():
    with pytest.raises(ValidationError):
        Packet(
            capture_id=uuid4(),
            packet_number=1,
            timestamp=datetime.now(timezone.utc),
            captured_length=101,
            original_length=100,
        )
