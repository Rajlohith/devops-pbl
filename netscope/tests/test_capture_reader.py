import struct
from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP
from scapy.utils import PcapNgWriter, PcapWriter, wrpcap

from app.services.capture_reader import CaptureReadError, iter_capture_packets


def test_reads_valid_pcap_file(tmp_path: Path):
    capture_path = tmp_path / "traffic.pcap"
    wrpcap(
        str(capture_path),
        [IP(src="192.168.1.1", dst="192.168.1.2") / TCP(dport=80)],
    )

    packets = list(iter_capture_packets(capture_path))

    assert len(packets) == 1
    assert packets[0].haslayer(TCP)


def test_reads_valid_pcapng_file(tmp_path: Path):
    capture_path = tmp_path / "traffic.pcapng"
    with PcapNgWriter(str(capture_path)) as writer:
        writer.write(IP(src="192.168.1.1", dst="192.168.1.2") / TCP(dport=443))

    packets = list(iter_capture_packets(capture_path))

    assert len(packets) == 1
    assert packets[0].haslayer(TCP)


def _pcapng_section(byte_order: str) -> bytes:
    endian = "<" if byte_order == "little" else ">"
    packet_data = bytes.fromhex("00112233445566778899aabb0800")
    section_header = struct.pack(
        f"{endian}II",
        0x0A0D0D0A,
        28,
    ) + (
        b"\x4d\x3c\x2b\x1a"
        if byte_order == "little"
        else b"\x1a\x2b\x3c\x4d"
    ) + struct.pack(f"{endian}HHq", 1, 0, -1) + struct.pack(
        f"{endian}I", 28
    )
    interface_description = struct.pack(
        f"{endian}IIHHI",
        1,
        20,
        1,
        0,
        65535,
    ) + struct.pack(f"{endian}I", 20)
    packet_block_length = 48
    packet_block = struct.pack(
        f"{endian}IIIIIII",
        6,
        packet_block_length,
        0,
        0,
        0,
        len(packet_data),
        len(packet_data),
    ) + packet_data + b"\x00\x00" + struct.pack(
        f"{endian}I", packet_block_length
    )
    return section_header + interface_description + packet_block


def test_reads_packets_from_mixed_endian_pcapng_sections(tmp_path: Path):
    capture_path = tmp_path / "mixed-endian.pcapng"
    capture_path.write_bytes(
        _pcapng_section("little") + _pcapng_section("big")
    )

    packets = list(iter_capture_packets(capture_path))

    assert len(packets) == 2
    assert [bytes(packet) for packet in packets] == [
        bytes.fromhex("00112233445566778899aabb0800"),
        bytes.fromhex("00112233445566778899aabb0800"),
    ]


def test_iterates_through_multiple_packets(tmp_path: Path):
    capture_path = tmp_path / "multiple.pcap"
    expected_packets = [IP(dst=f"192.168.1.{number}") for number in range(1, 4)]
    wrpcap(str(capture_path), expected_packets)

    packets = list(iter_capture_packets(capture_path))

    assert len(packets) == len(expected_packets)
    assert [packet[IP].dst for packet in packets] == [
        packet[IP].dst for packet in expected_packets
    ]


def test_reads_empty_pcap_file(tmp_path: Path):
    capture_path = tmp_path / "empty.pcap"
    with PcapWriter(str(capture_path), linktype=1):
        pass

    assert list(iter_capture_packets(capture_path)) == []


@pytest.mark.parametrize(
    "byte_order, timestamp_precision",
    [
        ("<", "microseconds"),
        (">", "microseconds"),
        ("<", "nanoseconds"),
        (">", "nanoseconds"),
    ],
)
def test_reads_pcap_byte_orders_and_timestamp_precisions(
    tmp_path: Path, byte_order: str, timestamp_precision: str
):
    magic = {
        ("<", "microseconds"): b"\xd4\xc3\xb2\xa1",
        (">", "microseconds"): b"\xa1\xb2\xc3\xd4",
        ("<", "nanoseconds"): b"\x4d\x3c\xb2\xa1",
        (">", "nanoseconds"): b"\xa1\xb2\x3c\x4d",
    }[(byte_order, timestamp_precision)]
    packet_data = bytes.fromhex("00112233445566778899aabb0800")
    capture_path = tmp_path / f"{byte_order}_{timestamp_precision}.pcap"
    global_header = magic + struct.pack(
        f"{byte_order}HHiiII", 2, 4, 0, 0, 65535, 1
    )
    packet_header = struct.pack(
        f"{byte_order}IIII", 1, 2, len(packet_data), len(packet_data)
    )
    capture_path.write_bytes(global_header + packet_header + packet_data)

    packets = list(iter_capture_packets(capture_path))

    assert len(packets) == 1
    assert bytes(packets[0]) == packet_data


def test_rejects_nonexistent_file(tmp_path: Path):
    with pytest.raises(CaptureReadError, match="does not exist"):
        list(iter_capture_packets(tmp_path / "missing.pcap"))


@pytest.mark.parametrize(
    "contents, error_message",
    [
        (b"", "empty"),
        (b"\xd4\xc3", "truncated"),
        (b"not a capture", "Unsupported"),
        (b"\x0a\x0d\x0d\x0a\x00\x00\x00\x00", "truncated"),
    ],
)
def test_rejects_invalid_capture_file(
    tmp_path: Path, contents: bytes, error_message: str
):
    capture_path = tmp_path / "invalid.capture"
    capture_path.write_bytes(contents)

    with pytest.raises(CaptureReadError, match=error_message):
        list(iter_capture_packets(capture_path))


def test_rejects_corrupt_capture_with_valid_signature(tmp_path: Path):
    capture_path = tmp_path / "corrupt.pcap"
    capture_path.write_bytes(
        b"\xd4\xc3\xb2\xa1"
        + struct.pack("<HHiiII", 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 1, 0, 10, 10)
        + b"short"
    )

    with pytest.raises(CaptureReadError, match="PCAP file is truncated"):
        list(iter_capture_packets(capture_path))


def test_rejects_pcap_captured_length_greater_than_original_length(
    tmp_path: Path,
):
    capture_path = tmp_path / "invalid-lengths.pcap"
    packet_data = b"0123456789"
    capture_path.write_bytes(
        b"\xd4\xc3\xb2\xa1"
        + struct.pack("<HHiiII", 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 1, 0, len(packet_data), 5)
        + packet_data
    )

    with pytest.raises(
        CaptureReadError, match="captured length exceeds original length"
    ):
        list(iter_capture_packets(capture_path))


@pytest.mark.parametrize(
    "contents, error_message",
    [
        (
            b"\x0a\x0d\x0d\x0a"
            + struct.pack("<I", 24)
            + b"\x4d\x3c\x2b\x1a"
            + b"\x01\x00\x00\x00\xff\xff\xff\xff",
            "invalid block length",
        ),
        (
            _pcapng_section("little")[:28]
            + b"\x01\x00\x00\x00"
            + struct.pack("<I", 8),
            "invalid block length",
        ),
    ],
)
def test_rejects_undersized_pcapng_blocks(
    tmp_path: Path, contents: bytes, error_message: str
):
    capture_path = tmp_path / "undersized.pcapng"
    capture_path.write_bytes(contents)

    with pytest.raises(CaptureReadError, match=error_message):
        list(iter_capture_packets(capture_path))


def test_reader_does_not_modify_capture_file(tmp_path: Path):
    capture_path = tmp_path / "unchanged.pcap"
    wrpcap(str(capture_path), [IP(dst="192.168.1.1")])
    original_contents = capture_path.read_bytes()

    list(iter_capture_packets(capture_path))

    assert capture_path.read_bytes() == original_contents
