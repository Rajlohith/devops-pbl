"""Validator tests that need no Scapy: they build capture bytes by hand."""

import struct
from pathlib import Path

import pytest

from app.services.capture_reader import CaptureReadError, validate_capture

PCAP_LE_MAGIC = b"\xd4\xc3\xb2\xa1"


def _pcap(packets: list[bytes], snaplen: int = 65535) -> bytes:
    data = PCAP_LE_MAGIC + struct.pack("<HHiiII", 2, 4, 0, 0, snaplen, 1)
    for payload in packets:
        data += struct.pack("<IIII", 1, 0, len(payload), len(payload)) + payload
    return data


def _pcapng(blocks_after_shb: bytes = b"") -> bytes:
    shb = (
        struct.pack("<II", 0x0A0D0D0A, 28)
        + b"\x4d\x3c\x2b\x1a"
        + struct.pack("<HHq", 1, 0, -1)
        + struct.pack("<I", 28)
    )
    return shb + blocks_after_shb


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_valid_pcap_and_pcapng_are_detected(tmp_path):
    idb = struct.pack("<IIHHI", 1, 20, 1, 0, 65535) + struct.pack("<I", 20)
    assert validate_capture(_write(tmp_path, "a.pcap", _pcap([b"x" * 20]))) == "pcap"
    assert validate_capture(_write(tmp_path, "b.pcapng", _pcapng(idb))) == "pcapng"


def test_empty_pcap_with_only_header_is_valid(tmp_path):
    assert validate_capture(_write(tmp_path, "e.pcap", _pcap([]))) == "pcap"


def test_pcap_snaplen_zero_is_accepted(tmp_path):
    path = _write(tmp_path, "s0.pcap", _pcap([b"y" * 60], snaplen=0))
    assert validate_capture(path) == "pcap"


def test_pcap_declared_length_beyond_file_is_truncated_without_allocating(tmp_path):
    data = (
        PCAP_LE_MAGIC
        + struct.pack("<HHiiII", 2, 4, 0, 0, 0xFFFFFFFF, 1)
        + struct.pack("<IIII", 1, 0, 0x7FFFFFFF, 0x7FFFFFFF)
        + b"short"
    )
    with pytest.raises(CaptureReadError, match="truncated"):
        validate_capture(_write(tmp_path, "huge.pcap", data))


def test_pcapng_declared_block_length_beyond_file_is_truncated(tmp_path):
    bad_block = struct.pack("<II", 6, 0x7FFFFFF0) + b"\x00" * 8
    with pytest.raises(CaptureReadError, match="truncated"):
        validate_capture(_write(tmp_path, "huge.pcapng", _pcapng(bad_block)))


def test_pcapng_trailing_length_mismatch_is_corrupt(tmp_path):
    block = struct.pack("<II", 6, 16) + b"\x00" * 4 + struct.pack("<I", 99)
    with pytest.raises(CaptureReadError, match="corrupt"):
        validate_capture(_write(tmp_path, "mismatch.pcapng", _pcapng(block)))


def test_pcapng_must_start_with_section_header(tmp_path):
    block = struct.pack("<II", 1, 12) + struct.pack("<I", 12)
    with pytest.raises(CaptureReadError):
        validate_capture(_write(tmp_path, "nosh.pcapng", block))


@pytest.mark.parametrize(
    "contents, message",
    [(b"", "empty"), (b"\xd4\xc3", "truncated"), (b"not a capture", "Unsupported")],
)
def test_invalid_files_rejected(tmp_path, contents, message):
    with pytest.raises(CaptureReadError, match=message):
        validate_capture(_write(tmp_path, "bad.bin", contents))


def test_missing_file_and_directory_rejected(tmp_path):
    with pytest.raises(CaptureReadError, match="does not exist"):
        validate_capture(tmp_path / "missing.pcap")
    with pytest.raises(CaptureReadError, match="not a file"):
        validate_capture(tmp_path)


def test_validation_does_not_modify_file(tmp_path):
    path = _write(tmp_path, "keep.pcap", _pcap([b"z" * 30]))
    before = path.read_bytes()
    validate_capture(path)
    assert path.read_bytes() == before
