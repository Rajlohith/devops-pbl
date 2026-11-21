from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scapy.packet import Packet


class CaptureReadError(Exception):
    """Raised when a capture cannot be opened or read."""


_PCAP_MAGIC_BYTES = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
}
_PCAPNG_BLOCK_TYPE = b"\x0a\x0d\x0d\x0a"
_PCAPNG_BYTE_ORDER_MAGIC = {b"\x1a\x2b\x3c\x4d", b"\x4d\x3c\x2b\x1a"}


def _detect_capture_format(path: Path) -> str:
    try:
        with path.open("rb") as capture_file:
            signature = capture_file.read(12)
    except OSError as exc:
        raise CaptureReadError(f"Unable to read capture file: {path}") from exc

    if not signature:
        raise CaptureReadError(f"Capture file is empty: {path}")

    if signature[:4] in _PCAP_MAGIC_BYTES:
        if len(signature) < 4:
            raise CaptureReadError(f"Capture file is truncated: {path}")
        return "pcap"

    if signature[:4] == _PCAPNG_BLOCK_TYPE:
        if len(signature) < 12:
            raise CaptureReadError(f"PCAPNG file is truncated: {path}")
        if signature[8:12] not in _PCAPNG_BYTE_ORDER_MAGIC:
            raise CaptureReadError(
                f"PCAPNG file has an invalid byte-order marker: {path}"
            )
        return "pcapng"

    if len(signature) < 4:
        raise CaptureReadError(f"Capture file is truncated: {path}")

    raise CaptureReadError(f"Unsupported capture format: {path}")


def _validate_pcap_structure(path: Path) -> None:
    """Check PCAP record framing using seeks, never reading packet bodies."""
    try:
        file_size = path.stat().st_size
        with path.open("rb") as capture_file:
            header = capture_file.read(24)
            if len(header) < 24:
                raise CaptureReadError(f"PCAP file is truncated: {path}")

            byte_order = "little" if header[:4] in {
                b"\xd4\xc3\xb2\xa1",
                b"\x4d\x3c\xb2\xa1",
            } else "big"
            snap_length = int.from_bytes(header[16:20], byte_order)

            while True:
                packet_header = capture_file.read(16)
                if not packet_header:
                    return
                if len(packet_header) < 16:
                    raise CaptureReadError(f"PCAP file is truncated: {path}")

                captured_length = int.from_bytes(
                    packet_header[8:12],
                    byte_order,
                )
                original_length = int.from_bytes(
                    packet_header[12:16],
                    byte_order,
                )
                if captured_length > original_length:
                    raise CaptureReadError(
                        "PCAP captured length exceeds original length: "
                        f"{path}"
                    )
                # Some tools write a snapshot length of 0 meaning "unset".
                if snap_length and captured_length > snap_length:
                    raise CaptureReadError(
                        f"PCAP packet length exceeds snapshot length: {path}"
                    )
                packet_end = capture_file.tell() + captured_length
                if packet_end > file_size:
                    raise CaptureReadError(f"PCAP file is truncated: {path}")
                capture_file.seek(packet_end)
    except OSError as exc:
        raise CaptureReadError(f"Unable to read capture file: {path}") from exc


_PCAPNG_BYTE_ORDERS = {
    b"\x1a\x2b\x3c\x4d": "big",
    b"\x4d\x3c\x2b\x1a": "little",
}


def _validate_pcapng_structure(path: Path) -> None:
    """Check PCAPNG block framing using seeks, never reading block bodies."""
    try:
        file_size = path.stat().st_size
        with path.open("rb") as capture_file:
            byte_order = None
            while True:
                block_start = capture_file.tell()
                block_type = capture_file.read(4)
                if not block_type:
                    return
                if len(block_type) < 4:
                    raise CaptureReadError(f"PCAPNG file is truncated: {path}")

                if block_type == _PCAPNG_BLOCK_TYPE:
                    section_header = capture_file.read(8)
                    if len(section_header) < 8:
                        raise CaptureReadError(
                            f"PCAPNG file is truncated: {path}"
                        )
                    byte_order = _PCAPNG_BYTE_ORDERS.get(section_header[4:8])
                    if byte_order is None:
                        raise CaptureReadError(
                            "PCAPNG file has an invalid byte-order marker: "
                            f"{path}"
                        )
                    block_length = int.from_bytes(
                        section_header[:4],
                        byte_order,
                    )
                    minimum_length = 28
                else:
                    if byte_order is None:
                        raise CaptureReadError(
                            "PCAPNG file must begin with a Section Header "
                            f"Block: {path}"
                        )
                    length_bytes = capture_file.read(4)
                    if len(length_bytes) < 4:
                        raise CaptureReadError(
                            f"PCAPNG file is truncated: {path}"
                        )
                    block_length = int.from_bytes(length_bytes, byte_order)
                    minimum_length = 12

                if block_length < minimum_length or block_length % 4:
                    raise CaptureReadError(
                        f"PCAPNG file has an invalid block length: {path}"
                    )
                block_end = block_start + block_length
                if block_end > file_size:
                    raise CaptureReadError(f"PCAPNG file is truncated: {path}")

                capture_file.seek(block_end - 4)
                trailing_length = capture_file.read(4)
                if int.from_bytes(trailing_length, byte_order) != block_length:
                    raise CaptureReadError(f"PCAPNG file is corrupt: {path}")
    except OSError as exc:
        raise CaptureReadError(f"Unable to read capture file: {path}") from exc


def validate_capture(path: str | Path) -> str:
    """Validate a capture's format and framing without parsing packets.

    Returns "pcap" or "pcapng". Raises CaptureReadError when the file is
    missing, empty, truncated, corrupt or not a supported capture format.
    Intended for upload-time checks; it reads headers only.
    """
    capture_path = Path(path)
    if not capture_path.exists():
        raise CaptureReadError(f"Capture file does not exist: {capture_path}")
    if not capture_path.is_file():
        raise CaptureReadError(f"Capture path is not a file: {capture_path}")

    capture_format = _detect_capture_format(capture_path)
    if capture_format == "pcap":
        _validate_pcap_structure(capture_path)
    else:
        _validate_pcapng_structure(capture_path)
    return capture_format


def iter_capture_packets(path: str | Path) -> Iterator["Packet"]:
    """Yield Scapy packets from a PCAP or PCAPNG file one at a time."""
    from scapy.utils import PcapNgReader, PcapReader

    capture_path = Path(path)
    capture_format = validate_capture(capture_path)

    reader = None

    try:
        reader = (
            PcapReader(str(capture_path))
            if capture_format == "pcap"
            else PcapNgReader(str(capture_path))
        )
        yield from reader
    except CaptureReadError:
        raise
    except Exception as exc:
        raise CaptureReadError(
            f"Unable to read {capture_format.upper()} capture: {capture_path}"
        ) from exc
    finally:
        if reader is not None:
            reader.close()
