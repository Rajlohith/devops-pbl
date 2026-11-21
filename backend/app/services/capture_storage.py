"""Secure on-disk storage for uploaded captures.

Files are stored as <UPLOAD_FOLDER>/<owner_id>/<capture_id>.<format>. The client's
filename never takes part in the path, so it cannot cause traversal or collisions.
"""

import hashlib
import logging
import os
import uuid
from dataclasses import dataclass
from pathlib import Path

from flask import current_app

from app.services.capture_reader import CaptureReadError, validate_capture

logger = logging.getLogger(__name__)
_CHUNK = 1024 * 1024


class UploadRejected(Exception):
    """The uploaded file was refused; the message is safe to show to the user."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class StoredCapture:
    file_format: str
    size_bytes: int
    sha256: str
    storage_path: str  # relative to UPLOAD_FOLDER


def upload_root() -> Path:
    root = Path(current_app.config["UPLOAD_FOLDER"]).resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def resolve_storage_path(storage_path: str) -> Path:
    """Resolve a stored relative path, refusing anything outside the upload root."""
    root = upload_root()
    full = (root / storage_path).resolve()
    if not full.is_relative_to(root):
        raise ValueError("storage path escapes the upload folder")
    return full


def public_error_message(exc: BaseException, path: Path | str) -> str:
    """Error text with server filesystem paths removed, for showing to users."""
    return str(exc).replace(str(path), "capture file")[:500]


def has_allowed_extension(filename: str) -> bool:
    allowed = current_app.config["ALLOWED_CAPTURE_EXTENSIONS"]
    return filename.lower().endswith(tuple(allowed))


def save_upload(stream, owner_id: uuid.UUID, capture_id: uuid.UUID) -> StoredCapture:
    """Stream an upload to disk, validate it by content, and move it into place."""
    max_bytes = current_app.config["MAX_UPLOAD_BYTES"]
    owner_dir = upload_root() / str(owner_id)
    owner_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    incoming = owner_dir / f".incoming-{uuid.uuid4().hex}"

    digest = hashlib.sha256()
    size = 0
    try:
        with incoming.open("wb") as out:
            while chunk := stream.read(_CHUNK):
                size += len(chunk)
                if size > max_bytes:
                    raise UploadRejected(
                        f"File exceeds the {max_bytes // (1024 * 1024)} MB upload limit.",
                        413,
                    )
                digest.update(chunk)
                out.write(chunk)

        try:
            file_format = validate_capture(incoming)
        except CaptureReadError as exc:
            raise UploadRejected(
                f"Not a valid PCAP/PCAPNG capture: {public_error_message(exc, incoming)}"
            ) from exc

        final = owner_dir / f"{capture_id}.{file_format}"
        os.replace(incoming, final)
    except BaseException:
        incoming.unlink(missing_ok=True)
        raise

    return StoredCapture(
        file_format=file_format,
        size_bytes=size,
        sha256=digest.hexdigest(),
        storage_path=f"{owner_id}/{capture_id}.{file_format}",
    )


def delete_stored_file(storage_path: str) -> None:
    """Delete a capture file. A file that is already gone is not an error."""
    try:
        resolve_storage_path(storage_path).unlink(missing_ok=True)
    except ValueError:
        logger.error("Refusing to delete path outside upload folder: %r", storage_path)
        raise
