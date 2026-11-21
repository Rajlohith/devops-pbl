"""Capture lifecycle: upload, ownership-scoped queries, analysis submission, deletion.

Every lookup takes the requesting user and filters by owner, so one user can never
read, analyse or delete another user's capture. Callers see "not found" either way.
"""

import logging
import uuid

from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from app.extensions import db
from app.models.capture import CaptureStatus
from app.orm import CaptureRecord, User
from app.services import capture_storage
from app.services.capture_storage import UploadRejected

logger = logging.getLogger(__name__)

_QUEUEABLE = (CaptureStatus.UPLOADED, CaptureStatus.FAILED)


class AnalysisConflict(Exception):
    """The capture is not in a state where analysis can be (re)started."""


class QueueUnavailable(Exception):
    """The job could not be handed to the broker."""


def create_capture(user: User, upload: FileStorage | None, analyze: bool = True) -> CaptureRecord:
    if upload is None or not upload.filename:
        raise UploadRejected("No file was uploaded.")
    if not capture_storage.has_allowed_extension(upload.filename):
        raise UploadRejected("Unsupported file type. Upload a .pcap or .pcapng file.")

    display_name = secure_filename(upload.filename)[:255] or "capture"
    capture_id = uuid.uuid4()
    stored = capture_storage.save_upload(upload.stream, user.id, capture_id)

    record = CaptureRecord(
        id=capture_id,
        owner_id=user.id,
        original_filename=display_name,
        file_format=stored.file_format,
        file_size_bytes=stored.size_bytes,
        sha256=stored.sha256,
        storage_path=stored.storage_path,
        status=CaptureStatus.UPLOADED,
    )
    db.session.add(record)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        capture_storage.delete_stored_file(stored.storage_path)
        raise

    if analyze:
        try:
            queue_analysis(record)
        except QueueUnavailable:
            pass  # recorded on the capture as FAILED with a reason; user can retry
    return record


def list_captures(user: User, page: int, per_page: int, status: CaptureStatus | None = None):
    query = db.select(CaptureRecord).filter_by(owner_id=user.id)
    if status is not None:
        query = query.filter_by(status=status)
    query = query.order_by(CaptureRecord.uploaded_at.desc(), CaptureRecord.id)
    return db.paginate(query, page=page, per_page=per_page, error_out=False)


def get_owned_capture(user: User, capture_id: uuid.UUID) -> CaptureRecord | None:
    return db.session.execute(
        db.select(CaptureRecord).filter_by(id=capture_id, owner_id=user.id)
    ).scalar_one_or_none()


def queue_analysis(record: CaptureRecord) -> None:
    from app.workers.tasks import analyze_capture

    task_id = str(uuid.uuid4())
    # Atomic claim so two concurrent requests cannot both queue the same capture.
    claimed = db.session.execute(
        db.update(CaptureRecord)
        .where(CaptureRecord.id == record.id, CaptureRecord.status.in_(_QUEUEABLE))
        .values(
            status=CaptureStatus.PENDING,
            celery_task_id=task_id,
            error_message=None,
            processing_started_at=None,
            processing_completed_at=None,
            packet_count=None,
        )
    )
    db.session.commit()
    if claimed.rowcount == 0:
        db.session.refresh(record)
        raise AnalysisConflict(
            f"Capture is {record.status.value}; analysis can only be started "
            "for uploaded or failed captures."
        )

    try:
        analyze_capture.apply_async(
            args=[str(record.id)],
            task_id=task_id,
            retry=True,
            retry_policy={"max_retries": 2, "interval_start": 0, "interval_step": 0.3},
        )
    except Exception as exc:
        logger.exception("Could not queue analysis for capture %s", record.id)
        db.session.execute(
            db.update(CaptureRecord)
            .where(CaptureRecord.id == record.id, CaptureRecord.status == CaptureStatus.PENDING)
            .values(
                status=CaptureStatus.FAILED,
                error_message="Could not queue the analysis job; the job service is unavailable. Try again shortly.",
            )
        )
        db.session.commit()
        db.session.refresh(record)
        raise QueueUnavailable(str(exc)) from exc
    db.session.refresh(record)


def delete_capture(record: CaptureRecord) -> None:
    """Remove the file first (so a failure keeps the row), then the record."""
    capture_storage.delete_stored_file(record.storage_path)
    db.session.delete(record)
    db.session.commit()
