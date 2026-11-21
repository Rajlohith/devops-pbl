"""Celery tasks."""

import logging
import uuid

from celery import shared_task

from app.extensions import db
from app.models.capture import CaptureStatus
from app.orm import CaptureRecord
from app.orm.user import utcnow
from app.services.analysis_pipeline import AnalysisError, analyze_file, clear_results
from app.services.capture_reader import CaptureReadError
from app.services.capture_storage import public_error_message, resolve_storage_path

logger = logging.getLogger(__name__)


@shared_task(name="netscope.analyze_capture")
def analyze_capture(capture_id: str) -> None:
    cid = uuid.UUID(capture_id)

    # Claim the job: only a PENDING capture is processed, which makes redelivered
    # or duplicate messages harmless.
    claimed = db.session.execute(
        db.update(CaptureRecord)
        .where(CaptureRecord.id == cid, CaptureRecord.status == CaptureStatus.PENDING)
        .values(status=CaptureStatus.PROCESSING, processing_started_at=utcnow())
    )
    db.session.commit()
    if claimed.rowcount == 0:
        logger.warning("Capture %s is missing or not pending; skipping", cid)
        return

    record = db.session.get(CaptureRecord, cid)
    path = resolve_storage_path(record.storage_path)
    try:
        packet_count = _run_analysis(cid, path)
    except AnalysisError as exc:
        _fail(cid, str(exc))
    except CaptureReadError as exc:
        logger.warning("Capture %s could not be read: %s", cid, exc)
        _fail(cid, public_error_message(exc, path))
    except Exception:
        logger.exception("Unexpected failure analysing capture %s", cid)
        _fail(cid, "Analysis failed unexpectedly. The failure has been logged.")
    else:
        _finish(cid, CaptureStatus.COMPLETED, packet_count=packet_count)


def _run_analysis(cid: uuid.UUID, path) -> int:
    return analyze_file(cid, path)


def _fail(cid, message: str) -> None:
    """Record a failure and discard partial results so none are ever served."""
    db.session.rollback()
    try:
        clear_results(cid)
    except Exception:  # noqa: BLE001 - e.g. the capture was deleted mid-run
        db.session.rollback()
        logger.exception("Could not clear partial results for capture %s", cid)
    _finish(cid, CaptureStatus.FAILED, error_message=message)


def _finish(cid, status, *, packet_count=None, error_message=None) -> None:
    # Guarded on PROCESSING so a capture deleted mid-run is simply left alone.
    db.session.rollback()
    db.session.execute(
        db.update(CaptureRecord)
        .where(CaptureRecord.id == cid, CaptureRecord.status == CaptureStatus.PROCESSING)
        .values(
            status=status,
            processing_completed_at=utcnow(),
            packet_count=packet_count,
            error_message=error_message,
        )
    )
    db.session.commit()
