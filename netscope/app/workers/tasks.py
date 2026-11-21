"""Celery tasks.

Phase 1 worker: streams the stored capture through the existing reader, counts the
packets and records the outcome. Packet extraction and analytics build on this loop.
"""

import logging
import uuid

from celery import shared_task
from flask import current_app

from app.extensions import db
from app.models.capture import CaptureStatus
from app.orm import CaptureRecord
from app.orm.user import utcnow
from app.services.capture_reader import CaptureReadError, iter_capture_packets
from app.services.capture_storage import public_error_message, resolve_storage_path

logger = logging.getLogger(__name__)


class AnalysisError(Exception):
    """A failure whose message is safe to show to the capture's owner."""


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
        packet_count = _count_packets(path)
    except AnalysisError as exc:
        _finish(cid, CaptureStatus.FAILED, error_message=str(exc))
    except CaptureReadError as exc:
        logger.warning("Capture %s could not be read: %s", cid, exc)
        _finish(cid, CaptureStatus.FAILED, error_message=public_error_message(exc, path))
    except Exception:
        logger.exception("Unexpected failure analysing capture %s", cid)
        _finish(
            cid,
            CaptureStatus.FAILED,
            error_message="Analysis failed unexpectedly. The failure has been logged.",
        )
    else:
        _finish(cid, CaptureStatus.COMPLETED, packet_count=packet_count)


def _count_packets(path) -> int:
    limit = current_app.config["MAX_PACKETS_PER_CAPTURE"]
    count = 0
    for _ in iter_capture_packets(path):
        count += 1
        if count > limit:
            raise AnalysisError(f"Capture exceeds the limit of {limit} packets.")
    return count


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
