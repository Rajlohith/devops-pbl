import uuid
from pathlib import Path

from app.extensions import db
from app.models.capture import CaptureStatus
from app.orm import CaptureRecord
from app.workers.tasks import analyze_capture
from tests.conftest import upload


def _record(client, pcap_bytes, **form):
    capture_id = upload(client, pcap_bytes, analyze="false", **form).get_json()["capture"]["id"]
    return db.session.get(CaptureRecord, uuid.UUID(capture_id))


def _set_status(record, status):
    record.status = status
    db.session.commit()


def test_task_skips_captures_that_are_not_pending(auth_client, pcap_bytes):
    record = _record(auth_client, pcap_bytes)

    analyze_capture(str(record.id))  # still UPLOADED, so it must not be processed

    db.session.refresh(record)
    assert record.status == CaptureStatus.UPLOADED


def test_task_marks_failure_when_file_is_missing(auth_client, pcap_bytes, app):
    record = _record(auth_client, pcap_bytes)
    (Path(app.config["UPLOAD_FOLDER"]) / record.storage_path).unlink()
    _set_status(record, CaptureStatus.PENDING)

    analyze_capture(str(record.id))

    db.session.refresh(record)
    assert record.status == CaptureStatus.FAILED
    assert "does not exist" in record.error_message
    assert app.config["UPLOAD_FOLDER"] not in record.error_message
    assert record.processing_completed_at is not None


def test_task_marks_failure_when_file_is_corrupted_after_upload(auth_client, pcap_bytes, app):
    record = _record(auth_client, pcap_bytes)
    path = Path(app.config["UPLOAD_FOLDER"]) / record.storage_path
    path.write_bytes(pcap_bytes[:-5])  # truncate the last packet
    _set_status(record, CaptureStatus.PENDING)

    analyze_capture(str(record.id))

    db.session.refresh(record)
    assert record.status == CaptureStatus.FAILED
    assert "truncated" in record.error_message


def test_task_enforces_packet_limit(auth_client, pcap_bytes, app):
    app.config["MAX_PACKETS_PER_CAPTURE"] = 2
    record = _record(auth_client, pcap_bytes)
    _set_status(record, CaptureStatus.PENDING)

    analyze_capture(str(record.id))

    db.session.refresh(record)
    assert record.status == CaptureStatus.FAILED
    assert "limit of 2 packets" in record.error_message


def test_task_unexpected_error_is_recorded_not_raised(auth_client, pcap_bytes, monkeypatch):
    record = _record(auth_client, pcap_bytes)
    _set_status(record, CaptureStatus.PENDING)
    monkeypatch.setattr("app.workers.tasks._run_analysis", lambda cid, path: 1 / 0)

    analyze_capture(str(record.id))

    db.session.refresh(record)
    assert record.status == CaptureStatus.FAILED
    assert "unexpectedly" in record.error_message


def test_failed_capture_can_be_retried(auth_client, pcap_bytes, app):
    record = _record(auth_client, pcap_bytes)
    path = Path(app.config["UPLOAD_FOLDER"]) / record.storage_path
    path.write_bytes(pcap_bytes[:-5])
    _set_status(record, CaptureStatus.PENDING)
    analyze_capture(str(record.id))
    db.session.refresh(record)
    assert record.status == CaptureStatus.FAILED

    path.write_bytes(pcap_bytes)
    response = auth_client.post(f"/api/v1/captures/{record.id}/analyze")

    assert response.status_code == 202
    capture = response.get_json()["capture"]
    assert capture["status"] == "completed" and capture["error_message"] is None


def test_unknown_capture_id_is_ignored(app):
    analyze_capture(str(uuid.uuid4()))  # must not raise
