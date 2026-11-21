import io
import uuid
from pathlib import Path

from app.extensions import db
from app.models.capture import CaptureStatus
from app.orm import CaptureRecord
from tests.conftest import register, upload


def test_upload_valid_pcap_stores_file_and_runs_analysis(auth_client, pcap_bytes, app):
    response = upload(auth_client, pcap_bytes, "My Trace.pcap")

    assert response.status_code == 201
    capture = response.get_json()["capture"]
    uuid.UUID(capture["id"])
    assert capture["original_filename"] == "My_Trace.pcap"
    assert capture["file_format"] == "pcap"
    assert capture["file_size_bytes"] == len(pcap_bytes)
    # Celery runs eagerly under the testing config, so analysis has already finished.
    assert capture["status"] == "completed"
    assert capture["packet_count"] == 3
    assert capture["processing_completed_at"] is not None

    record = db.session.get(CaptureRecord, uuid.UUID(capture["id"]))
    stored = Path(app.config["UPLOAD_FOLDER"]) / record.storage_path
    assert stored.read_bytes() == pcap_bytes
    assert "My" not in record.storage_path  # client filename never used in the path


def test_upload_without_analysis_leaves_capture_uploaded(auth_client, pcap_bytes):
    capture = upload(auth_client, pcap_bytes, analyze="false").get_json()["capture"]
    assert capture["status"] == "uploaded"
    assert capture["packet_count"] is None


def test_upload_rejects_bad_requests(auth_client, pcap_bytes):
    assert auth_client.post("/api/v1/captures").status_code == 400
    assert upload(auth_client, pcap_bytes, "trace.txt").status_code == 400
    assert upload(auth_client, b"", "empty.pcap").status_code == 400
    garbage = upload(auth_client, b"this is not a capture at all", "fake.pcap")
    assert garbage.status_code == 400
    assert "valid PCAP" in garbage.get_json()["error"]["message"]
    assert auth_client.get("/api/v1/captures").get_json()["total"] == 0


def test_rejected_upload_leaves_no_files_behind(auth_client, app):
    upload(auth_client, b"junk" * 10, "fake.pcap")
    leftovers = [p for p in Path(app.config["UPLOAD_FOLDER"]).rglob("*") if p.is_file()]
    assert leftovers == []


def test_upload_error_does_not_leak_server_paths(auth_client, app):
    message = upload(auth_client, b"junk" * 10, "fake.pcap").get_json()["error"]["message"]
    assert app.config["UPLOAD_FOLDER"] not in message
    assert ".incoming" not in message


def test_upload_size_limit(auth_client, pcap_bytes, app):
    app.config["MAX_UPLOAD_BYTES"] = 50
    app.config["MAX_CONTENT_LENGTH"] = None
    response = upload(auth_client, pcap_bytes)
    assert response.status_code == 413
    assert [p for p in Path(app.config["UPLOAD_FOLDER"]).rglob("*") if p.is_file()] == []


def test_content_decides_format_not_extension(auth_client, pcap_bytes):
    capture = upload(auth_client, pcap_bytes, "actually-pcap.pcapng").get_json()["capture"]
    assert capture["file_format"] == "pcap"


def test_list_get_and_status(auth_client, pcap_bytes):
    ids = [upload(auth_client, pcap_bytes, f"t{i}.pcap").get_json()["capture"]["id"] for i in range(3)]

    listing = auth_client.get("/api/v1/captures?per_page=2").get_json()
    assert listing["total"] == 3 and len(listing["items"]) == 2
    page2 = auth_client.get("/api/v1/captures?per_page=2&page=2").get_json()
    assert len(page2["items"]) == 1

    assert auth_client.get("/api/v1/captures?status=failed").get_json()["total"] == 0
    assert auth_client.get("/api/v1/captures?status=bogus").status_code == 400
    assert auth_client.get("/api/v1/captures?per_page=0").status_code == 400
    assert auth_client.get("/api/v1/captures?page=abc").status_code == 400

    detail = auth_client.get(f"/api/v1/captures/{ids[0]}")
    assert detail.status_code == 200
    status = auth_client.get(f"/api/v1/captures/{ids[0]}/status").get_json()
    assert status["status"] == "completed" and status["packet_count"] == 3


def test_users_cannot_access_each_others_captures(auth_client, make_client, pcap_bytes):
    capture_id = upload(auth_client, pcap_bytes).get_json()["capture"]["id"]
    other = make_client()
    register(other, "mallory@example.com")

    assert other.get("/api/v1/captures").get_json() == {"items": [], "page": 1, "per_page": 20, "total": 0}
    for method, path in [
        ("get", f"/api/v1/captures/{capture_id}"),
        ("get", f"/api/v1/captures/{capture_id}/status"),
        ("post", f"/api/v1/captures/{capture_id}/analyze"),
        ("delete", f"/api/v1/captures/{capture_id}"),
    ]:
        assert getattr(other, method)(path).status_code == 404, path

    # The owner's capture is untouched.
    assert auth_client.get(f"/api/v1/captures/{capture_id}").status_code == 200


def test_delete_removes_record_and_file(auth_client, pcap_bytes, app):
    capture_id = upload(auth_client, pcap_bytes).get_json()["capture"]["id"]
    record = db.session.get(CaptureRecord, uuid.UUID(capture_id))
    stored = Path(app.config["UPLOAD_FOLDER"]) / record.storage_path
    assert stored.exists()
    db.session.expire_all()

    assert auth_client.delete(f"/api/v1/captures/{capture_id}").status_code == 204
    assert not stored.exists()
    assert auth_client.get(f"/api/v1/captures/{capture_id}").status_code == 404
    assert auth_client.delete(f"/api/v1/captures/{capture_id}").status_code == 404


def test_analyze_conflict_and_retry_rules(auth_client, pcap_bytes):
    capture_id = upload(auth_client, pcap_bytes, analyze="false").get_json()["capture"]["id"]

    first = auth_client.post(f"/api/v1/captures/{capture_id}/analyze")
    assert first.status_code == 202
    assert first.get_json()["capture"]["status"] == "completed"
    # Already completed: not re-queueable.
    assert auth_client.post(f"/api/v1/captures/{capture_id}/analyze").status_code == 409


def test_broker_outage_is_reported_not_swallowed(auth_client, pcap_bytes, monkeypatch):
    from app.workers.tasks import analyze_capture

    def boom(*args, **kwargs):
        raise ConnectionError("redis down")

    monkeypatch.setattr(analyze_capture, "apply_async", boom)

    capture_id = upload(auth_client, pcap_bytes, analyze="false").get_json()["capture"]["id"]
    response = auth_client.post(f"/api/v1/captures/{capture_id}/analyze")

    assert response.status_code == 503
    status = auth_client.get(f"/api/v1/captures/{capture_id}/status").get_json()
    assert status["status"] == "failed"
    assert "queue" in status["error_message"].lower()

    # Once the broker is back the user can retry from the failed state.
    monkeypatch.undo()
    assert auth_client.post(f"/api/v1/captures/{capture_id}/analyze").status_code == 202
    assert auth_client.get(f"/api/v1/captures/{capture_id}/status").get_json()["status"] == "completed"


def test_upload_with_broker_outage_still_saves_capture_as_failed(auth_client, pcap_bytes, monkeypatch):
    from app.workers.tasks import analyze_capture

    monkeypatch.setattr(analyze_capture, "apply_async", lambda *a, **k: (_ for _ in ()).throw(OSError("down")))
    response = upload(auth_client, pcap_bytes)

    assert response.status_code == 201
    capture = response.get_json()["capture"]
    assert capture["status"] == "failed" and capture["error_message"]
