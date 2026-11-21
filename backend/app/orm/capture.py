import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Mapped, mapped_column

from app.extensions import db
from app.models.capture import Capture, CaptureFormat, CaptureStatus
from app.orm.user import utcnow


def _enum(enum_cls):
    # Stored as VARCHAR holding the lowercase values: portable, no PG enum type.
    return db.Enum(
        enum_cls,
        native_enum=False,
        length=16,
        create_constraint=False,
        values_callable=lambda e: [member.value for member in e],
    )


def _aware(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


class CaptureRecord(db.Model):
    """A user's uploaded capture. The file itself lives on disk, not in the DB."""

    __tablename__ = "captures"

    id: Mapped[uuid.UUID] = mapped_column(db.Uuid, primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        db.Uuid, db.ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    original_filename: Mapped[str] = mapped_column(db.String(255))
    file_format: Mapped[CaptureFormat] = mapped_column(_enum(CaptureFormat))
    file_size_bytes: Mapped[int] = mapped_column(db.BigInteger)
    sha256: Mapped[str] = mapped_column(db.String(64))
    # Path relative to UPLOAD_FOLDER; never derived from the client filename.
    storage_path: Mapped[str] = mapped_column(db.String(512))
    status: Mapped[CaptureStatus] = mapped_column(
        _enum(CaptureStatus), default=CaptureStatus.UPLOADED, index=True
    )
    uploaded_at: Mapped[datetime] = mapped_column(
        db.DateTime(timezone=True), default=utcnow
    )
    processing_started_at: Mapped[datetime | None] = mapped_column(
        db.DateTime(timezone=True)
    )
    processing_completed_at: Mapped[datetime | None] = mapped_column(
        db.DateTime(timezone=True)
    )
    error_message: Mapped[str | None] = mapped_column(db.Text)
    celery_task_id: Mapped[str | None] = mapped_column(db.String(64))
    packet_count: Mapped[int | None] = mapped_column(db.Integer)

    owner = db.relationship("User", back_populates="captures")

    def to_domain(self) -> Capture:
        """Reuse the existing Pydantic Capture model as the API representation."""
        return Capture(
            id=self.id,
            owner_user_id=self.owner_id,
            original_filename=self.original_filename,
            file_format=self.file_format,
            file_size_bytes=self.file_size_bytes,
            status=self.status,
            uploaded_at=_aware(self.uploaded_at),
            processing_started_at=_aware(self.processing_started_at),
            processing_completed_at=_aware(self.processing_completed_at),
            error_message=self.error_message,
        )

    def to_dict(self) -> dict:
        data = self.to_domain().model_dump(mode="json")
        data["sha256"] = self.sha256
        data["packet_count"] = self.packet_count
        return data
