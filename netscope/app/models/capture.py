from datetime import datetime, timezone
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


class CaptureFormat(StrEnum):
    PCAP = "pcap"
    PCAPNG = "pcapng"


class CaptureStatus(StrEnum):
    UPLOADED = "uploaded"
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class Capture(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    owner_user_id: UUID | None = None
    original_filename: str
    file_format: CaptureFormat
    file_size_bytes: int = Field(gt=0)
    status: CaptureStatus
    uploaded_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    processing_started_at: datetime | None = None
    processing_completed_at: datetime | None = None
    error_message: str | None = None

    @field_validator("original_filename")
    @classmethod
    def validate_original_filename(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("original_filename must not be empty")
        return value
