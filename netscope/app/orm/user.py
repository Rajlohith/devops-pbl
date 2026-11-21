import uuid
from datetime import datetime, timezone

from flask_login import UserMixin
from sqlalchemy.orm import Mapped, mapped_column

from app.extensions import db


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(db.Uuid, primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(db.String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(db.String(256))
    created_at: Mapped[datetime] = mapped_column(
        db.DateTime(timezone=True), default=utcnow
    )

    captures = db.relationship(
        "CaptureRecord", back_populates="owner", cascade="all, delete-orphan"
    )

    def get_id(self) -> str:
        return str(self.id)

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "email": self.email,
            "created_at": iso_utc(self.created_at),
        }


def iso_utc(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:  # SQLite drops tzinfo; values are always stored as UTC
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()
