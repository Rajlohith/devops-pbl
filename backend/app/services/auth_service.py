"""User registration and authentication."""

import re
import uuid

from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db
from app.orm import User

MIN_PASSWORD_LENGTH = 8
# Upper bound keeps password hashing from being used as a CPU-exhaustion vector.
MAX_PASSWORD_LENGTH = 128
_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_dummy_hash: str | None = None


class ValidationError(Exception):
    def __init__(self, errors: dict[str, str]):
        super().__init__("; ".join(errors.values()))
        self.errors = errors


class DuplicateUserError(Exception):
    pass


def normalize_email(email: str | None) -> str:
    return (email or "").strip().lower()


def validate_registration(email: str | None, password: str | None) -> dict[str, str]:
    errors: dict[str, str] = {}
    normalized = normalize_email(email)
    if not normalized or len(normalized) > 320 or not _EMAIL_PATTERN.match(normalized):
        errors["email"] = "Enter a valid email address."
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        errors["password"] = f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    elif len(password) > MAX_PASSWORD_LENGTH:
        errors["password"] = f"Password must be at most {MAX_PASSWORD_LENGTH} characters."
    return errors


def register_user(email: str | None, password: str | None) -> User:
    errors = validate_registration(email, password)
    if errors:
        raise ValidationError(errors)

    normalized = normalize_email(email)
    if db.session.execute(db.select(User.id).filter_by(email=normalized)).first():
        raise DuplicateUserError(normalized)

    user = User(email=normalized, password_hash=generate_password_hash(password))
    db.session.add(user)
    try:
        db.session.commit()
    except IntegrityError as exc:  # concurrent registration of the same email
        db.session.rollback()
        raise DuplicateUserError(normalized) from exc
    return user


def authenticate(email: str | None, password: str | None) -> User | None:
    user = db.session.execute(
        db.select(User).filter_by(email=normalize_email(email))
    ).scalar_one_or_none()
    candidate = password if isinstance(password, str) else ""
    if user is None:
        # Spend comparable time so response timing does not reveal valid emails.
        global _dummy_hash
        if _dummy_hash is None:
            _dummy_hash = generate_password_hash("netscope-dummy")
        check_password_hash(_dummy_hash, candidate[:MAX_PASSWORD_LENGTH])
        return None
    if not check_password_hash(user.password_hash, candidate[:MAX_PASSWORD_LENGTH]):
        return None
    return user


def load_user(user_id: str) -> User | None:
    try:
        return db.session.get(User, uuid.UUID(user_id))
    except (ValueError, TypeError):
        return None
