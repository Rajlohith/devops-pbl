"""Flask extension instances, bound to the app in create_app()."""

from pathlib import Path

from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect

db = SQLAlchemy()
# Absolute path, so `flask db ...` works regardless of the current working directory.
MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"

migrate = Migrate(directory=str(MIGRATIONS_DIR))
login_manager = LoginManager()
csrf = CSRFProtect()
