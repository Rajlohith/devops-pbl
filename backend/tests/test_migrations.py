from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from flask_migrate import upgrade

from app import create_app
from app.config import TestingConfig
from app.extensions import db


def test_migrations_match_models(tmp_path):
    """Running the migrations must produce exactly the schema the models declare."""

    class Cfg(TestingConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'migrated.db'}"
        UPLOAD_FOLDER = str(tmp_path / "uploads")

    app = create_app(Cfg)
    with app.app_context():
        upgrade()  # uses the directory configured on Migrate
        with db.engine.connect() as connection:
            context = MigrationContext.configure(connection)
            assert compare_metadata(context, db.metadata) == []
