"""Migrations must produce exactly the schema the ORM models describe."""

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import inspect

from app.db.base import Base
from app.db.session import build_engine
from tests.conftest import alembic_config


def test_migrations_match_models(migrated_database_url: str) -> None:
    engine = build_engine(migrated_database_url)
    with engine.connect() as connection:
        context = MigrationContext.configure(connection)
        diff = compare_metadata(context, Base.metadata)
    engine.dispose()

    # A non-empty diff means someone changed a model without adding a migration.
    assert diff == []


def test_downgrade_to_base_removes_tables(migrated_database_url: str) -> None:
    command.downgrade(alembic_config(migrated_database_url), "base")

    engine = build_engine(migrated_database_url)
    tables = set(inspect(engine).get_table_names())
    engine.dispose()

    assert tables <= {"alembic_version"}
