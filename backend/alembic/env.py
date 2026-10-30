"""Alembic migration environment.

The database URL comes from AEGIS settings (``AEGIS_DATABASE_URL``) unless a
caller has already set ``sqlalchemy.url`` on the config (the migration tests
do this to target a temporary database).
"""

from logging.config import fileConfig

from alembic import context

from app.core.config import get_settings
from app.db.base import Base
from app.db.session import build_engine
from app.models import Event, IngestionBatch  # noqa: F401 - registers tables on Base.metadata

config = context.config

if config.config_file_name is not None and config.attributes.get("configure_logger", True):
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _database_url() -> str:
    return config.get_main_option("sqlalchemy.url") or get_settings().database_url


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    # Foreign keys are NOT enforced while migrating. SQLite batch mode rebuilds
    # a table (copy, DROP, rename); with enforcement on, DROP TABLE would fire
    # ON DELETE CASCADE and silently delete rows in child tables (for example
    # every alert_events link). Integrity is verified explicitly afterwards.
    engine = build_engine(_database_url(), enforce_foreign_keys=False)
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            # SQLite cannot ALTER most column/constraint changes in place;
            # batch mode rebuilds the table instead.
            render_as_batch=True,
        )
        with context.begin_transaction():
            context.run_migrations()
        if connection.dialect.name == "sqlite":
            problems = connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall()
            if problems:
                raise RuntimeError(f"Foreign key violations after migration: {problems[:10]}")
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
