"""Migrations must produce exactly the schema the ORM models describe."""

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import inspect, text

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


def test_upgrading_a_populated_database_keeps_alert_evidence(database_url: str) -> None:
    # Regression: SQLite "batch" migrations rebuild a table (copy, DROP, rename).
    # With foreign keys enforced, DROP TABLE alerts would cascade-delete every
    # alert_events link, silently removing the evidence behind existing alerts.
    config = alembic_config(database_url)
    command.upgrade(config, "0002")
    engine = build_engine(database_url)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO events (id, event_id, timestamp, ingested_at, event_source, "
                "event_type, severity, raw_event, normalized_fields, data_origin) VALUES "
                "(1, 'e1', '2026-01-01', '2026-01-01', 's', 't', 'low', '{}', '{}', 'synthetic')"
            )
        )
        conn.execute(
            text(
                "INSERT INTO alerts (id, fingerprint, rule_id, rule_version, title, severity, "
                "status, created_at, updated_at, first_seen, last_seen, hosts, users, ips, "
                "explanation, rule_params) VALUES (1, 'fp', 'R', 1, 't', 'low', 'new', "
                "'2026-01-01', '2026-01-01', '2026-01-01', '2026-01-01', '[]', '[]', '[]', "
                "'{}', '{}')"
            )
        )
        conn.execute(text("INSERT INTO alert_events (alert_id, event_id) VALUES (1, 1)"))
    engine.dispose()

    command.upgrade(config, "head")

    engine = build_engine(database_url)
    with engine.connect() as conn:
        links = conn.execute(text("SELECT COUNT(*) FROM alert_events")).scalar()
        problems = conn.execute(text("PRAGMA foreign_key_check")).fetchall()
    engine.dispose()
    assert links == 1
    assert problems == []


def test_downgrade_to_base_removes_tables(migrated_database_url: str) -> None:
    command.downgrade(alembic_config(migrated_database_url), "base")

    engine = build_engine(migrated_database_url)
    tables = set(inspect(engine).get_table_names())
    engine.dispose()

    assert tables <= {"alembic_version"}
