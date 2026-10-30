"""System health checks.

Kept separate from the HTTP layer so the checks can be unit-tested and reused
(for example by a CLI) without going through FastAPI.
"""

import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from alembic.script import ScriptDirectory
from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models import Event, IngestionBatch

logger = logging.getLogger("aegis.health")

ALEMBIC_DIR = Path(__file__).resolve().parents[2] / "alembic"


@dataclass(frozen=True)
class DatabaseHealth:
    reachable: bool
    schema_revision: str | None
    expected_revision: str | None
    error: str | None = None

    @property
    def schema_current(self) -> bool:
        return self.reachable and self.schema_revision == self.expected_revision


@dataclass(frozen=True)
class DataSummary:
    event_count: int
    ingestion_batch_count: int
    latest_event_at: datetime | None
    last_ingestion_at: datetime | None


def expected_schema_revision() -> str | None:
    """The newest migration shipped with this code (Alembic 'head')."""
    return ScriptDirectory(str(ALEMBIC_DIR)).get_current_head()


def check_database(session: Session) -> DatabaseHealth:
    expected = expected_schema_revision()
    try:
        session.execute(text("SELECT 1"))
    except SQLAlchemyError:
        logger.exception("Database connectivity check failed")
        # The exception text may contain file paths or connection details,
        # so only a generic message is returned to the client.
        return DatabaseHealth(False, None, expected, error="Database is unreachable.")

    try:
        revision = session.execute(text("SELECT version_num FROM alembic_version")).scalar()
    except SQLAlchemyError:
        # Table missing: the database exists but migrations were never applied.
        session.rollback()
        revision = None

    return DatabaseHealth(True, revision, expected)


def summarize_data(session: Session) -> DataSummary:
    return DataSummary(
        event_count=session.scalar(select(func.count()).select_from(Event)) or 0,
        ingestion_batch_count=session.scalar(select(func.count()).select_from(IngestionBatch)) or 0,
        latest_event_at=session.scalar(select(func.max(Event.timestamp))),
        last_ingestion_at=session.scalar(select(func.max(IngestionBatch.completed_at))),
    )
