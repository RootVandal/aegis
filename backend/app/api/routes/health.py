from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app import __version__
from app.db.base import utc_now
from app.db.session import get_db
from app.schemas.health import (
    DatabaseComponent,
    DataSummaryResponse,
    HealthResponse,
    LivenessResponse,
)
from app.services.health import check_database, summarize_data

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live", response_model=LivenessResponse, summary="Liveness probe")
def liveness() -> LivenessResponse:
    """Returns 200 while the API process is running. Does not touch the database."""
    return LivenessResponse()


@router.get("", response_model=HealthResponse, summary="Detailed system health")
def health(request: Request, db: Annotated[Session, Depends(get_db)]) -> HealthResponse:
    """Reports database connectivity, migration state and stored-data counts.

    Always answers 200 so the UI can display *why* the system is unhealthy;
    the overall state is in the ``status`` field.
    """
    db_health = check_database(db)

    if not db_health.reachable:
        database = DatabaseComponent(
            status="error",
            message=db_health.error or "Database is unreachable.",
            schema_revision=None,
            expected_revision=db_health.expected_revision,
        )
        data = None
    else:
        if db_health.schema_current:
            database = DatabaseComponent(
                status="ok",
                message="Connected; schema is up to date.",
                schema_revision=db_health.schema_revision,
                expected_revision=db_health.expected_revision,
            )
        else:
            database = DatabaseComponent(
                status="degraded",
                message="Connected, but migrations are not applied. Run `alembic upgrade head`.",
                schema_revision=db_health.schema_revision,
                expected_revision=db_health.expected_revision,
            )
        data = _data_summary(db) if db_health.schema_current else None

    return HealthResponse(
        status=database.status,
        version=__version__,
        environment=request.app.state.settings.environment,
        server_time=utc_now(),
        database=database,
        data=data,
    )


def _data_summary(db: Session) -> DataSummaryResponse:
    summary = summarize_data(db)
    return DataSummaryResponse(
        event_count=summary.event_count,
        ingestion_batch_count=summary.ingestion_batch_count,
        latest_event_at=summary.latest_event_at,
        last_ingestion_at=summary.last_ingestion_at,
    )
