"""Response models for the health endpoints."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class LivenessResponse(BaseModel):
    status: Literal["ok"] = "ok"


class DatabaseComponent(BaseModel):
    status: Literal["ok", "degraded", "error"]
    message: str
    schema_revision: str | None = Field(description="Migration currently applied.")
    expected_revision: str | None = Field(description="Newest migration shipped with the code.")


class DataSummaryResponse(BaseModel):
    event_count: int
    ingestion_batch_count: int
    latest_event_at: datetime | None = Field(description="Timestamp of the newest stored event.")
    last_ingestion_at: datetime | None = Field(
        description="When the most recent ingestion batch finished."
    )


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded", "error"]
    version: str
    environment: str
    server_time: datetime
    database: DatabaseComponent
    # None when the database cannot be queried; never a made-up zero.
    data: DataSummaryResponse | None
