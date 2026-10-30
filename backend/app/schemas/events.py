"""Request and response models for event search and ingestion."""

from datetime import datetime
from ipaddress import ip_address
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.enums import DataOrigin, IngestionStatus, Severity


class EventFilters(BaseModel):
    """Query-string filters for GET /events. Unknown parameters are rejected
    so a typo (``?hostnme=``) fails loudly instead of returning everything."""

    model_config = ConfigDict(extra="forbid")

    start: datetime | None = Field(default=None, description="Inclusive lower bound (UTC).")
    end: datetime | None = Field(default=None, description="Exclusive upper bound (UTC).")
    event_type: list[str] = Field(default_factory=list)
    severity: list[Severity] = Field(default_factory=list)
    hostname: str | None = Field(default=None, max_length=255)
    username: str | None = Field(default=None, max_length=255)
    source_ip: str | None = None
    data_origin: DataOrigin | None = None
    q: str | None = Field(default=None, max_length=200, description="Case-insensitive text search.")
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=200)
    sort: Literal["timestamp_desc", "timestamp_asc"] = "timestamp_desc"

    @field_validator("start", "end")
    @classmethod
    def _require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.utcoffset() is None:
            raise ValueError("must include a timezone, e.g. 2026-10-01T00:00:00Z")
        return value

    @field_validator("source_ip")
    @classmethod
    def _canonical_ip(cls, value: str | None) -> str | None:
        if not value:
            return None
        try:
            return str(ip_address(value.strip()))
        except ValueError:
            raise ValueError("is not a valid IP address") from None

    @field_validator("hostname", "username", "q")
    @classmethod
    def _blank_is_none(cls, value: str | None) -> str | None:
        return value.strip() or None if value is not None else None

    @model_validator(mode="after")
    def _ordered_range(self) -> Self:
        if self.start and self.end and self.end <= self.start:
            raise ValueError("end must be later than start")
        return self


class EventSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_id: str
    timestamp: datetime
    event_source: str
    event_type: str
    severity: Severity
    hostname: str | None
    username: str | None
    source_ip: str | None
    destination_ip: str | None
    destination_port: int | None
    process_name: str | None
    parent_process_name: str | None
    process_command_line: str | None
    windows_event_id: int | None
    data_origin: DataOrigin
    scenario_id: str | None


class AlertRef(BaseModel):
    id: int
    rule_id: str
    title: str
    severity: Severity
    status: str


class EventDetail(EventSummary):
    ingested_at: datetime
    batch_id: int | None
    raw_event: dict[str, Any]
    normalized_fields: dict[str, Any]
    alerts: list[AlertRef] = Field(
        default_factory=list, description="Alerts that cite this event as evidence."
    )


class EventPage(BaseModel):
    items: list[EventSummary]
    total: int
    page: int
    page_size: int


class FacetValue(BaseModel):
    value: str
    count: int


class EventFacets(BaseModel):
    """Distinct values present in the stored events, for filter controls."""

    event_types: list[FacetValue]
    event_sources: list[FacetValue]
    severities: list[FacetValue]
    data_origins: list[FacetValue]


class IngestionBatchOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source_name: str
    input_format: str
    data_origin: DataOrigin
    status: IngestionStatus
    started_at: datetime
    completed_at: datetime | None
    received_count: int
    accepted_count: int
    duplicate_count: int
    rejected_count: int


class RecordRejectionOut(BaseModel):
    position: int = Field(description="Line number (JSONL) or array position (JSON), 1-based.")
    message: str


class IngestionResponse(BaseModel):
    batch: IngestionBatchOut
    rejections: list[RecordRejectionOut] = Field(
        description="Why records were rejected. Capped at 100 entries; see batch counts for totals."
    )


class DatasetOut(BaseModel):
    id: str
    name: str
    description: str
    data_origin: DataOrigin
    event_count: int
