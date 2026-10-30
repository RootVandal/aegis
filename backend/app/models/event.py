"""Normalized security events and the ingestion batches that produced them."""

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Enum, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UTCDateTime, utc_now
from app.models.enums import DataOrigin, IngestionStatus, Severity


def _enum_column(enum_cls: type[Any], name: str) -> Enum:
    # Store the enum *value* ("high"), not the Python member name ("HIGH"),
    # and add a CHECK constraint so invalid values cannot be written directly.
    return Enum(
        enum_cls,
        name=name,
        native_enum=False,
        create_constraint=True,
        length=16,
        values_callable=lambda members: [m.value for m in members],
        validate_strings=True,
    )


class IngestionBatch(Base):
    """One import run (a file, an API request, or a bundled sample dataset).

    Keeping per-batch counters lets the UI show recent ingestion activity and
    explain why records were skipped, instead of silently dropping them.
    """

    __tablename__ = "ingestion_batches"

    id: Mapped[int] = mapped_column(primary_key=True)
    source_name: Mapped[str] = mapped_column(String(255))
    input_format: Mapped[str] = mapped_column(String(16))
    data_origin: Mapped[DataOrigin] = mapped_column(_enum_column(DataOrigin, "data_origin"))
    status: Mapped[IngestionStatus] = mapped_column(
        _enum_column(IngestionStatus, "ingestion_status")
    )
    started_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())

    received_count: Mapped[int] = mapped_column(Integer, default=0)
    accepted_count: Mapped[int] = mapped_column(Integer, default=0)
    duplicate_count: Mapped[int] = mapped_column(Integer, default=0)
    rejected_count: Mapped[int] = mapped_column(Integer, default=0)

    events: Mapped[list["Event"]] = relationship(back_populates="batch")


class Event(Base):
    """A security event after normalization.

    Most telemetry fields are optional because real sources only populate the
    fields that make sense for them (an authentication event has no parent
    process; a network flow has no Windows event ID). The untouched original
    record is kept in ``raw_event`` so analysts can always check what the
    normalizer did.
    """

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(primary_key=True)

    # Stable identifier used for de-duplication. Taken from the source when it
    # provides one; otherwise derived deterministically during ingestion.
    event_id: Mapped[str] = mapped_column(String(128), unique=True)

    timestamp: Mapped[datetime] = mapped_column(UTCDateTime(), index=True)
    ingested_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)

    event_source: Mapped[str] = mapped_column(String(64))
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[Severity] = mapped_column(
        _enum_column(Severity, "severity"), default=Severity.INFORMATIONAL
    )

    hostname: Mapped[str | None] = mapped_column(String(255), index=True)
    username: Mapped[str | None] = mapped_column(String(255), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45))
    destination_port: Mapped[int | None] = mapped_column(Integer)

    process_name: Mapped[str | None] = mapped_column(String(512))
    parent_process_name: Mapped[str | None] = mapped_column(String(512))
    process_command_line: Mapped[str | None] = mapped_column(Text)
    windows_event_id: Mapped[int | None] = mapped_column(Integer)

    raw_event: Mapped[dict[str, Any]] = mapped_column(JSON)
    normalized_fields: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    data_origin: Mapped[DataOrigin] = mapped_column(_enum_column(DataOrigin, "data_origin"))
    scenario_id: Mapped[str | None] = mapped_column(String(64), index=True)

    batch_id: Mapped[int | None] = mapped_column(
        ForeignKey("ingestion_batches.id", ondelete="SET NULL"), index=True
    )
    batch: Mapped[IngestionBatch | None] = relationship(back_populates="events")

    __table_args__ = (
        # Supports stable "newest first" pagination: ORDER BY timestamp, id.
        Index("ix_events_timestamp_id", "timestamp", "id"),
    )
