"""Scenario Lab attempts."""

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UTCDateTime, enum_column, utc_now
from app.models.enums import AttemptStatus


class ScenarioAttempt(Base):
    """One try at a scenario. Closed once submitted or revealed; a new attempt can start."""

    __tablename__ = "scenario_attempts"

    id: Mapped[int] = mapped_column(primary_key=True)
    scenario_id: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[AttemptStatus] = mapped_column(
        enum_column(AttemptStatus, "attempt_status"), default=AttemptStatus.IN_PROGRESS
    )
    started_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    # Recorded for the analyst's own reference; never used in grading.
    hints_used: Mapped[int] = mapped_column(Integer, default=0)
    answers: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    evidence_event_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    rationale: Mapped[str] = mapped_column(Text, default="")
    evaluation: Mapped[dict[str, Any] | None] = mapped_column(JSON)
