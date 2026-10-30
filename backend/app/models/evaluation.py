"""Stored detection evaluation runs."""

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UTCDateTime, utc_now


class EvaluationRun(Base):
    """One execution of the labeled suite.

    The dataset version (content hash) and each rule's version and effective
    parameters are stored, so a run can be reproduced exactly and two runs
    can be compared knowing what changed between them.
    """

    __tablename__ = "evaluation_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, index=True)
    dataset_id: Mapped[str] = mapped_column(String(64))
    dataset_version: Mapped[str] = mapped_column(String(80))
    settings_source: Mapped[str] = mapped_column(String(16))  # "current" or "defaults"
    rules: Mapped[dict[str, Any]] = mapped_column(JSON)  # rule_id -> {version, params}
    results: Mapped[dict[str, Any]] = mapped_column(JSON)  # per_rule, totals, cases, ...
