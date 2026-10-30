"""Detection results: alerts, the runs that produced them, and rule settings."""

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, Boolean, Column, ForeignKey, Integer, String, Table
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UTCDateTime, enum_column, utc_now
from app.models.enums import AlertStatus, DetectionTrigger, Severity
from app.models.event import Event

if TYPE_CHECKING:
    from app.models.investigation import AlertNote, AlertStatusChange, Incident

# Links an alert to the events that caused it.
# * Deleting an alert removes only these link rows (CASCADE).
# * Deleting an event that an alert references is refused (RESTRICT), so
#   evidence can never disappear silently from under an alert.
alert_events = Table(
    "alert_events",
    Base.metadata,
    Column("alert_id", ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True),
    Column("event_id", ForeignKey("events.id", ondelete="RESTRICT"), primary_key=True),
)


class RuleSetting(Base):
    """User overrides for one detection rule. Absent row = rule defaults."""

    __tablename__ = "rule_settings"

    rule_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # Only the parameters the user changed; defaults live in the rule code.
    params: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)


class DetectionRun(Base):
    """One execution of the detection engine over the stored events."""

    __tablename__ = "detection_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    trigger: Mapped[DetectionTrigger] = mapped_column(enum_column(DetectionTrigger, "trigger"))
    started_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    events_evaluated: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    alerts_created: Mapped[int] = mapped_column(Integer, default=0)
    alerts_existing: Mapped[int] = mapped_column(Integer, default=0)
    # Per rule: id, version, effective params and number of findings. Makes the
    # run reproducible: the same events + this configuration = the same result.
    rules: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)


class Alert(Base):
    """A detection finding that an analyst can triage.

    The explanation, rule version and parameters are stored as a snapshot
    taken when the alert was created, so the alert still explains itself
    correctly after the rule or its configuration changes.
    """

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Hash of rule ID + the triggering event IDs. Re-running detection over the
    # same events finds the existing alert instead of creating a duplicate.
    fingerprint: Mapped[str] = mapped_column(String(80), unique=True)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    rule_version: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[Severity] = mapped_column(enum_column(Severity, "severity"), index=True)
    status: Mapped[AlertStatus] = mapped_column(
        enum_column(AlertStatus, "alert_status"), default=AlertStatus.NEW, index=True
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime())
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime())

    hosts: Mapped[list[str]] = mapped_column(JSON, default=list)
    users: Mapped[list[str]] = mapped_column(JSON, default=list)
    ips: Mapped[list[str]] = mapped_column(JSON, default=list)

    explanation: Mapped[dict[str, Any]] = mapped_column(JSON)
    rule_params: Mapped[dict[str, Any]] = mapped_column(JSON)

    detection_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("detection_runs.id", ondelete="SET NULL"), index=True
    )
    # An alert belongs to at most one incident.
    incident_id: Mapped[int | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), index=True
    )
    incident: Mapped["Incident | None"] = relationship(back_populates="alerts")
    notes: Mapped[list["AlertNote"]] = relationship(
        cascade="all, delete-orphan", order_by="AlertNote.id"
    )
    status_changes: Mapped[list["AlertStatusChange"]] = relationship(
        cascade="all, delete-orphan", order_by="AlertStatusChange.id"
    )

    detection_run: Mapped[DetectionRun | None] = relationship()
    events: Mapped[list[Event]] = relationship(
        secondary=alert_events, order_by=(Event.timestamp, Event.id)
    )
