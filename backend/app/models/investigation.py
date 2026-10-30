"""Analyst work: alert notes and history, incidents, evidence and assessments.

AEGIS has no user accounts yet, so ``author`` is a free-text label
(default "analyst"), not an authenticated identity. See SECURITY.md.
"""

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UTCDateTime, enum_column, utc_now
from app.models.enums import AlertStatus, AssessmentVerdict, IncidentStatus, NoteKind, Severity
from app.models.event import Event

if TYPE_CHECKING:
    from app.models.detection import Alert

DEFAULT_AUTHOR = "analyst"


class AlertNote(Base):
    __tablename__ = "alert_notes"

    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    author: Mapped[str] = mapped_column(String(64), default=DEFAULT_AUTHOR)
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)


class AlertStatusChange(Base):
    """Every status change of an alert, so its triage history is auditable."""

    __tablename__ = "alert_status_changes"

    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    from_status: Mapped[AlertStatus] = mapped_column(enum_column(AlertStatus, "from_status"))
    to_status: Mapped[AlertStatus] = mapped_column(enum_column(AlertStatus, "to_status"))
    reason: Mapped[str | None] = mapped_column(Text)
    author: Mapped[str] = mapped_column(String(64), default=DEFAULT_AUTHOR)
    changed_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[Severity] = mapped_column(enum_column(Severity, "severity"))
    status: Mapped[IncidentStatus] = mapped_column(
        enum_column(IncidentStatus, "incident_status"), default=IncidentStatus.NEW, index=True
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime())

    # Final assessment: required before the incident can be resolved.
    verdict: Mapped[AssessmentVerdict | None] = mapped_column(
        enum_column(AssessmentVerdict, "verdict")
    )
    final_assessment: Mapped[str | None] = mapped_column(Text)
    resolution_summary: Mapped[str | None] = mapped_column(Text)

    alerts: Mapped[list["Alert"]] = relationship(back_populates="incident")
    evidence: Mapped[list["IncidentEvidence"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", order_by="IncidentEvidence.id"
    )
    notes: Mapped[list["IncidentNote"]] = relationship(
        cascade="all, delete-orphan", order_by="IncidentNote.id"
    )
    history: Mapped[list["IncidentHistory"]] = relationship(
        cascade="all, delete-orphan", order_by="IncidentHistory.id"
    )


class IncidentEvidence(Base):
    """An event the analyst explicitly attached to the incident, with a reason."""

    __tablename__ = "incident_evidence"
    __table_args__ = (UniqueConstraint("incident_id", "event_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    # RESTRICT: documented evidence cannot be deleted from under an incident.
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id", ondelete="RESTRICT"))
    note: Mapped[str] = mapped_column(Text)
    author: Mapped[str] = mapped_column(String(64), default=DEFAULT_AUTHOR)
    added_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)

    incident: Mapped[Incident] = relationship(back_populates="evidence")
    event: Mapped[Event] = relationship()


class IncidentNote(Base):
    __tablename__ = "incident_notes"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[NoteKind] = mapped_column(enum_column(NoteKind, "note_kind"))
    author: Mapped[str] = mapped_column(String(64), default=DEFAULT_AUTHOR)
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)


class IncidentHistory(Base):
    """Append-only record of significant changes to an incident."""

    __tablename__ = "incident_history"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    action: Mapped[str] = mapped_column(String(32))
    summary: Mapped[str] = mapped_column(Text)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    author: Mapped[str] = mapped_column(String(64), default=DEFAULT_AUTHOR)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
