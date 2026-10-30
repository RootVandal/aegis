"""Request and response models for alert triage, correlation and incidents."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import AlertStatus, AssessmentVerdict, IncidentStatus, NoteKind, Severity
from app.schemas.detection import AlertDetail, AlertSummary
from app.schemas.events import EventSummary

# No authentication yet: "author" is a label the client supplies, not an identity.
Author = Field(default="analyst", min_length=1, max_length=64)


class _Request(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# --- Alerts -------------------------------------------------------------------


class AlertStatusUpdate(_Request):
    status: AlertStatus
    reason: str | None = Field(
        default=None, max_length=2000, description="Required when closing or reopening."
    )
    author: str = Author


class NoteCreate(_Request):
    body: str = Field(min_length=1, max_length=5000)
    author: str = Author


class AlertNoteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    author: str
    body: str
    created_at: datetime


class AlertStatusChangeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    from_status: AlertStatus
    to_status: AlertStatus
    reason: str | None
    author: str
    changed_at: datetime


class IncidentRef(BaseModel):
    id: int
    title: str
    status: IncidentStatus


class CorrelationReasonOut(BaseModel):
    criterion: str
    value: str
    description: str


class CorrelatedEventOut(BaseModel):
    event: EventSummary
    reasons: list[CorrelationReasonOut]
    relation: Literal["before", "during", "after"]
    offset_seconds: float
    explanation: str
    alert_ids: list[int] = Field(description="Other alerts that cite this event.")
    rule_ids: list[str]


class RelatedAlertOut(BaseModel):
    alert: AlertSummary
    shared_event_ids: list[str]


class CorrelationOut(BaseModel):
    window_minutes: int
    criteria: list[str]
    seed_event_ids: list[str]
    total: int
    truncated: bool
    events: list[CorrelatedEventOut]
    related_alerts: list[RelatedAlertOut]


# --- Incidents ----------------------------------------------------------------


class IncidentCreate(_Request):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=5000)
    severity: Severity | None = Field(
        default=None, description="Defaults to the most severe linked alert."
    )
    alert_ids: list[int] = Field(default_factory=list, max_length=100)
    author: str = Author


class IncidentUpdate(_Request):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=5000)
    severity: Severity | None = None
    status: IncidentStatus | None = None
    author: str = Author


class IncidentAlertsAdd(_Request):
    alert_ids: list[int] = Field(min_length=1, max_length=100)
    author: str = Author


class EvidenceCreate(_Request):
    event_id: str = Field(min_length=1, max_length=128)
    note: str = Field(min_length=1, max_length=2000, description="Why this event matters.")
    author: str = Author


class IncidentNoteCreate(_Request):
    kind: NoteKind = NoteKind.NOTE
    body: str = Field(min_length=1, max_length=5000)
    author: str = Author


class AssessmentUpdate(_Request):
    verdict: AssessmentVerdict
    final_assessment: str = Field(
        min_length=1, max_length=10_000, description="What happened, based on which evidence."
    )
    resolution_summary: str = Field(min_length=1, max_length=5000)
    author: str = Author


class EvidenceOut(BaseModel):
    id: int
    note: str
    author: str
    added_at: datetime
    event: EventSummary


class IncidentNoteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    kind: NoteKind
    author: str
    body: str
    created_at: datetime


class IncidentHistoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    action: str
    summary: str
    author: str
    created_at: datetime


class IncidentSummary(BaseModel):
    id: int
    title: str
    severity: Severity
    status: IncidentStatus
    verdict: AssessmentVerdict | None
    created_at: datetime
    updated_at: datetime
    alert_count: int


class IncidentDetail(IncidentSummary):
    description: str
    resolved_at: datetime | None
    final_assessment: str | None
    resolution_summary: str | None
    allowed_transitions: list[IncidentStatus]
    alerts: list[AlertSummary]
    evidence: list[EvidenceOut]
    notes: list[IncidentNoteOut]
    history: list[IncidentHistoryOut]


class IncidentPage(BaseModel):
    items: list[IncidentSummary]
    total: int
    page: int
    page_size: int


class TimelineSourceOut(BaseModel):
    kind: Literal["alert", "evidence", "correlated"]
    description: str
    alert_id: int | None
    rule_id: str | None


class TimelineEntryOut(BaseModel):
    event: EventSummary
    sources: list[TimelineSourceOut]
    rule_ids: list[str]


class AlertCaseDetail(AlertDetail):
    """Alert detail plus its triage state: notes, history and incident link."""

    notes: list[AlertNoteOut]
    status_changes: list[AlertStatusChangeOut]
    incident: IncidentRef | None
    allowed_transitions: list[AlertStatus]
