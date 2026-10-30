"""Incident case management."""

from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.routes.alerts import alert_summary
from app.db.session import get_db
from app.investigation import workflow
from app.investigation.correlation import Criterion
from app.investigation.report import render_report
from app.investigation.timeline import build_timeline
from app.models import Alert, Incident
from app.models.enums import IncidentStatus
from app.schemas.events import EventSummary
from app.schemas.investigation import (
    AssessmentUpdate,
    EvidenceCreate,
    EvidenceOut,
    IncidentAlertsAdd,
    IncidentCreate,
    IncidentDetail,
    IncidentHistoryOut,
    IncidentNoteCreate,
    IncidentNoteOut,
    IncidentPage,
    IncidentSummary,
    IncidentUpdate,
    TimelineEntryOut,
    TimelineSourceOut,
)

router = APIRouter(prefix="/incidents", tags=["incidents"])

DB = Annotated[Session, Depends(get_db)]


def _summary(incident: Incident, alert_count: int) -> IncidentSummary:
    return IncidentSummary(
        id=incident.id,
        title=incident.title,
        severity=incident.severity,
        status=incident.status,
        verdict=incident.verdict,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        alert_count=alert_count,
    )


def _detail(incident: Incident) -> IncidentDetail:
    return IncidentDetail(
        **_summary(incident, len(incident.alerts)).model_dump(),
        description=incident.description,
        resolved_at=incident.resolved_at,
        final_assessment=incident.final_assessment,
        resolution_summary=incident.resolution_summary,
        allowed_transitions=sorted(workflow.INCIDENT_TRANSITIONS[incident.status]),
        alerts=[alert_summary(a) for a in sorted(incident.alerts, key=lambda a: a.id)],
        evidence=[
            EvidenceOut(
                id=item.id,
                note=item.note,
                author=item.author,
                added_at=item.added_at,
                event=EventSummary.model_validate(item.event),
            )
            for item in incident.evidence
        ],
        notes=[IncidentNoteOut.model_validate(n) for n in incident.notes],
        history=[IncidentHistoryOut.model_validate(h) for h in incident.history],
    )


@router.get("", response_model=IncidentPage, summary="List incidents")
def list_incidents(
    db: DB,
    status: Annotated[list[IncidentStatus] | None, Query()] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 50,
) -> IncidentPage:
    conditions = [Incident.status.in_(status)] if status else []
    total = db.scalar(select(func.count()).select_from(Incident).where(*conditions)) or 0
    alert_counts = (
        select(Alert.incident_id, func.count().label("n")).group_by(Alert.incident_id).subquery()
    )
    rows = db.execute(
        select(Incident, func.coalesce(alert_counts.c.n, 0))
        .outerjoin(alert_counts, alert_counts.c.incident_id == Incident.id)
        .where(*conditions)
        .order_by(Incident.updated_at.desc(), Incident.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    return IncidentPage(
        items=[_summary(incident, count) for incident, count in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("", response_model=IncidentDetail, status_code=201, summary="Create an incident")
def create_incident(body: IncidentCreate, db: DB) -> IncidentDetail:
    """Create an incident, optionally from one or more alerts. Linked alerts
    that are still new or acknowledged move to investigating."""
    incident = workflow.create_incident(
        db,
        title=body.title,
        description=body.description,
        severity=body.severity,
        alert_ids=body.alert_ids,
        author=body.author,
    )
    return _detail(incident)


@router.get("/{incident_id}", response_model=IncidentDetail, summary="Incident details")
def get_incident(incident_id: int, db: DB) -> IncidentDetail:
    return _detail(workflow.get_incident(db, incident_id))


@router.patch("/{incident_id}", response_model=IncidentDetail, summary="Update an incident")
def update_incident(incident_id: int, body: IncidentUpdate, db: DB) -> IncidentDetail:
    """Edit title/description/severity or move the status along
    new -> investigating -> contained -> resolved. Resolving requires a
    recorded final assessment; resolved incidents can be reopened."""
    incident = workflow.update_incident(
        db,
        workflow.get_incident(db, incident_id),
        changes=body.model_dump(exclude={"author"}),
        author=body.author,
    )
    return _detail(incident)


@router.post("/{incident_id}/alerts", response_model=IncidentDetail, summary="Link alerts")
def link_alerts(incident_id: int, body: IncidentAlertsAdd, db: DB) -> IncidentDetail:
    incident = workflow.get_incident(db, incident_id)
    return _detail(workflow.add_alerts(db, incident, body.alert_ids, body.author))


@router.delete(
    "/{incident_id}/alerts/{alert_id}", response_model=IncidentDetail, summary="Unlink an alert"
)
def unlink_alert(incident_id: int, alert_id: int, db: DB) -> IncidentDetail:
    incident = workflow.get_incident(db, incident_id)
    return _detail(workflow.remove_alert(db, incident, alert_id, "analyst"))


@router.post(
    "/{incident_id}/evidence", response_model=IncidentDetail, status_code=201,
    summary="Record an event as evidence",
)  # fmt: skip
def add_evidence(incident_id: int, body: EvidenceCreate, db: DB) -> IncidentDetail:
    incident = workflow.get_incident(db, incident_id)
    workflow.add_evidence(db, incident, body.event_id, body.note, body.author)
    return _detail(incident)


@router.delete(
    "/{incident_id}/evidence/{evidence_id}", response_model=IncidentDetail,
    summary="Remove an evidence item",
)  # fmt: skip
def remove_evidence(incident_id: int, evidence_id: int, db: DB) -> IncidentDetail:
    incident = workflow.get_incident(db, incident_id)
    return _detail(workflow.remove_evidence(db, incident, evidence_id, "analyst"))


@router.post(
    "/{incident_id}/notes", response_model=IncidentNoteOut, status_code=201,
    summary="Add a note or hypothesis",
)  # fmt: skip
def add_note(incident_id: int, body: IncidentNoteCreate, db: DB) -> IncidentNoteOut:
    incident = workflow.get_incident(db, incident_id)
    return IncidentNoteOut.model_validate(
        workflow.add_incident_note(db, incident, body.kind, body.body, body.author)
    )


@router.put(
    "/{incident_id}/assessment", response_model=IncidentDetail, summary="Record final assessment"
)
def put_assessment(incident_id: int, body: AssessmentUpdate, db: DB) -> IncidentDetail:
    incident = workflow.record_assessment(
        db,
        workflow.get_incident(db, incident_id),
        verdict=body.verdict,
        final_assessment=body.final_assessment,
        resolution_summary=body.resolution_summary,
        author=body.author,
    )
    return _detail(incident)


@router.get(
    "/{incident_id}/timeline", response_model=list[TimelineEntryOut], summary="Event timeline"
)
def get_timeline(
    incident_id: int,
    db: DB,
    include_correlated: bool = False,
    window_minutes: Annotated[int, Query(ge=1, le=10_080)] = 60,
    criteria: Annotated[list[Criterion] | None, Query()] = None,
) -> list[TimelineEntryOut]:
    """Events from linked alerts and recorded evidence, oldest first, each with
    the reason it is on the timeline. ``include_correlated`` adds events that
    share an entity with them (see the correlation rules)."""
    entries = build_timeline(
        db,
        workflow.get_incident(db, incident_id),
        include_correlated=include_correlated,
        window=timedelta(minutes=window_minutes),
        criteria=frozenset(criteria or ("host", "user", "ip", "scenario")),
    )
    return [
        TimelineEntryOut(
            event=EventSummary.model_validate(e.event),
            sources=[
                TimelineSourceOut(kind=s.kind, description=s.description,
                                  alert_id=s.alert_id, rule_id=s.rule_id)
                for s in e.sources
            ],
            rule_ids=e.rule_ids,
        )
        for e in entries
    ]  # fmt: skip


@router.get(
    "/{incident_id}/report",
    response_class=PlainTextResponse,
    summary="Incident report (Markdown)",
    responses={200: {"content": {"text/markdown": {}}}},
)
def get_report(incident_id: int, db: DB) -> PlainTextResponse:
    incident = workflow.get_incident(db, incident_id)
    report = render_report(incident, build_timeline(db, incident))
    return PlainTextResponse(
        report,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="incident-{incident.id}.md"'},
    )
