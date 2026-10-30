"""Alert listing, triage (status and notes) and correlation."""

from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import ColumnElement, case, func, select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.detection.registry import RULES_BY_ID
from app.investigation.correlation import Criterion, Seed, correlate, time_bounds
from app.investigation.timeline import rules_by_event
from app.investigation.workflow import (
    ALERT_TRANSITIONS,
    add_alert_note,
    change_alert_status,
    get_alert,
)
from app.models import Alert, Event
from app.schemas.detection import AlertFilters, AlertPage, AlertSummary
from app.schemas.events import EventSummary
from app.schemas.investigation import (
    AlertCaseDetail,
    AlertNoteOut,
    AlertStatusChangeOut,
    AlertStatusUpdate,
    CorrelatedEventOut,
    CorrelationOut,
    CorrelationReasonOut,
    IncidentRef,
    NoteCreate,
    RelatedAlertOut,
)
from app.services.detection import to_record
from app.services.event_query import escape_like

router = APIRouter(prefix="/alerts", tags=["alerts"])

SEVERITY_RANK = case(
    {s: rank for rank, s in enumerate(("informational", "low", "medium", "high", "critical"))},
    value=Alert.severity,
)


def alert_summary(alert: Alert) -> AlertSummary:
    rule = RULES_BY_ID.get(alert.rule_id)
    return AlertSummary(
        id=alert.id,
        rule_id=alert.rule_id,
        rule_name=rule.name if rule else alert.explanation.get("rule", {}).get("name", ""),
        rule_version=alert.rule_version,
        title=alert.title,
        severity=alert.severity,
        status=alert.status,
        created_at=alert.created_at,
        first_seen=alert.first_seen,
        last_seen=alert.last_seen,
        event_count=int(alert.explanation.get("evidence", {}).get("event_count", 0)),
        hosts=alert.hosts,
        users=alert.users,
        ips=alert.ips,
        incident_id=alert.incident_id,
    )


def alert_detail(alert: Alert) -> AlertCaseDetail:
    return AlertCaseDetail(
        **alert_summary(alert).model_dump(),
        explanation=alert.explanation,
        rule_params=alert.rule_params,
        detection_run_id=alert.detection_run_id,
        events=[EventSummary.model_validate(event) for event in alert.events],
        notes=[AlertNoteOut.model_validate(n) for n in alert.notes],
        status_changes=[AlertStatusChangeOut.model_validate(c) for c in alert.status_changes],
        incident=IncidentRef(
            id=alert.incident.id, title=alert.incident.title, status=alert.incident.status
        )
        if alert.incident
        else None,
        allowed_transitions=sorted(ALERT_TRANSITIONS[alert.status]),
    )


@router.get("", response_model=AlertPage, summary="List alerts")
def list_alerts(
    filters: Annotated[AlertFilters, Query()], db: Annotated[Session, Depends(get_db)]
) -> AlertPage:
    conditions: list[ColumnElement[bool]] = []
    if filters.status:
        conditions.append(Alert.status.in_(filters.status))
    if filters.severity:
        conditions.append(Alert.severity.in_(filters.severity))
    if filters.rule_id:
        conditions.append(Alert.rule_id == filters.rule_id)
    if filters.q:
        pattern = f"%{escape_like(filters.q.lower())}%"
        conditions.append(func.lower(Alert.title).like(pattern, escape="\\"))
    order = {
        "last_seen_desc": (Alert.last_seen.desc(), Alert.id.desc()),
        "created_desc": (Alert.created_at.desc(), Alert.id.desc()),
        "severity_desc": (SEVERITY_RANK.desc(), Alert.last_seen.desc(), Alert.id.desc()),
    }[filters.sort]
    total = db.scalar(select(func.count()).select_from(Alert).where(*conditions)) or 0
    alerts = db.scalars(
        select(Alert)
        .where(*conditions)
        .order_by(*order)
        .offset((filters.page - 1) * filters.page_size)
        .limit(filters.page_size)
    )
    return AlertPage(
        items=[alert_summary(a) for a in alerts],
        total=total,
        page=filters.page,
        page_size=filters.page_size,
    )


@router.get("/{alert_id}", response_model=AlertCaseDetail, summary="Alert details")
def get_alert_detail(alert_id: int, db: Annotated[Session, Depends(get_db)]) -> AlertCaseDetail:
    return alert_detail(get_alert(db, alert_id))


@router.patch("/{alert_id}", response_model=AlertCaseDetail, summary="Change alert status")
def update_alert_status(
    alert_id: int, update: AlertStatusUpdate, db: Annotated[Session, Depends(get_db)]
) -> AlertCaseDetail:
    """Moves the alert through new -> acknowledged -> investigating -> resolved /
    false_positive. Closing or reopening requires a reason. Evidence links are
    never touched by status changes."""
    alert = change_alert_status(db, get_alert(db, alert_id), update.status, update.reason,
                                update.author)  # fmt: skip
    return alert_detail(alert)


@router.post(
    "/{alert_id}/notes", response_model=AlertNoteOut, status_code=201, summary="Add a note"
)
def create_alert_note(
    alert_id: int, note: NoteCreate, db: Annotated[Session, Depends(get_db)]
) -> AlertNoteOut:
    return AlertNoteOut.model_validate(
        add_alert_note(db, get_alert(db, alert_id), note.body, note.author)
    )


@router.get(
    "/{alert_id}/correlation", response_model=CorrelationOut, summary="Related events and alerts"
)
def alert_correlation(
    alert_id: int,
    db: Annotated[Session, Depends(get_db)],
    window_minutes: Annotated[int, Query(ge=1, le=10_080)] = 60,
    criteria: Annotated[list[Criterion] | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> CorrelationOut:
    """Events that share a host, user, IP or scenario with this alert's events
    within ``window_minutes`` of them. Time proximity alone never qualifies."""
    alert = get_alert(db, alert_id)
    selected: frozenset[Criterion] = frozenset(criteria or ("host", "user", "ip", "scenario"))
    window = timedelta(minutes=window_minutes)
    seed_records = [to_record(e) for e in alert.events]
    start, end = time_bounds(Seed.from_events(seed_records), window)
    candidates = db.scalars(
        select(Event).where(Event.timestamp >= start, Event.timestamp <= end)
    ).all()
    by_event_id = {e.event_id: e for e in candidates}
    found = correlate(seed_records, [to_record(e) for e in candidates], window=window,
                      criteria=selected)  # fmt: skip

    shown = found[:limit]
    citations = rules_by_event(db, [by_event_id[c.event.event_id].id for c in shown])
    related: dict[int, list[str]] = {}
    events_out = []
    for item in shown:
        cited = [(a, r) for a, r in citations.get(by_event_id[item.event.event_id].id, [])
                 if a != alert.id]  # fmt: skip
        for other_alert_id, _ in cited:
            related.setdefault(other_alert_id, []).append(item.event.event_id)
        events_out.append(
            CorrelatedEventOut(
                event=EventSummary.model_validate(by_event_id[item.event.event_id]),
                reasons=[CorrelationReasonOut(criterion=r.criterion, value=r.value,
                                              description=r.description) for r in item.reasons],
                relation=item.relation,
                offset_seconds=item.offset_seconds,
                explanation=item.explanation(),
                alert_ids=sorted({a for a, _ in cited}),
                rule_ids=sorted({r for _, r in cited}),
            )
        )  # fmt: skip

    return CorrelationOut(
        window_minutes=window_minutes,
        criteria=sorted(selected),
        seed_event_ids=[e.event_id for e in alert.events],
        total=len(found),
        truncated=len(found) > limit,
        events=events_out,
        related_alerts=[
            RelatedAlertOut(alert=alert_summary(get_alert(db, other)), shared_event_ids=ids)
            for other, ids in sorted(related.items())
        ],
    )
