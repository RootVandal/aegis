"""Alert triage and incident case management.

All state changes go through these functions so the rules live in one
place: which status transitions are allowed, when a reason is required,
and what gets written to the history. Route handlers stay thin.
"""

from collections.abc import Iterable, Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import AppError
from app.db.base import utc_now
from app.models import (
    Alert,
    AlertNote,
    AlertStatusChange,
    Event,
    Incident,
    IncidentEvidence,
    IncidentHistory,
    IncidentNote,
)
from app.models.enums import AlertStatus, AssessmentVerdict, IncidentStatus, NoteKind, Severity

# --- Alerts -------------------------------------------------------------------

ALERT_TRANSITIONS: dict[AlertStatus, frozenset[AlertStatus]] = {
    AlertStatus.NEW: frozenset(
        {
            AlertStatus.ACKNOWLEDGED,
            AlertStatus.INVESTIGATING,
            AlertStatus.RESOLVED,
            AlertStatus.FALSE_POSITIVE,
        }
    ),  # fmt: skip
    AlertStatus.ACKNOWLEDGED: frozenset(
        {AlertStatus.INVESTIGATING, AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE}
    ),
    AlertStatus.INVESTIGATING: frozenset({AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE}),
    # Closed alerts can be reopened, but never jump straight between verdicts.
    AlertStatus.RESOLVED: frozenset({AlertStatus.INVESTIGATING}),
    AlertStatus.FALSE_POSITIVE: frozenset({AlertStatus.INVESTIGATING}),
}
CLOSED_ALERT_STATUSES = frozenset({AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE})


def get_alert(session: Session, alert_id: int) -> Alert:
    alert = session.get(Alert, alert_id)
    if alert is None:
        raise AppError(404, "alert_not_found", f"No alert with ID {alert_id}.")
    return alert


def _record_alert_status(
    alert: Alert, to_status: AlertStatus, reason: str | None, author: str
) -> None:
    alert.status_changes.append(
        AlertStatusChange(
            from_status=alert.status, to_status=to_status, reason=reason, author=author
        )
    )
    alert.status = to_status
    alert.updated_at = utc_now()


def change_alert_status(
    session: Session, alert: Alert, to_status: AlertStatus, reason: str | None, author: str
) -> Alert:
    if to_status == alert.status:
        raise AppError(409, "invalid_transition", f"The alert is already {to_status.value}.")
    if to_status not in ALERT_TRANSITIONS[alert.status]:
        allowed = ", ".join(sorted(s.value for s in ALERT_TRANSITIONS[alert.status]))
        raise AppError(
            409,
            "invalid_transition",
            f"An alert cannot go from {alert.status.value} to {to_status.value}. "
            f"Allowed: {allowed}.",
        )
    closing = to_status in CLOSED_ALERT_STATUSES
    reopening = alert.status in CLOSED_ALERT_STATUSES
    if (closing or reopening) and not (reason and reason.strip()):
        raise AppError(
            422,
            "reason_required",
            "A reason is required when closing or reopening an alert.",
        )
    _record_alert_status(alert, to_status, reason.strip() if reason else None, author)
    session.commit()
    return alert


def add_alert_note(session: Session, alert: Alert, body: str, author: str) -> AlertNote:
    note = AlertNote(body=body, author=author)
    alert.notes.append(note)
    alert.updated_at = utc_now()
    session.commit()
    return note


# --- Incidents ----------------------------------------------------------------

INCIDENT_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.NEW: frozenset({IncidentStatus.INVESTIGATING}),
    IncidentStatus.INVESTIGATING: frozenset({IncidentStatus.CONTAINED, IncidentStatus.RESOLVED}),
    IncidentStatus.CONTAINED: frozenset({IncidentStatus.RESOLVED, IncidentStatus.INVESTIGATING}),
    IncidentStatus.RESOLVED: frozenset({IncidentStatus.INVESTIGATING}),  # reopen
}
SEVERITY_ORDER = (
    Severity.INFORMATIONAL,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)


def get_incident(session: Session, incident_id: int) -> Incident:
    incident = session.get(Incident, incident_id)
    if incident is None:
        raise AppError(404, "incident_not_found", f"No incident with ID {incident_id}.")
    return incident


def _history(incident: Incident, action: str, summary: str, author: str, **details: Any) -> None:
    incident.history.append(
        IncidentHistory(action=action, summary=summary, details=details, author=author)
    )
    incident.updated_at = utc_now()


def _load_alerts(session: Session, alert_ids: Iterable[int]) -> list[Alert]:
    alerts = []
    for alert_id in dict.fromkeys(alert_ids):  # de-duplicate, keep order
        alerts.append(get_alert(session, alert_id))
    return alerts


def _attach_alerts(incident: Incident, alerts: Sequence[Alert], author: str) -> None:
    for alert in alerts:
        if alert.incident_id is not None and alert.incident_id != incident.id:
            raise AppError(
                409,
                "alert_in_other_incident",
                f"Alert {alert.id} already belongs to incident {alert.incident_id}.",
            )
    for alert in alerts:
        if alert in incident.alerts:
            continue
        incident.alerts.append(alert)
        # Linking an untriaged alert to an incident means it is being investigated.
        if alert.status in (AlertStatus.NEW, AlertStatus.ACKNOWLEDGED):
            _record_alert_status(
                alert, AlertStatus.INVESTIGATING, f"Linked to incident #{incident.id}.", author
            )
        _history(
            incident,
            "alert_added",
            f"Alert #{alert.id} ({alert.rule_id}) linked: {alert.title}",
            author,
            alert_id=alert.id,
        )


def create_incident(
    session: Session,
    *,
    title: str,
    description: str,
    severity: Severity | None,
    alert_ids: Sequence[int],
    author: str,
) -> Incident:
    alerts = _load_alerts(session, alert_ids)
    if severity is None:
        # Default to the most severe linked alert; medium for an empty incident.
        severity = max(
            (a.severity for a in alerts), key=SEVERITY_ORDER.index, default=Severity.MEDIUM
        )
    incident = Incident(title=title, description=description, severity=severity)
    session.add(incident)
    session.flush()  # assigns incident.id for the history messages below
    _history(incident, "created", f"Incident created: {title}", author)
    _attach_alerts(incident, alerts, author)
    session.commit()
    return incident


def update_incident(
    session: Session,
    incident: Incident,
    *,
    changes: dict[str, Any],
    author: str,
) -> Incident:
    title, description = changes.get("title"), changes.get("description")
    if title is not None and title != incident.title:
        _history(incident, "title_changed", "Title updated", author, old=incident.title, new=title)
        incident.title = title
    if description is not None and description != incident.description:
        _history(incident, "description_changed", "Description updated", author)
        incident.description = description
    severity = changes.get("severity")
    if severity is not None and severity != incident.severity:
        _history(
            incident,
            "severity_changed",
            f"Severity {incident.severity.value} -> {severity.value}",
            author,
            old=incident.severity.value,
            new=severity.value,
        )
        incident.severity = severity
    status = changes.get("status")
    if status is not None and status != incident.status:
        _change_incident_status(incident, status, author)
    session.commit()
    return incident


def _change_incident_status(incident: Incident, to_status: IncidentStatus, author: str) -> None:
    if to_status not in INCIDENT_TRANSITIONS[incident.status]:
        allowed = ", ".join(sorted(s.value for s in INCIDENT_TRANSITIONS[incident.status]))
        raise AppError(
            409,
            "invalid_transition",
            f"An incident cannot go from {incident.status.value} to {to_status.value}. "
            f"Allowed: {allowed}.",
        )
    if to_status == IncidentStatus.RESOLVED:
        missing = [
            name
            for name, value in (
                ("verdict", incident.verdict),
                ("final_assessment", incident.final_assessment),
                ("resolution_summary", incident.resolution_summary),
            )
            if not value
        ]
        if missing:
            raise AppError(
                409,
                "assessment_required",
                "Record the final assessment before resolving. Missing: " + ", ".join(missing),
            )
        incident.resolved_at = utc_now()
    elif incident.status == IncidentStatus.RESOLVED:
        incident.resolved_at = None  # reopened
    _history(
        incident,
        "status_changed",
        f"Status {incident.status.value} -> {to_status.value}",
        author,
        old=incident.status.value,
        new=to_status.value,
    )
    incident.status = to_status


def add_alerts(
    session: Session, incident: Incident, alert_ids: Sequence[int], author: str
) -> Incident:
    _attach_alerts(incident, _load_alerts(session, alert_ids), author)
    session.commit()
    return incident


def remove_alert(session: Session, incident: Incident, alert_id: int, author: str) -> Incident:
    alert = get_alert(session, alert_id)
    if alert.incident_id != incident.id:
        raise AppError(404, "alert_not_linked", f"Alert {alert_id} is not part of this incident.")
    incident.alerts.remove(alert)
    _history(incident, "alert_removed", f"Alert #{alert.id} unlinked", author, alert_id=alert.id)
    session.commit()
    return incident


def add_evidence(
    session: Session, incident: Incident, event_id: str, note: str, author: str
) -> IncidentEvidence:
    event = session.scalar(select(Event).where(Event.event_id == event_id))
    if event is None:
        raise AppError(404, "event_not_found", f"No event with ID {event_id!r}.")
    if any(item.event_id == event.id for item in incident.evidence):
        raise AppError(409, "evidence_exists", "This event is already recorded as evidence.")
    evidence = IncidentEvidence(event=event, note=note, author=author)
    incident.evidence.append(evidence)
    _history(
        incident, "evidence_added", f"Evidence added: {event_id}: {note}", author,
        event_id=event_id,
    )  # fmt: skip
    session.commit()
    return evidence


def remove_evidence(
    session: Session, incident: Incident, evidence_id: int, author: str
) -> Incident:
    evidence = next((e for e in incident.evidence if e.id == evidence_id), None)
    if evidence is None:
        raise AppError(404, "evidence_not_found", f"No evidence item {evidence_id}.")
    incident.evidence.remove(evidence)
    _history(
        incident, "evidence_removed", f"Evidence removed: {evidence.event.event_id}", author,
        event_id=evidence.event.event_id,
    )  # fmt: skip
    session.commit()
    return incident


def add_incident_note(
    session: Session, incident: Incident, kind: NoteKind, body: str, author: str
) -> IncidentNote:
    note = IncidentNote(kind=kind, body=body, author=author)
    incident.notes.append(note)
    label = "Hypothesis recorded (unverified)" if kind == NoteKind.HYPOTHESIS else "Note added"
    _history(incident, "note_added", label, author, kind=kind.value)
    session.commit()
    return note


def record_assessment(
    session: Session,
    incident: Incident,
    *,
    verdict: AssessmentVerdict,
    final_assessment: str,
    resolution_summary: str,
    author: str,
) -> Incident:
    incident.verdict = verdict
    incident.final_assessment = final_assessment
    incident.resolution_summary = resolution_summary
    _history(
        incident,
        "assessment_recorded",
        f"Final assessment recorded: {verdict.value}",
        author,
        verdict=verdict.value,
    )
    session.commit()
    return incident
