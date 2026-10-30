"""Chronological timeline of an incident, with the reason each event is on it."""

from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.investigation.correlation import ALL_CRITERIA, Criterion, Seed, correlate, time_bounds
from app.models import Alert, Event, Incident, alert_events
from app.services.detection import to_record


@dataclass
class TimelineSource:
    kind: str  # alert | evidence | correlated
    description: str
    alert_id: int | None = None
    rule_id: str | None = None


@dataclass
class TimelineEntry:
    event: Event
    sources: list[TimelineSource] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)  # every rule that alerted on this event


def rules_by_event(session: Session, event_ids: list[int]) -> dict[int, list[tuple[int, str]]]:
    """Internal event id -> [(alert id, rule id)] for every alert that cites it."""
    if not event_ids:
        return {}
    rows = session.execute(
        select(alert_events.c.event_id, Alert.id, Alert.rule_id)
        .join(Alert, Alert.id == alert_events.c.alert_id)
        .where(alert_events.c.event_id.in_(event_ids))
        .order_by(Alert.id)
    )
    mapping: dict[int, list[tuple[int, str]]] = {}
    for event_id, alert_id, rule_id in rows:
        mapping.setdefault(event_id, []).append((alert_id, rule_id))
    return mapping


def build_timeline(
    session: Session,
    incident: Incident,
    *,
    include_correlated: bool = False,
    window: timedelta = timedelta(hours=1),
    criteria: frozenset[Criterion] = ALL_CRITERIA,
) -> list[TimelineEntry]:
    entries: dict[int, TimelineEntry] = {}

    def entry(event: Event) -> TimelineEntry:
        return entries.setdefault(event.id, TimelineEntry(event))

    for alert in sorted(incident.alerts, key=lambda a: a.id):
        for event in alert.events:
            entry(event).sources.append(
                TimelineSource(
                    "alert",
                    f"Evidence for alert #{alert.id} ({alert.rule_id}): {alert.title}",
                    alert_id=alert.id,
                    rule_id=alert.rule_id,
                )
            )
    for evidence in incident.evidence:
        entry(evidence.event).sources.append(
            TimelineSource("evidence", f"Added as evidence: {evidence.note}")
        )

    if include_correlated and entries:
        seed_records = [to_record(e.event) for e in entries.values()]
        start, end = time_bounds(Seed.from_events(seed_records), window)
        candidates = session.scalars(
            select(Event).where(Event.timestamp >= start, Event.timestamp <= end)
        ).all()
        by_record_id = {e.event_id: e for e in candidates}
        for found in correlate(
            seed_records, [to_record(e) for e in candidates], window=window, criteria=criteria
        ):
            entry(by_record_id[found.event.event_id]).sources.append(
                TimelineSource("correlated", f"Correlated: {found.explanation()}")
            )

    rules = rules_by_event(session, list(entries))
    for event_id, item in entries.items():
        item.rule_ids = sorted({rule_id for _, rule_id in rules.get(event_id, [])})

    return sorted(entries.values(), key=lambda e: (e.event.timestamp, e.event.event_id))
