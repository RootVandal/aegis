"""Overview dashboard: every number is a query over stored data.

Two kinds of metrics, kept apart on purpose:

* **Current state** (open alerts, open incidents, totals) ignores the time
  range: it answers "what needs attention now?".
* **In range** (events, alerts raised, severity mix, top rules, events over
  time) uses the selected window, anchored to the real current time.

The range is never shifted to wherever the data happens to be. If the newest
event is three weeks old, "last 7 days" is honestly empty, and the response
says how old the data is so the UI can explain why.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from sqlalchemy import ColumnElement, func, select
from sqlalchemy.orm import Session

from app.db.base import utc_now
from app.models import Alert, DetectionRun, Event, Incident, IngestionBatch
from app.models.enums import AlertStatus, DataOrigin, IncidentStatus

Range = Literal["24h", "7d", "30d", "all"]
RANGE_LENGTH: dict[str, timedelta] = {
    "24h": timedelta(hours=1 * 24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}
OPEN_ALERT_STATUSES = (AlertStatus.NEW, AlertStatus.ACKNOWLEDGED, AlertStatus.INVESTIGATING)

Bucket = Literal["hour", "day", "month"]
# SQLite strftime formats; buckets are computed in the database.
BUCKET_FORMAT: dict[Bucket, str] = {
    "hour": "%Y-%m-%dT%H:00:00",
    "day": "%Y-%m-%dT00:00:00",
    "month": "%Y-%m-01T00:00:00",
}


@dataclass(frozen=True)
class Window:
    start: datetime | None
    end: datetime


def window_for(selected: Range, now: datetime) -> Window:
    if selected == "all":
        return Window(None, now)
    return Window(now - RANGE_LENGTH[selected], now)


def choose_bucket(first: datetime, last: datetime) -> Bucket:
    span = last - first
    if span <= timedelta(days=2):
        return "hour"
    if span <= timedelta(days=120):
        return "day"
    return "month"


def _floor(moment: datetime, bucket: Bucket) -> datetime:
    if bucket == "hour":
        return moment.replace(minute=0, second=0, microsecond=0)
    if bucket == "day":
        return moment.replace(hour=0, minute=0, second=0, microsecond=0)
    return moment.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _step(moment: datetime, bucket: Bucket) -> datetime:
    if bucket == "hour":
        return moment + timedelta(hours=1)
    if bucket == "day":
        return moment + timedelta(days=1)
    return (moment.replace(day=28) + timedelta(days=4)).replace(day=1)


def events_over_time(
    session: Session, conditions: list[ColumnElement[bool]], window: Window
) -> dict[str, Any]:
    bounds = session.execute(
        select(func.min(Event.timestamp), func.max(Event.timestamp)).where(*conditions)
    ).one()
    if bounds[0] is None:
        return {"bucket": "day", "points": []}
    # Defensive: normalize to aware UTC whatever form the driver returns.
    first, last = (_as_utc(value) for value in bounds)
    if window.start is not None:
        first = window.start
        last = window.end
    bucket = choose_bucket(first, last)

    label = func.strftime(BUCKET_FORMAT[bucket], Event.timestamp)
    rows = session.execute(
        select(label, Event.data_origin, func.count())
        .where(*conditions)
        .group_by(label, Event.data_origin)
    )
    counts: dict[str, dict[str, int]] = {}
    for bucket_start, origin, count in rows:
        counts.setdefault(bucket_start, {})[DataOrigin(origin).value] = count

    # Emit every bucket in the span, including empty ones, so the chart's time
    # axis is continuous and a gap really means "no events".
    points: list[dict[str, Any]] = []
    cursor = _floor(first, bucket)
    while cursor <= last and len(points) < 2000:
        key = cursor.strftime(BUCKET_FORMAT[bucket])
        found = counts.get(key, {})
        points.append(
            {
                "start": cursor,
                "synthetic": found.get("synthetic", 0),
                "imported": found.get("imported", 0),
            }
        )
        cursor = _step(cursor, bucket)
    return {"bucket": bucket, "points": points}


def _as_utc(value: datetime | str) -> datetime:
    parsed = datetime.fromisoformat(value) if isinstance(value, str) else value
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def build_dashboard(session: Session, selected: Range) -> dict[str, Any]:
    now = utc_now()
    window = window_for(selected, now)

    event_in_range: list[ColumnElement[bool]] = [Event.timestamp <= window.end]
    alert_in_range: list[ColumnElement[bool]] = [Alert.last_seen <= window.end]
    if window.start is not None:
        event_in_range.append(Event.timestamp >= window.start)
        alert_in_range.append(Alert.last_seen >= window.start)

    def count(model: Any, *where: ColumnElement[bool]) -> int:
        return session.scalar(select(func.count()).select_from(model).where(*where)) or 0

    by_origin = dict(
        session.execute(select(Event.data_origin, func.count()).group_by(Event.data_origin)).all()
    )
    latest = session.scalar(select(func.max(Event.timestamp)))
    earliest = session.scalar(select(func.min(Event.timestamp)))

    severity_rows = session.execute(
        select(Alert.severity, func.count()).where(*alert_in_range).group_by(Alert.severity)
    ).all()
    top_rules = session.execute(
        select(Alert.rule_id, func.count().label("n"))
        .where(*alert_in_range)
        .group_by(Alert.rule_id)
        .order_by(func.count().desc(), Alert.rule_id)
        .limit(8)
    ).all()

    return {
        "range": selected,
        "start": window.start,
        "end": window.end,
        "generated_at": now,
        "data": {
            "events_total": sum(by_origin.values()),
            "synthetic_events": by_origin.get(DataOrigin.SYNTHETIC, 0),
            "imported_events": by_origin.get(DataOrigin.IMPORTED, 0),
            "earliest_event_at": _as_utc(earliest) if earliest else None,
            "latest_event_at": _as_utc(latest) if latest else None,
        },
        "current": {
            "alerts_new": count(Alert, Alert.status == AlertStatus.NEW),
            "alerts_open": count(Alert, Alert.status.in_(OPEN_ALERT_STATUSES)),
            "incidents_open": count(Incident, Incident.status != IncidentStatus.RESOLVED),
        },
        "in_range": {
            "events": count(Event, *event_in_range),
            "alerts": count(Alert, *alert_in_range),
            "alert_severity": {sev.value: n for sev, n in severity_rows},
            "top_rules": [{"rule_id": rule_id, "count": n} for rule_id, n in top_rules],
            "events_over_time": events_over_time(session, event_in_range, window),
        },
        "recent_alerts": list(
            session.scalars(
                select(Alert).order_by(Alert.created_at.desc(), Alert.id.desc()).limit(6)
            )
        ),
        "recent_incidents": list(
            session.scalars(
                select(Incident).order_by(Incident.updated_at.desc(), Incident.id.desc()).limit(5)
            )
        ),
        "recent_batches": list(
            session.scalars(select(IngestionBatch).order_by(IngestionBatch.id.desc()).limit(5))
        ),
        "last_detection_run": session.scalar(
            select(DetectionRun).order_by(DetectionRun.id.desc()).limit(1)
        ),
    }
