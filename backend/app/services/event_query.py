"""Read-side queries over stored events."""

from typing import Any

from sqlalchemy import ColumnElement, func, or_, select
from sqlalchemy.orm import Session

from app.models import Event
from app.schemas.events import EventFacets, EventFilters, FacetValue

# Columns covered by free-text search. Kept explicit so it is obvious what
# "search" means, and so raw JSON blobs are not scanned on every request.
SEARCHABLE_COLUMNS = (
    Event.event_id,
    Event.event_type,
    Event.hostname,
    Event.username,
    Event.source_ip,
    Event.destination_ip,
    Event.process_name,
    Event.parent_process_name,
    Event.process_command_line,
)


def escape_like(text: str) -> str:
    """Make user input literal inside a LIKE pattern.

    Without this, searching for "%" or "_" would act as a wildcard and match
    everything (or the wrong things).
    """
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _conditions(filters: EventFilters) -> list[ColumnElement[bool]]:
    conditions: list[ColumnElement[bool]] = []
    if filters.start:
        conditions.append(Event.timestamp >= filters.start)
    if filters.end:
        conditions.append(Event.timestamp < filters.end)
    if filters.event_type:
        conditions.append(Event.event_type.in_([t.lower() for t in filters.event_type]))
    if filters.severity:
        conditions.append(Event.severity.in_(filters.severity))
    if filters.hostname:
        conditions.append(Event.hostname == filters.hostname.lower())
    if filters.username:
        conditions.append(func.lower(Event.username) == filters.username.lower())
    if filters.source_ip:
        conditions.append(Event.source_ip == filters.source_ip)
    if filters.data_origin:
        conditions.append(Event.data_origin == filters.data_origin)
    if filters.scenario_id:
        conditions.append(Event.scenario_id == filters.scenario_id)
    if filters.q:
        # SQLite's LIKE is case-insensitive for ASCII; lower() makes the
        # behaviour explicit and portable to other databases.
        pattern = f"%{escape_like(filters.q.lower())}%"
        conditions.append(
            or_(*(func.lower(col).like(pattern, escape="\\") for col in SEARCHABLE_COLUMNS))
        )
    return conditions


def search_events(session: Session, filters: EventFilters) -> tuple[list[Event], int]:
    conditions = _conditions(filters)
    total = session.scalar(select(func.count()).select_from(Event).where(*conditions)) or 0

    if filters.sort == "timestamp_asc":
        order: tuple[Any, ...] = (Event.timestamp.asc(), Event.id.asc())
    else:
        order = (Event.timestamp.desc(), Event.id.desc())

    # Offset pagination is simple and fine at the scale AEGIS targets (tens of
    # thousands of events). The id tie-breaker keeps page boundaries stable
    # when many events share a timestamp.
    query = (
        select(Event)
        .where(*conditions)
        .order_by(*order)
        .offset((filters.page - 1) * filters.page_size)
        .limit(filters.page_size)
    )
    return list(session.scalars(query)), total


def get_event(session: Session, event_id: str) -> Event | None:
    return session.scalar(select(Event).where(Event.event_id == event_id))


def event_facets(session: Session) -> EventFacets:
    def counts(column: Any) -> list[FacetValue]:
        rows = session.execute(
            select(column, func.count())
            .where(column.is_not(None))
            .group_by(column)
            .order_by(func.count().desc(), column)
        )
        return [FacetValue(value=str(value), count=count) for value, count in rows]

    return EventFacets(
        event_types=counts(Event.event_type),
        event_sources=counts(Event.event_source),
        severities=counts(Event.severity),
        data_origins=counts(Event.data_origin),
    )
