from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.errors import AppError
from app.db.session import get_db
from app.schemas.events import EventDetail, EventFacets, EventFilters, EventPage, EventSummary
from app.services.event_query import event_facets, get_event, search_events

router = APIRouter(prefix="/events", tags=["events"])


@router.get("", response_model=EventPage, summary="Search and filter events")
def list_events(
    filters: Annotated[EventFilters, Query()],
    db: Annotated[Session, Depends(get_db)],
) -> EventPage:
    """Paginated event search. All filters are combined with AND; repeat
    ``event_type`` or ``severity`` to match any of several values."""
    events, total = search_events(db, filters)
    return EventPage(
        items=[EventSummary.model_validate(event) for event in events],
        total=total,
        page=filters.page,
        page_size=filters.page_size,
    )


@router.get("/facets", response_model=EventFacets, summary="Distinct values for filters")
def facets(db: Annotated[Session, Depends(get_db)]) -> EventFacets:
    return event_facets(db)


@router.get("/{event_id}", response_model=EventDetail, summary="Event details")
def event_detail(event_id: str, db: Annotated[Session, Depends(get_db)]) -> EventDetail:
    """Normalized fields plus the original record exactly as it was ingested."""
    event = get_event(db, event_id)
    if event is None:
        raise AppError(404, "event_not_found", f"No event with ID {event_id!r}.")
    return EventDetail.model_validate(event)
