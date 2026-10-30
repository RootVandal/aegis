"""Store parsed records as events and account for every one of them.

Each call creates one IngestionBatch. Every received record ends up in
exactly one bucket (accepted, duplicate or rejected), so
``received == accepted + duplicate + rejected`` always holds and nothing
is dropped silently.
"""

from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utc_now
from app.ingestion.normalizer import NormalizedEvent, RecordError, normalize_record
from app.ingestion.parser import InputFormat, ParsedRecord
from app.models import Event, IngestionBatch
from app.models.enums import DataOrigin, IngestionStatus

# Rejection messages returned to the client are capped; the counts are not.
MAX_REPORTED_ERRORS = 100
# SQLite limits the number of bound parameters per statement.
_ID_LOOKUP_CHUNK = 500


@dataclass(frozen=True)
class RecordRejection:
    position: int
    message: str


@dataclass
class IngestionResult:
    batch: IngestionBatch
    rejections: list[RecordRejection] = field(default_factory=list)


def ingest_records(
    session: Session,
    parsed: list[ParsedRecord],
    *,
    source_name: str,
    input_format: InputFormat,
    data_origin: DataOrigin,
) -> IngestionResult:
    batch = IngestionBatch(
        source_name=source_name,
        input_format=input_format.value,
        data_origin=data_origin,
        status=IngestionStatus.FAILED,
        started_at=utc_now(),
        received_count=len(parsed),
    )
    session.add(batch)

    rejections: list[RecordRejection] = []
    candidates: list[NormalizedEvent] = []
    for item in parsed:
        if item.error is not None or item.record is None:
            rejections.append(RecordRejection(item.position, item.error or "Empty record."))
            continue
        try:
            candidates.append(normalize_record(item.record))
        except RecordError as exc:
            rejections.append(RecordRejection(item.position, str(exc)))

    already_stored = _existing_ids(session, [c.event_id for c in candidates])
    seen_in_batch: set[str] = set()
    duplicates = 0
    for candidate in candidates:
        if candidate.event_id in already_stored or candidate.event_id in seen_in_batch:
            duplicates += 1
            continue
        seen_in_batch.add(candidate.event_id)
        session.add(_to_model(candidate, data_origin, batch))

    batch.accepted_count = len(seen_in_batch)
    batch.duplicate_count = duplicates
    batch.rejected_count = len(rejections)
    batch.status = _status(batch)
    batch.completed_at = utc_now()

    session.commit()
    return IngestionResult(batch=batch, rejections=rejections[:MAX_REPORTED_ERRORS])


def _existing_ids(session: Session, event_ids: list[str]) -> set[str]:
    found: set[str] = set()
    unique_ids = list(dict.fromkeys(event_ids))
    for start in range(0, len(unique_ids), _ID_LOOKUP_CHUNK):
        chunk = unique_ids[start : start + _ID_LOOKUP_CHUNK]
        found.update(session.scalars(select(Event.event_id).where(Event.event_id.in_(chunk))))
    return found


def _status(batch: IngestionBatch) -> IngestionStatus:
    if batch.rejected_count == 0:
        return IngestionStatus.COMPLETED
    if batch.accepted_count + batch.duplicate_count > 0:
        return IngestionStatus.PARTIAL
    return IngestionStatus.FAILED


def _to_model(event: NormalizedEvent, origin: DataOrigin, batch: IngestionBatch) -> Event:
    return Event(
        event_id=event.event_id,
        timestamp=event.timestamp,
        event_source=event.event_source,
        event_type=event.event_type,
        severity=event.severity,
        hostname=event.hostname,
        username=event.username,
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        destination_port=event.destination_port,
        process_name=event.process_name,
        parent_process_name=event.parent_process_name,
        process_command_line=event.process_command_line,
        windows_event_id=event.windows_event_id,
        scenario_id=event.scenario_id,
        raw_event=event.raw_event,
        normalized_fields=event.normalized_fields,
        data_origin=origin,
        batch=batch,
    )
