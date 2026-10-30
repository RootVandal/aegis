from datetime import UTC, datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.orm import Session

from app.models import Event, IngestionBatch
from app.models.enums import DataOrigin, IngestionStatus


def _event(**overrides: object) -> Event:
    fields: dict[str, object] = {
        "event_id": "evt-1",
        "timestamp": datetime(2026, 3, 1, 12, 0, tzinfo=UTC),
        "event_source": "test",
        "event_type": "process_creation",
        "raw_event": {"original": True},
        "data_origin": DataOrigin.SYNTHETIC,
    }
    fields.update(overrides)
    return Event(**fields)


def test_timestamps_are_converted_to_utc_and_read_back_aware(db_session: Session) -> None:
    plus_three = timezone(timedelta(hours=3))
    db_session.add(_event(timestamp=datetime(2026, 3, 1, 15, 0, tzinfo=plus_three)))
    db_session.commit()
    db_session.expire_all()

    stored = db_session.scalars(select(Event)).one()

    assert stored.timestamp == datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
    assert stored.timestamp.tzinfo is UTC


def test_naive_timestamps_are_rejected(db_session: Session) -> None:
    db_session.add(_event(timestamp=datetime(2026, 3, 1, 12, 0)))

    with pytest.raises(StatementError, match="Naive datetimes are not allowed"):
        db_session.commit()


def test_event_id_is_unique(db_session: Session) -> None:
    db_session.add(_event(event_id="dup"))
    db_session.commit()
    db_session.add(_event(event_id="dup"))

    with pytest.raises(IntegrityError):
        db_session.commit()


def test_invalid_severity_is_rejected_by_database_constraint(db_session: Session) -> None:
    # Bypass the ORM to prove the CHECK constraint itself protects the column.
    with pytest.raises(IntegrityError):
        db_session.execute(
            text(
                "INSERT INTO events (event_id, timestamp, ingested_at, event_source, event_type,"
                " severity, raw_event, normalized_fields, data_origin)"
                " VALUES ('x', '2026-01-01', '2026-01-01', 's', 't', 'apocalyptic',"
                " '{}', '{}', 'synthetic')"
            )
        )


def test_deleting_a_batch_keeps_its_events(db_session: Session) -> None:
    batch = IngestionBatch(
        source_name="sample",
        input_format="jsonl",
        data_origin=DataOrigin.SYNTHETIC,
        status=IngestionStatus.COMPLETED,
    )
    db_session.add(_event(batch=batch))
    db_session.commit()

    db_session.execute(text("DELETE FROM ingestion_batches"))
    db_session.commit()
    db_session.expire_all()

    # Evidence must survive bookkeeping changes: the event stays, unlinked.
    stored = db_session.scalars(select(Event)).one()
    assert stored.batch_id is None
    assert stored.raw_event == {"original": True}
