from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app import __version__
from app.main import create_app
from app.models import Event, IngestionBatch
from app.models.enums import DataOrigin, IngestionStatus
from app.services.health import expected_schema_revision
from tests.conftest import make_settings


def test_liveness_does_not_need_database(client: TestClient) -> None:
    response = client.get("/api/v1/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_reports_ok_on_migrated_empty_database(client: TestClient) -> None:
    body = client.get("/api/v1/health").json()

    assert body["status"] == "ok"
    assert body["version"] == __version__
    assert body["environment"] == "test"
    assert body["database"]["status"] == "ok"
    assert body["database"]["schema_revision"] == expected_schema_revision()
    assert body["data"] == {
        "event_count": 0,
        "ingestion_batch_count": 0,
        "latest_event_at": None,
        "last_ingestion_at": None,
    }


def test_health_counts_reflect_stored_rows(client: TestClient, db_session: Session) -> None:
    finished = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    event_time = datetime(2026, 1, 2, 3, 0, 0, tzinfo=UTC)
    batch = IngestionBatch(
        source_name="unit-test",
        input_format="jsonl",
        data_origin=DataOrigin.SYNTHETIC,
        status=IngestionStatus.COMPLETED,
        completed_at=finished,
    )
    db_session.add(batch)
    db_session.add(
        Event(
            event_id="evt-1",
            timestamp=event_time,
            event_source="test",
            event_type="authentication_failure",
            raw_event={"id": "evt-1"},
            data_origin=DataOrigin.SYNTHETIC,
            batch=batch,
        )
    )
    db_session.commit()

    data = client.get("/api/v1/health").json()["data"]

    assert data["event_count"] == 1
    assert data["ingestion_batch_count"] == 1
    assert datetime.fromisoformat(data["latest_event_at"]) == event_time
    assert datetime.fromisoformat(data["last_ingestion_at"]) == finished


def test_health_is_degraded_when_migrations_not_applied(database_url: str) -> None:
    # `database_url` is an empty SQLite file: reachable, but no schema.
    with TestClient(create_app(make_settings(database_url))) as client:
        body = client.get("/api/v1/health").json()

    assert body["status"] == "degraded"
    assert body["database"]["schema_revision"] is None
    assert "alembic upgrade head" in body["database"]["message"]
    # Counts are unknown, so they are omitted rather than reported as zero.
    assert body["data"] is None


def test_responses_carry_security_headers(client: TestClient) -> None:
    headers = client.get("/api/v1/health/live").headers

    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"


def test_cors_allows_only_configured_origins(client: TestClient) -> None:
    allowed = client.get("/api/v1/health/live", headers={"Origin": "http://localhost:5173"})
    denied = client.get("/api/v1/health/live", headers={"Origin": "https://evil.example"})

    assert allowed.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert "access-control-allow-origin" not in denied.headers
