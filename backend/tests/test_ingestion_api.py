import json
from collections.abc import Iterator

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.main import create_app
from app.models import Event
from tests.conftest import event, ingest_jsonl, make_settings


def test_jsonl_upload_stores_events(client: TestClient, db_session: Session) -> None:
    response = ingest_jsonl(
        client,
        [event(event_id="e1", hostname="WS-01"), event(event_id="e2")],
        source_name="lab.jsonl",
    )

    assert response.status_code == 201
    batch = response.json()["batch"]
    assert batch["status"] == "completed"
    assert batch["source_name"] == "lab.jsonl"
    assert batch["data_origin"] == "imported"
    assert (batch["received_count"], batch["accepted_count"]) == (2, 2)

    stored = db_session.scalars(select(Event).order_by(Event.event_id)).all()
    assert [e.event_id for e in stored] == ["e1", "e2"]
    assert stored[0].hostname == "ws-01"
    assert stored[0].raw_event["hostname"] == "WS-01"  # original kept verbatim
    assert stored[0].batch_id == batch["id"]


def test_json_array_upload(client: TestClient) -> None:
    response = client.post(
        "/api/v1/ingestion/batches",
        content=json.dumps([event(event_id="a"), event(event_id="b")]),
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 201
    assert response.json()["batch"]["accepted_count"] == 2


def test_reingesting_the_same_events_creates_no_duplicates(
    client: TestClient, db_session: Session
) -> None:
    records = [event(event_id="dup-1"), event(hostname="no-id-host")]
    ingest_jsonl(client, records)

    second = ingest_jsonl(client, records).json()["batch"]

    assert (second["accepted_count"], second["duplicate_count"]) == (0, 2)
    assert second["status"] == "completed"
    assert len(db_session.scalars(select(Event)).all()) == 2


def test_duplicates_inside_one_upload_are_counted(client: TestClient) -> None:
    batch = ingest_jsonl(client, [event(event_id="x"), event(event_id="x")]).json()["batch"]

    assert (batch["accepted_count"], batch["duplicate_count"]) == (1, 1)


def test_partial_upload_reports_rejections_by_line(client: TestClient) -> None:
    body = "\n".join(
        [
            json.dumps(event(event_id="good")),
            "{not json",
            json.dumps(event(source_ip="not-an-ip")),
        ]
    )
    response = client.post(
        "/api/v1/ingestion/batches",
        content=body,
        headers={"Content-Type": "application/x-ndjson"},
    )

    payload = response.json()
    assert payload["batch"]["status"] == "partial"
    assert (payload["batch"]["accepted_count"], payload["batch"]["rejected_count"]) == (1, 2)
    assert [r["position"] for r in payload["rejections"]] == [2, 3]
    assert "source_ip" in payload["rejections"][1]["message"]


def test_counts_always_add_up(client: TestClient) -> None:
    ingest_jsonl(client, [event(event_id="seen")])
    body = "\n".join([json.dumps(event(event_id="seen")), json.dumps(event(event_id="new")), "]"])

    batch = client.post(
        "/api/v1/ingestion/batches",
        content=body,
        headers={"Content-Type": "application/x-ndjson"},
    ).json()["batch"]

    assert batch["received_count"] == 3
    assert batch["received_count"] == (
        batch["accepted_count"] + batch["duplicate_count"] + batch["rejected_count"]
    )


def test_fully_invalid_upload_is_recorded_as_failed(client: TestClient) -> None:
    response = client.post(
        "/api/v1/ingestion/batches",
        content="oops\nstill oops",
        headers={"Content-Type": "application/x-ndjson"},
    )

    assert response.status_code == 201
    assert response.json()["batch"]["status"] == "failed"
    history = client.get("/api/v1/ingestion/batches").json()
    assert history[0]["status"] == "failed"


def test_empty_body_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/api/v1/ingestion/batches",
        content="\n\n",
        headers={"Content-Type": "application/x-ndjson"},
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "empty_body"


def test_unsupported_content_type_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/api/v1/ingestion/batches", content="a,b,c", headers={"Content-Type": "text/csv"}
    )

    assert response.status_code == 415


def test_invalid_utf8_body_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/api/v1/ingestion/batches",
        content=b'{"a": "\xff"}',
        headers={"Content-Type": "application/x-ndjson"},
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_body"


def test_body_size_limit_is_enforced(migrated_database_url: str) -> None:
    app = create_app(make_settings(migrated_database_url, max_ingest_bytes=200))
    body = "\n".join(json.dumps(event(event_id=f"e{i}")) for i in range(10))

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/ingestion/batches",
            content=body,
            headers={"Content-Type": "application/x-ndjson"},
        )

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "payload_too_large"


def test_body_limit_is_enforced_even_without_content_length(migrated_database_url: str) -> None:
    app = create_app(make_settings(migrated_database_url, max_ingest_bytes=200))

    def chunks() -> Iterator[bytes]:
        for i in range(10):
            yield (json.dumps(event(event_id=f"e{i}")) + "\n").encode()

    with TestClient(app) as client:
        # A generator body is sent with chunked transfer encoding (no Content-Length).
        response = client.post(
            "/api/v1/ingestion/batches",
            content=chunks(),
            headers={"Content-Type": "application/x-ndjson"},
        )

    assert response.status_code == 413


def test_record_count_limit_is_enforced(migrated_database_url: str) -> None:
    app = create_app(make_settings(migrated_database_url, max_ingest_records=2))

    with TestClient(app) as client:
        response = ingest_jsonl(client, [event(event_id=str(i)) for i in range(3)])

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "too_many_records"


def test_origin_label_can_be_set_explicitly(client: TestClient) -> None:
    batch = ingest_jsonl(client, [event()], data_origin="synthetic").json()["batch"]

    assert batch["data_origin"] == "synthetic"


def test_batch_history_is_newest_first(client: TestClient) -> None:
    ingest_jsonl(client, [event(event_id="1")], source_name="first")
    ingest_jsonl(client, [event(event_id="2")], source_name="second")

    history = client.get("/api/v1/ingestion/batches").json()

    assert [b["source_name"] for b in history] == ["second", "first"]
