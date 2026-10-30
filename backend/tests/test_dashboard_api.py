from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.sample_data.detection_lab import EXPECTED_FINDINGS
from app.services.dashboard import choose_bucket
from tests.conftest import event, ingest_jsonl


def get(client: TestClient, range_: str = "all") -> dict[str, Any]:
    response = client.get("/api/v1/dashboard", params={"range": range_})
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def iso(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


def test_empty_database_reports_zeros_not_placeholders(client: TestClient) -> None:
    body = get(client)

    assert body["data"]["events_total"] == 0
    assert body["data"]["latest_event_at"] is None
    assert body["current"] == {"alerts_new": 0, "alerts_open": 0, "incidents_open": 0}
    assert body["in_range"]["events"] == 0
    assert body["in_range"]["events_over_time"]["points"] == []
    assert body["recent_alerts"] == body["recent_incidents"] == body["recent_batches"] == []
    assert body["last_detection_run"] is None


def test_figures_match_the_stored_data(client: TestClient) -> None:
    client.post("/api/v1/datasets/baseline/load")
    client.post("/api/v1/datasets/detection-lab/load")
    expected_alerts = sum(len(found) for found in EXPECTED_FINDINGS.values())
    events_total = client.get("/api/v1/events").json()["total"]

    body = get(client)

    assert body["data"]["events_total"] == body["data"]["synthetic_events"] == events_total
    assert body["data"]["imported_events"] == 0
    assert body["current"]["alerts_new"] == body["current"]["alerts_open"] == expected_alerts
    assert body["in_range"]["alerts"] == expected_alerts
    assert sum(body["in_range"]["alert_severity"].values()) == expected_alerts
    top = body["in_range"]["top_rules"][0]
    assert (top["rule_id"], top["count"], top["name"]) == (
        "AEGIS-PERS-001",
        4,
        "Persistence Mechanism Changes",
    )
    assert body["last_detection_run"]["trigger"] == "ingestion"
    assert len(body["recent_batches"]) == 2


def test_events_over_time_is_continuous_and_sums_to_the_total(client: TestClient) -> None:
    client.post("/api/v1/datasets/baseline/load")  # 2026-10-05 .. 2026-10-07

    series = get(client)["in_range"]["events_over_time"]

    assert series["bucket"] == "day"
    days = [p["start"][:10] for p in series["points"]]
    assert days == ["2026-10-05", "2026-10-06", "2026-10-07"]
    assert sum(p["synthetic"] + p["imported"] for p in series["points"]) == 203


def test_ranges_are_anchored_to_now(client: TestClient) -> None:
    now = datetime.now(UTC)
    ingest_jsonl(
        client,
        [
            event(event_id="recent", timestamp=iso(now - timedelta(hours=1))),
            event(event_id="older", timestamp=iso(now - timedelta(days=3))),
            event(event_id="old", timestamp=iso(now - timedelta(days=20))),
        ],
    )

    counts = {r: get(client, r)["in_range"]["events"] for r in ("24h", "7d", "30d", "all")}

    assert counts == {"24h": 1, "7d": 2, "30d": 3, "all": 3}


def test_last_24_hours_are_bucketed_by_hour_with_empty_hours(client: TestClient) -> None:
    now = datetime.now(UTC)
    ingest_jsonl(client, [event(event_id="x", timestamp=iso(now - timedelta(hours=2)))])

    series = get(client, "24h")["in_range"]["events_over_time"]

    assert series["bucket"] == "hour"
    assert len(series["points"]) in (24, 25)  # depends on where "now" falls within the hour
    assert sum(p["imported"] for p in series["points"]) == 1
    assert sum(1 for p in series["points"] if p["imported"] == 0) >= 23


def test_current_state_ignores_the_range(client: TestClient) -> None:
    client.post("/api/v1/datasets/detection-lab/load")  # October 2026 data
    alert_id = client.get("/api/v1/alerts").json()["items"][0]["id"]
    client.post("/api/v1/incidents", json={"title": "Open case", "alert_ids": [alert_id]})

    all_time, last_day = get(client, "all"), get(client, "24h")

    assert all_time["current"] == last_day["current"]
    assert all_time["current"]["incidents_open"] == 1
    assert all_time["current"]["alerts_open"] == all_time["current"]["alerts_new"] + 1


def test_imported_and_synthetic_are_counted_separately(client: TestClient) -> None:
    client.post("/api/v1/datasets/baseline/load")
    ingest_jsonl(client, [event(event_id="mine")])

    data = get(client)["data"]

    assert (data["synthetic_events"], data["imported_events"]) == (203, 1)


def test_invalid_range_is_rejected(client: TestClient) -> None:
    assert client.get("/api/v1/dashboard", params={"range": "1y"}).status_code == 422


@pytest.mark.parametrize(
    ("span", "bucket"),
    [(timedelta(hours=30), "hour"), (timedelta(days=10), "day"), (timedelta(days=400), "month")],
)
def test_bucket_size_follows_the_span(span: timedelta, bucket: str) -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    assert choose_bucket(start, start + span) == bucket


def test_event_detail_links_to_citing_alerts(client: TestClient) -> None:
    client.post("/api/v1/datasets/detection-lab/load")

    cited = client.get("/api/v1/events/syn-lab-001").json()["alerts"]
    lookalike = client.get("/api/v1/events/syn-lab-039").json()["alerts"]

    assert [a["rule_id"] for a in cited] == ["AEGIS-AUTH-001"]
    assert lookalike == []
