from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.conftest import event, ingest_jsonl

RECORDS = [
    event(
        event_id="auth-fail-1",
        timestamp="2026-10-01T08:00:00Z",
        event_source="windows-security",
        event_type="authentication_failure",
        severity="medium",
        hostname="DC-01",
        username="CORP\\Alice",
        source_ip="10.0.0.5",
    ),
    event(
        event_id="proc-1",
        timestamp="2026-10-01T09:00:00Z",
        event_type="process_creation",
        hostname="ws-01",
        username="bob",
        process_name="C:\\Windows\\System32\\cmd.exe",
        process_command_line="cmd.exe /c echo 100%_done",
    ),
    event(
        event_id="net-1",
        timestamp="2026-10-02T10:00:00Z",
        event_type="network_connection",
        severity="high",
        hostname="ws-01",
        source_ip="10.0.0.6",
        destination_ip="203.0.113.10",
    ),
]


@pytest.fixture
def seeded(client: TestClient) -> TestClient:
    assert ingest_jsonl(client, RECORDS).json()["batch"]["accepted_count"] == 3
    return client


def ids(response: Any) -> list[str]:
    return [item["event_id"] for item in response.json()["items"]]


def test_default_listing_is_newest_first_with_total(seeded: TestClient) -> None:
    response = seeded.get("/api/v1/events")

    assert response.status_code == 200
    assert ids(response) == ["net-1", "proc-1", "auth-fail-1"]
    assert response.json()["total"] == 3


def test_sorting_ascending(seeded: TestClient) -> None:
    assert ids(seeded.get("/api/v1/events", params={"sort": "timestamp_asc"}))[0] == "auth-fail-1"


def test_pagination_is_stable_and_reports_total(seeded: TestClient) -> None:
    pages = [
        seeded.get("/api/v1/events", params={"page": page, "page_size": 2}) for page in (1, 2, 3)
    ]

    assert [ids(p) for p in pages] == [["net-1", "proc-1"], ["auth-fail-1"], []]
    assert all(p.json()["total"] == 3 for p in pages)


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ({"start": "2026-10-01T08:30:00Z"}, ["net-1", "proc-1"]),
        ({"end": "2026-10-01T09:00:00Z"}, ["auth-fail-1"]),  # end is exclusive
        # 10:00+02:00 is 08:00Z, and start is inclusive, so the 08:00Z event is included.
        (
            {"start": "2026-10-01T10:00:00+02:00", "end": "2026-10-02T00:00:00Z"},
            ["proc-1", "auth-fail-1"],
        ),
        ({"event_type": "network_connection"}, ["net-1"]),
        ({"event_type": ["network_connection", "process_creation"]}, ["net-1", "proc-1"]),
        ({"severity": "high"}, ["net-1"]),
        ({"hostname": "WS-01"}, ["net-1", "proc-1"]),
        ({"username": "alice"}, ["auth-fail-1"]),
        ({"source_ip": "10.0.0.6"}, ["net-1"]),
        ({"data_origin": "synthetic"}, []),
        ({"hostname": "ws-01", "severity": "high"}, ["net-1"]),
    ],
)
def test_filters(seeded: TestClient, params: dict[str, Any], expected: list[str]) -> None:
    assert ids(seeded.get("/api/v1/events", params=params)) == expected


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("CMD.EXE", ["proc-1"]),  # case-insensitive
        ("203.0.113", ["net-1"]),
        ("auth-fail", ["auth-fail-1"]),
        ("100%_done", ["proc-1"]),  # literal % and _
        ("%", ["proc-1"]),  # only the event that really contains "%"
        ("_", ["net-1", "proc-1", "auth-fail-1"]),  # every event_id/type has "_" or "-"...
    ],
)
def test_text_search(seeded: TestClient, query: str, expected: list[str]) -> None:
    result = ids(seeded.get("/api/v1/events", params={"q": query}))

    assert sorted(result) == sorted(expected)


def test_search_wildcards_are_literal(seeded: TestClient) -> None:
    # Regression guard: unescaped, "a_c" would match "abc" style values.
    assert ids(seeded.get("/api/v1/events", params={"q": "c_d"})) == []


@pytest.mark.parametrize(
    "params",
    [
        {"start": "2026-10-01T00:00:00"},  # no timezone
        {"start": "2026-10-02T00:00:00Z", "end": "2026-10-01T00:00:00Z"},
        {"page_size": 201},
        {"page": 0},
        {"severity": "urgent"},
        {"source_ip": "nope"},
        {"hostnme": "typo"},
    ],
)
def test_invalid_query_parameters_are_rejected(seeded: TestClient, params: dict[str, Any]) -> None:
    response = seeded.get("/api/v1/events", params=params)

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_event_detail_includes_raw_and_normalized(seeded: TestClient) -> None:
    detail = seeded.get("/api/v1/events/auth-fail-1").json()

    assert detail["username"] == "Alice"
    assert detail["hostname"] == "dc-01"
    assert detail["raw_event"]["username"] == "CORP\\Alice"
    assert detail["normalized_fields"] == {"user_domain": "CORP"}
    assert detail["data_origin"] == "imported"


def test_unknown_event_returns_404(seeded: TestClient) -> None:
    response = seeded.get("/api/v1/events/does-not-exist")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "event_not_found"


def test_facets_count_stored_values(seeded: TestClient) -> None:
    facets = seeded.get("/api/v1/events/facets").json()

    assert {"value": "process_creation", "count": 1} in facets["event_types"]
    assert facets["data_origins"] == [{"value": "imported", "count": 3}]
    assert {f["value"] for f in facets["severities"]} == {"informational", "medium", "high"}
