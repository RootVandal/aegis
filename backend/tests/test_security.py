"""Hardening added during the Milestone 8 security review."""

import json
from collections.abc import Iterator

from fastapi.testclient import TestClient


def test_oversized_json_body_is_refused_outside_ingestion(client: TestClient) -> None:
    body = json.dumps({"body": "x" * (1024 * 1024 + 10)})

    response = client.post(
        "/api/v1/alerts/1/notes", content=body, headers={"Content-Type": "application/json"}
    )

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "payload_too_large"


def test_body_limit_counts_streamed_bytes_without_content_length(client: TestClient) -> None:
    def chunks() -> Iterator[bytes]:
        for _ in range(20):
            yield b"x" * 65536

    response = client.post(
        "/api/v1/incidents", content=chunks(), headers={"Content-Type": "application/json"}
    )

    assert response.status_code == 413


def test_ingestion_keeps_its_own_larger_limit(client: TestClient) -> None:
    lines = "\n".join(
        json.dumps(
            {
                "event_id": f"e{i}",
                "timestamp": "2026-01-01T00:00:00Z",
                "event_source": "t",
                "event_type": "t",
                "pad": "x" * 2000,
            }
        )
        for i in range(600)
    )
    assert len(lines) > 1024 * 1024

    response = client.post(
        "/api/v1/ingestion/batches",
        content=lines,
        headers={"Content-Type": "application/x-ndjson"},
    )

    assert response.status_code == 201


def test_small_bodies_still_work(client: TestClient) -> None:
    response = client.post("/api/v1/incidents", json={"title": "ok"})

    assert response.status_code == 201


def test_api_responses_forbid_rendering(client: TestClient) -> None:
    api = client.get("/api/v1/health/live")
    docs = client.get("/docs")

    assert api.headers["Content-Security-Policy"] == "default-src 'none'; frame-ancestors 'none'"
    assert "Content-Security-Policy" not in docs.headers


def test_cors_preflight_allows_every_method_the_api_uses(client: TestClient) -> None:
    for method in ("POST", "PATCH", "PUT", "DELETE"):
        response = client.options(
            "/api/v1/incidents/1/assessment",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": method,
                "Access-Control-Request-Headers": "Content-Type",
            },
        )
        assert response.status_code == 200, method


def test_settings_view_exposes_no_paths_or_secrets(client: TestClient) -> None:
    body = client.get("/api/v1/settings").json()

    assert body["database"] == "sqlite (aegis-test.db)"
    assert body["rule_count"] == 8
    assert body["authentication"].startswith("none")
