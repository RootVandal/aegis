from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.main import create_app
from app.sample_data.detection_lab import EXPECTED_FINDINGS
from tests.conftest import event, ingest_jsonl, make_settings

EXPECTED_TOTAL = sum(len(found) for found in EXPECTED_FINDINGS.values())


def failures(n: int, user: str = "alice") -> list[dict[str, Any]]:
    return [
        event(
            event_id=f"{user}-fail-{i}",
            timestamp=f"2026-10-08T09:00:{i * 5:02d}Z",
            event_type="authentication_failure",
            username=user,
            source_ip="10.0.0.5",
        )
        for i in range(n)
    ]


# --- Rules -------------------------------------------------------------------


def test_rule_listing(client: TestClient) -> None:
    rules = client.get("/api/v1/rules").json()

    assert len(rules) == 8
    auth = next(r for r in rules if r["id"] == "AEGIS-AUTH-001")
    assert auth["enabled"] is True and auth["customized"] is False
    assert auth["mitre"][0]["id"] == "T1110.001"
    assert auth["mitre"][0]["url"] == "https://attack.mitre.org/techniques/T1110/001/"


def test_rule_detail_documents_the_rule(client: TestClient) -> None:
    detail = client.get("/api/v1/rules/AEGIS-AUTH-001").json()

    assert detail["params"] == detail["default_params"]
    assert detail["default_params"]["threshold"] == 5
    assert detail["params_schema"]["properties"]["threshold"]["minimum"] == 2
    for key in ("logic", "required_fields", "investigation_steps", "false_positives",
                "limitations", "unknowns", "changelog", "mitre_details"):  # fmt: skip
        assert detail[key], key
    assert detail["attack_version"] == "v20.0"


def test_unknown_rule_is_404(client: TestClient) -> None:
    assert client.get("/api/v1/rules/NOPE").json()["error"]["code"] == "rule_not_found"


def test_rule_parameters_can_be_changed_and_reset(client: TestClient) -> None:
    updated = client.patch("/api/v1/rules/AEGIS-AUTH-001", json={"params": {"threshold": 3}})

    assert updated.status_code == 200
    assert updated.json()["params"]["threshold"] == 3
    assert updated.json()["customized"] is True

    reset = client.patch("/api/v1/rules/AEGIS-AUTH-001", json={"params": {}}).json()
    assert reset["params"]["threshold"] == 5
    assert reset["customized"] is False


@pytest.mark.parametrize(
    "params",
    [{"threshold": 1}, {"threshold": "many"}, {"no_such_option": True}, {"group_by": "hostname"}],
)
def test_invalid_rule_parameters_are_rejected(client: TestClient, params: dict[str, Any]) -> None:
    response = client.patch("/api/v1/rules/AEGIS-AUTH-001", json={"params": params})

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_rule_params"
    # Nothing was saved.
    assert client.get("/api/v1/rules/AEGIS-AUTH-001").json()["customized"] is False


# --- Detection runs and alerts ----------------------------------------------


def test_ingestion_triggers_detection_and_creates_alerts(client: TestClient) -> None:
    response = ingest_jsonl(client, failures(5)).json()

    assert response["detection"]["trigger"] == "ingestion"
    assert response["detection"]["alerts_created"] == 1
    alerts = client.get("/api/v1/alerts").json()
    assert alerts["total"] == 1
    assert alerts["items"][0]["rule_id"] == "AEGIS-AUTH-001"
    assert alerts["items"][0]["status"] == "new"
    assert alerts["items"][0]["users"] == ["alice"]


def test_patterns_spanning_two_uploads_are_detected(client: TestClient) -> None:
    events = failures(5)
    first = ingest_jsonl(client, events[:3]).json()
    second = ingest_jsonl(client, events[3:]).json()

    assert first["detection"]["alerts_created"] == 0
    assert second["detection"]["alerts_created"] == 1


def test_rerunning_detection_does_not_duplicate_alerts(client: TestClient) -> None:
    ingest_jsonl(client, failures(5))

    run = client.post("/api/v1/detections/runs").json()

    assert (run["alerts_created"], run["alerts_existing"]) == (0, 1)
    assert client.get("/api/v1/alerts").json()["total"] == 1
    assert run["rules"][0]["version"] == 1
    assert run["trigger"] == "manual"


def test_duplicate_upload_does_not_start_detection(client: TestClient) -> None:
    ingest_jsonl(client, failures(5))
    again = ingest_jsonl(client, failures(5)).json()

    assert again["detection"] is None


def test_disabled_rule_produces_no_alerts(client: TestClient) -> None:
    client.patch("/api/v1/rules/AEGIS-AUTH-001", json={"enabled": False})

    ingest_jsonl(client, failures(5))

    assert client.get("/api/v1/alerts").json()["total"] == 0
    run = client.get("/api/v1/detections/runs").json()[0]
    assert "AEGIS-AUTH-001" not in [r["rule_id"] for r in run["rules"]]


def test_custom_threshold_is_used_and_recorded(client: TestClient) -> None:
    client.patch("/api/v1/rules/AEGIS-AUTH-001", json={"params": {"threshold": 3}})

    ingest_jsonl(client, failures(3))

    alert = client.get("/api/v1/alerts").json()["items"][0]
    detail = client.get(f"/api/v1/alerts/{alert['id']}").json()
    assert detail["rule_params"]["threshold"] == 3
    assert detail["explanation"]["rule"]["params"]["threshold"] == 3


def test_alert_detail_contains_explanation_and_evidence(client: TestClient) -> None:
    ingest_jsonl(client, failures(5))
    alert_id = client.get("/api/v1/alerts").json()["items"][0]["id"]

    detail = client.get(f"/api/v1/alerts/{alert_id}").json()

    assert [e["event_id"] for e in detail["events"]] == [f"alice-fail-{i}" for i in range(5)]
    explanation = detail["explanation"]
    for key in ("what", "triggering_events", "conditions", "evidence", "unknowns",
                "next_steps", "false_positives", "mitre", "disclaimer"):  # fmt: skip
        assert explanation[key], key


def test_alert_filters_and_404(client: TestClient) -> None:
    ingest_jsonl(client, failures(5))

    assert client.get("/api/v1/alerts", params={"severity": "high"}).json()["total"] == 0
    assert client.get("/api/v1/alerts", params={"status": "new"}).json()["total"] == 1
    assert client.get("/api/v1/alerts", params={"rule_id": "AEGIS-NET-001"}).json()["total"] == 0
    assert client.get("/api/v1/alerts", params={"status": "bogus"}).status_code == 422
    assert client.get("/api/v1/alerts/999").json()["error"]["code"] == "alert_not_found"


def test_events_referenced_by_an_alert_cannot_be_deleted(
    client: TestClient, db_session: Session
) -> None:
    ingest_jsonl(client, failures(5))

    with pytest.raises(IntegrityError):
        db_session.execute(text("DELETE FROM events WHERE event_id = 'alice-fail-0'"))
        db_session.commit()


def test_deleting_an_alert_keeps_its_events(client: TestClient, db_session: Session) -> None:
    ingest_jsonl(client, failures(5))

    db_session.execute(text("DELETE FROM alerts"))
    db_session.commit()

    assert db_session.execute(text("SELECT COUNT(*) FROM events")).scalar() == 5
    assert db_session.execute(text("SELECT COUNT(*) FROM alert_events")).scalar() == 0


def test_loading_the_detection_lab_creates_the_labeled_alerts(client: TestClient) -> None:
    response = client.post("/api/v1/datasets/detection-lab/load").json()

    assert response["detection"]["alerts_created"] == EXPECTED_TOTAL
    by_rule = {
        rule_id: client.get("/api/v1/alerts", params={"rule_id": rule_id}).json()["total"]
        for rule_id in EXPECTED_FINDINGS
    }
    assert by_rule == {rule_id: len(found) for rule_id, found in EXPECTED_FINDINGS.items()}


def test_baseline_dataset_creates_no_alerts(client: TestClient) -> None:
    response = client.post("/api/v1/datasets/baseline/load").json()

    assert response["detection"]["alerts_created"] == 0


def test_auto_detection_can_be_turned_off(migrated_database_url: str) -> None:
    app = create_app(make_settings(migrated_database_url, auto_detect=False))
    with TestClient(app) as client:
        response = ingest_jsonl(client, failures(5)).json()
        assert response["detection"] is None
        assert client.get("/api/v1/alerts").json()["total"] == 0
        assert client.post("/api/v1/detections/runs").json()["alerts_created"] == 1
