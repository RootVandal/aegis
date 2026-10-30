from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session


@pytest.fixture
def lab(client: TestClient) -> TestClient:
    """The detection-lab dataset: 19 alerts with known content."""
    client.post("/api/v1/datasets/detection-lab/load")
    return client


def alert_for(client: TestClient, rule_id: str) -> dict[str, Any]:
    items: list[dict[str, Any]] = client.get("/api/v1/alerts", params={"rule_id": rule_id}).json()[
        "items"
    ]
    return items[0]


def patch_status(client: TestClient, alert_id: int, status: str, reason: str | None = None) -> Any:
    body: dict[str, Any] = {"status": status}
    if reason is not None:
        body["reason"] = reason
    return client.patch(f"/api/v1/alerts/{alert_id}", json=body)


def new_incident(client: TestClient, alert_ids: list[int], **fields: Any) -> dict[str, Any]:
    body = {"title": "Suspicious logons on dc-01", "alert_ids": alert_ids, **fields}
    response = client.post("/api/v1/incidents", json=body)
    assert response.status_code == 201, response.text
    result: dict[str, Any] = response.json()
    return result


# --- Alert triage -------------------------------------------------------------


def test_alert_status_workflow_is_recorded(lab: TestClient) -> None:
    alert = alert_for(lab, "AEGIS-AUTH-001")

    acknowledged = patch_status(lab, alert["id"], "acknowledged").json()
    resolved = patch_status(lab, alert["id"], "resolved", "User confirmed typo.").json()

    assert resolved["status"] == "resolved"
    assert [(c["from_status"], c["to_status"]) for c in resolved["status_changes"]] == [
        ("new", "acknowledged"),
        ("acknowledged", "resolved"),
    ]
    assert resolved["status_changes"][1]["reason"] == "User confirmed typo."
    assert set(acknowledged["allowed_transitions"]) == {
        "investigating",
        "resolved",
        "false_positive",
    }
    assert resolved["allowed_transitions"] == ["investigating"]


@pytest.mark.parametrize("closing", ["resolved", "false_positive"])
def test_closing_requires_a_reason(lab: TestClient, closing: str) -> None:
    alert = alert_for(lab, "AEGIS-AUTH-001")

    response = patch_status(lab, alert["id"], closing, "   ")

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "reason_required"
    assert lab.get(f"/api/v1/alerts/{alert['id']}").json()["status"] == "new"


def test_reopening_requires_a_reason(lab: TestClient) -> None:
    alert = alert_for(lab, "AEGIS-AUTH-001")
    patch_status(lab, alert["id"], "false_positive", "Known test account.")

    assert patch_status(lab, alert["id"], "investigating").status_code == 422
    assert patch_status(lab, alert["id"], "investigating", "New evidence.").status_code == 200


@pytest.mark.parametrize(
    ("first", "then"), [("resolved", "acknowledged"), ("resolved", "false_positive"), (None, "new")]
)
def test_invalid_transitions_are_rejected(lab: TestClient, first: str | None, then: str) -> None:
    alert = alert_for(lab, "AEGIS-AUTH-001")
    if first:
        patch_status(lab, alert["id"], first, "closing")

    response = patch_status(lab, alert["id"], then, "x")

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "invalid_transition"


def test_status_changes_never_remove_evidence(lab: TestClient) -> None:
    alert = alert_for(lab, "AEGIS-AUTH-001")
    before = [e["event_id"] for e in lab.get(f"/api/v1/alerts/{alert['id']}").json()["events"]]

    patch_status(lab, alert["id"], "false_positive", "Benign.")
    after = [e["event_id"] for e in lab.get(f"/api/v1/alerts/{alert['id']}").json()["events"]]

    assert after == before and len(after) == 8


def test_alert_notes(lab: TestClient) -> None:
    alert = alert_for(lab, "AEGIS-AUTH-001")

    created = lab.post(f"/api/v1/alerts/{alert['id']}/notes", json={"body": "Called the user."})

    assert created.status_code == 201
    assert created.json()["author"] == "analyst"
    detail = lab.get(f"/api/v1/alerts/{alert['id']}").json()
    assert [n["body"] for n in detail["notes"]] == ["Called the user."]
    for bad in ({"body": ""}, {"body": "x" * 5001}, {"body": "ok", "extra": 1}):
        assert lab.post(f"/api/v1/alerts/{alert['id']}/notes", json=bad).status_code == 422


def test_alert_search_and_severity_sort(lab: TestClient) -> None:
    found = lab.get("/api/v1/alerts", params={"q": "suspicious powershell"}).json()
    by_severity = lab.get("/api/v1/alerts", params={"sort": "severity_desc"}).json()["items"]

    assert found["total"] == 2
    ranks = ["informational", "low", "medium", "high", "critical"]
    severities = [ranks.index(a["severity"]) for a in by_severity]
    assert severities == sorted(severities, reverse=True)
    assert lab.get("/api/v1/alerts", params={"q": "%"}).json()["total"] == 0


# --- Correlation --------------------------------------------------------------


def test_correlation_explains_every_link(lab: TestClient) -> None:
    alert = alert_for(lab, "AEGIS-AUTH-001")  # j.martin, dc-01, 10.10.1.99

    result = lab.get(f"/api/v1/alerts/{alert['id']}/correlation").json()

    assert result["total"] > 0
    assert all(item["reasons"] for item in result["events"])
    assert not set(result["seed_event_ids"]) & {i["event"]["event_id"] for i in result["events"]}
    # The spray against j.martin from another address is linked by user, and its alert is related.
    spray = next(i for i in result["events"] if i["event"]["event_id"] == "syn-lab-021")
    # Every lab event shares the scenario ID, so that criterion matches too.
    assert [r["criterion"] for r in spray["reasons"]] == ["user", "scenario"]
    assert spray["rule_ids"] == ["AEGIS-AUTH-002"]
    assert "AEGIS-AUTH-002" in [r["alert"]["rule_id"] for r in result["related_alerts"]]


def test_correlation_criteria_and_window_narrow_the_result(lab: TestClient) -> None:
    alert = alert_for(lab, "AEGIS-AUTH-001")
    url = f"/api/v1/alerts/{alert['id']}/correlation"

    by_user = lab.get(url, params={"criteria": "user"}).json()
    short = lab.get(url, params={"criteria": "user", "window_minutes": 30}).json()

    assert {i["event"]["username"] for i in by_user["events"]} == {"j.martin"}
    assert short["total"] == 0  # the spray happened ~58 minutes later
    assert lab.get(url, params={"criteria": "color"}).status_code == 422


# --- Incidents ----------------------------------------------------------------


def test_creating_an_incident_from_an_alert(lab: TestClient) -> None:
    alert = alert_for(lab, "AEGIS-AUTH-001")

    incident = new_incident(lab, [alert["id"]])

    assert incident["severity"] == alert["severity"] == "high"
    assert incident["status"] == "new"
    assert [a["id"] for a in incident["alerts"]] == [alert["id"]]
    linked = lab.get(f"/api/v1/alerts/{alert['id']}").json()
    assert linked["status"] == "investigating"
    assert linked["incident"]["id"] == incident["id"]
    assert [h["action"] for h in incident["history"]] == ["created", "alert_added"]


def test_an_alert_belongs_to_one_incident(lab: TestClient) -> None:
    alert = alert_for(lab, "AEGIS-AUTH-001")
    new_incident(lab, [alert["id"]])

    response = lab.post("/api/v1/incidents", json={"title": "Other", "alert_ids": [alert["id"]]})

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "alert_in_other_incident"
    assert lab.get("/api/v1/incidents").json()["total"] == 1  # nothing half-created


def test_linking_and_unlinking_alerts(lab: TestClient) -> None:
    first, second = alert_for(lab, "AEGIS-AUTH-001"), alert_for(lab, "AEGIS-AUTH-002")
    incident = new_incident(lab, [first["id"]])

    linked = lab.post(
        f"/api/v1/incidents/{incident['id']}/alerts", json={"alert_ids": [second["id"]]}
    )
    unlinked = lab.delete(f"/api/v1/incidents/{incident['id']}/alerts/{first['id']}")

    assert [a["id"] for a in linked.json()["alerts"]] == [first["id"], second["id"]]
    assert [a["id"] for a in unlinked.json()["alerts"]] == [second["id"]]
    assert lab.get(f"/api/v1/alerts/{first['id']}").json()["incident"] is None
    assert lab.get("/api/v1/incidents").json()["items"][0]["alert_count"] == 1


def test_evidence_is_documented_and_protected(lab: TestClient, db_session: Session) -> None:
    incident = new_incident(lab, [])
    url = f"/api/v1/incidents/{incident['id']}/evidence"

    added = lab.post(url, json={"event_id": "syn-lab-040", "note": "Internal SMB, ruled out."})

    assert added.status_code == 201
    assert added.json()["evidence"][0]["event"]["event_id"] == "syn-lab-040"
    assert lab.post(url, json={"event_id": "syn-lab-040", "note": "again"}).status_code == 409
    assert lab.post(url, json={"event_id": "nope", "note": "x"}).status_code == 404
    with pytest.raises(IntegrityError):
        db_session.execute(text("DELETE FROM events WHERE event_id = 'syn-lab-040'"))
        db_session.commit()


def test_incident_lifecycle_requires_an_assessment(lab: TestClient) -> None:
    incident = new_incident(lab, [alert_for(lab, "AEGIS-AUTH-001")["id"]])
    url = f"/api/v1/incidents/{incident['id']}"

    assert lab.patch(url, json={"status": "contained"}).status_code == 409
    assert lab.patch(url, json={"status": "investigating"}).status_code == 200
    blocked = lab.patch(url, json={"status": "resolved"})
    assert blocked.status_code == 409
    assert blocked.json()["error"]["code"] == "assessment_required"

    lab.put(f"{url}/assessment", json={
        "verdict": "benign_activity",
        "final_assessment": "Failures and success came from the user's new laptop.",
        "resolution_summary": "No action needed; user re-enrolled the device.",
    })  # fmt: skip
    resolved = lab.patch(url, json={"status": "resolved"}).json()
    reopened = lab.patch(url, json={"status": "investigating"}).json()

    assert resolved["status"] == "resolved" and resolved["resolved_at"] is not None
    assert reopened["resolved_at"] is None
    assert reopened["verdict"] == "benign_activity"  # the assessment is kept on reopen
    statuses = [h["summary"] for h in reopened["history"] if h["action"] == "status_changed"]
    assert statuses == [
        "Status new -> investigating",
        "Status investigating -> resolved",
        "Status resolved -> investigating",
    ]


def test_incident_validation(lab: TestClient) -> None:
    assert lab.post("/api/v1/incidents", json={"title": ""}).status_code == 422
    assert lab.post("/api/v1/incidents", json={"title": "x", "alert_ids": [999]}).status_code == 404
    incident = new_incident(lab, [])
    url = f"/api/v1/incidents/{incident['id']}"
    assert lab.patch(url, json={"status": "closed"}).status_code == 422
    assert lab.put(f"{url}/assessment", json={"verdict": "guilty", "final_assessment": "x",
                                              "resolution_summary": "y"}).status_code == 422  # fmt: skip
    assert lab.get("/api/v1/incidents/999").json()["error"]["code"] == "incident_not_found"


def test_timeline_explains_why_each_event_is_present(lab: TestClient) -> None:
    alert = alert_for(lab, "AEGIS-AUTH-001")
    incident = new_incident(lab, [alert["id"]])
    lab.post(f"/api/v1/incidents/{incident['id']}/evidence",
             json={"event_id": "syn-lab-021", "note": "Same account sprayed later."})  # fmt: skip
    url = f"/api/v1/incidents/{incident['id']}/timeline"

    plain = lab.get(url).json()
    wide = lab.get(url, params={"include_correlated": True}).json()

    times = [e["event"]["timestamp"] for e in plain]
    assert times == sorted(times)
    assert len(plain) == 9  # 8 alert events + 1 evidence event
    assert {s["kind"] for e in plain for s in e["sources"]} == {"alert", "evidence"}
    spray = next(e for e in plain if e["event"]["event_id"] == "syn-lab-021")
    assert spray["rule_ids"] == ["AEGIS-AUTH-002"]
    correlated = [e for e in wide if any(s["kind"] == "correlated" for s in e["sources"])]
    assert len(wide) > len(plain) and correlated
    assert all("Same " in s["description"] for e in correlated for s in e["sources"]
               if s["kind"] == "correlated")  # fmt: skip


def test_report_labels_hypotheses_and_escapes_untrusted_text(lab: TestClient) -> None:
    alert = alert_for(lab, "AEGIS-EXEC-001")
    event_id = lab.get(f"/api/v1/alerts/{alert['id']}").json()["events"][0]["event_id"]
    incident = new_incident(lab, [alert["id"]])
    base = f"/api/v1/incidents/{incident['id']}"
    lab.post(f"{base}/notes", json={"kind": "hypothesis", "body": "Initial access via phishing."})
    lab.post(f"{base}/evidence",
             json={"event_id": "syn-lab-035", "note": "<script>alert(1)</script> [x](http://evil)"})  # fmt: skip

    response = lab.get(f"{base}/report")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/markdown")
    report = response.text
    assert "**Hypothesis (unverified)**" in report
    assert "_No final assessment has been recorded yet._" in report
    assert "<script>" not in report and "[x](http://evil)" not in report
    assert "\\<script\\>" in report
    assert "## Timeline" in report and event_id.replace("-", "\\-") in report


def test_full_investigation_produces_a_documented_assessment(lab: TestClient) -> None:
    """Milestone 4 acceptance: alert -> investigation -> documented incident assessment."""
    alert = alert_for(lab, "AEGIS-AUTH-001")
    correlation = lab.get(f"/api/v1/alerts/{alert['id']}/correlation").json()
    related = [r["alert"]["id"] for r in correlation["related_alerts"]]

    incident = new_incident(lab, [alert["id"], *related], description="Brute force then spray.")
    base = f"/api/v1/incidents/{incident['id']}"
    lab.patch(base, json={"status": "investigating"})
    lab.post(
        f"{base}/evidence", json={"event_id": "syn-lab-008", "note": "Success after 7 failures."}
    )
    lab.post(f"{base}/notes", json={"kind": "hypothesis", "body": "Password was guessed."})
    lab.post(f"{base}/notes", json={"body": "Account owner did not log on at 09:02."})
    lab.patch(base, json={"status": "contained"})
    lab.put(f"{base}/assessment", json={
        "verdict": "true_positive",
        "final_assessment": "syn-lab-008 shows a successful logon right after 7 failures; the owner "
                            "denies it. Password guessing succeeded.",
        "resolution_summary": "Password reset, sessions revoked, source blocked.",
    })  # fmt: skip
    final = lab.patch(base, json={"status": "resolved"}).json()
    report = lab.get(f"{base}/report").text

    assert final["status"] == "resolved"
    assert len(final["alerts"]) == 1 + len(related)
    assert "True positive" in report
    assert "Password reset, sessions revoked, source blocked\\." in report
    assert "**Hypothesis (unverified)**" in report
