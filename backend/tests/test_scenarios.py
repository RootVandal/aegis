import json
from ipaddress import ip_address, ip_network
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.detection.engine import RuleConfig, run_rules
from app.detection.registry import RULES, RULES_BY_ID
from app.scenarios.catalog import SCENARIOS
from app.scenarios.model import GradeInput, GradingError, Scenario, grade
from tests.detection.helpers import from_raw

ALL = list(SCENARIOS.values())
DOC_NETS = (ip_network("203.0.113.0/24"), ip_network("198.51.100.0/24"))
RATIONALE = "The evidence shows a clear sequence of related events supporting this conclusion."


def perfect(scenario: Scenario) -> GradeInput:
    return GradeInput(
        answers={q.id: q.correct for q in scenario.questions},
        evidence_event_ids=[item.event_ids[0] for item in scenario.required_evidence],
        rationale=RATIONALE,
    )


def event_ids(scenario: Scenario) -> set[str]:
    return {r["event_id"] for r in scenario.generate()}


# --- Content consistency --------------------------------------------------------


def test_there_are_four_scenarios_covering_all_difficulties() -> None:
    assert len(ALL) == 4
    assert {s.difficulty for s in ALL} == {"beginner", "intermediate", "advanced"}


@pytest.mark.parametrize("scenario", ALL, ids=lambda s: s.id)
def test_dataset_is_deterministic_tagged_and_unique(scenario: Scenario) -> None:
    records = scenario.generate()

    assert records == scenario.generate()
    assert {r["scenario_id"] for r in records} == {scenario.scenario_tag}
    assert len({r["event_id"] for r in records}) == len(records)


@pytest.mark.parametrize("scenario", ALL, ids=lambda s: s.id)
def test_answer_key_references_real_events_and_options(scenario: Scenario) -> None:
    ids = event_ids(scenario)
    required = {i for item in scenario.required_evidence for i in item.event_ids}
    decoys = {i for d in scenario.decoys for i in d.event_ids}
    supporting = set(scenario.supporting_evidence)

    assert required | decoys | supporting <= ids
    assert not required & decoys and not required & supporting and not decoys & supporting
    assert scenario.decoys, "every scenario needs at least one benign lookalike"
    for question in scenario.questions:
        options = [o.id for o in question.options]
        assert question.correct in options and len(options) == len(set(options)) >= 3


@pytest.mark.parametrize("scenario", ALL, ids=lambda s: s.id)
def test_briefing_is_complete(scenario: Scenario) -> None:
    for field in ("summary", "context", "objectives", "hints", "questions", "reasoning",
                  "false_positive_discussion", "relevant_rules"):  # fmt: skip
        assert getattr(scenario, field), field
    assert set(scenario.relevant_rules) <= set(RULES_BY_ID)


@pytest.mark.parametrize("scenario", ALL, ids=lambda s: s.id)
def test_every_relevant_rule_fires_on_the_dataset(scenario: Scenario) -> None:
    results = run_rules(
        [from_raw(r) for r in scenario.generate()], [RuleConfig(r, {}) for r in RULES]
    )
    fired = {r.rule.id for r in results if r.findings}

    assert set(scenario.relevant_rules) <= fired


@pytest.mark.parametrize("scenario", ALL, ids=lambda s: s.id)
def test_only_private_or_documentation_addresses(scenario: Scenario) -> None:
    for record in scenario.generate():
        for key in ("source_ip", "destination_ip", "assigned_ip"):
            if key in record:
                address = ip_address(record[key])
                assert address.is_private or any(address in n for n in DOC_NETS), record


# --- Grading --------------------------------------------------------------------


@pytest.mark.parametrize("scenario", ALL, ids=lambda s: s.id)
def test_a_perfect_submission_completes(scenario: Scenario) -> None:
    result = grade(scenario, perfect(scenario), event_ids(scenario))

    assert result["completed"] is True
    assert all(o["met"] for o in result["objectives"])


def test_wrong_answer_fails_only_that_objective() -> None:
    scenario = SCENARIOS["auth-takeover"]
    submission = perfect(scenario)
    answers = {**submission.answers, "source": "10.10.200.14"}

    result = grade(
        scenario, GradeInput(answers, submission.evidence_event_ids, RATIONALE), event_ids(scenario)
    )

    met = {o["objective"]: o["met"] for o in result["objectives"]}
    assert met["Reach correct conclusions"] is False
    assert met["Cite the key evidence"] is True
    wrong = next(q for q in result["questions"] if q["id"] == "source")
    assert (wrong["your_answer"], wrong["correct"]) == ("10.10.200.14", False)


def test_any_event_of_a_required_group_satisfies_it() -> None:
    scenario = SCENARIOS["multistage"]
    beacons = next(r for r in scenario.required_evidence if "Beaconing" in r.description)
    evidence = [r.event_ids[0] for r in scenario.required_evidence if r is not beacons]

    result = grade(scenario, GradeInput(perfect(scenario).answers, [*evidence, beacons.event_ids[-1]], RATIONALE),
                   event_ids(scenario))  # fmt: skip

    assert result["completed"] is True


def test_missing_required_evidence_is_reported() -> None:
    scenario = SCENARIOS["office-macro"]
    submission = perfect(scenario)

    result = grade(scenario, GradeInput(submission.answers, submission.evidence_event_ids[1:], RATIONALE),
                   event_ids(scenario))  # fmt: skip

    assert result["completed"] is False
    assert [r["cited"] for r in result["evidence"]["required"]] == [False, True, True, True]


def test_citing_a_decoy_is_reported_with_its_benign_explanation() -> None:
    scenario = SCENARIOS["service-escalation"]
    decoy = scenario.decoys[0]
    submission = perfect(scenario)

    result = grade(scenario, GradeInput(submission.answers, [*submission.evidence_event_ids, decoy.event_ids[0]],
                                        RATIONALE), event_ids(scenario))  # fmt: skip

    assert result["completed"] is False
    assert result["evidence"]["decoys_cited"] == [
        {"event_ids": [decoy.event_ids[0]], "why": decoy.why}
    ]


def test_supporting_and_unrelated_citations_are_listed_without_penalty() -> None:
    scenario = SCENARIOS["auth-takeover"]
    submission = perfect(scenario)
    background = "scn-a-001"  # j.martin's ordinary logon: not part of the key

    result = grade(scenario, GradeInput(submission.answers,
                                        [*submission.evidence_event_ids, scenario.supporting_evidence[0], background],
                                        RATIONALE), event_ids(scenario))  # fmt: skip

    assert result["completed"] is True
    assert result["evidence"]["supporting_cited"] == [scenario.supporting_evidence[0]]
    assert result["evidence"]["unrelated_cited"] == [background]


def test_short_rationale_does_not_complete() -> None:
    scenario = SCENARIOS["auth-takeover"]
    submission = perfect(scenario)

    result = grade(scenario, GradeInput(submission.answers, submission.evidence_event_ids, "it was bad"),
                   event_ids(scenario))  # fmt: skip

    assert result["completed"] is False


@pytest.mark.parametrize(
    "bad",
    [
        GradeInput({"nope": "x"}, [], RATIONALE),
        GradeInput({"source": "not-an-option"}, [], RATIONALE),
        GradeInput({}, ["scn-b-001"], RATIONALE),  # evidence from another scenario
    ],
)
def test_submissions_that_do_not_fit_the_scenario_are_errors(bad: GradeInput) -> None:
    scenario = SCENARIOS["auth-takeover"]
    with pytest.raises(GradingError):
        grade(scenario, bad, event_ids(scenario))


# --- API ------------------------------------------------------------------------


def secrets(scenario: Scenario) -> list[str]:
    """Text that must never appear before an attempt is closed."""
    return [
        *(q.explanation for q in scenario.questions),
        *scenario.reasoning,
        *scenario.false_positive_discussion,
        *(d.why for d in scenario.decoys),
        *(r.description for r in scenario.required_evidence),
    ]


def start(client: TestClient, scenario_id: str) -> dict[str, Any]:
    response = client.post(f"/api/v1/scenarios/{scenario_id}/attempts")
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


def submit(client: TestClient, attempt_id: int, submission: GradeInput) -> Any:
    return client.post(
        f"/api/v1/scenario-attempts/{attempt_id}/submit",
        json={
            "answers": dict(submission.answers),
            "evidence_event_ids": list(submission.evidence_event_ids),
            "rationale": submission.rationale,
        },
    )


def test_listing_before_anything_is_loaded(client: TestClient) -> None:
    listing = client.get("/api/v1/scenarios").json()

    assert [s["id"] for s in listing] == list(SCENARIOS)
    assert all(s["loaded_events"] == 0 and s["latest_attempt"] is None for s in listing)


@pytest.mark.parametrize("scenario", ALL, ids=lambda s: s.id)
def test_answers_do_not_leak_before_the_attempt_is_closed(
    client: TestClient, scenario: Scenario
) -> None:
    attempt = start(client, scenario.id)
    for _ in range(len(scenario.hints)):
        client.post(f"/api/v1/scenario-attempts/{attempt['id']}/hints")

    exposed = json.dumps([
        client.get(f"/api/v1/scenarios/{scenario.id}").json(),
        client.get(f"/api/v1/scenario-attempts/{attempt['id']}").json(),
        client.get(f"/api/v1/scenarios/{scenario.id}/attempts").json(),
    ])  # fmt: skip

    assert all(text not in exposed for text in secrets(scenario))
    assert '"correct' not in exposed


def test_starting_loads_data_once_and_raises_the_alerts(client: TestClient) -> None:
    scenario = SCENARIOS["office-macro"]

    start(client, scenario.id)
    start(client, scenario.id)  # a second attempt must not duplicate events
    detail = client.get(f"/api/v1/scenarios/{scenario.id}").json()

    assert detail["loaded_events"] == detail["event_count"] == len(scenario.generate())
    assert detail["attempt_count"] == 2
    assert {a["rule_id"] for a in detail["alerts"]} == set(scenario.relevant_rules)
    scoped = client.get("/api/v1/events", params={"scenario_id": scenario.scenario_tag}).json()
    assert scoped["total"] == len(scenario.generate())


def test_hints_are_revealed_one_at_a_time(client: TestClient) -> None:
    scenario = SCENARIOS["auth-takeover"]
    attempt = start(client, scenario.id)
    url = f"/api/v1/scenario-attempts/{attempt['id']}/hints"

    first = client.post(url).json()
    assert first["hints"] == [scenario.hints[0]]
    assert first["hints_remaining"] == len(scenario.hints) - 1
    for _ in range(len(scenario.hints) - 1):
        client.post(url)
    response = client.post(url)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "no_more_hints"


def test_submitting_grades_closes_and_unlocks_the_solution(client: TestClient) -> None:
    scenario = SCENARIOS["multistage"]
    attempt = start(client, scenario.id)
    assert attempt["solution"] is None and attempt["evaluation"] is None

    graded = submit(client, attempt["id"], perfect(scenario)).json()

    assert graded["status"] == "submitted"
    assert graded["evaluation"]["completed"] is True
    assert graded["solution"]["reasoning"] == list(scenario.reasoning)
    assert graded["solution"]["answers"]["unsupported"]["correct"] == "exfil"
    assert submit(client, attempt["id"], perfect(scenario)).status_code == 409
    assert client.post(f"/api/v1/scenario-attempts/{attempt['id']}/hints").status_code == 409
    summary = next(s for s in client.get("/api/v1/scenarios").json() if s["id"] == scenario.id)
    assert summary["completed"] is True
    assert summary["latest_attempt"] == {
        "id": attempt["id"],
        "status": "submitted",
        "completed": True,
    }


def test_invalid_submission_keeps_the_attempt_open(client: TestClient) -> None:
    attempt = start(client, "auth-takeover")

    response = submit(client, attempt["id"], GradeInput({}, ["syn-lab-001"], RATIONALE))

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_submission"
    assert (
        client.get(f"/api/v1/scenario-attempts/{attempt['id']}").json()["status"] == "in_progress"
    )


def test_revealing_without_submitting(client: TestClient) -> None:
    attempt = start(client, "service-escalation")

    revealed = client.post(f"/api/v1/scenario-attempts/{attempt['id']}/reveal").json()

    assert revealed["status"] == "revealed"
    assert revealed["evaluation"] is None
    assert revealed["solution"] is not None
    summary = next(
        s for s in client.get("/api/v1/scenarios").json() if s["id"] == "service-escalation"
    )
    assert summary["completed"] is False


def test_unknown_scenario_and_attempt(client: TestClient) -> None:
    assert (
        client.post("/api/v1/scenarios/nope/attempts").json()["error"]["code"]
        == "scenario_not_found"
    )
    assert (
        client.get("/api/v1/scenario-attempts/999").json()["error"]["code"] == "attempt_not_found"
    )
    assert client.post("/api/v1/scenario-attempts/1/submit", json={"extra": 1}).status_code == 422
