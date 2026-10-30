from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.detection.engine import RuleConfig
from app.detection.registry import RULES, RULES_BY_ID
from app.evaluation.metrics import Counts, f1, macro_average, precision, recall, summarize
from app.evaluation.runner import evaluate
from app.evaluation.suite import CASES, CATEGORIES, dataset_version

DEFAULTS = [RuleConfig(rule, {}) for rule in RULES]

# Regression snapshot: per-rule outcomes on the suite with default parameters.
# A change here means a rule's behavior changed. Update it only together with a
# rule version bump and changelog entry that explain why.
EXPECTED_COUNTS = {
    "AEGIS-AUTH-001": (4, 1, 2, 44),
    "AEGIS-AUTH-002": (1, 1, 1, 48),
    "AEGIS-DEF-001": (3, 1, 1, 46),
    "AEGIS-EXEC-001": (2, 1, 2, 46),
    "AEGIS-NET-001": (2, 1, 1, 47),
    "AEGIS-PERS-001": (3, 1, 1, 46),
    "AEGIS-PRIV-001": (2, 1, 1, 47),
    "AEGIS-PROC-001": (3, 1, 2, 45),
}


# --- Metrics ----------------------------------------------------------------


def test_metrics_from_counts() -> None:
    c = Counts(tp=6, fp=2, fn=3, tn=10)

    assert precision(c) == 6 / 8
    assert recall(c) == 6 / 9
    assert f1(c) == 12 / 17


@pytest.mark.parametrize(
    ("counts", "expected"),
    [
        (Counts(tn=5), {"precision": None, "recall": None, "f1": None}),  # nothing to measure
        (Counts(fn=3, tn=5), {"precision": None, "recall": 0.0, "f1": 0.0}),  # never fired
        (Counts(fp=2, tn=5), {"precision": 0.0, "recall": None, "f1": 0.0}),  # no positives exist
        (Counts(tp=4), {"precision": 1.0, "recall": 1.0, "f1": 1.0}),
    ],
)
def test_undefined_metrics_are_none_not_zero(counts: Counts, expected: dict[str, Any]) -> None:
    summary = summarize(counts)

    assert {k: summary[k] for k in expected} == expected


def test_macro_average_ignores_undefined_values_and_says_so() -> None:
    assert macro_average([1.0, None, 0.5]) == (0.75, 2)
    assert macro_average([None, None]) == (None, 0)


# --- Suite content -----------------------------------------------------------


def test_suite_covers_every_category_and_every_rule() -> None:
    assert {c.category for c in CASES} == set(CATEGORIES)
    assert len({c.id for c in CASES}) == len(CASES)
    for rule in RULES:
        positives = [c for c in CASES if rule.id in c.expected]
        assert len(positives) >= 2, rule.id
        assert any(c.category in ("gap", "incomplete") for c in positives), (
            f"{rule.id} needs a known miss so recall is not trivially perfect"
        )
    assert all(set(c.expected) <= set(RULES_BY_ID) for c in CASES)


def test_malformed_records_are_rejected_and_reach_no_rule() -> None:
    result = evaluate(DEFAULTS)
    malformed = [c for c in result["cases"] if c["category"] == "malformed"]

    assert malformed and all(c["rejected"] == c["records"] and not c["fired"] for c in malformed)
    assert result["input_handling_ok"] is True


# --- Execution ---------------------------------------------------------------


def test_regression_snapshot_with_default_parameters() -> None:
    per_rule = evaluate(DEFAULTS)["per_rule"]

    actual = {r: (m["tp"], m["fp"], m["fn"], m["tn"]) for r, m in per_rule.items()}
    assert actual == EXPECTED_COUNTS


def test_every_rule_sees_every_case_once() -> None:
    per_rule = evaluate(DEFAULTS)["per_rule"]

    assert all(sum(m[k] for k in ("tp", "fp", "fn", "tn")) == len(CASES) for m in per_rule.values())


def test_misclassified_cases_are_named() -> None:
    per_rule = evaluate(DEFAULTS)["per_rule"]

    assert per_rule["AEGIS-AUTH-001"]["fn_cases"] == ["auth-slow-guessing", "auth-no-username"]
    assert per_rule["AEGIS-EXEC-001"]["fp_cases"] == ["ps-sccm-encoded"]


def test_results_are_reproducible() -> None:
    first, second = evaluate(DEFAULTS), evaluate(DEFAULTS)

    assert first == second
    assert dataset_version() == dataset_version()


def test_an_overly_strict_threshold_never_fires_and_precision_is_undefined() -> None:
    configs = [RuleConfig(r, {"threshold": 9} if r.id == "AEGIS-AUTH-001" else {}) for r in RULES]

    result = evaluate(configs)
    per_rule = result["per_rule"]["AEGIS-AUTH-001"]

    # No case has 9 failures in one window: the rule stays silent.
    assert (per_rule["tp"], per_rule["fp"], per_rule["fn"]) == (0, 0, 6)
    assert per_rule["recall"] == 0.0
    assert per_rule["precision"] is None  # never fired: no precision, not 0% or 100%
    assert result["rules"]["AEGIS-AUTH-001"]["params"]["threshold"] == 9


# --- API ---------------------------------------------------------------------


def test_dataset_listing_describes_the_suite(client: TestClient) -> None:
    datasets = client.get("/api/v1/evaluation/datasets").json()

    assert datasets[0]["case_count"] == len(CASES)
    assert datasets[0]["version"] == dataset_version()
    assert "Undefined" in datasets[0]["metric_definitions"]["precision"]
    cases = client.get(f"/api/v1/evaluation/datasets/{datasets[0]['id']}/cases").json()
    assert len(cases) == len(CASES) and cases[0]["records"]


def test_run_is_stored_and_reproducible(client: TestClient) -> None:
    first = client.post("/api/v1/evaluation/runs", json={}).json()
    second = client.post("/api/v1/evaluation/runs", json={}).json()

    assert first["results"]["per_rule"] == second["results"]["per_rule"]
    assert first["comparison"] is None
    assert second["comparison"] == {
        "previous_run_id": first["id"],
        "dataset_changed": False,
        "rules": {},
    }
    assert first["rules"]["AEGIS-PERS-001"]["version"] == 2
    listed = client.get("/api/v1/evaluation/runs").json()
    assert [r["id"] for r in listed] == [second["id"], first["id"]]


def test_tuning_shows_up_in_the_comparison(client: TestClient) -> None:
    client.post("/api/v1/evaluation/runs", json={})
    client.patch("/api/v1/rules/AEGIS-AUTH-001", json={"params": {"threshold": 9}})

    tuned = client.post("/api/v1/evaluation/runs", json={"settings": "current"}).json()
    defaults = client.post("/api/v1/evaluation/runs", json={"settings": "defaults"}).json()

    change = tuned["comparison"]["rules"]["AEGIS-AUTH-001"]
    assert change["params_changed"] is True
    assert change["delta"]["tp"] < 0  # a stricter threshold misses positives
    assert tuned["rules"]["AEGIS-AUTH-001"]["params"]["threshold"] == 9
    assert defaults["rules"]["AEGIS-AUTH-001"]["params"]["threshold"] == 5


def test_disabled_rules_are_still_evaluated(client: TestClient) -> None:
    client.patch("/api/v1/rules/AEGIS-NET-001", json={"enabled": False})

    run = client.post("/api/v1/evaluation/runs", json={}).json()

    assert run["rules"]["AEGIS-NET-001"]["enabled"] is False
    assert run["results"]["per_rule"]["AEGIS-NET-001"]["tp"] == 2


def test_errors(client: TestClient) -> None:
    assert client.post("/api/v1/evaluation/runs", json={"dataset_id": "x"}).status_code == 404
    assert client.post("/api/v1/evaluation/runs", json={"settings": "magic"}).status_code == 422
    assert client.get("/api/v1/evaluation/runs/99").json()["error"]["code"] == "run_not_found"


def test_published_results_match_the_snapshot() -> None:
    """docs/DETECTION_EVALUATION.md must not drift from what the rules really do."""
    import re
    from pathlib import Path

    doc = (Path(__file__).resolve().parents[2] / "docs" / "DETECTION_EVALUATION.md").read_text(
        encoding="utf-8"
    )
    published = {
        rule_id: tuple(int(n) for n in counts)
        for rule_id, *counts in re.findall(
            r"^\| (AEGIS-[A-Z]+-\d+) v\d+ \| (\d+) \| (\d+) \| (\d+) \| (\d+) \|", doc, re.MULTILINE
        )
    }

    assert published == EXPECTED_COUNTS
