"""Engine-level guarantees: labeled results, determinism, complete documentation."""

import random
from typing import Any

import pytest

from app.detection.engine import RuleConfig, run_rules
from app.detection.explain import build_explanation
from app.detection.mitre import TECHNIQUES
from app.detection.model import EventRecord
from app.detection.registry import RULES, RULES_BY_ID
from app.sample_data.baseline import generate_baseline
from app.sample_data.detection_lab import EXPECTED_FINDINGS, generate_detection_lab
from tests.detection.helpers import from_raw, rec

ALL_RULES = [RuleConfig(rule, {}) for rule in RULES]


def findings_by_rule(raw_events: list[dict[str, Any]]) -> dict[str, set[tuple[str, ...]]]:
    results = run_rules([from_raw(r) for r in raw_events], ALL_RULES)
    return {r.rule.id: {f.event_ids for f in r.findings} for r in results}


def test_there_are_eight_rules_with_unique_ids() -> None:
    assert len(RULES) == 8
    assert len(RULES_BY_ID) == 8


def test_detection_lab_matches_its_labels_exactly() -> None:
    assert findings_by_rule(generate_detection_lab()) == EXPECTED_FINDINGS


def test_baseline_office_activity_produces_no_findings() -> None:
    assert all(found == set() for found in findings_by_rule(generate_baseline()).values())


def test_results_do_not_depend_on_input_order() -> None:
    events = [from_raw(r) for r in generate_detection_lab()]
    shuffled = events[:]
    random.Random(7).shuffle(shuffled)

    def snapshot(evts: list[EventRecord]) -> list[object]:
        return [
            (r.rule.id, [(f.event_ids, f.severity, f.title) for f in r.findings])
            for r in run_rules(evts, ALL_RULES)
        ]

    assert snapshot(events) == snapshot(shuffled) == snapshot(list(reversed(events)))


def test_identical_timestamps_are_ordered_by_event_id() -> None:
    # Real logs often contain several events in the same second. Without a
    # tie-breaker the evidence order would depend on how events were loaded.
    events = [
        rec("authentication_failure", 0, event_id=f"same-{n}", username="alice") for n in "ecadb"
    ]

    forward = run_rules(events, ALL_RULES[:1])[0].findings[0].event_ids
    backward = run_rules(list(reversed(events)), ALL_RULES[:1])[0].findings[0].event_ids

    assert forward == backward == tuple(f"same-{n}" for n in "abcde")


def test_disabled_rules_are_simply_not_configured() -> None:
    results = run_rules([from_raw(r) for r in generate_detection_lab()], ALL_RULES[:1])
    assert [r.rule.id for r in results] == [RULES[0].id]


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_every_rule_is_fully_documented(rule: object) -> None:
    for attribute in (
        "id", "name", "description", "event_types", "required_fields", "logic",
        "investigation_steps", "false_positives", "limitations", "unknowns", "changelog",
    ):  # fmt: skip
        assert getattr(rule, attribute), f"{rule} is missing {attribute}"
    assert rule.version == max(change.version for change in rule.changelog)  # type: ignore[attr-defined]


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_every_mitre_mapping_is_a_verified_technique(rule: object) -> None:
    for mapping in rule.mitre:  # type: ignore[attr-defined]
        assert TECHNIQUES[mapping.technique.id] == mapping.technique
        assert mapping.relationship and mapping.telemetry and mapping.limitations


def test_findings_only_reference_their_rules_mappings() -> None:
    for result in run_rules([from_raw(r) for r in generate_detection_lab()], ALL_RULES):
        declared = {m.technique.id for m in result.rule.mitre}
        for finding in result.findings:
            assert set(finding.mitre_ids) <= declared


def test_explanation_is_derived_from_the_finding() -> None:
    events = [
        rec("authentication_failure", i * 10, username="alice", source_ip="10.0.0.5")
        for i in range(5)
    ]
    rule = RULES_BY_ID["AEGIS-AUTH-001"]
    finding = rule.run(events, {})[0]

    explanation = build_explanation(rule, finding, {"threshold": 5})

    assert [e["event_id"] for e in explanation["triggering_events"]] == list(finding.event_ids)
    assert explanation["evidence"]["users"] == ["alice"]
    assert explanation["evidence"]["event_count"] == 5
    assert explanation["conditions"][0]["observed"].startswith("5 failures")
    assert explanation["mitre"][0]["id"] == "T1110.001"
    assert explanation["next_steps"] == list(rule.investigation_steps)
    assert explanation["false_positives"] == list(rule.false_positives)
    assert explanation["unknowns"]
    assert "not proof of compromise" in explanation["disclaimer"]


def test_rule_catalog_document_is_up_to_date() -> None:
    from pathlib import Path

    from app.detection.catalog import render_markdown

    committed = Path(__file__).resolve().parents[3] / "docs" / "DETECTION_RULES.md"
    assert committed.read_text(encoding="utf-8") == render_markdown(), (
        "docs/DETECTION_RULES.md is stale; regenerate it with "
        "`python -m app.detection.catalog > ../docs/DETECTION_RULES.md`"
    )
