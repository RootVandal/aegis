import pytest
from pydantic import ValidationError

from app.detection.model import EventRecord
from app.detection.registry import RULES_BY_ID
from app.models.enums import Severity
from tests.detection.helpers import rec, run

AUTH1, AUTH2 = "AEGIS-AUTH-001", "AEGIS-AUTH-002"


def failures(n: int, spacing: float = 10, start: float = 0, **fields: object) -> list[EventRecord]:
    fields.setdefault("username", "alice")
    fields.setdefault("source_ip", "10.0.0.5")
    return [rec("authentication_failure", start + i * spacing, **fields) for i in range(n)]


# --- AEGIS-AUTH-001 ---------------------------------------------------------


def test_threshold_failures_in_window_fire_once() -> None:
    findings = run(AUTH1, failures(6))

    assert len(findings) == 1
    assert len(findings[0].events) == 6
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].mitre_ids == ("T1110.001",)


def test_one_below_threshold_does_not_fire() -> None:
    assert run(AUTH1, failures(4)) == []


def test_window_boundary_is_inclusive() -> None:
    # 5 failures exactly 300 s from first to last: inside a 300 s window.
    assert len(run(AUTH1, failures(5, spacing=75))) == 1
    # 1 s more and the fifth failure falls outside.
    assert run(AUTH1, failures(5, spacing=75.25)) == []


def test_threshold_and_window_are_configurable() -> None:
    events = failures(3, spacing=50)

    assert run(AUTH1, events) == []
    assert len(run(AUTH1, events, threshold=3)) == 1
    assert run(AUTH1, events, threshold=3, window_seconds=60) == []


def test_usernames_are_grouped_case_insensitively() -> None:
    events = failures(3, username="Alice") + failures(2, start=30, username="ALICE")

    assert len(run(AUTH1, events)) == 1


def test_different_users_are_not_combined() -> None:
    events = failures(3, username="alice") + failures(3, start=1, username="bob")

    assert run(AUTH1, events) == []


def test_group_by_source_ip_combines_users() -> None:
    events = failures(3, username="alice") + failures(3, start=1, username="bob")

    assert len(run(AUTH1, events, group_by="source_ip")) == 1


def test_long_burst_produces_separate_non_overlapping_findings() -> None:
    findings = run(AUTH1, failures(12, spacing=60))  # 660 s: two windows of 6

    ids = [e.event_id for f in findings for e in f.events]
    assert len(findings) == 2
    assert len(ids) == len(set(ids))  # no event reported twice


def test_following_success_raises_severity_and_is_included() -> None:
    events = failures(5)
    success = rec("authentication_success", 100, username="alice", source_ip="10.0.0.9")

    finding = run(AUTH1, [*events, success])[0]

    assert finding.severity is Severity.HIGH
    assert finding.events[-1] is success
    assert any("successful logon" in c.description for c in finding.conditions)


def test_success_before_the_failures_or_too_late_is_ignored() -> None:
    early = rec("authentication_success", -5, username="alice")
    late = rec("authentication_success", 2000, username="alice")

    finding = run(AUTH1, [early, *failures(5), late])[0]

    assert finding.severity is Severity.MEDIUM
    assert early not in finding.events and late not in finding.events


def test_events_without_the_grouping_field_are_skipped() -> None:
    assert run(AUTH1, failures(6, username=None)) == []


def test_invalid_parameters_are_rejected() -> None:
    rule = RULES_BY_ID[AUTH1]
    with pytest.raises(ValidationError):
        rule.parse_params({"threshold": 1})
    with pytest.raises(ValidationError):
        rule.parse_params({"group_by": "hostname"})
    with pytest.raises(ValidationError):
        rule.parse_params({"unknown_option": True})


# --- AEGIS-AUTH-002 ---------------------------------------------------------


def spray(
    users: list[str], source: str = "198.51.100.23", spacing: float = 20
) -> list[EventRecord]:
    return [
        rec("authentication_failure", i * spacing, username=u, source_ip=source)
        for i, u in enumerate(users)
    ]


def test_many_accounts_from_one_source_fire() -> None:
    findings = run(AUTH2, spray(["a", "b", "c", "d", "e"]))

    assert len(findings) == 1
    assert findings[0].mitre_ids == ("T1110.003",)
    assert "5 accounts" in findings[0].conditions[0].observed


def test_many_attempts_against_few_accounts_do_not_fire() -> None:
    assert run(AUTH2, spray(["a", "b", "a", "b", "a", "b", "c", "d"])) == []


def test_same_accounts_from_different_sources_do_not_fire() -> None:
    events = [
        rec("authentication_failure", i, username=u, source_ip=f"10.0.0.{i}")
        for i, u in enumerate("abcdef")
    ]
    assert run(AUTH2, events) == []


def test_spray_followed_by_success_is_high() -> None:
    events = spray(["a", "b", "c", "d", "e"])
    success = rec("authentication_success", 200, username="c", source_ip="198.51.100.23")

    finding = run(AUTH2, [*events, success])[0]

    assert finding.severity is Severity.HIGH
    assert success in finding.events


def test_spray_slower_than_the_window_does_not_fire() -> None:
    assert run(AUTH2, spray(["a", "b", "c", "d", "e"], spacing=200)) == []


def test_events_without_source_ip_are_skipped() -> None:
    events = [rec("authentication_failure", i, username=u) for i, u in enumerate("abcdef")]
    assert run(AUTH2, events) == []
