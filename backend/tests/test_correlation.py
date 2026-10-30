from datetime import timedelta

import pytest

from app.detection.model import EventRecord
from app.investigation.correlation import CorrelatedEvent, correlate, describe_offset
from tests.detection.helpers import rec

HOUR = timedelta(hours=1)


def seed() -> list[EventRecord]:
    return [
        rec("process_creation", 0, event_id="seed-1", hostname="ws-01", username="Alice",
            source_ip="10.0.0.5", scenario_id="lab"),
        rec("network_connection", 60, event_id="seed-2", hostname="ws-01",
            destination_ip="203.0.113.9"),
    ]  # fmt: skip


def ids(results: list[CorrelatedEvent]) -> list[str]:
    return [r.event.event_id for r in results]


def test_time_alone_never_correlates() -> None:
    unrelated = rec("logon", 30, hostname="ws-99", username="bob", source_ip="10.9.9.9")

    assert correlate(seed(), [unrelated], window=HOUR) == []


@pytest.mark.parametrize(
    ("fields", "criterion", "value"),
    [
        ({"hostname": "ws-01"}, "host", "ws-01"),
        ({"username": "ALICE"}, "user", "ALICE"),  # usernames compare case-insensitively
        ({"source_ip": "203.0.113.9"}, "ip", "203.0.113.9"),  # seed destination = candidate source
        ({"destination_ip": "10.0.0.5"}, "ip", "10.0.0.5"),
        ({"scenario_id": "lab"}, "scenario", "lab"),
    ],
)
def test_each_criterion_produces_a_named_reason(
    fields: dict[str, str], criterion: str, value: str
) -> None:
    result = correlate(seed(), [rec("other", 300, **fields)], window=HOUR)

    assert len(result) == 1
    assert [(r.criterion, r.value) for r in result[0].reasons] == [(criterion, value)]


def test_multiple_shared_entities_are_all_listed() -> None:
    event = rec("other", 300, hostname="ws-01", username="alice", source_ip="10.0.0.5")

    reasons = correlate(seed(), [event], window=HOUR)[0].reasons

    assert {r.criterion for r in reasons} == {"host", "user", "ip"}


def test_window_bounds_are_inclusive_and_relative_to_the_seed_span() -> None:
    before = rec("x", -3600, hostname="ws-01")  # exactly one hour before the first seed event
    too_early = rec("x", -3601, hostname="ws-01")
    after = rec("x", 60 + 3600, hostname="ws-01")  # one hour after the last seed event
    too_late = rec("x", 60 + 3601, hostname="ws-01")

    result = correlate(seed(), [before, too_early, after, too_late], window=HOUR)

    assert ids(result) == [before.event_id, after.event_id]
    assert [r.relation for r in result] == ["before", "after"]
    assert [r.offset_seconds for r in result] == [3600, 3600]


def test_events_inside_the_seed_span_are_during() -> None:
    result = correlate(seed(), [rec("x", 30, hostname="ws-01")], window=HOUR)

    assert result[0].relation == "during"
    assert "within the seed's time span" in result[0].explanation()


def test_criteria_can_be_switched_off() -> None:
    event = rec("x", 300, hostname="ws-01")

    assert correlate(seed(), [event], window=HOUR, criteria=frozenset({"user", "ip"})) == []


def test_seed_events_are_not_returned_and_results_are_chronological() -> None:
    a = rec("x", 900, hostname="ws-01")
    b = rec("x", -900, hostname="ws-01")

    result = correlate(seed(), [*seed(), a, b], window=HOUR)

    assert ids(result) == [b.event_id, a.event_id]


def test_explanation_names_values_and_time() -> None:
    event = rec("x", 60 + 600, hostname="ws-01", username="alice")

    text = correlate(seed(), [event], window=HOUR)[0].explanation()

    assert text == "Same host ws-01; Same user alice. Occurred 10 min after the seed events."


def test_offset_wording() -> None:
    assert describe_offset("before", 45) == "Occurred 45 s before the seed events"
    assert describe_offset("after", 3600) == "Occurred 60 min after the seed events"


def test_empty_seed_is_an_error() -> None:
    with pytest.raises(ValueError):
        correlate([], [], window=HOUR)
