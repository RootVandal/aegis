"""Run a set of rules over a set of events. Pure and deterministic."""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from app.detection.model import EventRecord, Finding
from app.detection.rule import Rule


@dataclass(frozen=True)
class RuleConfig:
    rule: Rule[Any]
    params: dict[str, Any]  # user overrides only; defaults come from the rule


@dataclass(frozen=True)
class RuleResult:
    rule: Rule[Any]
    effective_params: dict[str, Any]
    findings: list[Finding]


def sort_events(events: Iterable[EventRecord]) -> list[EventRecord]:
    """Canonical order. Ties on timestamp are broken by event ID so the
    result never depends on the order events were loaded or inserted."""
    return sorted(events, key=lambda e: (e.timestamp, e.event_id))


def run_rules(events: Iterable[EventRecord], configs: Sequence[RuleConfig]) -> list[RuleResult]:
    ordered = sort_events(events)
    results = []
    for config in sorted(configs, key=lambda c: c.rule.id):
        params = config.rule.parse_params(config.params)
        findings = config.rule.evaluate(ordered, params)
        results.append(RuleResult(config.rule, params.model_dump(mode="json"), findings))
    return results
