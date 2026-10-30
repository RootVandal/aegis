"""Base class for detection rules, plus shared helpers.

A rule is a small class with two parts:

* **Metadata** (class attributes) that documents the rule for analysts:
  what it looks for, which fields it needs, how it maps to ATT&CK, how to
  investigate it, and where it is known to fail.
* **Logic** (``evaluate``): a pure function from events and parameters to
  findings. No database, no clock, no randomness, so the same input always
  produces the same output.
"""

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict

from app.detection.model import EventRecord, Finding, MitreMapping
from app.models.enums import Severity


class RuleParams(BaseModel):
    """Base for rule parameters. Unknown keys are rejected, not ignored."""

    model_config = ConfigDict(extra="forbid", frozen=True)


@dataclass(frozen=True)
class RuleChange:
    version: int
    date: str
    description: str


class Rule[P: RuleParams](ABC):
    id: ClassVar[str]
    name: ClassVar[str]
    version: ClassVar[int]
    description: ClassVar[str]
    severity: ClassVar[Severity]  # default; a finding may raise or lower it with a reason
    event_types: ClassVar[tuple[str, ...]]
    required_fields: ClassVar[tuple[str, ...]]
    logic: ClassVar[tuple[str, ...]]  # step-by-step, human-readable
    mitre: ClassVar[tuple[MitreMapping, ...]]
    investigation_steps: ClassVar[tuple[str, ...]]
    false_positives: ClassVar[tuple[str, ...]]
    limitations: ClassVar[tuple[str, ...]]
    unknowns: ClassVar[tuple[str, ...]]  # what the alert alone cannot tell the analyst
    changelog: ClassVar[tuple[RuleChange, ...]]
    params_model: ClassVar[type[RuleParams]]

    @abstractmethod
    def evaluate(self, events: Sequence[EventRecord], params: P) -> list[Finding]:
        """Return findings. ``events`` are sorted by (timestamp, event_id)."""

    def parse_params(self, overrides: dict[str, Any]) -> P:
        """Defaults merged with user overrides, validated by the rule's model."""
        return self.params_model.model_validate(overrides)  # type: ignore[return-value]

    def run(self, events: Sequence[EventRecord], overrides: dict[str, Any]) -> list[Finding]:
        return self.evaluate(events, self.parse_params(overrides))


def greedy_windows(
    events: Sequence[EventRecord],
    window: timedelta,
    is_burst: Callable[[Sequence[EventRecord]], bool],
) -> Iterator[Sequence[EventRecord]]:
    """Split chronologically sorted events into non-overlapping bursts.

    Starting at the earliest unused event, take every event within ``window``
    of it. If that slice satisfies ``is_burst``, yield it and continue after
    its last event; otherwise move the start forward by one event.

    The result is deterministic and never reports the same event twice for
    one rule and group. Trade-off: a burst that straddles a window boundary
    may be split or missed; this is documented in each rule's limitations.
    """
    start = 0
    while start < len(events):
        limit = events[start].timestamp + window
        end = start
        while end + 1 < len(events) and events[end + 1].timestamp <= limit:
            end += 1
        candidate = events[start : end + 1]
        if is_burst(candidate):
            yield candidate
            start = end + 1
        else:
            start += 1


def lower(value: str | None) -> str | None:
    return value.lower() if value else None
