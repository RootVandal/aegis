"""Explainable event correlation.

Given the events behind an alert or incident (the *seed*), find other events
that are plausibly related, and say exactly why.

Rules of the game:

* **Time alone never correlates.** Proximity in time only limits *where* we
  look (``window`` before the first and after the last seed event). An event
  is returned only if it also shares something concrete with the seed: a
  host, a user, an IP address or a scenario identifier.
* **Every result carries its reasons.** Each reason names the criterion and
  the shared value, so an analyst can judge whether the link is meaningful.
* **Pure and deterministic**, like the detection engine.

Known limitation: very common entities (a domain controller that appears in
every logon, or a shared NAT address) produce many weak links. The analyst
can switch criteria off; there is no automatic weighting.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

from app.detection.model import EventRecord

Criterion = Literal["host", "user", "ip", "scenario"]
ALL_CRITERIA: frozenset[Criterion] = frozenset({"host", "user", "ip", "scenario"})


@dataclass(frozen=True)
class CorrelationReason:
    criterion: str  # host | user | ip | scenario | related_alert
    value: str
    description: str


@dataclass(frozen=True)
class CorrelatedEvent:
    event: EventRecord
    reasons: tuple[CorrelationReason, ...]
    relation: Literal["before", "during", "after"]
    offset_seconds: float  # distance to the seed time span (0 when inside it)

    def explanation(self) -> str:
        shared = "; ".join(reason.description for reason in self.reasons)
        return f"{shared}. {describe_offset(self.relation, self.offset_seconds)}."


@dataclass(frozen=True)
class Seed:
    first_seen: datetime
    last_seen: datetime
    hosts: frozenset[str]
    users: frozenset[str]
    ips: frozenset[str]
    scenarios: frozenset[str]

    @classmethod
    def from_events(cls, events: Sequence[EventRecord]) -> "Seed":
        if not events:
            raise ValueError("A correlation seed needs at least one event.")
        return cls(
            first_seen=min(e.timestamp for e in events),
            last_seen=max(e.timestamp for e in events),
            hosts=frozenset(e.hostname for e in events if e.hostname),
            users=frozenset(e.username.lower() for e in events if e.username),
            ips=frozenset(ip for e in events for ip in _ips(e)),
            scenarios=frozenset(e.scenario_id for e in events if e.scenario_id),
        )


def _ips(event: EventRecord) -> Iterable[str]:
    return (ip for ip in (event.source_ip, event.destination_ip) if ip)


def describe_offset(relation: str, seconds: float) -> str:
    if relation == "during":
        return "Occurred within the seed's time span"
    minutes = seconds / 60
    amount = f"{seconds:.0f} s" if seconds < 120 else f"{minutes:.0f} min"
    return f"Occurred {amount} {'before' if relation == 'before' else 'after'} the seed events"


def time_bounds(seed: Seed, window: timedelta) -> tuple[datetime, datetime]:
    return seed.first_seen - window, seed.last_seen + window


def correlate(
    seed_events: Sequence[EventRecord],
    candidates: Iterable[EventRecord],
    *,
    window: timedelta,
    criteria: frozenset[Criterion] = ALL_CRITERIA,
) -> list[CorrelatedEvent]:
    seed = Seed.from_events(seed_events)
    seed_ids = {e.event_id for e in seed_events}
    start, end = time_bounds(seed, window)

    results = []
    for event in candidates:
        if event.event_id in seed_ids or not start <= event.timestamp <= end:
            continue
        reasons = _reasons(event, seed, criteria)
        if not reasons:
            continue  # inside the window but sharing nothing: not correlated
        if event.timestamp < seed.first_seen:
            relation: Literal["before", "during", "after"] = "before"
            offset = (seed.first_seen - event.timestamp).total_seconds()
        elif event.timestamp > seed.last_seen:
            relation, offset = "after", (event.timestamp - seed.last_seen).total_seconds()
        else:
            relation, offset = "during", 0.0
        results.append(CorrelatedEvent(event, tuple(reasons), relation, offset))

    return sorted(results, key=lambda c: (c.event.timestamp, c.event.event_id))


def _reasons(
    event: EventRecord, seed: Seed, criteria: frozenset[Criterion]
) -> list[CorrelationReason]:
    reasons = []
    if "host" in criteria and event.hostname and event.hostname in seed.hosts:
        reasons.append(CorrelationReason("host", event.hostname, f"Same host {event.hostname}"))
    if "user" in criteria and event.username and event.username.lower() in seed.users:
        reasons.append(CorrelationReason("user", event.username, f"Same user {event.username}"))
    if "ip" in criteria:
        for ip in sorted(set(_ips(event)) & seed.ips):
            reasons.append(CorrelationReason("ip", ip, f"Same IP address {ip}"))
    if "scenario" in criteria and event.scenario_id and event.scenario_id in seed.scenarios:
        reasons.append(
            CorrelationReason("scenario", event.scenario_id, f"Same scenario {event.scenario_id}")
        )
    return reasons
