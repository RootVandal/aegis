"""Data types shared by the detection engine and its rules.

The engine works on these plain, immutable objects, not on ORM models, so
rules can be unit-tested by constructing events directly, without a database.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.models.enums import Severity


@dataclass(frozen=True)
class EventRecord:
    """A normalized event as seen by detection rules."""

    event_id: str
    timestamp: datetime
    event_type: str
    event_source: str = "test"
    severity: Severity = Severity.INFORMATIONAL
    hostname: str | None = None
    username: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    process_name: str | None = None
    parent_process_name: str | None = None
    process_command_line: str | None = None
    windows_event_id: int | None = None
    process_path: str | None = None
    extra: dict[str, Any] = field(default_factory=dict, hash=False, compare=False)

    def extra_text(self, *keys: str) -> str | None:
        """First non-empty extra field among ``keys`` (case-insensitive), as text."""
        lowered = {key.lower(): value for key, value in self.extra.items()}
        for key in keys:
            value = lowered.get(key.lower())
            if value is not None and str(value).strip():
                return str(value).strip()
        return None


@dataclass(frozen=True)
class Condition:
    """One satisfied condition, with the value actually observed."""

    description: str
    observed: str


@dataclass(frozen=True)
class Finding:
    """A single detection produced by a rule. Becomes (at most) one alert."""

    rule_id: str
    title: str
    severity: Severity
    summary: str
    events: tuple[EventRecord, ...]  # chronological; every event that supports the finding
    conditions: tuple[Condition, ...]
    mitre_ids: tuple[str, ...] = ()  # the rule's mappings that apply to *this* finding
    unknowns: tuple[str, ...] = ()  # finding-specific open questions

    @property
    def event_ids(self) -> tuple[str, ...]:
        return tuple(event.event_id for event in self.events)

    @property
    def first_seen(self) -> datetime:
        return self.events[0].timestamp

    @property
    def last_seen(self) -> datetime:
        return self.events[-1].timestamp

    @property
    def hosts(self) -> list[str]:
        return sorted({e.hostname for e in self.events if e.hostname})

    @property
    def users(self) -> list[str]:
        return sorted({e.username for e in self.events if e.username})

    @property
    def ips(self) -> list[str]:
        values = {e.source_ip for e in self.events} | {e.destination_ip for e in self.events}
        return sorted(v for v in values if v)


@dataclass(frozen=True)
class MitreTechnique:
    id: str
    name: str
    tactics: tuple[str, ...]

    @property
    def url(self) -> str:
        return "https://attack.mitre.org/techniques/" + self.id.replace(".", "/") + "/"


@dataclass(frozen=True)
class MitreMapping:
    """Why a rule relates to a technique, and where the relationship ends."""

    technique: MitreTechnique
    relationship: str
    telemetry: str
    limitations: str
