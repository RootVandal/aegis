from datetime import UTC, datetime, timedelta
from itertools import count
from typing import Any

from app.detection.model import EventRecord, Finding
from app.detection.registry import RULES_BY_ID
from app.ingestion.normalizer import normalize_record

T0 = datetime(2026, 10, 8, 9, 0, tzinfo=UTC)
_ids = count(1)


def rec(event_type: str, seconds: float = 0, **fields: Any) -> EventRecord:
    """An EventRecord for rule tests; IDs are unique and increase with creation order."""
    event_id = fields.pop("event_id", f"t-{next(_ids):05d}")
    return EventRecord(
        event_id=event_id,
        timestamp=T0 + timedelta(seconds=seconds),
        event_type=event_type,
        **fields,
    )


def proc(
    command: str, process: str = "powershell.exe", parent: str = "explorer.exe", **fields: Any
) -> EventRecord:
    return rec("process_creation", process_name=process, parent_process_name=parent,
               process_command_line=command, **fields)  # fmt: skip


def run(rule_id: str, events: list[EventRecord], **params: Any) -> list[Finding]:
    ordered = sorted(events, key=lambda e: (e.timestamp, e.event_id))
    return RULES_BY_ID[rule_id].run(ordered, params)


def from_raw(raw: dict[str, Any]) -> EventRecord:
    """Normalize a raw record exactly like ingestion does, then convert it."""
    n = normalize_record(raw)
    extra = n.normalized_fields.get("extra", {})
    return EventRecord(
        event_id=n.event_id,
        timestamp=n.timestamp,
        event_type=n.event_type,
        event_source=n.event_source,
        severity=n.severity,
        hostname=n.hostname,
        username=n.username,
        source_ip=n.source_ip,
        destination_ip=n.destination_ip,
        destination_port=n.destination_port,
        process_name=n.process_name,
        parent_process_name=n.parent_process_name,
        process_command_line=n.process_command_line,
        windows_event_id=n.windows_event_id,
        process_path=n.normalized_fields.get("process_path"),
        extra=extra,
    )
