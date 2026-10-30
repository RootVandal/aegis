"""Small helper for writing scenario datasets readably.

Each method appends one raw event record and returns its ID, so a scenario's
answer key references the exact events it created instead of hand-typed IDs.
"""

from datetime import datetime, timedelta
from typing import Any


class EventLog:
    def __init__(self, prefix: str, start: datetime, scenario_tag: str) -> None:
        self.prefix = prefix
        self.start = start
        self.scenario_tag = scenario_tag
        self.records: list[dict[str, Any]] = []

    def add(self, minute: float, event_type: str, **fields: Any) -> str:
        event_id = f"{self.prefix}-{len(self.records) + 1:03d}"
        moment = self.start + timedelta(minutes=minute)
        self.records.append(
            {
                "event_id": event_id,
                "timestamp": moment.isoformat().replace("+00:00", "Z"),
                "event_source": fields.pop("event_source", "windows-security"),
                "event_type": event_type,
                "scenario_id": self.scenario_tag,
                **fields,
            }
        )
        return event_id

    def logon(
        self, minute: float, user: str, source_ip: str, host: str, ok: bool, **extra: Any
    ) -> str:
        return self.add(
            minute,
            "authentication_success" if ok else "authentication_failure",
            windows_event_id=4624 if ok else 4625,
            hostname=host,
            username=user,
            source_ip=source_ip,
            **extra,
        )

    def process(
        self, minute: float, host: str, user: str, image: str, parent: str, command: str
    ) -> str:
        return self.add(
            minute,
            "process_creation",
            event_source="sysmon",
            windows_event_id=1,
            hostname=host,
            username=user,
            process_name=image,
            parent_process_name=parent,
            process_command_line=command,
        )

    def connection(
        self, minute: float, host: str, user: str, image: str, destination: str, port: int
    ) -> str:
        return self.add(
            minute,
            "network_connection",
            event_source="sysmon",
            windows_event_id=3,
            hostname=host,
            username=user,
            process_name=image,
            destination_ip=destination,
            destination_port=port,
        )
