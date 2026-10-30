"""Normalize one raw record into the AEGIS event model.

Normalization happens in two explicit steps:

1. **Field mapping.** Known aliases from common log formats (``Image``,
   ``src_ip``, ``@timestamp``...) are mapped to canonical names. Unknown
   fields are kept verbatim under ``normalized_fields["extra"]``.
2. **Validation and cleanup.** A Pydantic model checks types and ranges and
   applies small, documented transformations (UTC timestamps, lowercase
   host and process names, canonical IP notation).

Anything invalid rejects the *whole record* with a message naming the field.
A partially stored event is worse than a clearly rejected one, because an
analyst could not tell which of its fields to trust. The original record is
always kept unchanged in ``raw_event``.

See docs/EVENT_FORMAT.md for the user-facing description of these rules.
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.models.enums import Severity

# Canonical field -> accepted source names, in priority order. The canonical
# name itself always wins when several are present.
FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "event_id": ("event_id", "eventId", "uid"),
    "timestamp": ("timestamp", "@timestamp", "time", "TimeCreated", "UtcTime"),
    "event_source": ("event_source", "source", "provider"),
    "event_type": ("event_type", "type"),
    "severity": ("severity", "level"),
    "hostname": ("hostname", "host", "Computer", "computer_name"),
    "username": ("username", "user", "User", "user_name", "TargetUserName"),
    "source_ip": ("source_ip", "src_ip", "SourceIp", "IpAddress"),
    "destination_ip": ("destination_ip", "dst_ip", "dest_ip", "DestinationIp"),
    "destination_port": ("destination_port", "dst_port", "dest_port", "DestinationPort"),
    "process_name": ("process_name", "process", "Image", "NewProcessName"),
    "parent_process_name": ("parent_process_name", "ParentImage", "ParentProcessName"),
    "process_command_line": ("process_command_line", "command_line", "CommandLine"),
    "windows_event_id": ("windows_event_id", "EventID", "event_code"),
    "scenario_id": ("scenario_id",),
}

SEVERITY_ALIASES = {
    "info": Severity.INFORMATIONAL,
    "information": Severity.INFORMATIONAL,
    "informational": Severity.INFORMATIONAL,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

EVENT_TYPE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
MIN_TIMESTAMP = datetime(1970, 1, 1, tzinfo=UTC)
MAX_TIMESTAMP = datetime(2100, 1, 1, tzinfo=UTC)


class RecordError(ValueError):
    """The record cannot be normalized. The message is safe to show to users."""


@dataclass
class NormalizedEvent:
    event_id: str
    timestamp: datetime
    event_source: str
    event_type: str
    severity: Severity
    hostname: str | None
    username: str | None
    source_ip: str | None
    destination_ip: str | None
    destination_port: int | None
    process_name: str | None
    parent_process_name: str | None
    process_command_line: str | None
    windows_event_id: int | None
    scenario_id: str | None
    raw_event: dict[str, Any]
    normalized_fields: dict[str, Any] = field(default_factory=dict)


def _blank_to_none(value: Any) -> Any:
    if isinstance(value, str):
        value = value.strip()
        return value or None
    return value


class _EventFields(BaseModel):
    """Validation rules for the canonical fields (step 2)."""

    model_config = ConfigDict(str_strip_whitespace=True)

    event_id: str | None = Field(default=None, max_length=128)
    timestamp: datetime
    event_source: str = Field(min_length=1, max_length=64)
    event_type: str = Field(min_length=1, max_length=64)
    severity: Severity = Severity.INFORMATIONAL
    hostname: str | None = Field(default=None, max_length=255)
    username: str | None = Field(default=None, max_length=255)
    source_ip: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    process_name: str | None = Field(default=None, max_length=512)
    parent_process_name: str | None = Field(default=None, max_length=512)
    process_command_line: str | None = Field(default=None, max_length=32_768)
    windows_event_id: int | None = Field(default=None, ge=0, le=65535)
    scenario_id: str | None = Field(default=None, max_length=64)

    @field_validator("*", mode="before")
    @classmethod
    def _empty_strings_are_missing(cls, value: Any) -> Any:
        return _blank_to_none(value)

    @field_validator("event_id", mode="before")
    @classmethod
    def _integer_ids_become_text(cls, value: Any) -> Any:
        # Many sources use numeric record IDs; store them as text.
        if isinstance(value, int) and not isinstance(value, bool):
            return str(value)
        if value is not None and not isinstance(value, str):
            raise ValueError("must be a string or an integer")
        return value

    @field_validator(
        "event_source",
        "event_type",
        "hostname",
        "username",
        "source_ip",
        "destination_ip",
        "process_name",
        "parent_process_name",
        "process_command_line",
        "scenario_id",
        mode="before",
    )
    @classmethod
    def _must_be_text(cls, value: Any) -> Any:
        # Pydantic would otherwise coerce numbers into strings silently in
        # some modes; for identity fields a number is almost always a mistake.
        if value is not None and not isinstance(value, str):
            raise ValueError("must be a string")
        return value

    @field_validator("destination_port", "windows_event_id", mode="before")
    @classmethod
    def _integer_not_bool(cls, value: Any) -> Any:
        # bool is a subclass of int in Python: refuse "port": true.
        if isinstance(value, bool):
            raise ValueError("must be an integer")
        return value

    @field_validator("severity", mode="before")
    @classmethod
    def _severity_alias(cls, value: Any) -> Any:
        if value is None or (isinstance(value, str) and not value.strip()):
            return Severity.INFORMATIONAL
        if isinstance(value, str) and value.strip().lower() in SEVERITY_ALIASES:
            return SEVERITY_ALIASES[value.strip().lower()]
        raise ValueError(f"must be one of: {', '.join(s.value for s in Severity)}")

    @field_validator("event_type", "event_source")
    @classmethod
    def _lower_identifier(cls, value: str) -> str:
        value = value.lower()
        if not EVENT_TYPE_PATTERN.match(value):
            raise ValueError("may contain only letters, digits, '_', '.' and '-'")
        return value

    @field_validator("hostname")
    @classmethod
    def _lower_hostname(cls, value: str | None) -> str | None:
        # Hostnames are case-insensitive; one spelling makes grouping reliable.
        return value.lower() if value else value

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def _canonical_ip(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            # Canonical text form, e.g. "2001:DB8:0::1" -> "2001:db8::1".
            return str(ip_address(value))
        except ValueError:
            raise ValueError("is not a valid IPv4 or IPv6 address") from None


def normalize_record(record: dict[str, Any]) -> NormalizedEvent:
    canonical, extra = _map_fields(record)
    notes: list[str] = []

    canonical["timestamp"] = _parse_timestamp(canonical.get("timestamp"), notes)

    try:
        fields = _EventFields.model_validate(canonical)
    except ValidationError as exc:
        raise RecordError(_describe(exc)) from None

    normalized_fields: dict[str, Any] = {}
    process_name, process_path = _split_process(fields.process_name)
    parent_name, parent_path = _split_process(fields.parent_process_name)
    if process_path:
        normalized_fields["process_path"] = process_path
    if parent_path:
        normalized_fields["parent_process_path"] = parent_path
    username, user_domain = _split_domain(fields.username)
    if user_domain:
        normalized_fields["user_domain"] = user_domain
    if extra:
        normalized_fields["extra"] = extra
    if notes:
        normalized_fields["notes"] = notes

    return NormalizedEvent(
        event_id=fields.event_id or derive_event_id(record),
        timestamp=fields.timestamp,
        event_source=fields.event_source,
        event_type=fields.event_type,
        severity=fields.severity,
        hostname=fields.hostname,
        username=username,
        source_ip=fields.source_ip,
        destination_ip=fields.destination_ip,
        destination_port=fields.destination_port,
        process_name=process_name,
        parent_process_name=parent_name,
        process_command_line=fields.process_command_line,
        windows_event_id=fields.windows_event_id,
        scenario_id=fields.scenario_id,
        raw_event=record,
        normalized_fields=normalized_fields,
    )


def derive_event_id(record: dict[str, Any]) -> str:
    """Stable ID for records that carry none: a hash of the canonical JSON.

    Key order and whitespace do not matter, so importing the same file twice
    (even re-formatted) produces the same IDs and is de-duplicated. Two
    genuinely different events that are byte-for-byte identical in content
    would collapse into one; that is an accepted limitation.
    """
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _map_fields(record: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    canonical: dict[str, Any] = {}
    used: set[str] = set()
    for name, aliases in FIELD_ALIASES.items():
        for alias in aliases:
            if alias not in record:
                continue
            used.add(alias)
            if record[alias] is None:
                continue  # an explicit null means "absent"; try the next alias
            canonical[name] = record[alias]
            break
    extra = {key: value for key, value in record.items() if key not in used}
    return canonical, extra


def _parse_timestamp(value: Any, notes: list[str]) -> datetime:
    if value is None or (isinstance(value, str) and not value.strip()):
        raise RecordError("timestamp: field is required")
    if isinstance(value, bool):
        raise RecordError("timestamp: must be an ISO 8601 string or a Unix epoch number")

    if isinstance(value, int | float):
        # Heuristic: values beyond year ~5138 in seconds are milliseconds.
        seconds = value / 1000 if abs(value) >= 100_000_000_000 else value
        try:
            parsed = datetime.fromtimestamp(seconds, tz=UTC)
        except (OverflowError, OSError, ValueError):
            raise RecordError("timestamp: epoch value is out of range") from None
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.strip())
        except ValueError:
            raise RecordError(f"timestamp: {value!r} is not an ISO 8601 date-time") from None
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            parsed = parsed.replace(tzinfo=UTC)
            notes.append("timestamp had no timezone; assumed UTC")
    else:
        raise RecordError("timestamp: must be an ISO 8601 string or a Unix epoch number")

    parsed = parsed.astimezone(UTC)
    if not MIN_TIMESTAMP <= parsed < MAX_TIMESTAMP:
        raise RecordError("timestamp: must be between 1970 and 2100")
    return parsed


def _split_process(value: str | None) -> tuple[str | None, str | None]:
    """'C:\\Windows\\System32\\cmd.exe' -> ('cmd.exe', original path).

    Detection rules match on the executable name, so the name is stored
    lowercased (Windows paths are case-insensitive). The full original path
    is kept in normalized_fields.
    """
    if value is None:
        return None, None
    name = re.split(r"[\\/]", value)[-1].lower()
    path = value if name != value.lower() else None
    return name or None, path


def _split_domain(value: str | None) -> tuple[str | None, str | None]:
    r"""'CORP\a.kowalski' -> ('a.kowalski', 'CORP').

    Windows sources disagree on whether the domain is included. Without this
    step the same person would appear as two different users and grouping
    by user (for example, failed logins per account) would silently break.
    """
    if value is None or "\\" not in value:
        return value, None
    domain, _, name = value.rpartition("\\")
    return (name or None), (domain or None)


def _describe(exc: ValidationError) -> str:
    messages = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error["loc"]) or "record"
        message = str(error["msg"]).removeprefix("Value error, ")
        if error["type"] == "missing":
            message = "field is required"
        messages.append(f"{location}: {message}")
    return "; ".join(messages)
