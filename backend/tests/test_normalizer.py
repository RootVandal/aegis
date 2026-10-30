from datetime import UTC, datetime
from typing import Any

import pytest

from app.ingestion.normalizer import RecordError, derive_event_id, normalize_record
from app.models.enums import Severity
from tests.conftest import event


def test_minimal_record_gets_defaults() -> None:
    normalized = normalize_record(event())

    assert normalized.severity is Severity.INFORMATIONAL
    assert normalized.hostname is None
    assert normalized.event_id.startswith("sha256:")
    assert normalized.normalized_fields == {}


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-10-01T12:00:00Z", datetime(2026, 10, 1, 12, tzinfo=UTC)),
        ("2026-10-01T15:00:00+03:00", datetime(2026, 10, 1, 12, tzinfo=UTC)),
        ("2026-10-01 12:00:00.250", datetime(2026, 10, 1, 12, 0, 0, 250_000, tzinfo=UTC)),
        (1_790_000_000, datetime.fromtimestamp(1_790_000_000, tz=UTC)),
        (1_790_000_000_500, datetime.fromtimestamp(1_790_000_000.5, tz=UTC)),
    ],
)
def test_timestamp_formats_normalize_to_utc(value: Any, expected: datetime) -> None:
    assert normalize_record(event(timestamp=value)).timestamp == expected


def test_timestamp_without_timezone_is_assumed_utc_and_flagged() -> None:
    normalized = normalize_record(event(timestamp="2026-10-01T12:00:00"))

    assert normalized.timestamp == datetime(2026, 10, 1, 12, tzinfo=UTC)
    assert normalized.normalized_fields["notes"] == ["timestamp had no timezone; assumed UTC"]


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (None, "timestamp: field is required"),
        ("", "timestamp: field is required"),
        ("yesterday", "not an ISO 8601 date-time"),
        (True, "must be an ISO 8601 string"),
        ({"t": 1}, "must be an ISO 8601 string"),
        ("1899-01-01T00:00:00Z", "between 1970 and 2100"),
        (10**20, "out of range"),
    ],
)
def test_invalid_timestamps_are_rejected(value: Any, message: str) -> None:
    with pytest.raises(RecordError, match=message):
        normalize_record(event(timestamp=value))


def test_aliases_from_other_log_formats_are_mapped() -> None:
    record = {
        "UtcTime": "2026-10-01 12:00:00.000",
        "source": "Sysmon",
        "type": "Process_Creation",
        "EventID": "1",
        "Computer": "WS-FIN-01",
        "User": "CORP\\a.kowalski",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.EXE",
        "ParentImage": "C:\\Windows\\explorer.exe",
        "CommandLine": "powershell.exe -NoProfile",
        "SourceIp": "10.0.0.5",
        "DestinationIp": "203.0.113.10",
        "DestinationPort": 443,
        "Protocol": "tcp",
    }

    normalized = normalize_record(record)

    assert normalized.event_source == "sysmon"
    assert normalized.event_type == "process_creation"
    assert normalized.windows_event_id == 1
    assert normalized.hostname == "ws-fin-01"
    assert normalized.username == "a.kowalski"
    assert normalized.process_name == "powershell.exe"
    assert normalized.parent_process_name == "explorer.exe"
    assert normalized.process_command_line == "powershell.exe -NoProfile"
    assert (normalized.source_ip, normalized.destination_ip) == ("10.0.0.5", "203.0.113.10")
    assert normalized.destination_port == 443
    assert normalized.normalized_fields["user_domain"] == "CORP"
    assert normalized.normalized_fields["process_path"] == record["Image"]
    assert normalized.normalized_fields["extra"] == {"Protocol": "tcp"}
    assert normalized.raw_event is record  # the original is stored untouched


def test_canonical_field_wins_over_alias() -> None:
    normalized = normalize_record(event(hostname="canonical", host="alias"))

    assert normalized.hostname == "canonical"
    assert normalized.normalized_fields["extra"] == {"host": "alias"}


def test_null_canonical_field_falls_back_to_alias() -> None:
    assert normalize_record(event(hostname=None, host="from-alias")).hostname == "from-alias"


def test_ipv6_addresses_are_written_canonically() -> None:
    assert normalize_record(event(source_ip="2001:DB8:0:0::1")).source_ip == "2001:db8::1"


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"source_ip": "999.1.1.1"}, "source_ip: is not a valid IPv4 or IPv6 address"),
        ({"destination_port": 70000}, "destination_port"),
        ({"destination_port": True}, "destination_port: must be an integer"),
        ({"severity": "apocalyptic"}, "severity: must be one of"),
        ({"hostname": 12345}, "hostname: must be a string"),
        ({"event_type": "Process Creation!"}, "event_type: may contain only"),
        ({"hostname": "h" * 256}, "hostname"),
        ({"event_type": None}, "event_type: field is required"),
    ],
)
def test_invalid_fields_reject_the_record_with_a_clear_message(
    fields: dict[str, Any], message: str
) -> None:
    with pytest.raises(RecordError, match=message):
        normalize_record(event(**fields))


def test_missing_required_fields_are_all_reported() -> None:
    with pytest.raises(RecordError) as excinfo:
        normalize_record({"timestamp": "2026-10-01T00:00:00Z"})

    assert "event_source: field is required" in str(excinfo.value)
    assert "event_type: field is required" in str(excinfo.value)


@pytest.mark.parametrize(("raw", "expected"), [("INFO", "informational"), (" High ", "high")])
def test_severity_aliases_are_case_insensitive(raw: str, expected: str) -> None:
    assert normalize_record(event(severity=raw)).severity == expected


def test_blank_strings_count_as_missing() -> None:
    normalized = normalize_record(event(hostname="   ", severity=""))

    assert normalized.hostname is None
    assert normalized.severity is Severity.INFORMATIONAL


def test_source_event_id_is_used_and_numbers_become_text() -> None:
    assert normalize_record(event(event_id="  abc-1 ")).event_id == "abc-1"
    assert normalize_record(event(event_id=4711)).event_id == "4711"


def test_derived_event_id_ignores_key_order() -> None:
    first = {"a": 1, "b": {"c": 2, "d": 3}}
    second = {"b": {"d": 3, "c": 2}, "a": 1}

    assert derive_event_id(first) == derive_event_id(second)
    assert derive_event_id(first) != derive_event_id({"a": 2, "b": {"c": 2, "d": 3}})
