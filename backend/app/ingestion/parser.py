"""Turn an uploaded body into individual JSON records.

The parser knows nothing about security events: it only splits the input,
decodes JSON safely and reports *where* something went wrong. Each record is
parsed independently, so one bad line never hides the good ones.
"""

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class InputFormat(StrEnum):
    JSONL = "jsonl"  # one JSON object per line
    JSON = "json"  # a single object, or an array of objects


@dataclass(frozen=True)
class ParsedRecord:
    """One input record. Exactly one of ``record`` / ``error`` is set."""

    position: int  # 1-based line number (JSONL) or array index + 1 (JSON)
    record: dict[str, Any] | None = None
    error: str | None = None


class BodyError(ValueError):
    """The body as a whole is unusable (wrong encoding, not JSON at all...)."""


def _reject_constant(name: str) -> Any:
    # json.loads accepts NaN/Infinity by default, which are not valid JSON and
    # cannot be stored or compared reliably. Refuse them.
    raise ValueError(f"{name} is not allowed in JSON")


def _loads(text: str) -> Any:
    try:
        return json.loads(text, parse_constant=_reject_constant)
    except RecursionError:
        # Deeply nested input ([[[[...]]]]) exhausts the parser's recursion.
        raise ValueError("JSON is nested too deeply") from None


def decode_body(body: bytes) -> str:
    try:
        # utf-8-sig strips the byte-order mark Windows editors like to add.
        return body.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise BodyError(f"Body is not valid UTF-8 (byte offset {exc.start}).") from None


def parse_jsonl(text: str, max_record_bytes: int) -> list[ParsedRecord]:
    results: list[ParsedRecord] = []
    # Split on "\n" only. str.splitlines() would also split on characters such
    # as U+2028, which may legally appear inside a JSON string value.
    for line_number, raw_line in enumerate(text.split("\n"), start=1):
        line = raw_line.removesuffix("\r")
        if not line.strip():
            continue  # blank lines are allowed and ignored
        results.append(_parse_one(line, line_number, max_record_bytes))
    return results


def parse_json(text: str, max_record_bytes: int) -> list[ParsedRecord]:
    try:
        document = _loads(text)
    except ValueError as exc:
        raise BodyError(f"Body is not valid JSON: {exc}") from None

    items = document if isinstance(document, list) else [document]
    results: list[ParsedRecord] = []
    for index, item in enumerate(items, start=1):
        size = len(json.dumps(item, ensure_ascii=False).encode("utf-8"))
        if size > max_record_bytes:
            results.append(ParsedRecord(index, error=_too_large(size, max_record_bytes)))
        elif not isinstance(item, dict):
            results.append(ParsedRecord(index, error="Expected a JSON object."))
        else:
            results.append(ParsedRecord(index, record=item))
    return results


def _parse_one(line: str, position: int, max_record_bytes: int) -> ParsedRecord:
    size = len(line.encode("utf-8"))
    if size > max_record_bytes:
        return ParsedRecord(position, error=_too_large(size, max_record_bytes))
    try:
        value = _loads(line)
    except ValueError as exc:
        return ParsedRecord(position, error=f"Invalid JSON: {exc}")
    if not isinstance(value, dict):
        return ParsedRecord(position, error="Expected a JSON object.")
    return ParsedRecord(position, record=value)


def _too_large(size: int, limit: int) -> str:
    return f"Record is {size} bytes; the limit is {limit} bytes."
