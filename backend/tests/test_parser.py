import json

import pytest

from app.ingestion.parser import BodyError, decode_body, parse_json, parse_jsonl

LIMIT = 1024


def test_jsonl_skips_blank_lines_and_keeps_line_numbers() -> None:
    text = '{"a": 1}\n\n   \n{"b": 2}\r\n'

    parsed = parse_jsonl(text, LIMIT)

    assert [(p.position, p.record) for p in parsed] == [(1, {"a": 1}), (4, {"b": 2})]


def test_jsonl_bad_line_does_not_hide_good_ones() -> None:
    parsed = parse_jsonl('{"ok": 1}\n{broken\n[1, 2]\n"text"\n{"ok": 2}', LIMIT)

    assert [p.record for p in parsed] == [{"ok": 1}, None, None, None, {"ok": 2}]
    assert parsed[1].error is not None and parsed[1].error.startswith("Invalid JSON")
    assert parsed[2].error == "Expected a JSON object."
    assert parsed[3].error == "Expected a JSON object."


def test_jsonl_does_not_split_on_unicode_line_separator() -> None:
    # U+2028 is legal inside a JSON string; str.splitlines() would break here.
    text = '{"msg": "first second"}'

    parsed = parse_jsonl(text, LIMIT)

    assert parsed[0].record == {"msg": "first second"}


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_non_standard_json_constants_are_rejected(constant: str) -> None:
    parsed = parse_jsonl(f'{{"value": {constant}}}', LIMIT)

    assert parsed[0].error is not None and "not allowed" in parsed[0].error


def test_deeply_nested_json_is_rejected_without_crashing() -> None:
    nested = '{"a": ' * 100_000 + "1" + "}" * 100_000

    parsed = parse_jsonl(nested, 10_000_000)

    assert parsed[0].error is not None and "nested too deeply" in parsed[0].error


def test_oversized_record_is_rejected() -> None:
    line = json.dumps({"blob": "x" * LIMIT})

    parsed = parse_jsonl(line, LIMIT)

    assert parsed[0].error is not None and "limit is 1024 bytes" in parsed[0].error


def test_json_accepts_single_object_or_array() -> None:
    assert [p.record for p in parse_json('{"a": 1}', LIMIT)] == [{"a": 1}]
    assert [p.record for p in parse_json('[{"a": 1}, {"b": 2}]', LIMIT)] == [{"a": 1}, {"b": 2}]


def test_json_array_reports_non_object_items_by_position() -> None:
    parsed = parse_json('[{"a": 1}, 42]', LIMIT)

    assert parsed[1].position == 2
    assert parsed[1].error == "Expected a JSON object."


def test_invalid_json_document_is_a_body_error() -> None:
    with pytest.raises(BodyError, match="not valid JSON"):
        parse_json("[{", LIMIT)


def test_utf8_bom_is_stripped() -> None:
    assert decode_body('﻿{"a": 1}'.encode()) == '{"a": 1}'


def test_invalid_utf8_is_a_body_error() -> None:
    with pytest.raises(BodyError, match="not valid UTF-8"):
        decode_body(b'{"a": "\xff"}')
