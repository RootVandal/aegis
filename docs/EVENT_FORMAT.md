# AEGIS Event Import Format

AEGIS ingests security events as **JSON Lines** (one JSON object per line) or
as **JSON** (one object, or an array of objects). Every record is validated
and normalized independently. Valid records are stored, and invalid ones are
reported with their line number and the reason.

Examples:

- [`examples/sample-events.jsonl`](examples/sample-events.jsonl): valid
  records in several source styles.
- [`examples/malformed-events.jsonl`](examples/malformed-events.jsonl):
  one valid record followed by seven different kinds of invalid input.

## Sending events

| Method | How |
| --- | --- |
| UI | **Event Explorer → Import events**, choose a `.jsonl`, `.ndjson` or `.json` file. |
| API | `POST /api/v1/ingestion/batches` with the file as the raw request body. |

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/ingestion/batches?source_name=lab.jsonl" \
     -H "Content-Type: application/x-ndjson" \
     --data-binary @docs/examples/sample-events.jsonl
```

| Content-Type | Body |
| --- | --- |
| `application/x-ndjson` or `application/jsonl` | One JSON object per line. Blank lines are ignored. |
| `application/json` | A single JSON object, or an array of objects. |

Query parameters: `source_name` (a label shown in the ingestion history) and
`data_origin` (`imported` by default; `synthetic` for generated data).

The response describes the ingestion batch:

```json
{
  "batch": {"id": 3, "status": "partial", "received_count": 8, "accepted_count": 1,
            "duplicate_count": 0, "rejected_count": 7, "...": "..."},
  "rejections": [{"position": 2, "message": "timestamp: 'yesterday' is not an ISO 8601 date-time"}]
}
```

`received = accepted + duplicate + rejected` always holds. The `status` is
`completed` (nothing rejected), `partial` (some records rejected) or
`failed` (nothing usable). Only the first 100 rejection messages are
returned; the counts are always complete.

## Limits

| Limit | Default | Setting |
| --- | --- | --- |
| Request body | 5 MiB | `AEGIS_MAX_INGEST_BYTES` |
| Records per request | 10,000 | `AEGIS_MAX_INGEST_RECORDS` |
| Size of one record | 64 KiB | `AEGIS_MAX_RECORD_BYTES` |

The body limit is enforced while reading the stream, so a missing or false
`Content-Length` header cannot bypass it. Oversized requests receive
`413 payload_too_large` or `413 too_many_records`.

## Fields

Only three fields are required. Every other field is optional because real
sources fill in only the fields that apply to them.

| Field | Required | Accepted aliases | Normalization |
| --- | --- | --- | --- |
| `timestamp` | **yes** | `@timestamp`, `time`, `TimeCreated`, `UtcTime` | Converted to UTC (see below). |
| `event_source` | **yes** | `source`, `provider` | Lowercased. Letters, digits, `_ . -`. |
| `event_type` | **yes** | `type` | Lowercased. Letters, digits, `_ . -`. |
| `event_id` | no | `eventId`, `uid` | Used for de-duplication. Numbers are stored as text. |
| `severity` | no | `level` | `informational` (default, alias `info`), `low`, `medium`, `high`, `critical`. Case-insensitive. |
| `hostname` | no | `host`, `Computer`, `computer_name` | Lowercased. |
| `username` | no | `user`, `User`, `user_name`, `TargetUserName` | `DOMAIN\name` is split: `name` is stored, the domain goes to `normalized_fields.user_domain`. |
| `source_ip` | no | `src_ip`, `SourceIp`, `IpAddress` | Must be a valid IPv4/IPv6 address; stored in canonical form (`2001:DB8::0:1` → `2001:db8::1`). |
| `destination_ip` | no | `dst_ip`, `dest_ip`, `DestinationIp` | Same as `source_ip`. |
| `destination_port` | no | `dst_port`, `dest_port`, `DestinationPort` | Integer 0–65535. |
| `process_name` | no | `process`, `Image`, `NewProcessName` | A full path is reduced to the lowercased executable name; the original path goes to `normalized_fields.process_path`. |
| `parent_process_name` | no | `ParentImage`, `ParentProcessName` | As `process_name` (`parent_process_path`). |
| `process_command_line` | no | `command_line`, `CommandLine` | Stored verbatim (max 32 KiB). |
| `windows_event_id` | no | `EventID`, `event_code` | Integer 0–65535. |
| `scenario_id` | no | | Links events to a Scenario Lab exercise. |

When several names for the same field are present, the canonical name wins,
and the remaining names are kept under `normalized_fields.extra`. A field set
to `null` counts as absent. Empty strings count as absent too.

**Any other field** is stored unchanged under `normalized_fields.extra`, for
example `logon_type` or `action`. Nothing is silently dropped.

### Recommended `event_type` values

AEGIS accepts any `event_type` that matches the pattern above. The detection
rules (Milestone 3) look for these values:

`authentication_success`, `authentication_failure`, `logoff`,
`process_creation`, `network_connection`, `privilege_assignment`,
`scheduled_task_created`, `registry_modification`, `service_installed`,
`security_config_change`, `account_created`, `group_membership_change`.

### Timestamps

| Input | Interpretation |
| --- | --- |
| `"2026-10-05T08:15:00Z"`, `"2026-10-05T10:15:00+02:00"` | ISO 8601 with an offset, converted to UTC. |
| `"2026-10-05 08:15:00.120"` | No offset: **assumed to be UTC**, and the event gets the note `timestamp had no timezone; assumed UTC`. |
| `1791188700` | Unix epoch seconds. |
| `1791188700000` | Unix epoch milliseconds (values ≥ 10¹¹ are treated as milliseconds). |

Timestamps outside 1970–2100 are rejected.

Why assume UTC instead of rejecting? Sysmon's `UtcTime` and many exports
carry no zone designator, and rejecting them would make common data
unusable. The assumption is recorded on the event and shown in the UI, so
an analyst can always see that it was made.

## Validation errors

A record with **any** invalid field is rejected as a whole. Storing the valid
half of an event would leave an analyst unable to tell which fields to trust.
Typical messages:

```
timestamp: 'yesterday' is not an ISO 8601 date-time
source_ip: is not a valid IPv4 or IPv6 address
event_source: field is required
severity: must be one of: informational, low, medium, high, critical
Invalid JSON: Expecting property name enclosed in double quotes: line 1 column 2 (char 1)
Expected a JSON object.
Record is 70000 bytes; the limit is 65536 bytes.
```

Rejected for safety reasons as well: invalid UTF-8, `NaN` / `Infinity`
(not valid JSON), and deeply nested JSON. A UTF-8 byte-order mark at the
start of a file is accepted and ignored.

## De-duplication

Each event has a unique `event_id`:

1. If the record has an `event_id` (or alias), that value is used. **It must
   be unique across everything you import**, because a second record with the
   same ID is treated as a duplicate even if its content differs.
2. Otherwise AEGIS derives one: `sha256:` followed by the SHA-256 hash of the
   record's canonical JSON (keys sorted, whitespace removed). Re-importing the
   same file, even re-formatted, therefore produces no new events.
   Limitation: two genuinely separate events with byte-identical content
   collapse into one.

Duplicates are counted in `duplicate_count`, never stored twice, and never
reported as errors.

## What is stored

Each event keeps:

- the **normalized fields** above, used for search, filtering and detection;
- `normalized_fields`: derived values (`process_path`, `user_domain`), extra
  fields (`extra`) and normalization notes (`notes`);
- `raw_event`: **the original record exactly as received**, so the work of
  the normalizer can always be checked;
- `data_origin` (`synthetic` or `imported`) and the ingestion batch it came from.

## Not supported (yet)

- Native Windows `.evtx` files, syslog, CEF and CSV. Convert them to JSON Lines
  first. The ingestion layer separates parsing from normalization so that
  such parsers can be added later.
- Streaming or agent-based collection. AEGIS imports files and API requests only.
