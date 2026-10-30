# AEGIS Architecture

This document describes what exists **today** and the decisions behind it.
Sections for later milestones are added when those features are built.

## Overview

AEGIS is a modular monolith: one backend process, one database, one
single-page frontend. Nothing in the planned feature set (thousands, not
billions, of synthetic events) justifies message queues, caches or
microservices. Keeping one process makes the system easy to run, test and
reason about.

```
┌──────────── frontend/ (React SPA) ────────────┐
│ pages/      route-level screens               │
│ components/ layout, shared UI                 │
│ health/     shared health-check state         │
│ api/        typed HTTP client + DTO types     │
└───────────────────────┬───────────────────────┘
                        │ JSON over HTTP (/api/v1)
┌───────────────────────▼───────────────────────┐
│ backend/app/                                  │
│ api/routes/  thin FastAPI routers             │
│ schemas/     Pydantic request/response models │
│ services/    business logic, no HTTP types    │
│ models/      SQLAlchemy ORM tables            │
│ db/          engine, sessions, column types   │
│ core/        settings, error handling         │
└───────────────────────┬───────────────────────┘
                        │ SQLAlchemy
                    SQLite file (Alembic-managed schema)
```

### Layering rule

`routes → services → models`. Routes translate HTTP to Python calls and back;
services contain logic and know nothing about FastAPI. The detection engine
(Milestone 3) will be a pure-Python package on the same rule, so it can be
tested by passing it events directly and never through HTTP or the UI.

## Backend

### Application factory

`app.main.create_app(settings)` builds a fresh app with its own database
engine. Tests create one app per test against a temporary database, and
importing the module has no side effects. Uvicorn runs it with `--factory`.

### Configuration

`app.core.config.Settings` reads `AEGIS_*` environment variables (and an
optional `.env`). There are no secrets in source code. The CORS allow-list
refuses `*`.

### Errors

All errors use one envelope:

```json
{"error": {"code": "validation_error", "message": "...", "details": [...]}}
```

Validation errors report the location and reason but do not echo the
submitted input. Unhandled exceptions are logged with a traceback on the
server, and the client receives only `internal_error`.

### Data model (Milestone 1)

**`events`** stores one normalized security event:

| Column | Notes |
| --- | --- |
| `event_id` | Unique. Stable identifier used for de-duplication. |
| `timestamp` | When the event happened. Always stored as UTC. |
| `ingested_at` | When AEGIS stored it. |
| `event_source`, `event_type`, `severity` | Severity is a CHECK-constrained enum. |
| `hostname`, `username`, `source_ip`, `destination_ip`, `destination_port` | Optional entity fields. |
| `process_name`, `parent_process_name`, `process_command_line`, `windows_event_id` | Optional process telemetry. |
| `raw_event` | The original record, unchanged. Analysts can always see what the normalizer did. |
| `normalized_fields` | Source-specific extra fields. |
| `data_origin` | `synthetic` or `imported`. Shown wherever data is displayed. |
| `scenario_id` | Links training-scenario events (Milestone 6). |
| `batch_id` | The ingestion batch that produced the event (nullable, `ON DELETE SET NULL`). |

**`ingestion_batches`** records one import run with received, accepted,
duplicate and rejected counts, so skipped records are always accounted for.

Telemetry fields are nullable because real sources fill in only the fields
that apply to them. An authentication event has no parent process.

### Timestamps

SQLite has no timezone-aware datetime type. The `UTCDateTime` column type
(`app/db/base.py`) therefore:

- rejects naive datetimes, because an unknown zone is a correctness bug in a
  timeline;
- converts aware values to UTC before storing them;
- returns values tagged as UTC.

The frontend displays all timestamps in UTC.

### Migrations

Alembic owns the schema, and the app never calls `create_all()`. Migrations
run in batch mode (required for SQLite `ALTER`) and do not import application
code, so old migrations keep working when the models change. A test
(`tests/test_migrations.py`) fails if the models and migrations drift apart.

### Health endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /api/v1/health/live` | Process is up. No database access. Suitable for container liveness probes. |
| `GET /api/v1/health` | Database reachable? Schema at the expected migration? How much data is stored? |

`/health` always answers 200 and puts the state (`ok`, `degraded`, `error`)
in the body, so the UI can explain *why* something is wrong. When the schema
is not current, the data counts are `null` rather than a misleading zero.

## Event pipeline (Milestone 2)

```
request body ─► parser ─► normalizer ─► ingestion service ─► events table
 (bytes)        records    NormalizedEvent   de-dup + batch      + ingestion_batches
```

| Stage | Module | Responsibility |
| --- | --- | --- |
| Transport | `api/routes/ingestion.py` | Content type, streamed body-size limit, record-count limit. |
| Parsing | `ingestion/parser.py` | Bytes → JSON objects. UTF-8 (BOM-tolerant), one result per line, safe against `NaN`, deep nesting and oversized records. Knows nothing about events. |
| Normalization | `ingestion/normalizer.py` | Alias mapping, then a Pydantic model for types and ranges, then documented transformations (UTC, canonical IPs, `DOMAIN\user`, process path → name). Any invalid field rejects the whole record with a field-level message. |
| Storage | `ingestion/service.py` | De-duplication against the database and within the batch, insert, and batch counters (`received = accepted + duplicate + rejected`). |

The stages are separate so each can be tested alone, and so new input
formats (EVTX, syslog, CSV) only need a new parser that produces records for
the same normalizer.

The bundled datasets (`app/sample_data/`) go through the same normalizer
and storage path as uploads. The baseline generator uses a fixed seed and a
fixed start date, so it produces identical events and IDs on every run.

**Search** (`services/event_query.py`) combines filters with AND. It uses
offset pagination ordered by `(timestamp, id)` so pages stay stable, and a
case-insensitive `LIKE` over an explicit list of columns. User input is
escaped so `%` and `_` match literally. Unknown query parameters are
rejected (422) instead of being ignored.

## Detection engine (Milestone 3)

```
events table ─► EventRecord list ─► run_rules() ─► findings ─► alerts (+ alert_events links)
                (sorted by time, id)  pure Python    per rule    fingerprint de-dup, explanation snapshot
```

| Module | Responsibility |
| --- | --- |
| `detection/model.py` | Immutable `EventRecord`, `Finding`, `Condition` and MITRE types. Rules never see ORM objects. |
| `detection/rule.py` | `Rule` base class (metadata and `evaluate`), parameter models, and `greedy_windows`, which splits sorted events into deterministic, non-overlapping bursts. |
| `detection/rules/*.py` | The eight rules. Each is a class whose docstring-like attributes are its documentation. |
| `detection/mitre.py` | The only place technique IDs live, each verified against attack.mitre.org. Rules reference techniques through it, so an unverified ID cannot appear. |
| `detection/engine.py` | Sorts events by `(timestamp, event_id)` and runs the configured rules. |
| `detection/explain.py` | Builds the seven-part alert explanation from a finding and its rule. |
| `services/detection.py` | Loads events, applies rule settings, stores new alerts, records the run. |

**Determinism.** Rules have no access to the clock, randomness or the
database. Events are sorted with a tie-breaker, so equal timestamps cannot
reorder evidence. Tests run the engine on shuffled input and compare.

**Configuration.** Each rule declares a Pydantic parameter model
(`extra="forbid"`, ranges, enums). Users store *overrides* only
(`rule_settings` table); defaults stay in code, so a new rule version can
improve a default without touching tuned values.

**Versioning.** Every rule has a `version` and a changelog. Alerts store the
version, the effective parameters and the explanation that existed when
they were created. Changing a rule later never rewrites history.

**De-duplication.** An alert's fingerprint is SHA-256 of the rule ID plus the
triggering event IDs. Re-running detection counts existing findings instead
of duplicating them. The rule version is excluded on purpose, so a rule
upgrade does not re-raise evidence analysts have already seen. Changing a
threshold can produce a new, overlapping alert, because the evidence set
differs.

**When detection runs.** It runs after every ingestion batch that stored new
events (`AEGIS_AUTO_DETECT`), and on demand (`POST /api/v1/detections/runs`).
Each run evaluates all stored events, so patterns that span two uploads are
still found.

### Data model additions

| Table | Purpose |
| --- | --- |
| `alerts` | Rule, version, severity, status (`new` for now), time span, hosts/users/IPs, explanation and parameter snapshots, fingerprint (unique). |
| `alert_events` | Alert ↔ event links. `ON DELETE CASCADE` from the alert, `RESTRICT` from the event: an event that is evidence for an alert cannot be deleted. |
| `detection_runs` | Trigger, counts, and per-rule version/parameters/findings, which make each run reproducible. |
| `rule_settings` | Enabled flag and parameter overrides per rule. |

## Investigation workflow (Milestone 4)

All state changes go through `app/investigation/workflow.py`, so the rules
live in one place and route handlers stay thin.

### Alert lifecycle

```
new ──► acknowledged ──► investigating ──► resolved
 │            │                │    └────► false_positive
 └────────────┴────────────────┴─────────► resolved / false_positive
resolved / false_positive ──(reopen, reason required)──► investigating
```

- Closing (`resolved`, `false_positive`) or reopening requires a reason.
- Every change is stored in `alert_status_changes` (from, to, reason,
  author, time). Notes are stored in `alert_notes`.
- Linking a `new` or `acknowledged` alert to an incident moves it to
  `investigating`. Resolving the incident closes its still-open alerts:
  `false_positive` when the verdict is false positive, otherwise `resolved`.
- Status changes never touch the alert's evidence links.

### Incident lifecycle

```
new ──► investigating ──► contained ──► resolved
              │  ▲             │            │
              │  └─────────────┘            │
              └─────────────► resolved      └──(reopen)──► investigating
```

- Resolving requires a recorded **final assessment**: a verdict
  (`true_positive`, `benign_activity`, `false_positive`, `inconclusive`),
  the reasoning and evidence, and a resolution summary. This enforces the
  Milestone 4 acceptance criterion: an investigation ends with a documented
  assessment.
- Reopening keeps the assessment and clears `resolved_at`.
- An alert belongs to at most one incident (`alerts.incident_id`).
- Evidence (`incident_evidence`) links an event with the reason it matters,
  using `ON DELETE RESTRICT`.
- Notes have a kind: `note` or `hypothesis`. Hypotheses are labeled
  "unverified" in the UI and the report, so an analyst's guess is never
  presented as fact.
- `incident_history` is append-only and records creation, status changes,
  linked or unlinked alerts, evidence, notes and assessments.

### Correlation

`app/investigation/correlation.py` is a pure function, like the detection
engine. Given seed events (an alert's evidence or an incident's events):

1. Only events within `window` before the first or after the last seed
   event are considered. **Time is a filter, never a reason.**
2. An event is correlated only if it shares at least one selected entity:
   host, user (case-insensitive), IP address (source or destination), or
   scenario ID.
3. Every result lists its reasons (criterion and shared value) and its
   position in time (before, during or after the seed, and how far).

The API adds *related alerts*: other alerts that cite a correlated event.
This covers the "related detection rules" criterion.

Limitations: there is no weighting or rarity scoring. A busy domain
controller or a shared NAT address links many events weakly, so the
analyst narrows the result with the criteria toggles.

### Timeline and report

The incident timeline merges alert evidence, recorded evidence and
(optionally) correlated events, ordered by `(timestamp, event_id)`. Each
entry states why it is present and which rules alerted on it. The Markdown
report is generated from the stored data only. Every value is escaped,
because event and note text is untrusted and could otherwise inject links
or HTML into a rendered report.

### Migrations and data integrity

SQLite cannot alter most constraints in place. Alembic's batch mode rebuilds
the table instead (copy, `DROP`, rename). With foreign keys enforced, that
`DROP` would fire `ON DELETE CASCADE` and silently delete child rows. This
was found in Milestone 4 while adding `alerts.incident_id`. Migrations
therefore run with enforcement off and finish with `PRAGMA
foreign_key_check`, failing loudly on any violation.
`tests/test_migrations.py` upgrades a populated database to guard this.

## Overview dashboard (Milestone 5)

`GET /api/v1/dashboard?range=all|30d|7d|24h` (`services/dashboard.py`)
computes everything per request with aggregate SQL. Nothing is cached or
precomputed, so the numbers always agree with the lists they link to.

- **Two kinds of metric.** *Current state* (new/open alerts, open incidents)
  ignores the range. *In range* (events, alerts raised, severity mix, top
  rules, events over time) uses it. Alerts fall into a range by the time of
  their evidence (`last_seen`), not by when detection ran.
- **Ranges are anchored to now.** The window is never moved to where the data
  happens to be. The response includes the newest event time, so the UI can
  explain an empty range (for example, synthetic data from three weeks ago).
- **Events over time.** Buckets are hours (span ≤ 2 days), days (≤ 120 days)
  or months, computed with SQLite `strftime`. Empty buckets are filled with
  zeros so a gap on the axis means "no events". This is SQLite-specific SQL,
  isolated in one function.
- **Charts.** Recharts renders the time series as stacked columns
  (synthetic vs. imported). The colors are two validated categorical slots
  (CVD ΔE 26.8 against the panel surface); a legend, tooltip and table view
  mean color is never the only channel. Severity and rule counts are
  single-hue bars, with identity carried by the label beside each bar. A
  multi-hue severity palette was checked and rejected: high and medium were
  too close (ΔE 13.6).

## Scenario Lab (Milestone 6)

| Module | Responsibility |
| --- | --- |
| `scenarios/model.py` | `Scenario` definition and `grade()`, a pure function from a submission to an explainable evaluation. |
| `scenarios/builder.py` | Writes scenario datasets. Each helper returns the new event's ID, so answer keys reference real events. |
| `scenarios/catalog.py` | The four scenarios: data, briefing, questions, evidence key, hints, reasoning. |
| `scenarios/service.py` | Loading data (normal ingestion + detection, idempotent), attempts, hints, submit, reveal. |

**Evidence key.** *Required* evidence is a list of groups (citing any event
of a group satisfies it, e.g. one of three beacon connections). *Supporting*
events may be cited freely. *Decoys* look suspicious but have a benign
explanation; citing one fails the "avoid misleading evidence" objective.
The grade has five objectives: answer every question, correct
conclusions, key evidence cited, no decoy cited, and a written rationale.
The rationale is stored for self-review and is not judged automatically.

**No leaks by construction.** The public schemas (`ScenarioDetail`,
`AttemptOut` while in progress) have no fields for answers, explanations,
the evidence key or the reasoning. `SolutionOut` is attached only to closed
attempts. A test scans every pre-submission response of every scenario for
any of that text.

**Isolation.** Each scenario's events carry `scenario_id = lab-<id>` and sit
on their own September 2026 day, so scenarios do not correlate with each
other or with the baseline and detection-lab data. Consistency tests check
that every key references real events, that the evidence sets are disjoint,
that every listed rule fires on the data, and that addresses are private or
RFC 5737 documentation ranges.

**Attempts** (`scenario_attempts`) are closed by submitting (graded) or by
revealing (no grade). A new attempt can always be started. The UI keeps the
in-progress draft in `localStorage` so it survives navigating to the
investigation tools; this is a per-browser convenience, not stored state.

## Detection evaluation (Milestone 7)

| Module | Responsibility |
| --- | --- |
| `evaluation/suite.py` | The labeled cases and the suite's content hash (`dataset_version`). |
| `evaluation/runner.py` | Normalizes each case's records, runs every rule on each case in isolation, maps results to TP/FP/FN/TN. Pure. |
| `evaluation/metrics.py` | Precision, recall, F1 with `None` for undefined values; micro and macro totals. |
| `api/routes/evaluation.py` | Runs, stores (`evaluation_runs`) and compares with the previous run. |

Design choices, explained in [docs/DETECTION_EVALUATION.md](docs/DETECTION_EVALUATION.md):
cases are isolated so outcomes are independent; labels describe reality,
not rule behavior; undefined metrics are never shown as numbers; every rule
is evaluated, including disabled ones. A regression snapshot in the tests
pins each rule's counts, and a second test keeps the published results
table in sync with that snapshot.

## Frontend

- **Routing.** React Router. `src/navigation.ts` is the single list of pages.
  Pages that are not built yet render as disabled sidebar items with their
  milestone. They are never links to empty screens.
- **API access.** `src/api/client.ts` turns every failure into an `ApiError`.
  "Backend unreachable" (network failure, or a proxy answering 502/503/504
  without the AEGIS error envelope) is kept distinct from "backend returned
  an error".
- **Health state.** `HealthProvider` runs one health check shared by the top
  bar and the System Health page. It re-checks every 30 seconds with a
  `setTimeout` chain, so requests never overlap, and on demand through the
  Refresh button. A failed check clears the previous data instead of leaving
  stale "OK" values on screen.
- **Untrusted content.** Event data will contain attacker-controlled strings.
  React escapes text by default, and an ESLint rule forbids
  `dangerouslySetInnerHTML` across the codebase.

## Testing strategy

| Layer | Tool | What is tested |
| --- | --- | --- |
| Models / DB | pytest + real SQLite | UTC handling, uniqueness, CHECK constraints, evidence kept on batch delete |
| Migrations | pytest + Alembic | upgrade/downgrade work; schema matches the models |
| Parsing / normalization | pytest | every alias, timestamp format, invalid-field message, de-dup ID stability |
| API | pytest + `TestClient` (HTTPX) | health states, error envelope, CORS, security headers, ingestion limits, filters, search escaping |
| Detection rules | pytest on `EventRecord`s | positive, negative and edge cases per rule; thresholds and windows; parameter validation; labeled dataset gives exactly the expected findings; baseline gives none; order independence; documentation completeness; generated catalog is up to date |
| Investigation | pytest | alert/incident transitions and required reasons/assessment; correlation criteria, window bounds and "time alone never correlates"; timeline sources; report escaping; an end-to-end acceptance test from alert to resolved incident |
| Frontend | Vitest + React Testing Library | API client error mapping; Event Explorer filters, pagination, empty states, import flow and escaping of hostile content; rule configuration and alert explanations; alert triage, investigation workspace and incident workflow, against a path-routing `fetch` mock |

Backend tests run against real SQLite files created from the real migrations,
not mocks, so they exercise the same SQL the app runs.
