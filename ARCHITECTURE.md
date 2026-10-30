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
| API | pytest + `TestClient` (HTTPX) | health states, error envelope, CORS, security headers |
| Frontend | Vitest + React Testing Library | API client error mapping; pages rendered against mocked `fetch` responses |

Backend tests run against real SQLite files created from the real migrations,
not mocks, so they exercise the same SQL the app runs.
