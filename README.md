# AEGIS Security Platform

**Detect. Investigate. Defend.**

AEGIS is a defensive security platform for security event analysis, rule-based
threat detection, incident investigation and detection engineering. It turns
raw security events into explainable detections and structured investigations,
and lets analysts practise incident response on synthetic data in a safe lab.

AEGIS is a learning and portfolio project. It is **not** an enterprise SIEM, has
no real-world validation, and is not hardened for exposure to the internet
(see [SECURITY.md](SECURITY.md)).

## Project status

Development happens in milestones. Only features listed as done exist; the UI
shows planned pages as disabled items tagged with their milestone (`M2`, `M3`, …).

| Milestone | Scope | Status |
| --- | --- | --- |
| 1 | Working foundation: FastAPI, React, SQLite, migrations, health checks | **Done** |
| 2 | Event pipeline: normalization, JSON/JSONL ingestion, search | **Done** |
| 3 | Detection engine: 8 deterministic rules with explanations | Planned |
| 4 | Alert and incident workflows, correlation, timelines | Planned |
| 5 | Overview dashboard and remaining UI | Planned |
| 6 | Scenario Lab (4 training scenarios) | Planned |
| 7 | Detection evaluation lab (precision / recall on labeled data) | Planned |
| 8 | Portfolio release: security review, Docker, docs, screenshots | Planned |

### What works today (Milestones 1–2)

**Event pipeline (Milestone 2)**

- Import security events as **JSON Lines** or **JSON** through the UI or
  `POST /api/v1/ingestion/batches`. The format is documented in
  [docs/EVENT_FORMAT.md](docs/EVENT_FORMAT.md).
- Normalization: UTC timestamps (ISO 8601 or epoch), field aliases from
  Sysmon and Windows Security (`Image`, `UtcTime`, `Computer`...), canonical
  IP addresses, `DOMAIN\user` splitting, lowercased host and process names.
  The original record is always kept unchanged.
- Per-record validation: bad records are rejected with their line number and
  the reason, and never crash the import or block the good records.
- De-duplication by stable event ID (taken from the source, or a SHA-256 of
  the record), so re-importing a file is safe.
- Request limits: 5 MiB body (enforced on the stream), 10,000 records,
  64 KiB per record.
- Event search: pagination; filters by time range, type, severity, host,
  user, source IP and data origin; case-insensitive text search.
- **Event Explorer** UI with shareable filter URLs, an event detail view that
  shows normalized fields next to the original record, and an import page
  with ingestion history.
- A deterministic **synthetic baseline dataset** (203 events, three office
  days, no attack activity) that loads with one click and is labelled
  `synthetic` everywhere.

**Foundation (Milestone 1)**

- FastAPI backend with an application factory, typed settings from environment
  variables, explicit CORS allow-list and basic security headers.
- SQLite database managed with Alembic migrations. Initial tables:
  `events` (normalized security events) and `ingestion_batches`.
- `GET /api/v1/health/live` (liveness) and `GET /api/v1/health` (database
  connectivity, migration state and stored-data counts).
- Consistent JSON error envelope; unexpected errors never expose stack traces.
- React + TypeScript frontend with the AEGIS layout and a working
  **System Health** page that reads the real health endpoint.
- Automated tests for both halves, plus lint and static type checks.

## Architecture

```
 Browser ──► Vite dev server (:5173) ──/api proxy──► FastAPI (:8000) ──► SQLite
             React + TypeScript                       SQLAlchemy + Alembic
```

The backend is a modular monolith: HTTP routes stay thin and call plain Python
services, which use SQLAlchemy models. See [ARCHITECTURE.md](ARCHITECTURE.md).

## Technology stack

| Area | Choice |
| --- | --- |
| Backend | Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2.1, Alembic, SQLite |
| Frontend | React 19, TypeScript 6, Vite 8, Tailwind CSS 4, React Router 7 |
| Testing | pytest, HTTPX (via FastAPI `TestClient`), Vitest, React Testing Library |
| Quality | Ruff (lint + format), mypy `--strict`, ESLint, `tsc` |
| CI | GitHub Actions (`.github/workflows/ci.yml`) |

Exact dependency versions are pinned in `backend/requirements*.txt` and
`frontend/package.json` / `package-lock.json`.

## Local development

Prerequisites: **Python 3.12+** and **Node.js 22.12+** (tested with Node 26).

### Backend

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements-dev.txt
alembic upgrade head                 # creates backend/data/aegis.db
uvicorn app.main:create_app --factory --reload
```

The API listens on http://127.0.0.1:8000. Interactive OpenAPI docs:
http://127.0.0.1:8000/docs.

### Frontend

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173. The dev server forwards `/api` to the backend, so
no CORS configuration is needed in development.

### Verify it works

1. Open http://localhost:5173. You land on the **Event Explorer**. With an
   empty database it offers **Load sample dataset**.
2. Load it. The page shows `Stored events: 203 synthetic`.
3. Search for `powershell`: four routine administrator commands appear.
   Open one to compare the normalized fields with the original Sysmon record.
4. **Import events → Upload a file** with
   [docs/examples/malformed-events.jsonl](docs/examples/malformed-events.jsonl).
   One record is stored, and the other seven are listed with the reason each
   was rejected.
5. **System Health** shows the stored-event count. Stop the backend and press
   **Refresh**: the page reports that the backend cannot be reached instead
   of showing stale data.

To start from an empty database again, stop the backend, delete
`backend/data/aegis.db` and run `alembic upgrade head`.

### Troubleshooting

- **`[WinError 10013]` or `address already in use` when starting the backend.**
  Another process already listens on port 8000, often an earlier backend that is
  still running. Find it with `netstat -ano | findstr :8000` (Windows) or
  `lsof -i :8000` (macOS/Linux) and stop it, or start AEGIS on another port
  (`--port 8001`) and set `AEGIS_BACKEND_URL=http://127.0.0.1:8001` for the
  frontend dev server.
- **`Port 5173 is in use`.** The Vite server uses a fixed port so the proxy and
  CORS settings stay valid. Stop the other process that holds the port.
- **`npm` is not recognized.** Open a new terminal after installing Node.js so
  the updated `PATH` is picked up.

### Configuration

All settings are environment variables prefixed with `AEGIS_`. See
[.env.example](.env.example).

## Tests and checks

```bash
cd backend
pytest                       # unit, API and migration tests
ruff check . && ruff format --check .
mypy app tests
```

```bash
cd frontend
npm test                     # Vitest + React Testing Library
npm run lint
npm run typecheck
npm run build
```

## Known limitations

- **No authentication.** Anyone who can reach the API can use it. Run it on
  localhost only.
- No detections, alerts or incidents yet (Milestones 3–4).
- Event import accepts JSON / JSON Lines only. There is no native `.evtx`,
  syslog or CEF parsing.
- Text search uses SQL `LIKE` over selected columns. It is fine for tens of
  thousands of events but is not a full-text index.
- Docker files are not included yet: Docker was unavailable in the development
  environment, and they will be added and tested in Milestone 8.
- The GitHub Actions workflow has not yet run on GitHub; it mirrors the local
  commands listed above.
- Running the backend tests prints a deprecation warning from Starlette
  recommending `httpx2` over `httpx` for its test client. Tests are unaffected.

## License

Not yet chosen. See the repository's LICENSE file once added.
