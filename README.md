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
| 2 | Event pipeline: normalization, JSON/JSONL ingestion, search | Planned |
| 3 | Detection engine: 8 deterministic rules with explanations | Planned |
| 4 | Alert and incident workflows, correlation, timelines | Planned |
| 5 | Overview dashboard and remaining UI | Planned |
| 6 | Scenario Lab (4 training scenarios) | Planned |
| 7 | Detection evaluation lab (precision / recall on labeled data) | Planned |
| 8 | Portfolio release: security review, Docker, docs, screenshots | Planned |

### What works today (Milestone 1)

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

1. Open http://localhost:5173. You land on **System Health**.
2. The top bar shows `API · OPERATIONAL`, and the Database row shows schema
   revision `0001`.
3. Stop the backend and press **Refresh**. The page reports that the backend
   cannot be reached instead of showing stale data.

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
- No event ingestion, detections, alerts or incidents yet (Milestones 2–4).
- Docker files are not included yet: Docker was unavailable in the development
  environment, and they will be added and tested in Milestone 8.
- The GitHub Actions workflow has not yet run on GitHub; it mirrors the local
  commands listed above.
- Running the backend tests prints a deprecation warning from Starlette
  recommending `httpx2` over `httpx` for its test client. Tests are unaffected.

## License

Not yet chosen. See the repository's LICENSE file once added.
