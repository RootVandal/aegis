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
| 3 | Detection engine: 8 deterministic rules with explanations | **Done** |
| 4 | Alert and incident workflows, correlation, timelines | **Done** |
| 5 | Overview dashboard and remaining UI | **Done** |
| 6 | Scenario Lab (4 training scenarios) | **Done** |
| 7 | Detection evaluation lab (precision / recall on labeled data) | Planned |
| 8 | Portfolio release: security review, Docker, docs, screenshots | Planned |

### What works today (Milestones 1–6)

**Scenario Lab (Milestone 6)**

- Four guided investigations on synthetic data, from beginner to advanced:
  account takeover through password guessing; a malicious macro document
  next to a benign finance macro; privilege escalation through a
  misconfigured service next to an authorized change; and a multi-stage
  intrusion (phishing → persistence → credential misuse → defense
  impairment → command and control).
- Each scenario has a briefing, objectives, questions, progressive hints,
  the detection rules involved, the intended reasoning and a discussion of
  false positives. The explanation stays hidden until you submit or choose
  to reveal it. Answers are not part of any API response before that.
- **Evidence-based grading.** You cite the events your conclusions rest on.
  The grade checks that the conclusions are correct, that the key evidence
  is cited, and that no benign lookalike is cited as evidence. Written
  reasoning is stored and shown next to the model reasoning, but it is not
  auto-graded (that would need a human or a language model). Time and
  hints are recorded but never scored.
- Scenario data goes through the normal ingestion and detection pipeline,
  so you investigate with the real tools (Event Explorer, alerts,
  Investigation). Drafts survive navigation.

**Overview dashboard (Milestone 5)**

- The landing page summarizes stored data, all computed from the database at
  request time: open and new alerts, open incidents, events and alerts in the
  selected range, events over time (split into synthetic and imported),
  alerts by severity, most frequently triggered rules, and recent alerts,
  incidents and ingestion activity.
- Time ranges (all time, last 30 days, 7 days, 24 hours) are anchored to the
  real current time. The page shows how old the newest event is and explains
  when a range is empty, instead of shifting the window to fit the data.
- "Now" metrics (open alerts, incidents) are kept apart from range-based ones.
- With an empty database it offers the bundled synthetic datasets. Nothing
  refreshes or animates by itself: no simulated live telemetry.
- Every figure links to the list behind it, and the chart has a table view.
- The event detail page lists the alerts that cite the event, so navigation
  works in both directions.

**Investigation workflow (Milestone 4)**

- **Alert triage:** validated status transitions (new → acknowledged →
  investigating → resolved / false positive), a required reason for closing
  or reopening, notes, full status history, title search and severity sort.
- **Explainable correlation:** the Investigation workspace shows events that
  share a host, user, IP address or scenario with an alert's evidence inside
  a chosen time window, with the reason for every link. Time proximity alone
  never links events.
- **Incidents:** create one from an alert (or several related alerts), link
  and unlink alerts, record events as evidence with a reason, and keep notes
  and *hypotheses*, which are always labeled as unverified.
- **Lifecycle** new → investigating → contained → resolved. An incident
  cannot be resolved without a verdict, a written assessment and a
  resolution summary; resolving closes its open alerts. Every significant
  change is kept in an append-only history.
- **Timeline** of each incident, showing why each event is there and which
  rules cited it, optionally extended with correlated events.
- **Incident report:** downloadable Markdown generated from the recorded
  data, with untrusted text escaped.

**Detection engine (Milestone 3)**

- Eight deterministic, explainable rules: failed logins, multi-account
  authentication (password spraying), suspicious PowerShell, privilege
  escalation indicators, suspicious process relationships, persistence
  changes, suspicious outbound connections and security configuration
  changes. The full catalog is in
  [docs/DETECTION_RULES.md](docs/DETECTION_RULES.md), generated from the
  rule code.
- Each rule documents its logic, required fields, investigation steps,
  false positives, limitations and version history. ATT&CK mappings were
  verified against attack.mitre.org (v20.0).
- Configurable thresholds and lists per rule, validated on save. Rules can
  be enabled and disabled.
- Detection runs automatically after every import (and on demand). Alerts
  are de-duplicated, so re-running never creates the same alert twice.
- Every alert carries a structured explanation built from its own evidence:
  what was detected, which events, which conditions, what is unknown, next
  steps and likely false positives. No language model is involved.
- A labeled **detection-lab** dataset with positive cases and lookalikes
  for every rule. The engine produces exactly the 19 expected findings on
  it, and none on the 203-event baseline.
- **Alerts** pages with the explanation of every alert.

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
| Frontend | React 19, TypeScript 6, Vite 8, Tailwind CSS 4, React Router 7, Recharts 3 |
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

1. Open http://localhost:5173. You land on the **Overview**. With an empty
   database it offers the sample datasets: load **baseline office activity**.
   The dashboard fills with 203 synthetic events and no alerts.
2. Open **Event Explorer**. It shows `Stored events: 203 synthetic`.
3. Search for `powershell`: four routine administrator commands appear.
   Open one to compare the normalized fields with the original Sysmon record.
4. **Import events → Upload a file** with
   [docs/examples/malformed-events.jsonl](docs/examples/malformed-events.jsonl).
   One record is stored, and the other seven are listed with the reason each
   was rejected.
5. Back on **Import events**, load **Detection lab (labeled)**. The result
   reports `19 new alert(s)`, and the baseline data from step 2 adds none.
6. Open **Alerts → 7 failed logins for user j.martin followed by a success**
   to read the seven-part explanation, then follow a triggering event into
   the Event Explorer.
7. On **Detection Rules → AEGIS-AUTH-001**, change `threshold` and press
   **Run detections now** to see the effect of tuning.
8. Open **Investigation**, pick alert #1, and read why each correlated event
   is linked. Tick the related password-spraying alert and press **Create
   incident**.
9. In the incident: move it to *investigating*, mark the successful logon
   (`syn-lab-008`) as evidence, add a hypothesis, record the final assessment,
   then move to *contained* and *resolved*. **Preview** shows the report.
10. Open **Scenario Lab → Suspicious process investigation → Start
    investigation**. Use the linked Event Explorer view and the alerts, cite
    the events you rely on, answer the questions, and submit. The assessment
    lists which objectives were met and explains every answer.
11. **System Health** shows the stored-event count. Stop the backend and press
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
- Notes, status changes and history record a free-text `author` label
  (default `analyst`), not an authenticated user.
- Correlation has no weighting: very common values (a domain controller, a
  shared NAT address) create many weak links. Criteria can be switched off.
- Detection re-evaluates all stored events on each run. That is simple and
  correct for tens of thousands of events, but would need an incremental
  design for large volumes.
- The rules are tuned for the synthetic datasets. Good results on synthetic
  data do not show how they would perform on real telemetry.
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
