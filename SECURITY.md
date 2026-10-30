# Security

AEGIS is a defensive security learning and portfolio project. This document
describes its security assumptions and current limitations.

## Intended use

- Run AEGIS **locally** (bound to `127.0.0.1`) for analysis, detection
  engineering and training on **synthetic** data.
- Do **not** expose it to the public internet or an untrusted network. There is
  no authentication.
- Do not load sensitive production logs into it. It is not designed for
  handling regulated or confidential data.

## Security assumptions

- The person running AEGIS is its only user.
- Event content is untrusted. Field values may contain HTML, scripts or
  control characters and are always rendered as escaped text.
- AEGIS never executes commands on monitored systems and never sends event data
  to external services.

## Controls in place

- Input validation through Pydantic models on every API endpoint.
- Database access only through SQLAlchemy (parameterized queries).
- A uniform error envelope. Unhandled exceptions return a generic message, and
  tracebacks stay in the server log.
- Validation errors do not reflect submitted input back to the client.
- An explicit CORS allow-list. Wildcard origins are rejected at startup.
- `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` and
  `Referrer-Policy: no-referrer` on API responses, plus
  `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` on
  `/api` responses (JSON never needs to load anything). The interactive
  `/docs` page is excluded because Swagger UI loads from a CDN.
- A request-body limit of 1 MiB on every endpoint except event ingestion,
  counted on the stream so a missing or false `Content-Length` cannot
  bypass it. Oversized requests get `413 payload_too_large`.
- Configuration comes only from environment variables, with no secrets in the
  repository (`.env` files are git-ignored; see `.env.example`).
- A frontend lint rule forbids `dangerouslySetInnerHTML`. Event content,
  including the raw record, is rendered as escaped text, and a test checks
  that a `<script>` in a command line stays inert.
- Event ingestion limits: 5 MiB per request (counted on the stream, so a
  false `Content-Length` cannot bypass it), 10,000 records and 64 KiB per
  record. Invalid UTF-8, `NaN` / `Infinity` and deeply nested JSON are
  rejected without crashing the parser.
- Search input is escaped before it is used in SQL `LIKE` patterns.
- Detection rules never execute anything: they only read stored events.
  Rule parameters are validated against each rule's schema, and ATT&CK
  mappings can only reference verified techniques.
- Evidence integrity: an event referenced by an alert or recorded as incident
  evidence cannot be deleted (database `RESTRICT` constraint). Alert
  explanations are stored as snapshots, and alert and incident histories are
  append-only through the API.
- Migrations verify referential integrity (`PRAGMA foreign_key_check`) after
  running, so a schema change cannot silently drop evidence links.
- Incident reports escape all Markdown/HTML-significant characters from
  event data and analyst text.

## Known limitations

- **No authentication or authorization.** The `author` recorded on notes,
  status changes and history is a client-supplied label, not a verified
  identity, so the audit trail is not trustworthy against a malicious user.
- No rate limiting.
- In local development the Vite dev server serves the frontend without a
  CSP (its hot-reload client needs inline scripts). The Docker setup's nginx
  configuration sets a strict CSP for the built app, but that setup has not
  been run (see the README).
- SQLite is a single local file with no encryption at rest.
- Dependencies are pinned and `npm ci` reported no known vulnerabilities at
  release time, but there is no automated dependency scanning.

## Deployment notes

The Docker Compose setup publishes the app on `127.0.0.1:8080` only and runs
the backend as an unprivileged user. Do not change the port binding to
`0.0.0.0` or put AEGIS behind a public reverse proxy: without authentication,
anyone who can reach it can read and change all data.

## Reporting a vulnerability

Please do not open a public issue for security problems. Contact the
maintainer privately through GitHub (a private security advisory on the
repository) with a description and steps to reproduce.
