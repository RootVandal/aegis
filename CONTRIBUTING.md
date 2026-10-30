# Contributing to AEGIS

Thanks for your interest. AEGIS is a learning and portfolio project, so the
bar is correctness, explainability and honest documentation rather than
feature count.

## Getting started

Follow **Local development** in the [README](README.md). Then, before
opening a pull request, run everything CI runs:

```bash
cd backend
ruff check . && ruff format --check .
mypy app tests
pytest
```

```bash
cd frontend
npm run lint
npm run typecheck
npm test
npm run build
```

## Ground rules

- **Never fake a result.** No placeholder data in implemented features, no
  invented metrics, no "TODO" in code that claims to work. If something is
  not implemented, say so in the UI and the docs.
- **Tests come with the change.** New behavior needs tests, and a bug fix
  needs a regression test that fails without the fix.
- **Keep layers apart.** Routes stay thin. Logic lives in services or in the
  pure packages (`detection`, `investigation`, `evaluation`, `scenarios`),
  which must not import FastAPI or touch the database.
- **Untrusted data stays untrusted.** Event fields are attacker-controlled:
  render them as text (`dangerouslySetInnerHTML` is banned by lint), escape
  them in reports, and never execute them.
- **Schema changes need a migration.** Run
  `alembic revision --autogenerate -m "..."`, review the file, and replace
  application types with plain SQLAlchemy types. `tests/test_migrations.py`
  fails if models and migrations drift.

## Changing a detection rule

Rule behavior is versioned and measured, so a rule change touches several
places on purpose:

1. Change the logic in `backend/app/detection/rules/`.
2. Bump the rule's `version` and add a `RuleChange` entry that says what
   changed and why.
3. Add or update rule tests (positive, negative, edge case).
4. Regenerate the catalog:
   `python -m app.detection.catalog > ../docs/DETECTION_RULES.md`.
5. Run `pytest tests/test_evaluation.py`. If the regression snapshot
   changes, update `EXPECTED_COUNTS` **and** the table in
   `docs/DETECTION_EVALUATION.md` (a test keeps them equal) and explain the
   change in your pull request.
6. Run the detection-lab tests: the labeled expectations in
   `app/sample_data/detection_lab.py` must still hold, or change with a reason.

### MITRE ATT&CK mappings

Only add a technique after checking its page on https://attack.mitre.org.
Record it in `backend/app/detection/mitre.py` with the exact name and
tactics, and update `ATTACK_VERSION` / `VERIFIED_ON` when re-verifying. If no
mapping can be justified, leave the rule unmapped.

## Labels in the evaluation suite

Labels in `backend/app/evaluation/suite.py` describe whether the behavior is
really present, **not** what the rules currently detect. Do not relabel a
case to make a rule look better; a known miss is a documented limitation.

## Commits and pull requests

- One logical change per commit, with a message that explains *why*.
- Pull requests describe what was verified and how (commands and results),
  plus anything not verified.
- Security issues: do not open a public issue; see [SECURITY.md](SECURITY.md).
