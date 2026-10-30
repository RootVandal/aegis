# AEGIS demo

A walkthrough that shows every part of AEGIS on the bundled synthetic data.
It takes about 15 minutes and needs nothing beyond the
[local development setup](../README.md#local-development). Every number below
is what a fresh database produces; if yours differ, something is wrong.

All data in this demo is synthetic and labeled `synthetic` in the UI. No step
runs an attack or touches a real system.

## 0. Start from an empty database

```bash
cd backend
# stop the backend first if it is running
rm data/aegis.db            # Windows PowerShell: Remove-Item data\aegis.db
alembic upgrade head
uvicorn app.main:create_app --factory
```

In a second terminal: `cd frontend && npm run dev`, then open
http://localhost:5173.

## 1. Ingestion and normalization

1. The **Overview** is empty and offers the sample datasets. Load
   **baseline office activity**: 203 synthetic events, three office days,
   no attack activity, and **no alerts**.
2. **Event Explorer** shows `Stored events: 203 synthetic`. Search for
   `powershell`: four routine administrator commands. Open one to see the
   normalized fields next to the original Sysmon record.
3. **Import events → Upload a file** with
   [examples/malformed-events.jsonl](examples/malformed-events.jsonl).
   One record is stored; the other seven are listed with their line number
   and the reason each was rejected. The import does not fail as a whole.

*Point to make:* bad input is reported precisely and never blocks good
records; the raw record is always kept.

## 2. Detection

4. On **Import events**, load **Detection lab (labeled)**. Detection runs
   automatically and reports `19 new alert(s)`. The baseline data still adds
   none.
5. **Alerts → 7 failed logins for user j.martin followed by a success.**
   Read the explanation: what was detected, the triggering events, the
   conditions that matched, available evidence, what remains unknown, next
   steps and likely false positives. Follow a triggering event into the
   Event Explorer and back (the event page lists the alerts that cite it).
6. **Detection Rules → AEGIS-AUTH-001.** Logic, required fields, the
   verified ATT&CK mapping and its limits, false positives and change
   history. Set `threshold` to 9, save, and press **Run detections now**:
   the run finds 18 matches instead of 19 (no burst of failures reaches 9)
   and creates no alerts, because existing alerts are never duplicated. Set
   it back with **Reset to defaults**.

*Point to make:* every alert is explainable from its own evidence, built
deterministically, with no language model involved.

## 3. Investigation and incident response

7. **Investigation**, pick alert #1. Every correlated event shows *why* it
   is linked (shared host, user, IP address or scenario). Time proximity
   alone never links anything. Tick the related password-spraying alert
   (#2) and press **Create incident**.
8. In the incident: move it to *investigating*; on the timeline, mark the
   successful logon `syn-lab-008` as evidence with a reason; add a
   hypothesis (shown as *unverified*); record the verdict, assessment and
   resolution summary; then move to *contained* and *resolved*. Resolving
   closes both linked alerts.
9. **Preview** the report: Markdown generated from the recorded data, with
   untrusted text escaped. **Download** saves it.

*Point to make:* the lifecycle enforces discipline (no resolution without an
assessment) and the history is append-only.

## 4. Overview

10. Back on **Overview**: 261 stored events (260 synthetic: 203 baseline +
    57 detection lab; 1 imported: the valid record from the malformed file),
    alerts by severity, the most frequent rules and recent activity. Every
    figure links to the list behind it, and **Show as table** gives the
    chart's data. The ranges are anchored to the real current time, and the
    sample events are dated October 2026, so short ranges may be empty: the
    page says so instead of shifting the window to fit the data.

## 5. Scenario Lab

11. **Scenario Lab → Suspicious process investigation → Start
    investigation.** Read the briefing, use the linked Event Explorer view
    and the alerts, cite the events you rely on, answer the questions and
    submit. The assessment lists which objectives were met and explains each
    answer, including why the benign finance macro is not evidence. Citing
    the benign lookalike as evidence costs points.

*Point to make:* grading checks conclusions **and** the evidence behind
them, not speed.

## 6. Detection testing

12. **Detection Testing → Run evaluation.** 51 labeled cases, per-rule
    TP/FP/FN/TN, precision, recall and F1, and the misclassified cases with
    their records. With default parameters: precision 71.4%, recall 64.5%,
    F1 67.8%. The banner explains what these synthetic numbers do and do not
    show.
13. Set AEGIS-AUTH-001 `threshold` to 9 on its rule page, run the evaluation
    again, and read the comparison with the previous run: the stricter
    threshold misses every positive case for that rule (TP 4 → 0, FN 2 → 6),
    and overall recall drops from 64.5% to 51.6%. Reset it afterwards.

*Point to make:* tuning is measured, and the suite includes cases the rules
are known to miss.

## 7. Operations

14. **Settings** shows the server configuration (read-only), the request
    limits and the fact that there is no authentication.
15. **System Health** shows the schema revision and stored-data counts. Stop
    the backend and press **Refresh**: the page reports that the backend
    cannot be reached instead of showing stale data.
