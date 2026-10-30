# Detection Evaluation

AEGIS measures its detection rules against a labeled test suite. This
document explains the method, shows the current results, and states what
the results can and cannot tell you.

Run it yourself: **Detection Testing → Run evaluation**, or
`POST /api/v1/evaluation/runs`. Every number comes from executing the rules
at that moment.

## Method

**Unit of evaluation.** A *case* is a small set of raw events (for example
"eight failed logons in two minutes"). Each case goes through the real
normalizer and detection engine **in isolation**, so cases cannot influence
each other. Every rule is evaluated on every case, which gives exactly one
outcome per (rule, case) pair:

| | Rule fired | Rule silent |
| --- | --- | --- |
| **Behavior present** (label) | TP | FN |
| **Behavior absent** | FP | TN |

**Labels describe reality, not the rules.** A case is labeled positive for a
rule when the behavior that rule targets is really present, even when the
rule is known to miss it. The suite deliberately contains known misses and
false alarms. A suite written to agree with the rules would report a
meaningless 100%.

**Categories** (51 cases):

| Category | Purpose |
| --- | --- |
| positive | The behavior is present and in scope for the rule. |
| benign | Ordinary activity. |
| lookalike | Resembles an attack but is legitimate (finance macro, SCCM, NAT). |
| edge | Thresholds and unusual-but-valid input (exactly 5 failures in 300 s, a Run-key deletion). |
| incomplete | A field the rule relies on is missing (no username, no command line, no image path). |
| gap | The behavior is present but outside what the rule can see (slow guessing, WMI indirection, C2 over 443). |
| malformed | Records the normalizer must reject. The run checks that they are rejected and never reach a rule. |

**Metrics.**

- precision = TP / (TP + FP): when the rule fires, how often it is right.
- recall = TP / (TP + FN): of the cases it should catch, how many it does.
- F1 = 2·TP / (2·TP + FP + FN).
- A metric with a zero denominator is **undefined**. It is reported as
  `null` (UI: "n/a"), never as 0% or 100%. A rule that never fired has no
  precision.
- *Micro* totals sum the counts over all rules, then compute the ratios
  once. *Macro* totals average the per-rule values that are defined, and
  report how many rules that is.
- TN is large because every case is also a negative for the rules it was
  not written for. Specificity would therefore be inflated, so it is not
  reported.

**Reproducibility.** A run stores the suite's content hash and every rule's
version and effective parameters. The same hash, versions and parameters
produce identical results, which is tested. Each run is compared with the
previous one, listing count changes, version changes and parameter changes.

**Regression testing.** `backend/tests/test_evaluation.py` pins the per-rule
TP/FP/FN/TN with default parameters. Any change in rule behavior fails the
test, and the snapshot may only be updated together with a rule version
bump and changelog entry.

## Current results (default parameters)

| Rule | TP | FP | FN | TN | Precision | Recall | F1 | False positives | Misses |
| --- | --: | --: | --: | --: | --: | --: | --: | --- | --- |
| AEGIS-AUTH-001 v1 | 4 | 1 | 2 | 44 | 80.0% | 66.7% | 72.7% | stale service password | slow guessing; missing username |
| AEGIS-AUTH-002 v1 | 1 | 1 | 1 | 48 | 50.0% | 50.0% | 50.0% | users behind NAT | spraying from many sources |
| AEGIS-DEF-001 v1 | 3 | 1 | 1 | 46 | 75.0% | 75.0% | 75.0% | Defender upgrade restart | `auditpol /clear` |
| AEGIS-EXEC-001 v1 | 2 | 1 | 2 | 46 | 66.7% | 50.0% | 57.1% | SCCM `-EncodedCommand` | string-concatenated IEX; missing command line |
| AEGIS-NET-001 v1 | 2 | 1 | 1 | 47 | 66.7% | 66.7% | 66.7% | admin module update | C2 over 443 from a non-script binary |
| AEGIS-PERS-001 v2 | 3 | 1 | 1 | 46 | 75.0% | 75.0% | 75.0% | vendor updater service | Startup-folder persistence |
| AEGIS-PRIV-001 v1 | 2 | 1 | 1 | 47 | 66.7% | 66.7% | 66.7% | authorized change with ticket | localized group name |
| AEGIS-PROC-001 v1 | 3 | 1 | 2 | 45 | 75.0% | 60.0% | 66.7% | finance workbook macro | WMI indirection; missing image path |
| **All rules (micro)** | 20 | 8 | 11 | 369 | **71.4%** | **64.5%** | **67.8%** | | |

Every false positive and miss is a documented limitation of the rule (see
[DETECTION_RULES.md](DETECTION_RULES.md)). They are left in place on
purpose. Several could be tuned away with parameters (`allowed_names`,
thresholds), which the comparison view makes visible.

### A finding that changed a rule

The first run showed AEGIS-PERS-001 flagging case `pers-run-key-removed`:
deleting a Run-key value was reported as persistence, although the rule
documented itself as "creation events only". Version 2 skips registry
events whose operation is a deletion. Rule precision on the suite went from
60% to 75%, and a regression test covers the case.

## What these numbers do not show

- **The data is synthetic and written alongside the rules.** The suite
  shows that the rules behave as designed, including where they are
  designed to fail. It says nothing about detection rates on real
  telemetry, where attacks and benign activity are far more varied.
- **The cases are small and isolated.** Real event streams interleave many
  users and hosts. Window-based rules (AUTH-001, AUTH-002, NET-001
  aggregation) can behave differently when unrelated events share a window.
- **51 cases are few.** One case moves a rule's precision or recall by tens
  of percentage points, so differences between rules are not statistically
  meaningful.
- **Labels are judgments.** "Is a stale service password password-guessing?"
  is a decision written into the suite. Another analyst might label some
  cases differently.
- **No adversarial testing.** The suite does not search for evasions; it
  contains a few known ones.
