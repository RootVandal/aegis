"""Run the labeled suite through the real normalizer and detection engine.

Every case is evaluated in isolation (its own events only) against every
rule, so cases cannot influence each other and each (rule, case) pair has
exactly one outcome. Pure and deterministic: no database, no clock.
"""

from collections import defaultdict
from collections.abc import Sequence
from typing import Any

from app.detection.engine import RuleConfig, run_rules
from app.detection.model import EventRecord
from app.evaluation.metrics import Counts, macro_average, summarize
from app.evaluation.suite import CASES, Case
from app.ingestion.normalizer import NormalizedEvent, RecordError, normalize_record


def _record(n: NormalizedEvent) -> EventRecord:
    fields = n.normalized_fields
    extra = fields.get("extra")
    return EventRecord(
        event_id=n.event_id,
        timestamp=n.timestamp,
        event_type=n.event_type,
        event_source=n.event_source,
        severity=n.severity,
        hostname=n.hostname,
        username=n.username,
        source_ip=n.source_ip,
        destination_ip=n.destination_ip,
        destination_port=n.destination_port,
        process_name=n.process_name,
        parent_process_name=n.parent_process_name,
        process_command_line=n.process_command_line,
        windows_event_id=n.windows_event_id,
        process_path=fields.get("process_path"),
        scenario_id=n.scenario_id,
        extra=extra if isinstance(extra, dict) else {},
    )


def _outcome(expected: bool, fired: bool) -> str:
    if fired:
        return "tp" if expected else "fp"
    return "fn" if expected else "tn"


def evaluate(configs: Sequence[RuleConfig], cases: Sequence[Case] = CASES) -> dict[str, Any]:
    rule_ids = sorted(c.rule.id for c in configs)
    counts: dict[str, Counts] = {rule_id: Counts() for rule_id in rule_ids}
    misses: dict[str, dict[str, list[str]]] = defaultdict(lambda: {"fp": [], "fn": []})
    case_results = []
    effective: dict[str, dict[str, Any]] = {}

    for case in cases:
        events, rejected = [], 0
        for raw in case.records:
            try:
                events.append(_record(normalize_record(dict(raw))))
            except RecordError:
                rejected += 1
        results = run_rules(events, configs) if events else []
        fired = {r.rule.id: len(r.findings) for r in results}
        for result in results:
            effective[result.rule.id] = {
                "version": result.rule.version,
                "params": result.effective_params,
            }

        outcomes = {}
        for rule_id in rule_ids:
            outcome = _outcome(rule_id in case.expected, fired.get(rule_id, 0) > 0)
            outcomes[rule_id] = outcome
            counts[rule_id] = counts[rule_id] + Counts(**{outcome: 1})
            if outcome in ("fp", "fn"):
                misses[rule_id][outcome].append(case.id)
        case_results.append(
            {
                "case_id": case.id,
                "category": case.category,
                "expected": sorted(case.expected),
                "fired": sorted(rule_id for rule_id, n in fired.items() if n > 0),
                "outcomes": outcomes,
                "records": len(case.records),
                "rejected": rejected,
                "input_handled_as_expected": rejected == case.expected_rejected,
            }
        )

    per_rule = {
        rule_id: {**summarize(counts[rule_id]), "fp_cases": misses[rule_id]["fp"],
                  "fn_cases": misses[rule_id]["fn"]}
        for rule_id in rule_ids
    }  # fmt: skip
    total = sum(counts.values(), Counts())
    macro = {
        name: macro_average(per_rule[r][name] for r in rule_ids)  # type: ignore[misc]
        for name in ("precision", "recall", "f1")
    }
    return {
        "per_rule": per_rule,
        "totals": {
            "micro": summarize(total),
            "macro": {name: {"value": value, "rules": n} for name, (value, n) in macro.items()},
        },
        "cases": case_results,
        "rules": effective,
        "input_handling_ok": all(c["input_handled_as_expected"] for c in case_results),
    }
