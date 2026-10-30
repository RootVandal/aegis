"""Connects the pure detection engine to the database.

Flow: load stored events -> run every enabled rule -> store one alert per new
finding -> record the run (rules, versions, parameters, counts).

Every run evaluates *all* stored events. That keeps window-based rules
correct when related events arrive in different uploads, and it is fast
enough for the data sizes AEGIS targets (tens of thousands of events). It
would need to become incremental for much larger volumes.
"""

import hashlib
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import AppError
from app.db.base import utc_now
from app.detection.engine import RuleConfig, run_rules
from app.detection.explain import build_explanation
from app.detection.model import EventRecord, Finding
from app.detection.registry import RULES, RULES_BY_ID
from app.detection.rule import Rule
from app.models import Alert, DetectionRun, Event, RuleSetting
from app.models.enums import DetectionTrigger


def to_record(event: Event) -> EventRecord:
    fields = event.normalized_fields or {}
    extra = fields.get("extra")
    return EventRecord(
        event_id=event.event_id,
        timestamp=event.timestamp,
        event_type=event.event_type,
        event_source=event.event_source,
        severity=event.severity,
        hostname=event.hostname,
        username=event.username,
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        destination_port=event.destination_port,
        process_name=event.process_name,
        parent_process_name=event.parent_process_name,
        process_command_line=event.process_command_line,
        windows_event_id=event.windows_event_id,
        process_path=fields.get("process_path"),
        scenario_id=event.scenario_id,
        extra=extra if isinstance(extra, dict) else {},
    )


def fingerprint(finding: Finding) -> str:
    """Identity of an alert: the rule plus the exact events that triggered it.

    The rule *version* is deliberately excluded, so upgrading a rule does not
    re-raise alerts for evidence that analysts have already seen.
    """
    material = "\n".join((finding.rule_id, *finding.event_ids))
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def get_rule(rule_id: str) -> Rule[Any]:
    rule = RULES_BY_ID.get(rule_id)
    if rule is None:
        raise AppError(404, "rule_not_found", f"No detection rule with ID {rule_id!r}.")
    return rule


def rule_settings(session: Session) -> dict[str, RuleSetting]:
    return {s.rule_id: s for s in session.scalars(select(RuleSetting))}


def run_detection(session: Session, trigger: DetectionTrigger) -> DetectionRun:
    run = DetectionRun(trigger=trigger, started_at=utc_now())
    session.add(run)

    stored = list(session.scalars(select(Event).order_by(Event.timestamp, Event.id)))
    by_event_id = {event.event_id: event for event in stored}
    settings = rule_settings(session)
    configs = [
        RuleConfig(rule, settings[rule.id].params if rule.id in settings else {})
        for rule in RULES
        if rule.id not in settings or settings[rule.id].enabled
    ]

    results = run_rules((to_record(event) for event in stored), configs)
    known = set(session.scalars(select(Alert.fingerprint)))
    created = existing = findings_total = 0
    for result in results:
        for finding in result.findings:
            findings_total += 1
            alert_fingerprint = fingerprint(finding)
            if alert_fingerprint in known:
                existing += 1
                continue
            known.add(alert_fingerprint)
            created += 1
            session.add(
                Alert(
                    fingerprint=alert_fingerprint,
                    rule_id=result.rule.id,
                    rule_version=result.rule.version,
                    title=finding.title[:255],
                    severity=finding.severity,
                    first_seen=finding.first_seen,
                    last_seen=finding.last_seen,
                    hosts=finding.hosts,
                    users=finding.users,
                    ips=finding.ips,
                    explanation=build_explanation(result.rule, finding, result.effective_params),
                    rule_params=result.effective_params,
                    events=[by_event_id[event_id] for event_id in finding.event_ids],
                    detection_run=run,
                )
            )

    run.events_evaluated = len(stored)
    run.findings_count = findings_total
    run.alerts_created = created
    run.alerts_existing = existing
    run.rules = [
        {
            "rule_id": r.rule.id,
            "version": r.rule.version,
            "params": r.effective_params,
            "findings": len(r.findings),
        }
        for r in results
    ]
    run.completed_at = utc_now()
    session.commit()
    return run
