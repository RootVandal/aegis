"""Build the structured explanation shown with every alert.

Everything here is derived from the finding (its events and satisfied
conditions) and the rule's documented metadata. Nothing is generated or
guessed; no language model is involved.
"""

from typing import Any

from app.detection.mitre import ATTACK_VERSION
from app.detection.model import EventRecord, Finding
from app.detection.rule import Rule

DISCLAIMER = (
    "This alert is an indicator produced by a deterministic rule, not proof of "
    "compromise. ATT&CK mappings describe the behavior the rule may detect; they "
    "do not identify or attribute an adversary."
)


def describe_event(event: EventRecord) -> str:
    """One line describing what an event shows, from the fields it actually has."""
    parts = [event.event_type]
    if event.username:
        parts.append(f"user={event.username}")
    if event.hostname:
        parts.append(f"host={event.hostname}")
    if event.source_ip:
        parts.append(f"src={event.source_ip}")
    if event.destination_ip:
        port = f":{event.destination_port}" if event.destination_port is not None else ""
        parts.append(f"dst={event.destination_ip}{port}")
    if event.parent_process_name and event.process_name:
        parts.append(f"{event.parent_process_name} -> {event.process_name}")
    elif event.process_name:
        parts.append(f"process={event.process_name}")
    if event.process_command_line:
        parts.append(f"cmd={event.process_command_line}")
    return " ".join(parts)


def build_explanation(rule: Rule[Any], finding: Finding, params: dict[str, Any]) -> dict[str, Any]:
    mappings = [m for m in rule.mitre if m.technique.id in finding.mitre_ids]
    return {
        "what": f"{rule.description} {finding.summary}",
        "triggering_events": [
            {
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat(),
                "description": describe_event(event),
            }
            for event in finding.events
        ],
        "conditions": [
            {"description": c.description, "observed": c.observed} for c in finding.conditions
        ],
        "evidence": {
            "event_count": len(finding.events),
            "first_seen": finding.first_seen.isoformat(),
            "last_seen": finding.last_seen.isoformat(),
            "hosts": finding.hosts,
            "users": finding.users,
            "ips": finding.ips,
        },
        "unknowns": [*finding.unknowns, *rule.unknowns],
        "next_steps": list(rule.investigation_steps),
        "false_positives": list(rule.false_positives),
        "mitre": [
            {
                "id": m.technique.id,
                "name": m.technique.name,
                "tactics": list(m.technique.tactics),
                "url": m.technique.url,
                "relationship": m.relationship,
                "attack_version": ATTACK_VERSION,
            }
            for m in mappings
        ],
        "rule": {"id": rule.id, "name": rule.name, "version": rule.version, "params": params},
        "disclaimer": DISCLAIMER,
    }
