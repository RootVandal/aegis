"""Privilege escalation indicators: accounts added to privileged groups."""

import re
from collections.abc import Sequence

from pydantic import Field, field_validator

from app.detection.mitre import technique
from app.detection.model import Condition, EventRecord, Finding, MitreMapping
from app.detection.rule import Rule, RuleChange, RuleParams
from app.models.enums import Severity

# Windows: 4728 (global group), 4732 (local group), 4756 (universal group) =
# "A member was added to a security-enabled group".
GROUP_ADD_EVENT_IDS = frozenset({4728, 4732, 4756})

# net localgroup "Administrators" bob /add   |   net group "Domain Admins" bob /add /domain
NET_GROUP_ADD = re.compile(
    r"\bnet1?(?:\.exe)?\s+(?:local)?group\s+(?:\"([^\"]+)\"|(\S+))\s+(?:\"[^\"]+\"|\S+)\s+/add\b",
    re.IGNORECASE,
)
# Add-LocalGroupMember -Group "Administrators" ... | Add-ADGroupMember -Identity "Domain Admins" ...
PS_GROUP_ADD = re.compile(
    r"\badd-(?:local|ad)groupmember\b.*?-(?:group|identity)\s+(?:[\"']([^\"']+)[\"']|(\S+))",
    re.IGNORECASE,
)


class PrivilegeParams(RuleParams):
    privileged_groups: list[str] = Field(
        default=[
            "administrators",
            "domain admins",
            "enterprise admins",
            "schema admins",
            "backup operators",
            "account operators",
            "server operators",
        ],
        min_length=1,
        description="Group names (case-insensitive) treated as privileged.",
    )
    include_command_line: bool = Field(
        default=True, description="Also inspect process command lines (net group / PowerShell)."
    )

    @field_validator("privileged_groups")
    @classmethod
    def _normalize(cls, value: list[str]) -> list[str]:
        return sorted({group.strip().lower() for group in value if group.strip()})


class PrivilegeEscalationIndicators(Rule[PrivilegeParams]):
    id = "AEGIS-PRIV-001"
    name = "Privilege Escalation Indicators"
    version = 1
    description = (
        "An account was added, or a command tried to add an account, to a privileged group. "
        "This is an indicator of a privilege change, not proof of compromise."
    )
    severity = Severity.HIGH
    event_types = ("group_membership_change", "process_creation")
    required_fields = (
        "event_type or windows_event_id (4728/4732/4756)",
        "normalized_fields.extra.group_name (event path)",
        "process_command_line (command-line path)",
    )
    logic = (
        "Event path: a group_membership_change event (or Windows event 4728/4732/4756) "
        "whose extra field group_name is in `privileged_groups`.",
        "Command-line path (if include_command_line): a process command line that runs "
        "'net [local]group <privileged group> <account> /add' or "
        "Add-LocalGroupMember / Add-ADGroupMember with a privileged group.",
        "Each matching event is one finding.",
    )
    mitre = (
        MitreMapping(
            technique("T1098.007"),
            relationship="Adding an account to a privileged local or domain group is the "
            "behavior this sub-technique describes.",
            telemetry="Group membership change events (4728/4732/4756) or process command "
            "lines that perform the change.",
            limitations="Other ways to gain privileges (token theft, exploits, UAC bypass, "
            "service abuse) are not covered by this rule.",
        ),
    )
    investigation_steps = (
        "Confirm who made the change (actor) and which account was added (member).",
        "Check for a matching change ticket or administrator request.",
        "Review the added account: is it new, recently enabled, or a service account?",
        "Look at what the added account did after the change.",
        "If unauthorized, remove the membership and reset the affected credentials.",
    )
    false_positives = (
        "Planned administrative changes and onboarding of new administrators.",
        "Deployment scripts that grant local admin rights to support accounts.",
    )
    limitations = (
        "Group names are matched exactly (case-insensitive); localized names such as "
        "'Administratoren' must be added to privileged_groups.",
        "Nested group membership changes are not resolved.",
        "Command-line parsing covers the common net.exe and PowerShell forms only.",
    )
    unknowns = (
        "Whether the change was authorized.",
        "Whether the added account has since been used.",
    )
    changelog = (RuleChange(1, "2026-10-30", "Initial version."),)
    params_model = PrivilegeParams

    def evaluate(self, events: Sequence[EventRecord], params: PrivilegeParams) -> list[Finding]:
        privileged = set(params.privileged_groups)
        findings = []
        for event in events:
            is_group_event = (
                event.event_type == "group_membership_change"
                or event.windows_event_id in GROUP_ADD_EVENT_IDS
            )
            if is_group_event:
                group = event.extra_text("group_name", "TargetGroupName")
                if group and group.lower() in privileged:
                    member = event.extra_text("member_name", "MemberName") or "unknown account"
                    findings.append(
                        self._finding(
                            event,
                            group,
                            Condition(
                                "Group membership change event for a privileged group",
                                f"{member} added to '{group}' by {event.username or 'unknown'}",
                            ),
                        )
                    )
                continue
            if params.include_command_line and event.process_command_line:
                group = _commanded_group(event.process_command_line)
                if group and group.lower() in privileged:
                    findings.append(
                        self._finding(
                            event,
                            group,
                            Condition(
                                "Command line adds an account to a privileged group",
                                event.process_command_line,
                            ),
                        )
                    )
        return findings

    def _finding(self, event: EventRecord, group: str, condition: Condition) -> Finding:
        return Finding(
            rule_id=self.id,
            title=f"Account added to privileged group '{group}' on "
            f"{event.hostname or 'unknown host'}",
            severity=self.severity,
            summary=f"Membership of the privileged group '{group}' was changed.",
            events=(event,),
            conditions=(condition,),
            mitre_ids=("T1098.007",),
        )


def _commanded_group(command_line: str) -> str | None:
    for pattern in (NET_GROUP_ADD, PS_GROUP_ADD):
        match = pattern.search(command_line)
        if match:
            return match.group(1) or match.group(2)
    return None
