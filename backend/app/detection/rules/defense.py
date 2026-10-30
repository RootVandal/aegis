"""Changes that weaken security controls: AV/EDR, firewall, event logs."""

from collections.abc import Sequence

from pydantic import Field, field_validator

from app.detection.mitre import technique
from app.detection.model import Condition, EventRecord, Finding, MitreMapping
from app.detection.rule import Rule, RuleChange, RuleParams
from app.detection.rules.indicators import Indicator, indicator, matches
from app.models.enums import Severity

# Windows 1102: the Security log was cleared. 104: another event log was cleared.
LOG_CLEARED_EVENT_IDS = frozenset({1102, 104})
DISABLED_STATES = frozenset({"disabled", "off", "false", "0", "stopped"})

COMMAND_INDICATORS: tuple[Indicator, ...] = (
    indicator(
        "defender_disable",
        "Disables Microsoft Defender protection (Set-MpPreference -Disable...)",
        r"set-mppreference\b.*-disable(?:realtimemonitoring|behaviormonitoring|ioavprotection|"
        r"scriptscanning|intrusionpreventionsystem)\s+(?:\$true|1)\b",
        "T1685",
    ),
    indicator(
        "firewall_disable",
        "Turns the Windows firewall off (netsh)",
        r"\bnetsh(?:\.exe)?\s+(?:advfirewall\s+set\s+\w+\s+state\s+off|"
        r"firewall\s+set\s+opmode\s+(?:mode=)?disable)",
        "T1686",
    ),
    indicator(
        "clear_event_log",
        "Clears a Windows event log (wevtutil cl / Clear-EventLog)",
        r"\bwevtutil(?:\.exe)?\s+(?:cl|clear-log)\b|\bclear-eventlog\b",
        "T1685.005",
    ),
)


class DefenseParams(RuleParams):
    # control name -> ATT&CK technique ID ("" = deliberately unmapped)
    monitored_controls: dict[str, str] = Field(
        default={
            "defender_realtime_protection": "T1685",
            "defender_tamper_protection": "T1685",
            "antivirus": "T1685",
            "edr_agent": "T1685",
            "windows_firewall": "T1686",
            "audit_policy": "",
        },
        description="security_config_change controls to watch, with their ATT&CK mapping.",
    )
    include_command_line: bool = True

    @field_validator("monitored_controls")
    @classmethod
    def _verified_mappings_only(cls, value: dict[str, str]) -> dict[str, str]:
        # Users may add controls, but only with mappings this rule has verified.
        allowed = {"", "T1685", "T1686", "T1685.005"}
        for control, mapping in value.items():
            if mapping not in allowed:
                raise ValueError(
                    f"{control}: mapping must be one of {sorted(allowed)} ('' for none)"
                )
        return value


class SecurityConfigurationChanges(Rule[DefenseParams]):
    id = "AEGIS-DEF-001"
    name = "Security Configuration Changes"
    version = 1
    description = "A protective control was disabled, or a security event log was cleared."
    severity = Severity.HIGH
    event_types = ("security_config_change", "log_cleared", "process_creation")
    required_fields = (
        "event_type or windows_event_id (1102, 104)",
        "normalized_fields.extra.control and new_state (configuration events)",
        "process_command_line (command-line path)",
    )
    logic = (
        "Configuration event: event_type security_config_change whose extra field "
        "'control' is in monitored_controls and whose 'new_state' means disabled "
        "(disabled/off/false/0/stopped).",
        "Log clearing: event_type log_cleared, or Windows event 1102 / 104.",
        "If include_command_line: Set-MpPreference -Disable...$true, netsh firewall off, "
        "wevtutil cl or Clear-EventLog in a process command line.",
        "Re-enabling a control is not reported.",
    )
    mitre = (
        MitreMapping(
            technique("T1685"),
            relationship="Turning off antivirus / EDR protection is the behavior described.",
            telemetry="Security product configuration events or Set-MpPreference command lines.",
            limitations="Tampering that leaves no configuration event (driver unload, "
            "process kill) is not detected.",
        ),
        MitreMapping(
            technique("T1686"),
            relationship="Disabling the host firewall is the behavior described.",
            telemetry="Firewall configuration events or netsh command lines.",
            limitations="Adding permissive firewall rules (instead of disabling) is missed.",
        ),
        MitreMapping(
            technique("T1685.005"),
            relationship="Clearing Windows event logs is the behavior described.",
            telemetry="Windows 1102 / 104, or wevtutil / Clear-EventLog command lines.",
            limitations="Selective deletion or log tampering without a clear event is missed.",
        ),
    )
    investigation_steps = (
        "Identify the account and process that made the change.",
        "Check whether the change was part of approved troubleshooting or maintenance.",
        "Restore the control and confirm it is active again.",
        "Review activity on the host immediately before and after the change.",
        "For cleared logs: collect remaining logs from central storage or other hosts.",
    )
    false_positives = (
        "Administrators temporarily disabling protection while troubleshooting.",
        "Product upgrades that briefly stop the protection service.",
        "Lab or test machines where logs are cleared routinely.",
    )
    limitations = (
        "Configuration events depend on the security product writing them; field names "
        "follow the AEGIS convention (control, new_state).",
        "audit_policy changes are reported but intentionally not mapped to ATT&CK here.",
        "Only the listed command-line forms are recognized.",
    )
    unknowns = (
        "Whether the change was authorized.",
        "What happened on the host while the control was off.",
    )
    changelog = (RuleChange(1, "2026-10-30", "Initial version."),)
    params_model = DefenseParams

    def evaluate(self, events: Sequence[EventRecord], params: DefenseParams) -> list[Finding]:
        controls = {name.lower(): mapping for name, mapping in params.monitored_controls.items()}
        findings = []
        for event in events:
            match = self._match(event, controls, params.include_command_line)
            if match is None:
                continue
            title, condition, mitre_id = match
            findings.append(
                Finding(
                    rule_id=self.id,
                    title=f"{title} on {event.hostname or 'unknown host'}",
                    severity=self.severity,
                    summary=f"{title}.",
                    events=(event,),
                    conditions=(condition,),
                    mitre_ids=(mitre_id,) if mitre_id else (),
                )
            )
        return findings

    def _match(
        self, event: EventRecord, controls: dict[str, str], include_command_line: bool
    ) -> tuple[str, Condition, str] | None:
        if event.event_type == "security_config_change":
            control = (event.extra_text("control") or "").lower()
            state = (event.extra_text("new_state") or "").lower()
            if control in controls and state in DISABLED_STATES:
                return (
                    f"Security control '{control}' disabled",
                    Condition(
                        "A monitored security control was set to a disabled state",
                        f"{control} -> {state}",
                    ),
                    controls[control],
                )
            return None
        if event.event_type == "log_cleared" or event.windows_event_id in LOG_CLEARED_EVENT_IDS:
            log = event.extra_text("log_name", "Channel") or "event log"
            return (
                f"{log} cleared",
                Condition("An event log was cleared", f"{log} (event ID {event.windows_event_id})"),
                "T1685.005",
            )
        if include_command_line and event.event_type == "process_creation":
            hits = matches(COMMAND_INDICATORS, event.process_command_line)
            if hits:
                item, text = hits[0]
                return (
                    item.description,
                    Condition(item.description, f"matched '{text}'"),
                    (item.mitre_id or ""),
                )
        return None
