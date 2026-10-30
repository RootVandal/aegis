"""Persistence mechanism changes: scheduled tasks, services, Run keys."""

import re
from collections.abc import Sequence

from pydantic import Field

from app.detection.mitre import technique
from app.detection.model import Condition, EventRecord, Finding, MitreMapping
from app.detection.rule import Rule, RuleChange, RuleParams
from app.detection.rules.indicators import Indicator, indicator, matches
from app.models.enums import Severity

# Registry operations that remove rather than create (Sysmon EventType values included).
DELETE_OPERATIONS = frozenset({"deletevalue", "deletekey", "delete"})
TASK_EVENT_IDS = frozenset({4698})  # A scheduled task was created
SERVICE_EVENT_IDS = frozenset({7045, 4697})  # A service was installed
RUN_KEY = re.compile(
    r"\\software\\(?:wow6432node\\)?microsoft\\windows\\currentversion\\"
    r"(?:run|runonce|runonceex|runservices|runservicesonce)(?:\\|$)"
    r"|\\software\\microsoft\\windows nt\\currentversion\\winlogon\\(?:userinit|shell)$",
    re.IGNORECASE,
)

COMMAND_INDICATORS: tuple[Indicator, ...] = (
    indicator(
        "schtasks_create",
        "Creates a scheduled task (schtasks /create)",
        r"\bschtasks(?:\.exe)?\b.*\s/create\b",
        "T1053.005",
    ),
    indicator(
        "powershell_register_task",
        "Registers a scheduled task from PowerShell",
        r"\bregister-scheduledtask\b",
        "T1053.005",
    ),
    indicator(
        "sc_create",
        "Creates a Windows service (sc create)",
        r"\bsc(?:\.exe)?\s+(?:\\\\\S+\s+)?create\b",
        "T1543.003",
    ),
    indicator(
        "powershell_new_service",
        "Creates a Windows service from PowerShell (New-Service)",
        r"\bnew-service\b",
        "T1543.003",
    ),
    indicator(
        "reg_add_run_key",
        "Adds a value under a Run / RunOnce registry key",
        r"\breg(?:\.exe)?\s+add\s+\"?hk\w*\\software\\(?:wow6432node\\)?microsoft\\windows\\"
        r"currentversion\\run(?:once)?\b",
        "T1547.001",
    ),
)


class PersistenceParams(RuleParams):
    allowed_names: list[str] = Field(
        default=[],
        description="Task or service names (case-insensitive) known to be legitimate.",
    )
    include_command_line: bool = True


class PersistenceMechanismChanges(Rule[PersistenceParams]):
    id = "AEGIS-PERS-001"
    name = "Persistence Mechanism Changes"
    version = 2
    description = (
        "A scheduled task, service or autostart registry value was created, which lets a "
        "program start again automatically."
    )
    severity = Severity.MEDIUM
    event_types = (
        "scheduled_task_created",
        "service_installed",
        "registry_modification",
        "process_creation",
    )
    required_fields = (
        "event_type or windows_event_id (4698, 7045, 4697)",
        "normalized_fields.extra.registry_key or TargetObject (registry path)",
        "process_command_line (command-line path)",
    )
    logic = (
        "Scheduled task: event_type scheduled_task_created or Windows event 4698.",
        "Service: event_type service_installed or Windows event 7045 / 4697.",
        "Autostart: event_type registry_modification whose key (registry_key / "
        "TargetObject) is a Run, RunOnce, RunServices or Winlogon Userinit/Shell key, "
        "unless the recorded operation (operation / EventType) is a deletion.",
        "If include_command_line: process command lines that run schtasks /create, "
        "Register-ScheduledTask, sc create, New-Service, or reg add ...\\Run.",
        "Tasks or services whose name is in allowed_names are skipped.",
    )
    mitre = (
        MitreMapping(
            technique("T1053.005"),
            relationship="Creating a scheduled task is how this technique establishes "
            "recurring execution.",
            telemetry="Windows 4698, or schtasks / Register-ScheduledTask command lines.",
            limitations="Modified (not newly created) tasks and tasks created through the "
            "COM API without logging are missed.",
        ),
        MitreMapping(
            technique("T1543.003"),
            relationship="Installing a service gives a program automatic, often SYSTEM, execution.",
            telemetry="Windows 7045 / 4697, or sc create / New-Service command lines.",
            limitations="Changes to existing services' binary paths are not detected.",
        ),
        MitreMapping(
            technique("T1547.001"),
            relationship="Values under Run keys start programs at every logon.",
            telemetry="Registry set events (e.g. Sysmon 13) with the key path, or reg add "
            "command lines.",
            limitations="Startup folders and other autostart locations are not covered.",
        ),
    )
    investigation_steps = (
        "Identify what will be executed: task action, service binary path, or Run value data.",
        "Check who created it and from which process.",
        "Verify the binary: location, signature, hash reputation, creation time.",
        "Compare with software deployment records; add known-good names to allowed_names.",
    )
    false_positives = (
        "Software installers and updaters creating services, tasks and Run values.",
        "IT automation and backup agents.",
    )
    limitations = (
        "Detects creation events only. Registry deletions are skipped when the event "
        "records its operation; a registry event without an operation field is treated "
        "as a creation.",
        "Registry detection depends on registry auditing (e.g. Sysmon) being enabled.",
        "allowed_names matches exact names; renamed malicious tasks are not caught by name alone.",
    )
    unknowns = (
        "Whether the new task, service or value has executed yet.",
        "Whether the change was part of an approved software installation.",
    )
    changelog = (
        RuleChange(1, "2026-10-30", "Initial version."),
        RuleChange(
            2,
            "2026-10-31",
            "Ignore registry events whose operation is a deletion (DeleteValue / DeleteKey). "
            "Found by the evaluation suite (case pers-run-key-removed): removing an autostart "
            "entry was reported as persistence.",
        ),
    )
    params_model = PersistenceParams

    def evaluate(self, events: Sequence[EventRecord], params: PersistenceParams) -> list[Finding]:
        allowed = {name.strip().lower() for name in params.allowed_names}
        findings = []
        for event in events:
            found = self._match(event, params)
            if found is None:
                continue
            what, name, condition, mitre_id = found
            if name and name.lower() in allowed:
                continue
            findings.append(
                Finding(
                    rule_id=self.id,
                    title=f"{what}{f' {name!r}' if name else ''} on "
                    f"{event.hostname or 'unknown host'}",
                    severity=self.severity,
                    summary=f"{what}.",
                    events=(event,),
                    conditions=(condition,),
                    mitre_ids=(mitre_id,) if mitre_id else (),
                )
            )
        return findings

    def _match(
        self, event: EventRecord, params: PersistenceParams
    ) -> tuple[str, str | None, Condition, str | None] | None:
        if event.event_type == "scheduled_task_created" or event.windows_event_id in TASK_EVENT_IDS:
            name = event.extra_text("task_name", "TaskName")
            return (
                "New scheduled task",
                name,
                Condition("Scheduled task created", name or "(name not recorded)"),
                "T1053.005",
            )
        if event.event_type == "service_installed" or event.windows_event_id in SERVICE_EVENT_IDS:
            name = event.extra_text("service_name", "ServiceName")
            binary = event.extra_text("service_file_name", "ImagePath", "ServiceFileName")
            return (
                "New service",
                name,
                Condition("Service installed", f"{name or '(unnamed)'} -> {binary or '(no path)'}"),
                "T1543.003",
            )
        if event.event_type == "registry_modification":
            key = event.extra_text("registry_key", "TargetObject")
            operation = (event.extra_text("operation", "EventType") or "").lower()
            if operation in DELETE_OPERATIONS:
                return None  # removing an autostart entry is not persistence
            if key and RUN_KEY.search(key):
                return (
                    "New autostart registry value",
                    None,
                    Condition("Autostart (Run/Winlogon) registry key modified", key),
                    "T1547.001",
                )
            return None
        if params.include_command_line and event.event_type == "process_creation":
            hits = matches(COMMAND_INDICATORS, event.process_command_line)
            if hits:
                item, text = hits[0]
                return (
                    item.description,
                    None,
                    Condition(item.description, f"matched '{text}'"),
                    item.mitre_id,
                )
        return None
