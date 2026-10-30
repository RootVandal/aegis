"""Suspicious parent/child process relationships and system-binary masquerading."""

from collections.abc import Sequence

from pydantic import Field

from app.detection.mitre import technique
from app.detection.model import Condition, EventRecord, Finding, MitreMapping
from app.detection.rule import Rule, RuleChange, RuleParams
from app.models.enums import Severity

# Windows system binaries and the only directories they normally run from.
SYSTEM32 = ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\")
EXPECTED_LOCATIONS: dict[str, tuple[str, ...]] = {
    "svchost.exe": SYSTEM32,
    "lsass.exe": SYSTEM32,
    "services.exe": SYSTEM32,
    "csrss.exe": SYSTEM32,
    "winlogon.exe": SYSTEM32,
    "wininit.exe": SYSTEM32,
    "smss.exe": SYSTEM32,
    "spoolsv.exe": SYSTEM32,
    "taskhostw.exe": SYSTEM32,
    "explorer.exe": ("c:\\windows\\",),
}


def _lower_set(values: list[str]) -> list[str]:
    return sorted({v.strip().lower() for v in values if v.strip()})


class ProcessParams(RuleParams):
    office_parents: list[str] = Field(
        default=[
            "winword.exe",
            "excel.exe",
            "powerpnt.exe",
            "outlook.exe",
            "onenote.exe",
            "msaccess.exe",
            "mspub.exe",
        ]
    )
    server_parents: list[str] = Field(default=["w3wp.exe", "httpd.exe", "nginx.exe", "php-cgi.exe"])
    suspicious_children: list[str] = Field(
        default=[
            "cmd.exe",
            "powershell.exe",
            "pwsh.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
            "rundll32.exe",
            "regsvr32.exe",
            "certutil.exe",
            "bitsadmin.exe",
        ]
    )
    check_masquerading: bool = Field(
        default=True, description="Flag system binary names running from unexpected folders."
    )


class SuspiciousProcessRelationships(Rule[ProcessParams]):
    id = "AEGIS-PROC-001"
    name = "Suspicious Process Relationships"
    version = 1
    description = (
        "A process was started by a parent that should not normally launch it, or a "
        "Windows system binary name ran from an unexpected folder."
    )
    severity = Severity.HIGH
    event_types = ("process_creation",)
    required_fields = (
        "event_type",
        "process_name",
        "parent_process_name (relationship check)",
        "normalized_fields.process_path (masquerading check)",
    )
    logic = (
        "Office application (office_parents) starting a shell, script host or LOLBin "
        "(suspicious_children).",
        "Web server process (server_parents) starting one of suspicious_children.",
        "If check_masquerading: a process named like a Windows system binary "
        "(svchost.exe, lsass.exe, ...) whose full path is outside its normal folder.",
        "Each matching process event is one finding; all matching checks are listed.",
    )
    mitre = (
        MitreMapping(
            technique("T1204.002"),
            relationship="Office documents that spawn shells usually mean a user opened a "
            "file containing a macro or exploit.",
            telemetry="Process creation with parent image (Sysmon 1 / Windows 4688 with "
            "parent process).",
            limitations="Does not see the document itself; macros that act without "
            "spawning a child process are missed.",
        ),
        MitreMapping(
            technique("T1505.003"),
            relationship="A web server process spawning a shell is the typical footprint "
            "of a web shell executing commands.",
            telemetry="Process creation with parent image.",
            limitations="Web shells that run code in-process (no child process) are missed.",
        ),
        MitreMapping(
            technique("T1036.005"),
            relationship="A system binary name in a non-system folder suggests a "
            "program pretending to be a legitimate Windows component.",
            telemetry="Process creation with the full image path.",
            limitations="Only the listed names are checked; masquerading as third-party "
            "software is not detected.",
        ),
    )
    investigation_steps = (
        "For Office parents: identify the document that was open, where it came from "
        "(email, download) and whether the user expected macros.",
        "For web server parents: review web server logs around the time for requests "
        "to unusual pages or uploads.",
        "For masquerading: hash the file, check its signature and how it got to that folder.",
        "Review the child process command line and anything it started in turn.",
    )
    false_positives = (
        "Office add-ins or document automation that legitimately start helper processes.",
        "Web applications that intentionally call external commands.",
        "Portable or backup copies of system binaries kept outside System32.",
    )
    limitations = (
        "Only direct parent/child pairs are checked; longer chains (Office -> wmiprvse -> "
        "powershell) are missed.",
        "Masquerading needs the full image path in the event (process_path).",
        "Parent and child names are compared exactly, after lowercasing.",
    )
    unknowns = (
        "Whether the parent process was itself legitimate.",
        "What the child process went on to do.",
    )
    changelog = (RuleChange(1, "2026-10-30", "Initial version."),)
    params_model = ProcessParams

    def evaluate(self, events: Sequence[EventRecord], params: ProcessParams) -> list[Finding]:
        office = set(_lower_set(params.office_parents))
        servers = set(_lower_set(params.server_parents))
        children = set(_lower_set(params.suspicious_children))
        findings = []
        for event in events:
            if event.event_type != "process_creation" or not event.process_name:
                continue
            child, parent = event.process_name, event.parent_process_name or ""
            conditions: list[Condition] = []
            mitre_ids: list[str] = []
            if parent in office and child in children:
                conditions.append(
                    Condition(
                        "Office application started a shell or script host", f"{parent} -> {child}"
                    )
                )
                mitre_ids.append("T1204.002")
            if parent in servers and child in children:
                conditions.append(
                    Condition(
                        "Web server process started a shell or script host", f"{parent} -> {child}"
                    )
                )
                mitre_ids.append("T1505.003")
            if params.check_masquerading and event.process_path and child in EXPECTED_LOCATIONS:
                folder = event.process_path.replace("/", "\\").lower().rsplit("\\", 1)[0] + "\\"
                if folder not in EXPECTED_LOCATIONS[child]:
                    conditions.append(
                        Condition(
                            f"{child} ran outside its normal folder "
                            f"({', '.join(EXPECTED_LOCATIONS[child])})",
                            event.process_path,
                        )
                    )
                    mitre_ids.append("T1036.005")
            if conditions:
                findings.append(
                    Finding(
                        rule_id=self.id,
                        title=f"Suspicious process {parent + ' -> ' if parent else ''}{child} on "
                        f"{event.hostname or 'unknown host'}",
                        severity=self.severity,
                        summary="; ".join(c.description for c in conditions) + ".",
                        events=(event,),
                        conditions=tuple(conditions),
                        mitre_ids=tuple(mitre_ids),
                    )
                )
        return findings
