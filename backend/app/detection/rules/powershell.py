"""Suspicious PowerShell command-line characteristics."""

from collections.abc import Sequence

from pydantic import Field

from app.detection.mitre import technique
from app.detection.model import Condition, EventRecord, Finding, MitreMapping
from app.detection.rule import Rule, RuleChange, RuleParams
from app.detection.rules.indicators import indicator, matches
from app.models.enums import Severity

POWERSHELL_BINARIES = frozenset({"powershell.exe", "pwsh.exe", "powershell_ise.exe"})

# PowerShell accepts any unambiguous prefix of a parameter name, so
# "-enc", "-EncodedCommand" and "-e" all mean the same thing. Requiring a
# base64-looking argument afterwards keeps "-ExecutionPolicy" from matching.
INDICATORS = (
    indicator(
        "encoded_command",
        "Command passed as a base64-encoded string (-EncodedCommand / -enc / -e)",
        r"(?:^|\s)[-/](?:e|ec|en|enc\w*)\s+[A-Za-z0-9+/]{16,}={0,2}(?:\s|$)",
        mitre_id="T1027.010",
    ),
    indicator(
        "base64_decode",
        "Script decodes base64 content at runtime (FromBase64String)",
        r"frombase64string",
        mitre_id="T1027.010",
    ),
    indicator(
        "download_cradle",
        "Downloads content from the network (WebClient, Invoke-WebRequest, BITS...)",
        r"downloadstring|downloadfile|downloaddata|net\.webclient|invoke-webrequest|"
        r"invoke-restmethod|start-bitstransfer|\biwr\b|\birm\b",
        mitre_id="T1105",
    ),
    indicator(
        "invoke_expression",
        "Executes a string as code (Invoke-Expression / IEX)",
        # Must appear as a command (after whitespace, a quote, '(', ';', '|' or '&'
        # and followed by whitespace or '('), not inside a path like C:\iex-report.txt.
        r"(?:^|[\s\"'(;|&])(?:iex|invoke-expression)(?=[\s(]|$)",
    ),
    indicator(
        "hidden_window",
        "Hides the PowerShell window (-WindowStyle Hidden / -w hidden)",
        r"[-/]w\w*\s+h(?:idden)?\b",
    ),
    indicator(
        "execution_policy_bypass",
        "Bypasses the script execution policy (-ExecutionPolicy Bypass/Unrestricted)",
        r"[-/](?:ex\w*|ep)\s+(?:bypass|unrestricted)\b",
    ),
    indicator(
        "amsi_tampering",
        "References AMSI internals commonly targeted to disable script scanning",
        r"amsiutils|amsiinitfailed|amsiscanbuffer",
    ),
)


class PowerShellParams(RuleParams):
    min_indicators: int = Field(
        default=1, ge=1, le=len(INDICATORS), description="Indicators needed for a finding."
    )
    high_severity_at: int = Field(
        default=2, ge=1, le=len(INDICATORS), description="Indicators that make it high severity."
    )


class SuspiciousPowerShell(Rule[PowerShellParams]):
    id = "AEGIS-EXEC-001"
    name = "Suspicious PowerShell Characteristics"
    version = 1
    description = (
        "PowerShell started with command-line characteristics often used to hide or "
        "stage malicious code."
    )
    severity = Severity.MEDIUM
    event_types = ("process_creation",)
    required_fields = ("event_type", "process_name", "process_command_line")
    logic = (
        "Select process_creation events whose process is powershell.exe, pwsh.exe or "
        "powershell_ise.exe.",
        "Test the command line against each documented indicator: "
        + "; ".join(f"{i.id} ({i.description})" for i in INDICATORS)
        + ".",
        "Report a finding when at least `min_indicators` match; severity is high when "
        "at least `high_severity_at` match.",
        "PowerShell without any indicator (for example -NoProfile -Command Get-Service) "
        "is not reported.",
    )
    mitre = (
        MitreMapping(
            technique("T1059.001"),
            relationship="The rule only fires on PowerShell executions, with characteristics "
            "common in malicious use.",
            telemetry="Process creation events with image name and full command line.",
            limitations="Covers command-line characteristics only; script-block content, "
            "module loading and PowerShell run inside other hosts are not seen.",
        ),
        MitreMapping(
            technique("T1027.010"),
            relationship="Applies when the command is base64-encoded or decoded at runtime.",
            telemetry="Command line containing -EncodedCommand or FromBase64String.",
            limitations="Other obfuscation (string concatenation, tick marks, char codes) "
            "is not detected.",
        ),
        MitreMapping(
            technique("T1105"),
            relationship="Applies when the command line contains a download primitive.",
            telemetry="Command line containing WebClient, Invoke-WebRequest, BITS, etc.",
            limitations="Shows that a download was requested, not that it succeeded or "
            "what was transferred.",
        ),
    )
    investigation_steps = (
        "Decode any base64 argument (UTF-16LE) and read the actual script.",
        "Check the parent process: was PowerShell started by a user, a script, an Office "
        "document or a service?",
        "Look for network connections and file writes from the same host right after.",
        "Determine whether the user or an administrator recognizes the command.",
    )
    false_positives = (
        "Management and deployment tools (SCCM, Intune, installers) that use "
        "-EncodedCommand or -ExecutionPolicy Bypass legitimately.",
        "Administrators downloading scripts or modules with Invoke-WebRequest.",
        "Monitoring agents that start hidden PowerShell windows.",
    )
    limitations = (
        "Relies on the full command line being logged; truncated command lines can hide "
        "indicators.",
        "PowerShell started through a renamed binary or another host process is missed.",
        "A command that is itself launched via cmd.exe is only evaluated on the "
        "powershell.exe process event.",
    )
    unknowns = (
        "What the script actually did after it started (command line only shows intent).",
        "Whether the command was run deliberately by an authorized administrator.",
    )
    changelog = (RuleChange(1, "2026-10-30", "Initial version."),)
    params_model = PowerShellParams

    def evaluate(self, events: Sequence[EventRecord], params: PowerShellParams) -> list[Finding]:
        findings = []
        for event in events:
            if event.event_type != "process_creation":
                continue
            if (event.process_name or "") not in POWERSHELL_BINARIES:
                continue
            hits = matches(INDICATORS, event.process_command_line)
            if len(hits) < params.min_indicators:
                continue
            mitre_ids = ["T1059.001"] + sorted({i.mitre_id for i, _ in hits if i.mitre_id})
            findings.append(
                Finding(
                    rule_id=self.id,
                    title=f"Suspicious PowerShell on {event.hostname or 'unknown host'}: "
                    + ", ".join(i.id for i, _ in hits),
                    severity=Severity.HIGH
                    if len(hits) >= params.high_severity_at
                    else self.severity,
                    summary=f"{event.process_name} ran with {len(hits)} suspicious "
                    f"characteristic(s).",
                    events=(event,),
                    conditions=(
                        Condition("Process is PowerShell", event.process_name or ""),
                        *(Condition(i.description, f"matched '{text}'") for i, text in hits),
                    ),
                    mitre_ids=tuple(mitre_ids),
                )
            )
        return findings
