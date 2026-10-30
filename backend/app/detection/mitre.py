"""MITRE ATT&CK techniques referenced by AEGIS rules.

Every identifier, name and tactic below was checked against
https://attack.mitre.org (ATT&CK content v20.0) on 2026-10-30. Three IDs that
were common in older releases now redirect to new techniques and are recorded
under their v20 identifiers:

* T1562.001 -> T1685 (Disable or Modify Tools)
* T1562.004 -> T1686 (Disable or Modify System Firewall)
* T1070.001 -> T1685.005 (Disable or Modify Tools: Clear Windows Event Logs)

Do not add an entry here without checking the official page first.
"""

from app.detection.model import MitreTechnique

ATTACK_VERSION = "v20.0"
VERIFIED_ON = "2026-10-30"

_TECHNIQUES = [
    MitreTechnique("T1110.001", "Brute Force: Password Guessing", ("Credential Access",)),
    MitreTechnique("T1110.003", "Brute Force: Password Spraying", ("Credential Access",)),
    MitreTechnique("T1059.001", "Command and Scripting Interpreter: PowerShell", ("Execution",)),
    MitreTechnique(
        "T1027.010", "Obfuscated Files or Information: Command Obfuscation", ("Stealth",)
    ),
    MitreTechnique("T1105", "Ingress Tool Transfer", ("Command and Control",)),
    MitreTechnique(
        "T1098.007",
        "Account Manipulation: Additional Local or Domain Groups",
        ("Persistence", "Privilege Escalation"),
    ),
    MitreTechnique("T1204.002", "User Execution: Malicious File", ("Execution",)),
    MitreTechnique("T1505.003", "Server Software Component: Web Shell", ("Persistence",)),
    MitreTechnique(
        "T1036.005", "Masquerading: Match Legitimate Resource Name or Location", ("Stealth",)
    ),
    MitreTechnique(
        "T1053.005",
        "Scheduled Task/Job: Scheduled Task",
        ("Execution", "Persistence", "Privilege Escalation"),
    ),
    MitreTechnique(
        "T1543.003",
        "Create or Modify System Process: Windows Service",
        ("Persistence", "Privilege Escalation"),
    ),
    MitreTechnique(
        "T1547.001",
        "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        ("Persistence", "Privilege Escalation"),
    ),
    MitreTechnique("T1571", "Non-Standard Port", ("Command and Control",)),
    MitreTechnique("T1685", "Disable or Modify Tools", ("Defense Impairment",)),
    MitreTechnique("T1686", "Disable or Modify System Firewall", ("Defense Impairment",)),
    MitreTechnique(
        "T1685.005", "Disable or Modify Tools: Clear Windows Event Logs", ("Defense Impairment",)
    ),
]

TECHNIQUES: dict[str, MitreTechnique] = {t.id: t for t in _TECHNIQUES}


def technique(technique_id: str) -> MitreTechnique:
    """Look up a verified technique; fails loudly for anything unverified."""
    return TECHNIQUES[technique_id]
