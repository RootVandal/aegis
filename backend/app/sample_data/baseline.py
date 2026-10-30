"""Deterministic synthetic "baseline" dataset: three ordinary office days.

What it contains: logons (including the occasional mistyped password that is
immediately followed by a success), normal desktop applications, routine
administrator commands, a nightly backup job and logoffs, for a small fictional
company ("CORP") with eight employees and three servers.

What it deliberately does NOT contain: attack activity. The detection rules
(Milestone 3) are expected to produce few or no alerts on this dataset, which
makes it useful for spotting false positives. Some events intentionally look
"interesting" (an administrator running PowerShell, a failed logon) without
being malicious.

Design rules:

* **Deterministic.** A fixed seed and a fixed start date produce identical
  events and IDs on every run, so loading it twice de-duplicates cleanly and
  test results are reproducible.
* **Safe addresses only.** Internal hosts use 10.10.0.0/16 (private); external
  destinations use 203.0.113.0/24 and 198.51.100.0/24, which RFC 5737 reserves
  for documentation. No real organisation's IP appears in the data.
* **Two source formats.** Windows Security events use AEGIS field names;
  Sysmon events use Sysmon's own names (``Image``, ``UtcTime``, ``User``...),
  exercising the normalizer's alias mapping exactly as an import would.
"""

import random
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

SEED = 20261005
START = datetime(2026, 10, 5, tzinfo=UTC)  # a Monday
DAYS = 3
DOMAIN = "CORP"


@dataclass(frozen=True)
class Employee:
    username: str
    workstation: str
    ip: str
    is_admin: bool = False


EMPLOYEES = (
    Employee("a.kowalski", "ws-fin-01", "10.10.1.11"),
    Employee("j.martin", "ws-fin-02", "10.10.1.12"),
    Employee("s.nakamura", "ws-eng-01", "10.10.1.21"),
    Employee("m.okafor", "ws-eng-02", "10.10.1.22"),
    Employee("l.garcia", "ws-hr-01", "10.10.1.31"),
    Employee("p.novak", "ws-it-01", "10.10.1.41", is_admin=True),
    Employee("r.silva", "ws-sales-01", "10.10.1.51"),
    Employee("e.lindqvist", "ws-sales-02", "10.10.1.52"),
)

DC = ("dc-01", "10.10.0.10")
MAIL = ("mail-01", "10.10.0.20")
FILE = ("file-01", "10.10.0.30")

EXPLORER = r"C:\Windows\explorer.exe"
OFFICE = r"C:\Program Files\Microsoft Office\root\Office16"
EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
# (image path, command line)
DESKTOP_APPS = (
    (rf"{OFFICE}\OUTLOOK.EXE", rf'"{OFFICE}\OUTLOOK.EXE"'),
    (EDGE, rf'"{EDGE}" --profile-directory=Default'),
    (rf"{OFFICE}\EXCEL.EXE", rf'"{OFFICE}\EXCEL.EXE" /e'),
    (rf"{OFFICE}\WINWORD.EXE", rf'"{OFFICE}\WINWORD.EXE" /n'),
)
WEB_DESTINATIONS = ("203.0.113.10", "203.0.113.25", "198.51.100.40", "198.51.100.77")
ADMIN_COMMANDS = (
    (
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell.exe -NoProfile -Command \"Get-Service | Where-Object Status -eq 'Running'\"",
    ),
    (r"C:\Windows\System32\cmd.exe", "cmd.exe /c ipconfig /all"),
    (
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        'powershell.exe -NoProfile -Command "Get-EventLog -LogName System -Newest 20"',
    ),
)


class _Builder:
    def __init__(self) -> None:
        self.rng = random.Random(SEED)  # noqa: S311 - synthetic data, not security-sensitive
        self.records: list[dict[str, Any]] = []

    def jitter(self, base: datetime, max_seconds: int) -> datetime:
        return base + timedelta(seconds=self.rng.randint(0, max_seconds))

    # --- Windows Security log (AEGIS field names) -------------------------
    def security(self, when: datetime, event_type: str, win_id: int, **fields: Any) -> None:
        self.records.append(
            {
                "timestamp": when.isoformat().replace("+00:00", "Z"),
                "event_source": "windows-security",
                "event_type": event_type,
                "windows_event_id": win_id,
                "hostname": DC[0],
                **fields,
            }
        )

    # --- Sysmon (Sysmon's own field names, exercised by the alias mapping) -
    def sysmon(self, when: datetime, event_type: str, sysmon_id: int, **fields: Any) -> None:
        self.records.append(
            {
                # Sysmon writes UtcTime without a zone designator.
                "UtcTime": when.strftime("%Y-%m-%d %H:%M:%S.") + f"{when.microsecond // 1000:03d}",
                "source": "sysmon",
                "type": event_type,
                "EventID": sysmon_id,
                **fields,
            }
        )

    def workday(self, day: datetime, person: Employee) -> None:
        arrive = self.jitter(day.replace(hour=7, minute=45), 100 * 60)
        user = f"{DOMAIN}\\{person.username}"

        if self.rng.random() < 0.15:  # a mistyped password, corrected right away
            self.security(
                arrive,
                "authentication_failure",
                4625,
                username=person.username,
                source_ip=person.ip,
                logon_type=2,
                failure_reason="unknown user name or bad password",
            )
            arrive += timedelta(seconds=self.rng.randint(20, 90))
        self.security(
            arrive,
            "authentication_success",
            4624,
            username=person.username,
            source_ip=person.ip,
            logon_type=2,
        )

        moment = arrive + timedelta(minutes=2)
        for image, command in self.rng.sample(DESKTOP_APPS, k=self.rng.randint(2, 4)):
            moment = self.jitter(moment, 45 * 60)
            self.sysmon(
                moment,
                "process_creation",
                1,
                Computer=person.workstation,
                User=user,
                Image=image,
                ParentImage=EXPLORER,
                CommandLine=command,
            )
            self.connection(moment + timedelta(seconds=5), person, image)

        if person.is_admin:
            for image, command in self.rng.sample(ADMIN_COMMANDS, k=2):
                moment = self.jitter(moment, 90 * 60)
                self.sysmon(
                    moment,
                    "process_creation",
                    1,
                    Computer=FILE[0],
                    User=user,
                    Image=image,
                    ParentImage=EXPLORER,
                    CommandLine=command,
                )

        leave = self.jitter(day.replace(hour=16, minute=45), 100 * 60)
        self.security(
            leave,
            "logoff",
            4634,
            username=person.username,
            source_ip=person.ip,
            logon_type=2,
        )

    def connection(self, when: datetime, person: Employee, image: str) -> None:
        if image.lower().endswith("outlook.exe"):
            destination, port = MAIL[1], 443
        else:
            destination, port = self.rng.choice(WEB_DESTINATIONS), 443
        self.sysmon(
            when,
            "network_connection",
            3,
            Computer=person.workstation,
            User=f"{DOMAIN}\\{person.username}",
            Image=image,
            SourceIp=person.ip,
            DestinationIp=destination,
            DestinationPort=port,
            Protocol="tcp",
        )

    def nightly_backup(self, day: datetime) -> None:
        start = self.jitter(day.replace(hour=1), 5 * 60)
        self.security(
            start,
            "authentication_success",
            4624,
            username="svc_backup",
            source_ip=FILE[1],
            logon_type=5,
        )
        self.sysmon(
            start + timedelta(seconds=3),
            "process_creation",
            1,
            Computer=FILE[0],
            User=f"{DOMAIN}\\svc_backup",
            Image=r"C:\Program Files\CorpBackup\backup-agent.exe",
            ParentImage=r"C:\Windows\System32\services.exe",
            CommandLine=r'"C:\Program Files\CorpBackup\backup-agent.exe" --job nightly',
        )


def generate_baseline() -> list[dict[str, Any]]:
    builder = _Builder()
    for offset in range(DAYS):
        day = START + timedelta(days=offset)
        builder.nightly_backup(day)
        for person in EMPLOYEES:
            builder.workday(day, person)

    # Chronological order, then stable sequential IDs.
    records = sorted(builder.records, key=_sort_key)
    for number, record in enumerate(records, start=1):
        record["event_id"] = f"syn-baseline-{number:05d}"
    return records


def _sort_key(record: dict[str, Any]) -> str:
    value = record.get("timestamp") or record["UtcTime"].replace(" ", "T") + "Z"
    return str(value)
