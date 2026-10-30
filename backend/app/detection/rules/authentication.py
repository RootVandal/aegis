"""Authentication rules: repeated failures for one account, attempts across many accounts."""

from collections import defaultdict
from collections.abc import Sequence
from datetime import timedelta
from typing import Literal

from pydantic import Field

from app.detection.mitre import technique
from app.detection.model import Condition, EventRecord, Finding, MitreMapping
from app.detection.rule import Rule, RuleChange, RuleParams, greedy_windows, lower
from app.models.enums import Severity

FAILURE = "authentication_failure"
SUCCESS = "authentication_success"


def _later_success(
    events: Sequence[EventRecord],
    after: EventRecord,
    within: timedelta,
    *,
    username: str | None,
    source_ip: str | None,
) -> EventRecord | None:
    """First successful logon after ``after`` that matches the given identity."""
    if within.total_seconds() <= 0:
        return None
    for event in events:
        if event.event_type != SUCCESS or event.timestamp <= after.timestamp:
            continue
        if event.timestamp > after.timestamp + within:
            break
        if username is not None and lower(event.username) != username:
            continue
        if source_ip is not None and event.source_ip != source_ip:
            continue
        return event
    return None


class FailedLoginParams(RuleParams):
    threshold: int = Field(default=5, ge=2, le=1000, description="Failures needed in one window.")
    window_seconds: int = Field(default=300, ge=10, le=86_400)
    group_by: Literal["username", "source_ip", "username_and_source_ip"] = Field(
        default="username", description="What counts as 'the same target'."
    )
    success_lookahead_seconds: int = Field(
        default=600,
        ge=0,
        le=86_400,
        description="Look this long after the last failure for a successful logon (0 = off).",
    )


class MultipleFailedLogins(Rule[FailedLoginParams]):
    id = "AEGIS-AUTH-001"
    name = "Multiple Failed Logins"
    version = 1
    description = "Repeated failed authentication attempts against the same target in a short time."
    severity = Severity.MEDIUM
    event_types = (FAILURE, SUCCESS)
    required_fields = ("timestamp", "event_type", "username and/or source_ip (per group_by)")
    logic = (
        "Select authentication_failure events that have the grouping field(s).",
        "Group them by username (case-insensitive), source IP, or both (group_by).",
        "Within each group, take the earliest unused failure and every failure within "
        "window_seconds of it; if there are at least `threshold`, that is one finding.",
        "If a successful logon for the same target follows the last failure within "
        "success_lookahead_seconds, include it and raise severity to high.",
    )
    mitre = (
        MitreMapping(
            technique("T1110.001"),
            relationship="Many failures for one account in a short time is the pattern "
            "produced by guessing passwords for that account.",
            telemetry="Authentication failure events with username (e.g. Windows 4625).",
            limitations="Slow guessing below the threshold, or spread across windows, is "
            "missed. Failures caused by a user who forgot a password look identical.",
        ),
    )
    investigation_steps = (
        "Check whether the account owner recently changed or forgot their password.",
        "Identify the source IP: is it the user's usual workstation, a server, or external?",
        "If a success followed, review the session: logon type, host, and what ran next.",
        "Search for the same source IP failing against other accounts (password spraying).",
        "Check whether the account was locked out and whether lockout is configured.",
    )
    false_positives = (
        "A user mistyping or forgetting a password several times.",
        "A service or scheduled task still using an old, changed password.",
        "Mobile devices or mail clients retrying cached credentials.",
    )
    limitations = (
        "Events without the grouping field are not evaluated.",
        "Non-overlapping windows: a burst that straddles a window boundary can be split "
        "and fall below the threshold in both halves.",
        "Does not use failure reason codes (bad password vs. unknown user).",
    )
    unknowns = (
        "Whether the attempts were made by a person, a script, or a misconfigured service.",
        "Whether any successful logon was performed by the legitimate account owner.",
    )
    changelog = (RuleChange(1, "2026-10-30", "Initial version."),)
    params_model = FailedLoginParams

    def evaluate(self, events: Sequence[EventRecord], params: FailedLoginParams) -> list[Finding]:
        use_user = params.group_by in ("username", "username_and_source_ip")
        use_ip = params.group_by in ("source_ip", "username_and_source_ip")
        groups: dict[tuple[str | None, str | None], list[EventRecord]] = defaultdict(list)
        for event in events:
            if event.event_type != FAILURE:
                continue
            user, ip = lower(event.username), event.source_ip
            if (use_user and not user) or (use_ip and not ip):
                continue
            groups[(user if use_user else None, ip if use_ip else None)].append(event)

        window = timedelta(seconds=params.window_seconds)
        lookahead = timedelta(seconds=params.success_lookahead_seconds)
        findings = []
        for (user, ip), failures in sorted(groups.items(), key=lambda kv: str(kv[0])):
            target = " / ".join(
                part
                for part in (f"user {user}" if user else "", f"source {ip}" if ip else "")
                if part
            )
            for burst in greedy_windows(
                failures, window, lambda chunk: len(chunk) >= params.threshold
            ):
                span = (burst[-1].timestamp - burst[0].timestamp).total_seconds()
                conditions = [
                    Condition(
                        f"At least {params.threshold} failed logons for the same "
                        f"{params.group_by.replace('_', ' ')} within {params.window_seconds}s",
                        f"{len(burst)} failures for {target} over {span:.0f}s",
                    )
                ]
                success = _later_success(events, burst[-1], lookahead, username=user, source_ip=ip)
                severity = self.severity
                unknowns: tuple[str, ...] = ()
                evidence = tuple(burst)
                if success is not None:
                    severity = Severity.HIGH
                    evidence = (*burst, success)
                    conditions.append(
                        Condition(
                            "A successful logon for the same target followed the failures",
                            f"{success.event_id} at {success.timestamp.isoformat()}",
                        )
                    )
                    unknowns = ("Whether the successful logon used a guessed password.",)
                findings.append(
                    Finding(
                        rule_id=self.id,
                        title=f"{len(burst)} failed logins for {target}"
                        + (" followed by a success" if success else ""),
                        severity=severity,
                        summary=f"{len(burst)} failed logons for {target} within {span:.0f}s.",
                        events=evidence,
                        conditions=tuple(conditions),
                        mitre_ids=("T1110.001",),
                        unknowns=unknowns,
                    )
                )
        return findings


class MultiAccountParams(RuleParams):
    distinct_accounts: int = Field(
        default=5, ge=2, le=1000, description="Different accounts needed in one window."
    )
    window_seconds: int = Field(default=600, ge=10, le=86_400)
    success_lookahead_seconds: int = Field(default=600, ge=0, le=86_400)


class AuthenticationAcrossAccounts(Rule[MultiAccountParams]):
    id = "AEGIS-AUTH-002"
    name = "Authentication Across Multiple Accounts"
    version = 1
    description = "One source address failing to authenticate as many different accounts."
    severity = Severity.MEDIUM
    event_types = (FAILURE, SUCCESS)
    required_fields = ("timestamp", "event_type", "source_ip", "username")
    logic = (
        "Select authentication_failure events with both source_ip and username.",
        "Group them by source IP.",
        "Within each group, take the earliest unused failure and every failure within "
        "window_seconds of it; if they target at least `distinct_accounts` different "
        "usernames, that is one finding.",
        "If the same source then logs on successfully as one of those accounts within "
        "success_lookahead_seconds, include it and raise severity to high.",
    )
    mitre = (
        MitreMapping(
            technique("T1110.003"),
            relationship="Trying few passwords against many accounts from one source is "
            "the password-spraying pattern, which avoids per-account lockout.",
            telemetry="Authentication failure events with username and source IP.",
            limitations="Spraying spread across many source IPs, or slower than the "
            "window, is missed. Shared NAT addresses can merge unrelated users.",
        ),
    )
    investigation_steps = (
        "Identify the source IP: internal host, VPN pool, NAT gateway, or external?",
        "List the targeted accounts: do they look enumerated (alphabetical, common names)?",
        "If a success followed, treat that account as potentially compromised and review "
        "its activity after the logon.",
        "Check whether the same source attempted other services or hosts.",
    )
    false_positives = (
        "A shared kiosk or jump host where several users mistype passwords.",
        "Many users behind one NAT or proxy address failing for unrelated reasons.",
        "A misconfigured application cycling through a list of service accounts.",
    )
    limitations = (
        "Events without source_ip or username are not evaluated.",
        "Non-overlapping windows can split a spray that straddles a boundary.",
        "Usernames are compared case-insensitively but not across domains.",
    )
    unknowns = (
        "Whether the source address represents one actor or many users behind NAT.",
        "Which passwords were tried (not present in authentication logs).",
    )
    changelog = (RuleChange(1, "2026-10-30", "Initial version."),)
    params_model = MultiAccountParams

    def evaluate(self, events: Sequence[EventRecord], params: MultiAccountParams) -> list[Finding]:
        groups: dict[str, list[EventRecord]] = defaultdict(list)
        for event in events:
            if event.event_type == FAILURE and event.source_ip and event.username:
                groups[event.source_ip].append(event)

        def distinct(chunk: Sequence[EventRecord]) -> set[str]:
            return {lower(e.username) or "" for e in chunk}

        window = timedelta(seconds=params.window_seconds)
        lookahead = timedelta(seconds=params.success_lookahead_seconds)
        findings = []
        for ip, failures in sorted(groups.items()):
            for burst in greedy_windows(
                failures, window, lambda chunk: len(distinct(chunk)) >= params.distinct_accounts
            ):
                accounts = sorted(distinct(burst))
                conditions = [
                    Condition(
                        f"At least {params.distinct_accounts} different accounts failed from one "
                        f"source within {params.window_seconds}s",
                        f"{len(accounts)} accounts from {ip}: {', '.join(accounts)}",
                    )
                ]
                success = next(
                    (
                        s
                        for s in (
                            _later_success(events, burst[-1], lookahead, username=a, source_ip=ip)
                            for a in accounts
                        )
                        if s is not None
                    ),
                    None,
                )
                severity, evidence = self.severity, tuple(burst)
                if success is not None:
                    severity = Severity.HIGH
                    evidence = (*burst, success)
                    conditions.append(
                        Condition(
                            "The same source later logged on successfully as a targeted account",
                            f"{success.username} ({success.event_id})",
                        )
                    )
                findings.append(
                    Finding(
                        rule_id=self.id,
                        title=f"{ip} failed to log on as {len(accounts)} different accounts",
                        severity=severity,
                        summary=f"{len(burst)} failures from {ip} across {len(accounts)} accounts.",
                        events=evidence,
                        conditions=tuple(conditions),
                        mitre_ids=("T1110.003",),
                    )
                )
        return findings
