"""Outbound connections that match explicit, documented conditions."""

from collections import defaultdict
from collections.abc import Sequence
from datetime import timedelta
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network

from pydantic import Field, field_validator

from app.detection.mitre import technique
from app.detection.model import Condition, EventRecord, Finding, MitreMapping
from app.detection.rule import Rule, RuleChange, RuleParams, greedy_windows
from app.models.enums import Severity


class NetworkParams(RuleParams):
    # Explicit list instead of ipaddress.is_private: Python counts documentation
    # ranges (203.0.113.0/24 etc.) as private, but AEGIS training data uses them
    # to stand in for the internet.
    internal_networks: list[str] = Field(
        default=[
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "::1/128",
            "fc00::/7",
            "fe80::/10",
        ],
        description="Destinations inside these networks are not 'outbound'.",
    )
    expected_ports: list[int] = Field(
        default=[80, 443, 53, 123], description="External ports considered normal."
    )
    script_hosts: list[str] = Field(
        default=[
            "powershell.exe",
            "pwsh.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
            "rundll32.exe",
            "regsvr32.exe",
            "certutil.exe",
            "bitsadmin.exe",
        ],
        description="Processes that rarely need to talk to the internet directly.",
    )
    watchlist: list[str] = Field(default=[], description="Destination IPs that always match.")
    aggregate_window_seconds: int = Field(
        default=3600,
        ge=60,
        le=86_400,
        description="Repeated identical connections inside this window form one finding.",
    )

    @field_validator("internal_networks")
    @classmethod
    def _valid_networks(cls, value: list[str]) -> list[str]:
        for network in value:
            ip_network(network, strict=False)  # raises ValueError -> 422 for bad input
        return value

    @field_validator("watchlist")
    @classmethod
    def _valid_ips(cls, value: list[str]) -> list[str]:
        return [str(ip_address(v)) for v in value]

    @field_validator("expected_ports")
    @classmethod
    def _valid_ports(cls, value: list[int]) -> list[int]:
        if any(not 0 <= port <= 65535 for port in value):
            raise ValueError("ports must be between 0 and 65535")
        return sorted(set(value))


class SuspiciousOutboundConnections(Rule[NetworkParams]):
    id = "AEGIS-NET-001"
    name = "Suspicious Outbound Connections"
    version = 1
    description = "An outbound network connection matched one or more documented conditions."
    severity = Severity.MEDIUM
    event_types = ("network_connection",)
    required_fields = ("event_type", "destination_ip", "destination_port", "process_name")
    logic = (
        "Select network_connection events whose destination is outside internal_networks.",
        "Condition non_standard_port: destination port is not in expected_ports.",
        "Condition script_host: the connecting process is in script_hosts.",
        "Condition watchlist: the destination IP is in watchlist.",
        "At least one condition must hold. Identical (host, process, destination, port) "
        "connections within aggregate_window_seconds are reported as one finding. "
        "Severity is high when two or more conditions hold.",
    )
    mitre = (
        MitreMapping(
            technique("T1571"),
            relationship="Applies to the non_standard_port condition only: traffic to an "
            "unexpected port is how this technique is observed.",
            telemetry="Network connection events with destination port (e.g. Sysmon 3, "
            "firewall logs).",
            limitations="Command and control over 80/443 is not detected by this condition. "
            "The script_host and watchlist conditions are intentionally not mapped: a "
            "connection alone does not show which technique was used.",
        ),
    )
    investigation_steps = (
        "Identify the destination: reverse DNS, ownership, reputation, first time seen.",
        "Review the process: its command line, parent and user.",
        "Check the volume and regularity of connections (beaconing looks periodic).",
        "Look for files written or processes started around the same time.",
    )
    false_positives = (
        "Administrative scripts that download updates or call APIs.",
        "Business applications using uncommon ports (VPN clients, video, licensing).",
        "Developer and IT tooling run from PowerShell.",
    )
    limitations = (
        "Needs the process name on network events (e.g. Sysmon); plain firewall logs "
        "only support the port and watchlist conditions.",
        "Encrypted traffic content is not inspected.",
        "The watchlist is static and must be maintained by the user.",
    )
    unknowns = (
        "What data was transferred and whether the connection succeeded.",
        "Who operates the destination address.",
    )
    changelog = (RuleChange(1, "2026-10-30", "Initial version."),)
    params_model = NetworkParams

    def evaluate(self, events: Sequence[EventRecord], params: NetworkParams) -> list[Finding]:
        internal: list[IPv4Network | IPv6Network] = [
            ip_network(n, strict=False) for n in params.internal_networks
        ]
        expected_ports = set(params.expected_ports)
        script_hosts = {name.lower() for name in params.script_hosts}
        watchlist = set(params.watchlist)

        groups: dict[tuple[str, ...], list[tuple[EventRecord, tuple[Condition, ...], bool]]] = (
            defaultdict(list)
        )
        for event in events:
            if event.event_type != "network_connection" or not event.destination_ip:
                continue
            try:
                destination = ip_address(event.destination_ip)
            except ValueError:
                continue
            if any(destination in network for network in internal):
                continue
            conditions: list[Condition] = []
            non_standard = False
            if event.destination_port is not None and event.destination_port not in expected_ports:
                non_standard = True
                conditions.append(
                    Condition(
                        "External connection to a non-standard port", str(event.destination_port)
                    )
                )
            if (event.process_name or "") in script_hosts:
                conditions.append(
                    Condition(
                        "Script host or LOLBin connected to an external address",
                        event.process_name or "",
                    )
                )
            if event.destination_ip in watchlist:
                conditions.append(
                    Condition("Destination is on the watchlist", event.destination_ip)
                )
            if conditions:
                key = (
                    event.hostname or "",
                    event.process_name or "",
                    event.destination_ip,
                    str(event.destination_port),
                    "|".join(c.description for c in conditions),
                )
                groups[key].append((event, tuple(conditions), non_standard))

        window = timedelta(seconds=params.aggregate_window_seconds)
        findings = []
        for group_key in sorted(groups):
            entries = groups[group_key]
            group_conditions, port_condition = entries[0][1], entries[0][2]
            for burst in greedy_windows([e for e, _, _ in entries], window, lambda chunk: True):
                first = burst[0]
                port = f":{first.destination_port}" if first.destination_port is not None else ""
                findings.append(
                    Finding(
                        rule_id=self.id,
                        title=f"{first.process_name or 'Unknown process'} on "
                        f"{first.hostname or 'unknown host'} connected to "
                        f"{first.destination_ip}{port}",
                        severity=Severity.HIGH if len(group_conditions) >= 2 else self.severity,
                        summary=f"{len(burst)} outbound connection(s) matching "
                        f"{len(group_conditions)} condition(s).",
                        events=tuple(burst),
                        conditions=group_conditions,
                        mitre_ids=("T1571",) if port_condition else (),
                    )
                )
        return findings
