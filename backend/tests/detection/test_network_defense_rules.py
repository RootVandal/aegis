import pytest
from pydantic import ValidationError

from app.detection.registry import RULES_BY_ID
from app.models.enums import Severity
from tests.detection.helpers import proc, rec, run

NET, DEF = "AEGIS-NET-001", "AEGIS-DEF-001"


def conn(
    seconds: float = 0,
    process: str = "msedge.exe",
    ip: str = "203.0.113.10",
    port: int = 443,
    host: str = "ws-01",
) -> object:
    return rec("network_connection", seconds, hostname=host, process_name=process,
               destination_ip=ip, destination_port=port)  # fmt: skip


# --- AEGIS-NET-001 ----------------------------------------------------------


def test_browser_on_443_is_normal() -> None:
    assert run(NET, [conn()]) == []  # type: ignore[list-item]


def test_internal_destinations_are_never_outbound() -> None:
    events = [conn(process="powershell.exe", ip="10.10.0.30", port=4444),
              conn(process="powershell.exe", ip="fe80::1", port=4444)]  # fmt: skip
    assert run(NET, events) == []  # type: ignore[arg-type]


def test_non_standard_port_maps_to_t1571() -> None:
    finding = run(NET, [conn(port=8443)])[0]  # type: ignore[list-item]

    assert finding.severity is Severity.MEDIUM
    assert finding.mitre_ids == ("T1571",)


def test_script_host_alone_is_reported_without_a_mapping() -> None:
    finding = run(NET, [conn(process="powershell.exe", port=443)])[0]  # type: ignore[list-item]

    assert finding.mitre_ids == ()


def test_two_conditions_raise_severity() -> None:
    finding = run(NET, [conn(process="rundll32.exe", port=4444)])[0]  # type: ignore[list-item]

    assert finding.severity is Severity.HIGH


def test_repeated_connections_are_aggregated_per_window() -> None:
    events = [conn(t, port=4444) for t in (0, 60, 120)] + [conn(4000, port=4444)]

    findings = run(NET, events)  # type: ignore[arg-type]

    assert [len(f.events) for f in findings] == [3, 1]


def test_different_destinations_are_separate_findings() -> None:
    events = [conn(0, ip="203.0.113.1", port=4444), conn(1, ip="203.0.113.2", port=4444)]
    assert len(run(NET, events)) == 2  # type: ignore[arg-type]


def test_watchlist_and_internal_networks_are_configurable() -> None:
    event = conn(ip="203.0.113.10", port=443)

    assert run(NET, [event]) == []  # type: ignore[list-item]
    assert len(run(NET, [event], watchlist=["203.0.113.10"])) == 1  # type: ignore[list-item]
    internal = ["203.0.113.0/24", "10.0.0.0/8"]
    assert run(NET, [conn(port=4444)], internal_networks=internal) == []  # type: ignore[list-item]


def test_invalid_network_parameters_are_rejected() -> None:
    rule = RULES_BY_ID[NET]
    for bad in ({"internal_networks": ["not-a-net"]}, {"watchlist": ["999.1.1.1"]},
                {"expected_ports": [70000]}):  # fmt: skip
        with pytest.raises(ValidationError):
            rule.parse_params(bad)


def test_connection_without_destination_is_ignored() -> None:
    assert run(NET, [rec("network_connection", process_name="powershell.exe")]) == []


# --- AEGIS-DEF-001 ----------------------------------------------------------


@pytest.mark.parametrize(
    ("event", "mitre"),
    [
        (rec("security_config_change",
             extra={"control": "defender_realtime_protection", "new_state": "Disabled"}), "T1685"),
        (rec("security_config_change", extra={"control": "windows_firewall", "new_state": "off"}),
         "T1686"),
        (rec("log_cleared", extra={"log_name": "Security"}), "T1685.005"),
        (rec("other", windows_event_id=1102), "T1685.005"),
        (proc("Set-MpPreference -DisableRealtimeMonitoring $true"), "T1685"),
        (proc("netsh advfirewall set allprofiles state off", process="netsh.exe"), "T1686"),
        (proc("netsh firewall set opmode disable", process="netsh.exe"), "T1686"),
        (proc("wevtutil.exe cl Security", process="wevtutil.exe"), "T1685.005"),
        (proc("Clear-EventLog -LogName System"), "T1685.005"),
    ],
)  # fmt: skip
def test_weakened_defenses(event: object, mitre: str) -> None:
    findings = run(DEF, [event])  # type: ignore[list-item]

    assert len(findings) == 1
    assert findings[0].mitre_ids == (mitre,)


@pytest.mark.parametrize(
    "event",
    [
        rec("security_config_change", extra={"control": "windows_firewall", "new_state": "enabled"}),
        rec("security_config_change", extra={"control": "screen_saver", "new_state": "disabled"}),
        rec("security_config_change"),
        proc("Set-MpPreference -DisableRealtimeMonitoring $false"),
        proc("netsh advfirewall show allprofiles", process="netsh.exe"),
        proc("wevtutil qe Security /c:5", process="wevtutil.exe"),
    ],
)  # fmt: skip
def test_non_weakening_changes_are_ignored(event: object) -> None:
    assert run(DEF, [event]) == []  # type: ignore[list-item]


def test_audit_policy_is_reported_but_unmapped() -> None:
    event = rec("security_config_change", extra={"control": "audit_policy", "new_state": "off"})

    finding = run(DEF, [event])[0]

    assert finding.mitre_ids == ()


def test_unverified_mitre_ids_cannot_be_configured() -> None:
    with pytest.raises(ValidationError, match="mapping must be one of"):
        RULES_BY_ID[DEF].parse_params({"monitored_controls": {"edr": "T9999"}})
