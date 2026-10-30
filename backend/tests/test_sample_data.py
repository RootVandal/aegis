from ipaddress import ip_address, ip_network

from fastapi.testclient import TestClient

from app.ingestion.normalizer import normalize_record
from app.sample_data.baseline import generate_baseline

DOCUMENTATION_NETS = (ip_network("203.0.113.0/24"), ip_network("198.51.100.0/24"))


def test_baseline_is_deterministic() -> None:
    assert generate_baseline() == generate_baseline()


def test_every_baseline_record_normalizes() -> None:
    events = [normalize_record(record) for record in generate_baseline()]

    assert len({e.event_id for e in events}) == len(events)
    assert {e.event_type for e in events} >= {
        "authentication_success",
        "authentication_failure",
        "process_creation",
        "network_connection",
        "logoff",
    }


def test_baseline_uses_only_private_or_documentation_addresses() -> None:
    for normalized in map(normalize_record, generate_baseline()):
        for value in (normalized.source_ip, normalized.destination_ip):
            if value is None:
                continue
            address = ip_address(value)
            assert address.is_private or any(address in net for net in DOCUMENTATION_NETS), value


def test_sysmon_and_security_events_resolve_to_the_same_user() -> None:
    usernames = {normalize_record(r).username for r in generate_baseline()}

    assert "a.kowalski" in usernames
    assert not any("\\" in name for name in usernames if name)


def test_dataset_listing_and_loading(client: TestClient) -> None:
    datasets = client.get("/api/v1/datasets").json()
    assert [d["id"] for d in datasets] == ["baseline"]
    expected = datasets[0]["event_count"]

    first = client.post("/api/v1/datasets/baseline/load").json()["batch"]
    second = client.post("/api/v1/datasets/baseline/load").json()["batch"]

    assert (first["accepted_count"], first["data_origin"]) == (expected, "synthetic")
    assert (second["accepted_count"], second["duplicate_count"]) == (0, expected)
    stored = client.get("/api/v1/events", params={"data_origin": "synthetic"}).json()["total"]
    assert stored == expected


def test_unknown_dataset_returns_404(client: TestClient) -> None:
    response = client.post("/api/v1/datasets/nope/load")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "dataset_not_found"
