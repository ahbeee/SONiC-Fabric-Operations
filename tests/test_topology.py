import json

from collector.store import Store
from collector.topology import discover_lldp_links, merge_fabric_links


def test_lldp_links_are_mapped_by_hostname_and_deduplicated():
    devices = [
        {"name": "device-10.0.0.1", "address": "10.0.0.1", "hostname": "spine-01.example"},
        {"name": "device-10.0.0.2", "address": "10.0.0.2", "hostname": "leaf-01"},
    ]
    rows = [
        {"device": "device-10.0.0.1", "route_key": "/lldp/interfaces/interface[name=Ethernet0]/neighbors/neighbor[id=1]/state",
         "value_json": json.dumps({"system-name": "leaf-01.example", "port-id": "Ethernet48"}),
         "observed_at": "2026-01-01T00:00:00Z"},
        {"device": "device-10.0.0.2", "route_key": "/lldp/interfaces/interface[name=Ethernet48]/neighbors/neighbor[id=1]/state",
         "value_json": json.dumps({"system-name": "spine-01", "port-id": "Ethernet0"}),
         "observed_at": "2026-01-01T00:00:01Z"},
    ]

    links = discover_lldp_links(rows, devices)
    assert links == [{
        "name": "device-10.0.0.1--device-10.0.0.2",
        "a_device": "device-10.0.0.1", "b_device": "device-10.0.0.2",
        "a_interface": "Ethernet0", "b_interface": "Ethernet48",
        "status": "UP", "source": "LLDP", "evidence_count": 2,
        "observed_at": "2026-01-01T00:00:01Z",
    }]


def test_bgp_health_is_overlaid_on_discovered_physical_link():
    lldp = [{"a_device": "a", "b_device": "b", "status": "UP", "source": "LLDP"}]
    bgp = [{"a_device": "a", "b_device": "b", "status": "DOWN", "name": "a--b"}]
    merged = merge_fabric_links(lldp, bgp)
    assert merged[0]["source"] == "LLDP+BGP"
    assert merged[0]["status"] == "DOWN"


def test_lldp_age_churn_does_not_create_update_events(tmp_path):
    store = Store(tmp_path / "test.db")
    key = "/lldp/interfaces/interface[name=Ethernet0]/neighbors/neighbor[index=0]/state"
    before = {"system-name": "leaf-01", "port-id": "Ethernet48", "age": "10", "last-update": "3"}
    after = {**before, "age": "20", "last-update": "1"}
    store.apply_snapshot("spine-01", "lldp_neighbors", {key: before})
    result = store.apply_snapshot("spine-01", "lldp_neighbors", {key: after})
    assert result["changed"] == 0
