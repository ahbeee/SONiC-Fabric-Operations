import yaml
from fastapi.testclient import TestClient

from collector.store import Store
from collector.web import create_app


def test_device_api_never_exposes_credentials_and_topology_reports_link(tmp_path):
    (tmp_path / "static").mkdir()
    (tmp_path / "static" / "index.html").write_text("ok", encoding="utf-8")
    (tmp_path / "inventory.yaml").write_text(yaml.safe_dump({
        "devices": [{"name": "Spine-1", "address": "10.0.0.1", "notes": "Core rack A"},
                    {"name": "Leaf-1", "address": "10.0.0.2"}],
        "paths": {}, "ethernet_segments": [],
        "bgp_links": [{"name": "link", "a_device": "Spine-1", "a_neighbor": "Ethernet0",
                       "b_device": "Leaf-1", "b_neighbor": "Ethernet1"}],
    }, sort_keys=False), encoding="utf-8")
    store = Store(tmp_path / "test.db")
    store.set_status("Spine-1", "10.0.0.1", "UP")
    store.apply_snapshot("Spine-1", "bgp_neighbors", {"peer": {
        "neighbor-address": "Ethernet0",
        "state": {"session-state": "ESTABLISHED",
                  "host-name-cap": {"hostname-advertised": "fabric-spine-01"}},
    }})
    app = TestClient(create_app(store, tmp_path))

    devices = app.get("/api/config/devices").json()
    assert devices[0]["status"] == "UP"
    assert "password" not in str(devices).lower()
    response = app.post("/api/config/devices", json={"notes": "Rack B", "address": "10.0.0.3",
                                                      "username": "admin", "password": "secret"})
    assert response.status_code == 201
    assert "secret" not in response.text
    assert "secret" not in app.get("/api/config/devices").text
    assert "secret" in (tmp_path / "device-secrets.yaml").read_text(encoding="utf-8")
    assert app.post("/api/config/devices", json={"notes": "bad", "address": "x",
                                                  "username": "admin", "password": "secret",
                                                  "unexpected": True}).status_code == 422
    assert app.delete("/api/config/devices/device-10.0.0.3").status_code == 200
    assert "device-10.0.0.3" not in (tmp_path / "device-secrets.yaml").read_text(encoding="utf-8")

    topology = app.get("/api/topology").json()
    assert len(topology["nodes"]) == 2
    assert topology["nodes"][0]["hostname"] == "fabric-spine-01"
    assert topology["nodes"][0]["notes"] == "Core rack A"
    assert topology["bgp_links"][0]["status"] == "UNKNOWN"
    assert app.delete("/api/config/devices/Leaf-1").status_code == 409
