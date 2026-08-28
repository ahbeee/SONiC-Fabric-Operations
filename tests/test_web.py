from fastapi.testclient import TestClient

from collector.store import Store
from collector.web import create_app


def test_health_and_structured_evpn_routes(tmp_path):
    store = Store(tmp_path / "test.db")
    store.set_status("Leaf-1", "10.0.0.1", "UP")
    route = {"route-distinguisher": "1.1.1.1:10",
             "prefix": "[2]:[0]:[48]:[aa:bb:cc:dd:ee:ff]",
             "attr-sets": {"state": {"next-hop": "1.1.1.1"}}}
    store.apply_snapshot("Leaf-1", "evpn_loc_rib", {"route": route})
    client = TestClient(create_app(store, tmp_path))
    health = client.get("/api/health").json()
    routes = client.get("/api/evpn/routes?route_type=2").json()
    assert health["devices"] == {"UP": 1}
    assert health["route_counts"] == [{"dataset": "evpn_loc_rib", "count": 1}]
    assert routes[0]["mac"] == "aa:bb:cc:dd:ee:ff"
    assert routes[0]["vtep"] == "1.1.1.1"


def test_incident_history_and_detail_timeline(tmp_path):
    store = Store(tmp_path / "test.db")
    store.upsert_incident(fingerprint="test", severity="HIGH", category="TEST",
                          title="Test incident", summary="test", confidence="HIGH",
                          details={"device": "Leaf-1"})
    store.resolve_incident("test", "Recovered")
    client = TestClient(create_app(store, tmp_path))
    history = client.get("/api/incidents?status=ALL").json()
    detail = client.get(f"/api/incidents/{history[0]['id']}").json()
    assert history[0]["status"] == "RESOLVED"
    assert detail["details"]["resolution_reason"] == "Recovered"
    assert detail["events"] == []
