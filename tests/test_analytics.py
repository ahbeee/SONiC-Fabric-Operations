from collector.analytics import Analyzer, parse_route
from collector.store import Store, comparable, meaningful_change


def test_parse_type2_mac_and_vtep():
    route = parse_route({
        "route-distinguisher": "1.1.1.1:10",
        "prefix": "[2]:[0]:[48]:[aa:bb:cc:dd:ee:ff]:[32]:[192.0.2.1]",
        "attr-sets": {"state": {"next-hop": "1.1.1.1"}},
    })
    assert route.route_type == 2
    assert route.mac == "aa:bb:cc:dd:ee:ff"
    assert route.next_hop == "1.1.1.1"


def test_parse_type4():
    route = parse_route({"prefix": "[4]:[03:00:00:00:00:11:11:00:00:01]:[32]:[1.1.1.1]"})
    assert route.route_type == 4


def test_last_modified_is_not_a_route_change():
    assert comparable({"state": {"last-modified": "2", "next-hop": "1.1.1.1"}}) == comparable(
        {"state": {"last-modified": "1", "next-hop": "1.1.1.1"}}
    )


def test_normal_bgp_uptime_and_message_growth_is_not_an_event():
    old = {"neighbor-address": "Ethernet72", "state": {
        "session-state": "ESTABLISHED", "last-established": "10",
        "established-transitions": "2", "messages": {"received": {"KEEPALIVE": "5"}}}}
    new = {"neighbor-address": "Ethernet72", "state": {
        "session-state": "ESTABLISHED", "last-established": "20",
        "established-transitions": "2", "messages": {"received": {"KEEPALIVE": "6"}}}}
    assert not meaningful_change("bgp_neighbors", "neighbor", old, new)


def test_bgp_uptime_reset_is_an_event():
    old = {"state": {"session-state": "ESTABLISHED", "last-established": "100",
                     "established-transitions": "2"}}
    new = {"state": {"session-state": "ESTABLISHED", "last-established": "1",
                     "established-transitions": "3"}}
    assert meaningful_change("bgp_neighbors", "neighbor", old, new)


def test_interface_counter_only_change_is_not_an_event():
    assert not meaningful_change("interfaces", "/interface/state/counters/in-octets", "10", "20")


def test_interface_ra_counters_and_vlan_order_are_not_events():
    assert not meaningful_change("interfaces", "/ipv6/router-advertisement/state",
                                 {"interval": 10, "ra-pkt-rcvd": 1},
                                 {"interval": 10, "ra-pkt-rcvd": 2})
    assert not meaningful_change("interfaces", "/switched-vlan/state",
                                 {"trunk-vlans": [30, 10, 20]},
                                 {"trunk-vlans": [10, 20, 30]})


def test_mass_withdraw_creates_incident(tmp_path):
    store = Store(tmp_path / "test.db")
    route = {"route-distinguisher": "1:1", "prefix": "[3]:[0]:[32]:[1.1.1.1]",
             "attr-sets": {"state": {"next-hop": "1.1.1.1"}}}
    store.apply_snapshot("Leaf-1", "evpn_loc_rib", {"route-1": route})
    analyzer = Analyzer(store, mass_withdraw_threshold=1)
    analyzer.run()  # baseline
    store.apply_snapshot("Leaf-1", "evpn_loc_rib", {})
    assert analyzer.run() == 1
    incident = store.rows("SELECT * FROM incidents")[0]
    assert incident["category"] == "VTEP_FAILURE"
    assert incident["severity"] == "CRITICAL"


def test_vtep_failure_suppresses_device_vni_symptom(tmp_path):
    store = Store(tmp_path / "test.db")
    route = {"route-distinguisher": "3.3.3.3:10", "prefix": "[3]:[0]:[32]:[3.3.3.3]",
             "attr-sets": {"state": {"next-hop": "3.3.3.3"}}}
    store.apply_snapshot("Leaf-3", "evpn_loc_rib", {"route": route})
    analyzer = Analyzer(store, mass_withdraw_threshold=1,
                        vtep_devices={"3.3.3.3": "Leaf-3"})
    analyzer.run()
    store.upsert_incident(fingerprint="vni-coverage:Leaf-3", severity="HIGH",
                          category="VNI_COVERAGE_LOSS", title="VNI missing", summary="all",
                          confidence="HIGH", details={"device": "Leaf-3"})
    store.apply_snapshot("Leaf-3", "evpn_loc_rib", {})
    analyzer.run()
    assert store.rows("SELECT status FROM incidents WHERE fingerprint='vni-coverage:Leaf-3'")[0]["status"] == "RESOLVED"
    assert store.rows("SELECT status FROM incidents WHERE fingerprint='vtep-withdraw:3.3.3.3'")[0]["status"] == "ACTIVE"


def test_mac_mobility_pairs_announce_and_withdraw_across_observers(tmp_path):
    store = Store(tmp_path / "test.db")
    mac = "aa:bb:cc:dd:ee:ff"
    old = {"route-distinguisher": "3.3.3.3:10",
           "prefix": f"[2]:[0]:[48]:[{mac}]:[0]:[]",
           "attr-sets": {"state": {"next-hop": "3.3.3.3"}}}
    new = {"route-distinguisher": "1.1.1.1:10",
           "prefix": f"[2]:[0]:[48]:[{mac}]:[0]:[]",
           "attr-sets": {"state": {"next-hop": "1.1.1.1", "ext-community": ["MM:1"]}}}
    store.apply_snapshot("Spine-1", "evpn_loc_rib", {"old": old})
    store.apply_snapshot("Spine-2", "evpn_loc_rib", {"old": old})
    analyzer = Analyzer(store)
    analyzer.run()
    store.apply_snapshot("Spine-1", "evpn_loc_rib", {"new": new})
    store.apply_snapshot("Spine-2", "evpn_loc_rib", {"new": new})
    analyzer.run()
    incident = store.rows(
        "SELECT * FROM incidents WHERE fingerprint=?", (f"mac-mobility:{mac}",)
    )[0]
    details = __import__("json").loads(incident["details_json"])
    assert incident["category"] == "MAC_MOBILITY"
    assert details["old_vtep"] == "3.3.3.3"
    assert details["new_vtep"] == "1.1.1.1"
    assert details["observers"] == ["Spine-1", "Spine-2"]


def test_alternate_path_withdraw_is_not_vtep_failure(tmp_path):
    store = Store(tmp_path / "test.db")
    imet = {"route-distinguisher": "1:1", "prefix": "[3]:[0]:[32]:[1.1.1.1]",
            "attr-sets": {"state": {"next-hop": "1.1.1.1"}}}
    alternate = {"route-distinguisher": "1:2", "prefix": "[2]:[0]:[48]:[aa:bb:cc:dd:ee:ff]",
                 "attr-sets": {"state": {"next-hop": "1.1.1.1"}}}
    store.apply_snapshot("Spine-1", "evpn_loc_rib", {"imet": imet, "alternate": alternate})
    analyzer = Analyzer(store, mass_withdraw_threshold=1)
    analyzer.run()
    store.apply_snapshot("Spine-1", "evpn_loc_rib", {"imet": imet})
    analyzer.run()
    assert store.rows("SELECT * FROM incidents WHERE status='ACTIVE'") == []


def test_spine_down_suppresses_vtep_symptoms(tmp_path):
    store = Store(tmp_path / "test.db")
    route = {"route-distinguisher": "3:1", "prefix": "[3]:[0]:[32]:[3.3.3.3]",
             "attr-sets": {"state": {"next-hop": "3.3.3.3"}}}
    store.apply_snapshot("Leaf-1", "evpn_loc_rib", {"route": route})
    analyzer = Analyzer(store, mass_withdraw_threshold=1)
    analyzer.run()
    store.set_status("Spine-2", "10.0.0.2", "DOWN", "unreachable")
    store.apply_snapshot("Leaf-1", "evpn_loc_rib", {})
    analyzer.run()
    assert store.rows("SELECT * FROM incidents WHERE category='VTEP_FAILURE' AND status='ACTIVE'") == []


def test_incident_preserves_peak_severity_during_recovery(tmp_path):
    store = Store(tmp_path / "test.db")
    args = dict(fingerprint="device-down:Leaf-1", confidence="HIGH")
    store.upsert_incident(**args, severity="CRITICAL", category="DEVICE_UNREACHABLE",
                          title="unreachable", summary="all failed", details={"phase": "down"})
    store.upsert_incident(**args, severity="HIGH", category="DEVICE_DEGRADED",
                          title="degraded", summary="some failed", details={"phase": "recovering"})
    incident = store.rows("SELECT * FROM incidents")[0]
    assert incident["severity"] == "HIGH"
    assert incident["category"] == "DEVICE_DEGRADED"
    assert incident["title"] == "degraded"
    assert incident["peak_severity"] == "CRITICAL"
    assert incident["peak_category"] == "DEVICE_UNREACHABLE"


def test_bgp_uptime_reset_creates_and_resolves_incident(tmp_path):
    store = Store(tmp_path / "test.db")
    key = "/neighbors/neighbor[neighbor-address=Ethernet72]"
    before = {"neighbor-address": "Ethernet72", "state": {
        "session-state": "ESTABLISHED", "last-established": 40,
        "established-transitions": 2}}
    reset = {"neighbor-address": "Ethernet72", "state": {
        "session-state": "ESTABLISHED", "last-established": "0",
        "established-transitions": "3"}}
    stable = {"neighbor-address": "Ethernet72", "state": {
        "session-state": "ESTABLISHED", "last-established": 35,
        "established-transitions": 3}}
    store.apply_snapshot("Leaf-1", "bgp_neighbors", {key: before})
    analyzer = Analyzer(store)
    analyzer.run()
    store.apply_snapshot("Leaf-1", "bgp_neighbors", {key: reset})
    analyzer.run()
    incident = store.rows("SELECT * FROM incidents WHERE category='BGP_SESSION_RESET'")[0]
    assert incident["status"] == "ACTIVE"
    store.apply_snapshot("Leaf-1", "bgp_neighbors", {key: stable})
    analyzer.run()
    incident = store.rows("SELECT * FROM incidents WHERE category='BGP_SESSION_RESET'")[0]
    assert incident["status"] == "RESOLVED"


def test_bgp_established_to_idle_creates_reset_incident(tmp_path):
    store = Store(tmp_path / "test.db")
    key = "/neighbors/neighbor[neighbor-address=Ethernet72]"
    up = {"state": {"session-state": "ESTABLISHED", "last-established": "100",
                    "established-transitions": "2"}}
    idle = {"state": {"session-state": "IDLE", "last-established": "100",
                      "established-transitions": "2"}}
    store.apply_snapshot("Spine-2", "bgp_neighbors", {key: up})
    analyzer = Analyzer(store)
    analyzer.run()
    store.apply_snapshot("Spine-2", "bgp_neighbors", {key: idle})
    analyzer.run()
    incident = store.rows("SELECT category,status FROM incidents")[0]
    assert incident == {"category": "BGP_SESSION_RESET", "status": "ACTIVE"}


def test_type2_bestpath_change_without_mm_community_is_not_mac_mobility(tmp_path):
    store = Store(tmp_path / "test.db")
    mac = "00:00:00:10:10:10"
    old = {"prefix": f"[2]:[0]:[48]:[{mac}]",
           "attr-sets": {"state": {"next-hop": "2.2.2.2"}}}
    new = {"prefix": f"[2]:[0]:[48]:[{mac}]",
           "attr-sets": {"state": {"next-hop": "1.1.1.1"}}}
    store.apply_snapshot("Spine-1", "evpn_loc_rib", {"old": old})
    analyzer = Analyzer(store)
    analyzer.run()
    store.apply_snapshot("Spine-1", "evpn_loc_rib", {"new": new})
    analyzer.run()
    assert store.rows("SELECT * FROM incidents WHERE category='MAC_MOBILITY'") == []


def test_device_incident_suppresses_same_batch_peer_resets(tmp_path):
    store = Store(tmp_path / "test.db")
    key = "/neighbors/neighbor[neighbor-address=Ethernet0]"
    up = {"state": {"session-state": "ESTABLISHED", "established-transitions": "1"}}
    idle = {"state": {"session-state": "IDLE", "established-transitions": "1"}}
    for device in ("Leaf-1", "Spine-1", "Spine-2"):
        store.apply_snapshot(device, "bgp_neighbors", {key: up})
    analyzer = Analyzer(store)
    analyzer.run()
    store.upsert_incident(fingerprint="device-down:Leaf-1", severity="CRITICAL",
                          category="DEVICE_UNREACHABLE", title="Leaf down", summary="down",
                          confidence="HIGH", details={"device": "Leaf-1"})
    for device in ("Leaf-1", "Spine-1", "Spine-2"):
        store.apply_snapshot(device, "bgp_neighbors", {key: idle})
    analyzer.run()
    assert store.rows("SELECT * FROM incidents WHERE category='BGP_SESSION_RESET' AND status='ACTIVE'") == []


def test_recently_resolved_device_incident_suppresses_late_peer_resets(tmp_path):
    store = Store(tmp_path / "test.db")
    key = "/neighbors/neighbor[neighbor-address=Ethernet8]"
    up = {"state": {"session-state": "ESTABLISHED", "established-transitions": "1"}}
    idle = {"state": {"session-state": "IDLE", "established-transitions": "1"}}
    for device in ("Leaf-3", "Spine-1", "Spine-2"):
        store.apply_snapshot(device, "bgp_neighbors", {key: up})
    analyzer = Analyzer(store)
    analyzer.run()
    store.upsert_incident(fingerprint="device-down:Leaf-3", severity="HIGH",
                          category="DEVICE_DEGRADED", title="Leaf recovering", summary="boot",
                          confidence="HIGH", details={"device": "Leaf-3"})
    store.resolve_incident("device-down:Leaf-3", "Recovered")
    for device in ("Leaf-3", "Spine-1", "Spine-2"):
        store.apply_snapshot(device, "bgp_neighbors", {key: idle})
    analyzer.run()
    assert store.rows("SELECT * FROM incidents WHERE category='BGP_SESSION_RESET' AND status='ACTIVE'") == []


def test_streamed_interface_state_overrides_polled_snapshot(tmp_path):
    store = Store(tmp_path / "test.db")
    key = "/interfaces/interface[name=PortChannel1]/state"
    store.apply_snapshot("Leaf-1", "interfaces", {key: {
        "admin-status": "UP", "oper-status": "UP"}})
    store.set_point("Leaf-1", "interface_oper_status", "PortChannel1", "DOWN")
    analyzer = Analyzer(store)
    state = analyzer._interface_state("Leaf-1", "PortChannel1")
    assert state["admin-status"] == "UP"
    assert state["oper-status"] == "DOWN"
