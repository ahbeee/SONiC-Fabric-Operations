from collector.analytics import Analyzer
from collector.store import Store


def test_type4_withdraw_is_suppressed_when_attachment_is_down(tmp_path):
    store = Store(tmp_path / "test.db")
    esi = "03:00:00:00:00:11:11:00:00:01"
    segment = {"name": "ES-1", "esi": esi, "attachments": [
        {"device": "Leaf-1", "interface": "PortChannel1", "vtep": "1.1.1.1"},
        {"device": "Leaf-2", "interface": "PortChannel1", "vtep": "2.2.2.2"},
    ]}
    route = {"route-distinguisher": "1.1.1.1:100",
             "prefix": f"[4]:[{esi}]:[32]:[1.1.1.1]",
             "attr-sets": {"state": {"next-hop": "1.1.1.1"}}}
    store.set_point("Leaf-1", "interface_oper_status", "PortChannel1", "UP")
    store.set_point("Leaf-2", "interface_oper_status", "PortChannel1", "UP")
    store.apply_snapshot("Leaf-3", "evpn_loc_rib", {"type4": route})
    analyzer = Analyzer(store, ethernet_segments=[segment])
    analyzer.run()
    store.set_point("Leaf-1", "interface_oper_status", "PortChannel1", "DOWN")
    store.apply_snapshot("Leaf-3", "evpn_loc_rib", {})
    analyzer.run()
    active = store.rows("SELECT category,title FROM incidents WHERE status='ACTIVE'")
    assert active == [{"category": "ESI_DEGRADED",
                       "title": "Ethernet Segment redundancy degraded: ES-1"}]


def test_bgp_link_down_is_one_topology_incident(tmp_path):
    store = Store(tmp_path / "test.db")
    a_key = "/neighbor[neighbor-address=Ethernet8]"
    b_key = "/neighbor[neighbor-address=Ethernet72]"
    store.apply_snapshot("Spine-2", "bgp_neighbors", {a_key: {
        "neighbor-address": "Ethernet8", "state": {"session-state": "IDLE"}}})
    store.apply_snapshot("Leaf-3", "bgp_neighbors", {b_key: {
        "neighbor-address": "Ethernet72", "state": {"session-state": "IDLE"}}})
    link = {"name": "Spine-2--Leaf-3", "a_device": "Spine-2", "a_neighbor": "Ethernet8",
            "b_device": "Leaf-3", "b_neighbor": "Ethernet72"}
    analyzer = Analyzer(store, bgp_links=[link])
    store.set_status("Spine-2", "10.0.0.2", "UP")
    store.set_status("Leaf-3", "10.0.0.3", "UP")
    analyzer.run()
    active = store.rows("SELECT category,title FROM incidents WHERE status='ACTIVE'")
    assert active == [{"category": "BGP_SESSION_DOWN",
                       "title": "BGP adjacency down: Spine-2--Leaf-3"}]


def test_link_recovery_suppresses_endpoint_reset_incidents(tmp_path):
    store = Store(tmp_path / "test.db")
    link = {"name": "Spine-2--Leaf-3", "a_device": "Spine-2", "a_neighbor": "Ethernet8",
            "b_device": "Leaf-3", "b_neighbor": "Ethernet72"}
    analyzer = Analyzer(store, bgp_links=[link])
    store.upsert_incident(fingerprint="bgp-link-down:Spine-2--Leaf-3", severity="HIGH",
                          category="BGP_SESSION_DOWN", title="down", summary="down",
                          confidence="HIGH", details=link)
    store.resolve_incident("bgp-link-down:Spine-2--Leaf-3", "recovered")
    key = "/neighbor[neighbor-address=Ethernet72]"
    store.apply_snapshot("Leaf-3", "bgp_neighbors", {key: {"neighbor-address": "Ethernet72",
                         "state": {"session-state": "ESTABLISHED", "last-established": "100",
                                   "established-transitions": "1"}}})
    store.apply_snapshot("Leaf-3", "bgp_neighbors", {key: {"neighbor-address": "Ethernet72",
                         "state": {"session-state": "ESTABLISHED", "last-established": "1",
                                   "established-transitions": "2"}}})
    analyzer._bgp_session_resets(store.rows("SELECT * FROM events"))
    assert store.rows("SELECT * FROM incidents WHERE category='BGP_SESSION_RESET' AND status='ACTIVE'") == []


def test_all_leaf_links_down_aggregate_to_fabric_isolation(tmp_path):
    store = Store(tmp_path / "test.db")
    links = [
        {"name": "S1--L3", "a_device": "Spine-1", "a_neighbor": "Ethernet8",
         "b_device": "Leaf-3", "b_neighbor": "Ethernet76"},
        {"name": "S2--L3", "a_device": "Spine-2", "a_neighbor": "Ethernet8",
         "b_device": "Leaf-3", "b_neighbor": "Ethernet72"},
    ]
    snapshots = {}
    for link in links:
        for device, neighbor in ((link["a_device"], link["a_neighbor"]),
                                 (link["b_device"], link["b_neighbor"])):
            key = f"/neighbor[neighbor-address={neighbor}]"
            snapshots.setdefault(device, {})[key] = {
                "neighbor-address": neighbor, "state": {"session-state": "IDLE"}}
    for device, records in snapshots.items():
        store.apply_snapshot(device, "bgp_neighbors", records)
    analyzer = Analyzer(store, bgp_links=links)
    store.set_status("Spine-1", "10.0.0.1", "UP")
    store.set_status("Spine-2", "10.0.0.2", "UP")
    store.set_status("Leaf-3", "10.0.0.3", "UP")
    analyzer.run()
    active = store.rows("SELECT category,title FROM incidents WHERE status='ACTIVE'")
    assert active == [{"category": "FABRIC_ISOLATION", "title": "Leaf isolated from fabric: Leaf-3"}]


def test_device_down_suppresses_bgp_link_symptom(tmp_path):
    store = Store(tmp_path / "test.db")
    link = {"name": "S2--L3", "a_device": "Spine-2", "a_neighbor": "Ethernet8",
            "b_device": "Leaf-3", "b_neighbor": "Ethernet72"}
    store.set_status("Spine-2", "10.0.0.2", "UP")
    store.set_status("Leaf-3", "10.0.0.3", "DOWN", "unreachable")
    analyzer = Analyzer(store, bgp_links=[link])
    analyzer.run()
    assert store.rows("SELECT * FROM incidents WHERE category='BGP_SESSION_DOWN' AND status='ACTIVE'") == []


def test_missing_evpn_afi_creates_device_level_incident(tmp_path):
    store = Store(tmp_path / "test.db")
    links = [
        {"name": "S1--L3", "a_device": "Spine-1", "a_neighbor": "Ethernet8",
         "b_device": "Leaf-3", "b_neighbor": "Ethernet76"},
        {"name": "S2--L3", "a_device": "Spine-2", "a_neighbor": "Ethernet8",
         "b_device": "Leaf-3", "b_neighbor": "Ethernet72"},
    ]
    store.set_status("Leaf-3", "10.0.0.3", "UP")
    records = {}
    for neighbor in ("Ethernet72", "Ethernet76"):
        records[f"/neighbor[neighbor-address={neighbor}]"] = {
            "neighbor-address": neighbor, "state": {"session-state": "ESTABLISHED"},
            "afi-safis": {"afi-safi": [{"afi-safi-name": "IPV4_UNICAST",
                                           "state": {"active": True}}]}}
    store.apply_snapshot("Leaf-3", "bgp_neighbors", records)
    Analyzer(store, bgp_links=links)._analyze_evpn_afi()
    incident = store.rows("SELECT * FROM incidents WHERE status='ACTIVE'")[0]
    assert incident["category"] == "EVPN_AFI_INACTIVE"
    assert incident["severity"] == "CRITICAL"


def test_missing_single_local_type3_creates_vni_coverage_incident(tmp_path):
    store = Store(tmp_path / "test.db")
    store.set_status("Leaf-3", "10.0.0.3", "UP")
    route = {"route-distinguisher": "3.3.3.3:10", "prefix": "[3]:[0]:[32]:[3.3.3.3]",
             "attr-sets": {"state": {"next-hop": "3.3.3.3"}}}
    store.apply_snapshot("Leaf-3", "evpn_loc_rib", {"vni1010": route})
    analyzer = Analyzer(store)
    analyzer.expected_vnis = [
        {"device": "Leaf-3", "vtep": "3.3.3.3", "vni": 1010, "rd": "3.3.3.3:10"},
        {"device": "Leaf-3", "vtep": "3.3.3.3", "vni": 1040, "rd": "3.3.3.3:40"},
    ]
    analyzer._analyze_vni_coverage()
    incident = store.rows("SELECT * FROM incidents WHERE status='ACTIVE'")[0]
    assert incident["category"] == "VNI_COVERAGE_LOSS"
    assert "1040" in incident["summary"]


def test_up_attachment_with_missing_type4_is_membership_loss(tmp_path):
    store = Store(tmp_path / "test.db")
    esi = "03:00:00:00:00:11:11:00:00:01"
    segment = {"name": "ES-1", "esi": esi, "attachments": [
        {"device": "Leaf-1", "interface": "PortChannel1", "vtep": "1.1.1.1"},
        {"device": "Leaf-2", "interface": "PortChannel1", "vtep": "2.2.2.2"}]}
    store.set_status("Leaf-1", "10.0.0.1", "UP")
    store.set_status("Leaf-2", "10.0.0.2", "UP")
    store.set_point("Leaf-1", "interface_oper_status", "PortChannel1", "UP")
    store.set_point("Leaf-2", "interface_oper_status", "PortChannel1", "UP")
    type4 = {"route-distinguisher": "1.1.1.1:100",
             "prefix": f"[4]:[{esi}]:[32]:[1.1.1.1]",
             "attr-sets": {"state": {"next-hop": "1.1.1.1"}}}
    store.apply_snapshot("Spine-1", "evpn_loc_rib", {"leaf1": type4})
    analyzer = Analyzer(store, ethernet_segments=[segment])
    analyzer._analyze_ethernet_segments()
    incident = store.rows("SELECT * FROM incidents WHERE status='ACTIVE'")[0]
    assert incident["category"] == "ESI_MEMBERSHIP_LOSS"
    assert "Leaf-2/2.2.2.2" in incident["summary"]


def test_down_es_attachment_suppresses_vni_coverage_symptom(tmp_path):
    store = Store(tmp_path / "test.db")
    store.set_status("Leaf-1", "10.0.0.1", "UP")
    store.set_point("Leaf-1", "interface_oper_status", "PortChannel1", "DOWN")
    segment = {"name": "ES-1", "esi": "03:00:01", "attachments": [
        {"device": "Leaf-1", "interface": "PortChannel1", "vtep": "1.1.1.1"}]}
    analyzer = Analyzer(store, ethernet_segments=[segment])
    analyzer.expected_vnis = [
        {"device": "Leaf-1", "vtep": "1.1.1.1", "vni": 1010, "rd": "1.1.1.1:10"}]
    analyzer._analyze_vni_coverage()
    assert store.rows("SELECT * FROM incidents WHERE category='VNI_COVERAGE_LOSS' AND status='ACTIVE'") == []


def test_missing_es_trunk_vlan_creates_coverage_incident(tmp_path):
    store = Store(tmp_path / "test.db")
    esi = "03:00:00:00:00:11:11:00:00:01"
    segment = {"name": "ES-1", "esi": esi, "attachments": [
        {"device": "Leaf-1", "interface": "PortChannel1", "vtep": "1.1.1.1",
         "vlans": [10, 20, 30, 40]},
        {"device": "Leaf-2", "interface": "PortChannel1", "vtep": "2.2.2.2",
         "vlans": [10, 20, 30, 40]}]}
    for device, vtep, vlans in (("Leaf-1", "1.1.1.1", [10, 20, 30]),
                                ("Leaf-2", "2.2.2.2", [10, 20, 30, 40])):
        store.set_status(device, "10.0.0.1", "UP")
        store.set_point(device, "interface_oper_status", "PortChannel1", "UP")
        key = "/interface[name=PortChannel1]/aggregation/switched-vlan/state"
        store.apply_snapshot(device, "interfaces", {key: {"trunk-vlans": vlans}})
        type4 = {"route-distinguisher": f"{vtep}:100",
                 "prefix": f"[4]:[{esi}]:[32]:[{vtep}]",
                 "attr-sets": {"state": {"next-hop": vtep}}}
        store.apply_snapshot(device, "evpn_loc_rib", {f"type4-{device}": type4})
    Analyzer(store, ethernet_segments=[segment])._analyze_ethernet_segments()
    incident = store.rows("SELECT * FROM incidents WHERE category='ES_VLAN_COVERAGE_LOSS'")[0]
    assert incident["status"] == "ACTIVE"
    assert "Leaf-1/PortChannel1 missing VLAN(s) 40" in incident["summary"]


def test_vlan_gap_suppresses_matching_vni_loss(tmp_path):
    store = Store(tmp_path / "test.db")
    store.set_status("Leaf-1", "10.0.0.1", "UP")
    store.upsert_incident(fingerprint="ethernet-segment-vlans:esi", severity="HIGH",
                          category="ES_VLAN_COVERAGE_LOSS", title="VLAN gap", summary="40",
                          confidence="HIGH", details={"gaps": [
                              {"device": "Leaf-1", "missing_vlans": [40]}]})
    analyzer = Analyzer(store)
    analyzer.expected_vnis = [
        {"device": "Leaf-1", "vtep": "1.1.1.1", "vlan": 40,
         "vni": 1040, "rd": "1.1.1.1:40"}]
    analyzer._analyze_vni_coverage()
    assert store.rows("SELECT * FROM incidents WHERE category='VNI_COVERAGE_LOSS' AND status='ACTIVE'") == []
