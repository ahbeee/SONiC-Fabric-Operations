from collector.gnmi import normalize_get


def test_route_entries_get_independent_keys():
    response = {"notification": [{"prefix": "/ni", "update": [{"path": "routes", "val": {
        "openconfig-bgp-evpn-ext:routes": {"route": [
            {"route-distinguisher": "1:1", "prefix": "[2]:[0]:[48]:[aa:bb:cc:dd:ee:ff]", "path-id": 0},
            {"route-distinguisher": "1:1", "prefix": "[4]:[00:01]", "path-id": 1},
        ]}}}]}]}
    result = normalize_get(response)
    assert len(result) == 2
    assert any("route-distinguisher=1:1" in key and "path-id=0" in key for key in result)
