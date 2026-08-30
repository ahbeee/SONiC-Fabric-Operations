from __future__ import annotations

import json
import re
from typing import Any


INTERFACE = re.compile(r"interface\[name=([^\]]+)\]")


def hostname_aliases(value: str) -> set[str]:
    value = value.strip().lower().rstrip(".")
    return {value, value.split(".", 1)[0]} if value else set()


def discover_lldp_links(rows: list[dict[str, Any]], devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build managed-device links from current OpenConfig LLDP neighbor state."""
    aliases: dict[str, str] = {}
    addresses: dict[str, str] = {}
    for device in devices:
        for alias in hostname_aliases(str(device.get("hostname", ""))):
            aliases[alias] = device["name"]
        addresses[str(device["address"])] = device["name"]

    observations: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        value = json.loads(row["value_json"]) if isinstance(row.get("value_json"), str) else row.get("value", {})
        state = value.get("state", value) if isinstance(value, dict) else {}
        system_name = first(state, "system-name", "system_name", "neighbor-system-name")
        management = first(state, "management-address", "management_address")
        remote = next((aliases[a] for a in hostname_aliases(str(system_name or "")) if a in aliases), None)
        if not remote and management is not None:
            candidates = management if isinstance(management, list) else [management]
            remote = next((addresses.get(str(item)) for item in candidates if addresses.get(str(item))), None)
        local = row["device"]
        if not remote or remote == local:
            continue
        match = INTERFACE.search(row.get("route_key", ""))
        local_interface = first(state, "local-interface", "local_interface") or (match.group(1) if match else "unknown")
        remote_interface = first(state, "port-id", "port_id", "port-description", "port_description") or "unknown"
        pair = tuple(sorted((local, remote)))
        observation = observations.setdefault(pair, {
            "name": f"{pair[0]}--{pair[1]}", "a_device": pair[0], "b_device": pair[1],
            "a_interface": "unknown", "b_interface": "unknown", "status": "UP",
            "source": "LLDP", "evidence_count": 0, "observed_at": row.get("observed_at"),
        })
        if local == pair[0]:
            observation["a_interface"], observation["b_interface"] = str(local_interface), str(remote_interface)
        else:
            observation["b_interface"], observation["a_interface"] = str(local_interface), str(remote_interface)
        observation["evidence_count"] += 1
        observation["observed_at"] = max(filter(None, [observation.get("observed_at"), row.get("observed_at")]),
                                         default=None)
    return sorted(observations.values(), key=lambda item: (item["a_device"], item["b_device"]))


def merge_fabric_links(lldp_links: list[dict[str, Any]], bgp_links: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Prefer discovered physical links and overlay configured BGP health by device pair."""
    result = {tuple(sorted((link["a_device"], link["b_device"]))): dict(link) for link in lldp_links}
    for bgp in bgp_links:
        pair = tuple(sorted((bgp["a_device"], bgp["b_device"])))
        if pair in result:
            result[pair]["bgp_status"] = bgp["status"]
            result[pair]["status"] = bgp["status"]
            result[pair]["source"] = "LLDP+BGP"
        else:
            result[pair] = {**bgp, "source": "BGP_CONFIG",
                            "a_interface": bgp.get("a_neighbor", "unknown"),
                            "b_interface": bgp.get("b_neighbor", "unknown")}
    return sorted(result.values(), key=lambda item: (item["a_device"], item["b_device"]))


def first(data: dict[str, Any], *keys: str) -> Any:
    return next((data[key] for key in keys if data.get(key) not in (None, "")), None)
