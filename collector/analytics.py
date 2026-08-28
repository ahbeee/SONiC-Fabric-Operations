from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any
from datetime import datetime, timezone

from .store import Store

ROUTE_TYPE = re.compile(r"^\[(\d+)]")
MAC = re.compile(r"\[48]:\[([0-9a-f:]{17})]", re.I)
NEIGHBOR = re.compile(r"\[neighbor-address=([^]]+)]")


@dataclass(frozen=True)
class EvpnRoute:
    route_type: int | None
    prefix: str
    rd: str
    next_hop: str | None
    mac: str | None


def parse_route(value: dict[str, Any] | None) -> EvpnRoute:
    value = value or {}
    state = value.get("state", {})
    attrs = value.get("attr-sets", {}).get("state", {})
    prefix = str(value.get("prefix", state.get("prefix", "")))
    match = ROUTE_TYPE.match(prefix)
    mac = MAC.search(prefix)
    return EvpnRoute(
        route_type=int(match.group(1)) if match else None,
        prefix=prefix,
        rd=str(value.get("route-distinguisher", state.get("route-distinguisher", ""))),
        next_hop=attrs.get("next-hop"),
        mac=mac.group(1).lower() if mac else None,
    )


class Analyzer:
    def __init__(self, store: Store, mass_withdraw_threshold: int = 10, mac_flap_threshold: int = 4,
                 ethernet_segments: list[dict] | None = None, bgp_links: list[dict] | None = None,
                 vtep_devices: dict[str, str] | None = None):
        self.store = store
        self.mass_withdraw_threshold = mass_withdraw_threshold
        self.mac_flap_threshold = mac_flap_threshold
        self.ethernet_segments = ethernet_segments or []
        self.bgp_links = bgp_links or []
        self.vtep_devices = vtep_devices or {}
        self.expected_vnis: list[dict[str, Any]] = []

    def run(self) -> int:
        self._reconcile_active_incidents()
        self._analyze_ethernet_segments()
        self._analyze_bgp_links()
        self._analyze_evpn_afi()
        self._analyze_vni_coverage()
        cursor = self.store.analytics_cursor()
        all_rows = self.store.rows("SELECT * FROM events WHERE id>? ORDER BY id", (cursor,))
        rows = [row for row in all_rows if row["dataset"] == "evpn_loc_rib"]
        self._bgp_session_resets(all_rows)
        self._resolve_stable_bgp_resets()
        if not all_rows:
            return 0
        # The first database population is inventory, not a network incident.
        if cursor == 0:
            self.store.set_analytics_cursor(max(row["id"] for row in all_rows))
            return 0
        if rows:
            self._mass_withdraw(rows)
            self._mac_mobility(rows)
            self._esi_withdraw(rows)
        self.store.set_analytics_cursor(max(row["id"] for row in all_rows))
        return len(rows)

    @staticmethod
    def _neighbor_state(value: dict[str, Any]) -> dict[str, Any]:
        state = value.get("state", {}) if isinstance(value, dict) else {}
        return state if isinstance(state, dict) else {}

    @staticmethod
    def _number(value: Any) -> float | None:
        """SONiC may encode OpenConfig uint counters as JSON strings."""
        try:
            return float(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    def _bgp_session_resets(self, rows: list[dict[str, Any]]) -> None:
        evpn_withdraws = sum(
            1 for row in rows
            if row["dataset"] == "evpn_loc_rib" and row["event_type"] == "WITHDRAW"
        )
        resets: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            if row["dataset"] != "bgp_neighbors" or row["event_type"] != "UPDATE":
                continue
            current = self._neighbor_state(self.value(row))
            previous = self._neighbor_state(self.value(row, previous=True))
            current_uptime = self._number(current.get("last-established"))
            previous_uptime = self._number(previous.get("last-established"))
            current_transitions = self._number(current.get("established-transitions"))
            previous_transitions = self._number(previous.get("established-transitions"))
            uptime_reset = (current_uptime is not None and previous_uptime is not None
                            and current_uptime < previous_uptime)
            transition = (current_transitions is not None and previous_transitions is not None
                          and current_transitions > previous_transitions)
            state_drop = (str(previous.get("session-state", "")).upper() == "ESTABLISHED"
                          and str(current.get("session-state", "")).upper() != "ESTABLISHED")
            if not (uptime_reset or transition or state_drop):
                continue
            match = NEIGHBOR.search(row["route_key"])
            neighbor = match.group(1) if match else current.get("neighbor-address", row["route_key"])
            resets[row["device"]].append({
                "neighbor": neighbor, "previous_last_established": previous_uptime,
                "current_last_established": current_uptime,
                "previous_established_transitions": previous_transitions,
                "current_established_transitions": current_transitions,
                "previous_session_state": previous.get("session-state"),
                "current_session_state": current.get("session-state"),
            })
        # A fast poll commonly captures both the down edge and recovery edge
        # before the analyzer runs. They describe one reset, not two sessions.
        for device, items in list(resets.items()):
            by_neighbor: dict[str, dict[str, Any]] = {}
            for item in items:
                previous_item = by_neighbor.get(item["neighbor"])
                if previous_item is None:
                    by_neighbor[item["neighbor"]] = item
                elif item.get("current_session_state") == "ESTABLISHED":
                    previous_item["recovered_session_state"] = "ESTABLISHED"
                    previous_item["recovered_last_established"] = item.get("current_last_established")
            resets[device] = list(by_neighbor.values())
        if not resets:
            return
        recent_device_roots = set()
        now = datetime.now(timezone.utc)
        for incident in self.store.rows(
            "SELECT updated_at,details_json FROM incidents WHERE "
            "category IN ('DEVICE_UNREACHABLE','DEVICE_DEGRADED','TELEMETRY_UNAVAILABLE')"
        ):
            updated = datetime.fromisoformat(incident["updated_at"])
            if (now - updated).total_seconds() > 300:
                continue
            root_device = str(json.loads(incident["details_json"]).get("device", ""))
            if root_device:
                recent_device_roots.add(root_device)
        batch_roots = recent_device_roots.intersection(resets)
        if batch_roots:
            reason = ("Suppressed as peer-side BGP churn caused by active device incident(s): "
                      f"{', '.join(sorted(batch_roots))}.")
            for device in resets:
                self.store.resolve_incident(f"bgp-reset:{device}", reason)
            return
        spine_roots = [device for device, items in resets.items()
                       if device.lower().startswith("spine") and len(items) >= 2]
        for spine in spine_roots:
            for link in self.bgp_links:
                if spine in (link["a_device"], link["b_device"]):
                    self.store.resolve_incident(
                        f"bgp-link-down:{link['name']}",
                        f"Suppressed by aggregated multi-session BGP reset on {spine}.",
                    )
        selected = spine_roots or list(resets)
        for device in selected:
            items = resets[device]
            if not device.lower().startswith("spine") and self._control_plane_context():
                self.store.resolve_incident(
                    f"bgp-reset:{device}",
                    f"Suppressed as recovery churn after Spine control-plane restart(s): {', '.join(self._control_plane_context())}."
                )
                continue
            linked_recovery = [item for item in items
                               if self._recent_bgp_link_incident(device, item["neighbor"])]
            if device not in spine_roots and len(linked_recovery) == len(items):
                # Both endpoint counters reset when a known topology link comes
                # back. The link incident already records outage and recovery.
                self.store.resolve_incident(
                    f"bgp-reset:{device}",
                    "Suppressed as recovery evidence for a topology-aware BGP link incident."
                )
                continue
            existing = self.store.rows(
                "SELECT details_json FROM incidents WHERE fingerprint=? AND status='ACTIVE'",
                (f"bgp-reset:{device}",),
            )
            if existing:
                old = json.loads(existing[0]["details_json"])
                by_neighbor = {item["neighbor"]: item for item in old.get("session_evidence", [])}
                by_neighbor.update({item["neighbor"]: item for item in items})
                items = list(by_neighbor.values())
            neighbors = [item["neighbor"] for item in items]
            self.store.upsert_incident(
                fingerprint=f"bgp-reset:{device}",
                severity="HIGH" if evpn_withdraws else "WARNING",
                category="BGP_SESSION_RESET",
                title=f"BGP sessions reset: {device}",
                summary=(f"{len(items)} BGP session(s) reset ({', '.join(neighbors)}); "
                         f"{evpn_withdraws} EVPN withdrawal(s) observed in the same collection cycle."),
                confidence="HIGH",
                details={"device": device, "neighbors": neighbors, "session_evidence": items,
                         "peer_side_resets": {key: [x["neighbor"] for x in value]
                                              for key, value in resets.items() if key != device},
                         "evpn_withdrawals_same_cycle": evpn_withdraws},
            )

    def _recent_bgp_link_incident(self, device: str, neighbor: str,
                                  window_seconds: int = 120) -> bool:
        now = datetime.now(timezone.utc)
        for link in self.bgp_links:
            endpoints = {(link["a_device"], link["a_neighbor"]),
                         (link["b_device"], link["b_neighbor"])}
            if (device, neighbor) not in endpoints:
                continue
            rows = self.store.rows(
                "SELECT updated_at FROM incidents WHERE fingerprint=?",
                (f"bgp-link-down:{link['name']}",),
            )
            if rows and (now - datetime.fromisoformat(rows[0]["updated_at"])).total_seconds() <= window_seconds:
                return True
        return False

    def _resolve_stable_bgp_resets(self, stable_seconds: int = 30) -> None:
        active = self.store.rows(
            "SELECT fingerprint,details_json FROM incidents "
            "WHERE status='ACTIVE' AND category='BGP_SESSION_RESET'"
        )
        for incident in active:
            details = json.loads(incident["details_json"])
            device = details.get("device")
            uptimes = []
            stable = True
            for neighbor in details.get("neighbors", [details.get("neighbor")]):
                rows = self.store.rows(
                    "SELECT value_json FROM current_state WHERE device=? AND dataset='bgp_neighbors' "
                    "AND route_key LIKE ?", (device, f"%[neighbor-address={neighbor}]%")
                )
                if not rows:
                    stable = False
                    break
                state = self._neighbor_state(json.loads(rows[0]["value_json"]))
                uptime = self._number(state.get("last-established"))
                uptimes.append(uptime)
                if state.get("session-state") != "ESTABLISHED" or uptime is None or uptime < stable_seconds:
                    stable = False
            if stable:
                self.store.resolve_incident(
                    incident["fingerprint"],
                    f"All affected BGP sessions are ESTABLISHED; minimum stable time is {min(uptimes)} seconds."
                )

    def _bgp_state(self, device: str, neighbor: str) -> str:
        rows = self.store.rows(
            "SELECT value_json FROM current_state WHERE device=? AND dataset='bgp_neighbors' "
            "AND route_key LIKE ?", (device, f"%[neighbor-address={neighbor}]%")
        )
        if not rows:
            return "UNKNOWN"
        return str(self._neighbor_state(json.loads(rows[0]["value_json"])).get("session-state", "UNKNOWN"))

    def _device_status(self, device: str) -> str:
        rows = self.store.rows("SELECT status FROM device_status WHERE device=?", (device,))
        return str(rows[0]["status"]) if rows else "UNKNOWN"

    def _evpn_afi_incident_active(self, device: str) -> bool:
        return bool(self.store.rows(
            "SELECT 1 FROM incidents WHERE fingerprint=? AND status='ACTIVE'",
            (f"evpn-afi-inactive:{device}",),
        ))

    def _analyze_bgp_links(self) -> None:
        down_by_leaf: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for link in self.bgp_links:
            if (self._device_status(link["a_device"]) != "UP"
                    or self._device_status(link["b_device"]) != "UP"
                    or self._evpn_afi_incident_active(link["a_device"])
                    or self._evpn_afi_incident_active(link["b_device"])):
                self.store.resolve_incident(
                    f"bgp-link-down:{link['name']}",
                    "Suppressed by device telemetry outage/degradation at one adjacency endpoint."
                )
                continue
            a_state = self._bgp_state(link["a_device"], link["a_neighbor"])
            b_state = self._bgp_state(link["b_device"], link["b_neighbor"])
            fingerprint = f"bgp-link-down:{link['name']}"
            if a_state == "ESTABLISHED" and b_state == "ESTABLISHED":
                self.store.resolve_incident(fingerprint, "Both ends of the BGP adjacency are ESTABLISHED again.")
                continue
            # UNKNOWN during initial inventory/device outage is handled by the
            # device incident; do not create a speculative adjacency alert.
            if "UNKNOWN" in (a_state, b_state):
                continue
            down_by_leaf[link["b_device"]].append({**link, "a_state": a_state, "b_state": b_state})
            self.store.upsert_incident(
                fingerprint=fingerprint, severity="HIGH", category="BGP_SESSION_DOWN",
                title=f"BGP adjacency down: {link['name']}",
                summary=(f"{link['a_device']}/{link['a_neighbor']}={a_state}; "
                         f"{link['b_device']}/{link['b_neighbor']}={b_state}."),
                confidence="HIGH", details={**link, "a_state": a_state, "b_state": b_state},
            )
        leaves = {link["b_device"] for link in self.bgp_links}
        for leaf in leaves:
            configured = [link for link in self.bgp_links if link["b_device"] == leaf]
            down = down_by_leaf.get(leaf, [])
            fingerprint = f"fabric-isolation:{leaf}"
            if self._device_status(leaf) != "UP" or self._evpn_afi_incident_active(leaf):
                self.store.resolve_incident(
                    fingerprint, "Suppressed by device telemetry outage/degradation on the Leaf."
                )
                continue
            if len(configured) >= 2 and len(down) == len(configured):
                for link in down:
                    self.store.resolve_incident(
                        f"bgp-link-down:{link['name']}",
                        f"Superseded by complete fabric isolation of {leaf}."
                    )
                self.store.upsert_incident(
                    fingerprint=fingerprint, severity="CRITICAL", category="FABRIC_ISOLATION",
                    title=f"Leaf isolated from fabric: {leaf}",
                    summary=f"All {len(configured)} configured fabric BGP uplinks are down.",
                    confidence="HIGH", details={"device": leaf, "down_links": down},
                )
            else:
                self.store.resolve_incident(
                    fingerprint, "At least one configured fabric BGP uplink is ESTABLISHED again."
                )

    def _analyze_evpn_afi(self) -> None:
        expected: dict[str, set[str]] = defaultdict(set)
        for link in self.bgp_links:
            expected[link["a_device"]].add(link["a_neighbor"])
            expected[link["b_device"]].add(link["b_neighbor"])
        for device, neighbors in expected.items():
            fingerprint = f"evpn-afi-inactive:{device}"
            if self._device_status(device) != "UP":
                self.store.resolve_incident(
                    fingerprint, "Suppressed while device telemetry is not fully UP."
                )
                continue
            inactive = []
            established = []
            for neighbor in sorted(neighbors):
                rows = self.store.rows(
                    "SELECT value_json FROM current_state WHERE device=? AND dataset='bgp_neighbors' "
                    "AND route_key LIKE ?", (device, f"%[neighbor-address={neighbor}]%")
                )
                if not rows:
                    inactive.append(neighbor)
                    continue
                value = json.loads(rows[0]["value_json"])
                if self._neighbor_state(value).get("session-state") != "ESTABLISHED":
                    continue
                established.append(neighbor)
                afis = value.get("afi-safis", {}).get("afi-safi", [])
                evpn = [afi.get("state", {}) for afi in afis
                        if "L2VPN_EVPN" in str(afi.get("afi-safi-name", afi.get("state", {}).get("afi-safi-name", "")))]
                if not evpn or not any(state.get("active") is True for state in evpn):
                    inactive.append(neighbor)
            if not established:
                self.store.resolve_incident(
                    fingerprint, "No established BGP peers on which to evaluate EVPN AFI/SAFI; link incidents take precedence."
                )
                continue
            if not inactive:
                self.store.resolve_incident(fingerprint, "L2VPN_EVPN is active on all configured BGP peers.")
                continue
            all_inactive = len(inactive) == len(established)
            self.store.upsert_incident(
                fingerprint=fingerprint, severity="CRITICAL" if all_inactive else "HIGH",
                category="EVPN_AFI_INACTIVE",
                title=f"EVPN AFI/SAFI {'inactive' if all_inactive else 'degraded'}: {device}",
                summary=f"L2VPN_EVPN inactive or absent on {len(inactive)} of {len(established)} established peer(s): {', '.join(inactive)}.",
                confidence="HIGH", details={"device": device, "inactive_neighbors": inactive,
                                             "configured_neighbors": sorted(neighbors)},
            )

    def _analyze_vni_coverage(self) -> None:
        by_device: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for expected in self.expected_vnis:
            by_device[expected["device"]].append(expected)
        for device, expected_items in by_device.items():
            fingerprint = f"vni-coverage:{device}"
            if (self._device_status(device) != "UP" or self._evpn_afi_incident_active(device)):
                self.store.resolve_incident(
                    fingerprint, "Suppressed while device or EVPN AFI/SAFI is not fully operational."
                )
                continue
            active_vtep = next((str(item["vtep"]) for item in expected_items if self.store.rows(
                "SELECT 1 FROM incidents WHERE fingerprint=? AND status='ACTIVE'",
                (f"vtep-withdraw:{item['vtep']}",),
            )), None)
            if active_vtep:
                self.store.resolve_incident(
                    fingerprint, f"Suppressed by aggregate VTEP failure for {active_vtep}."
                )
                continue
            attachment_down = any(
                item.get("device") == device
                and self._interface_state(device, item["interface"]).get("oper-status") != "UP"
                for segment in self.ethernet_segments for item in segment.get("attachments", [])
            )
            if attachment_down:
                self.store.resolve_incident(
                    fingerprint, "Suppressed because the device's Ethernet Segment attachment is down."
                )
                continue
            routes = [parse_route(json.loads(row["value_json"])) for row in self.store.rows(
                "SELECT value_json FROM current_state WHERE device=? AND dataset='evpn_loc_rib'", (device,)
            )]
            missing = [item for item in expected_items if not any(
                route.route_type == 3 and route.rd == str(item["rd"])
                and (route.next_hop == str(item["vtep"]) or f"[32]:[{item['vtep']}]" in route.prefix)
                for route in routes
            )]
            vlan_incidents = self.store.rows(
                "SELECT details_json FROM incidents WHERE status='ACTIVE' "
                "AND category='ES_VLAN_COVERAGE_LOSS'"
            )
            explained_vlans = {
                int(vlan)
                for incident in vlan_incidents
                for gap in json.loads(incident["details_json"]).get("gaps", [])
                if gap.get("device") == device
                for vlan in gap.get("missing_vlans", [])
            }
            unexplained = [item for item in missing
                           if int(item.get("vlan", -1)) not in explained_vlans]
            if missing and not unexplained:
                self.store.resolve_incident(
                    fingerprint, "Missing VNI routes are explained by an active ES VLAN coverage incident."
                )
                continue
            missing = unexplained
            if not missing:
                self.store.resolve_incident(fingerprint, "All expected local Type-3 IMET VNI routes are present.")
                continue
            self.store.upsert_incident(
                fingerprint=fingerprint, severity="HIGH", category="VNI_COVERAGE_LOSS",
                title=f"Expected VNI route missing: {device}",
                summary=f"Missing {len(missing)} of {len(expected_items)} expected local VNI(s): "
                        f"{', '.join(str(item['vni']) for item in missing)}.",
                confidence="HIGH", details={"device": device, "missing_vnis": missing,
                                             "expected_vnis": expected_items},
            )

    @staticmethod
    def value(row: dict[str, Any], previous: bool = False) -> dict[str, Any]:
        raw = row.get("previous_value_json" if previous else "value_json")
        return json.loads(raw) if raw else {}

    def _mass_withdraw(self, rows: list[dict[str, Any]]) -> None:
        groups: dict[str, list[tuple[dict[str, Any], EvpnRoute]]] = defaultdict(list)
        for row in rows:
            if row["event_type"] == "WITHDRAW":
                route = parse_route(self.value(row))
                if route.next_hop:
                    groups[route.next_hop].append((row, route))
        for vtep, items in groups.items():
            count = len(items)
            types = sorted({route.route_type for _, route in items if route.route_type})
            if count < self.mass_withdraw_threshold and not (4 in types and count >= 2):
                continue
            owner = self.vtep_devices.get(vtep)
            if owner and self.store.rows(
                "SELECT 1 FROM incidents WHERE fingerprint=? AND status='ACTIVE'",
                (f"evpn-afi-inactive:{owner}",),
            ):
                self.store.resolve_incident(
                    f"vtep-withdraw:{vtep}",
                    f"Suppressed as a downstream symptom of EVPN AFI/SAFI inactive on {owner}."
                )
                continue
            attachment = self._down_attachment_for_vtep(vtep)
            if attachment:
                self.store.resolve_incident(
                    f"vtep-withdraw:{vtep}",
                    f"Device is reachable; withdrawals correlate with down Ethernet Segment attachment "
                    f"{attachment['device']}/{attachment['interface']}.",
                )
                continue
            control_plane_nodes = self._control_plane_context()
            if control_plane_nodes:
                self.store.resolve_incident(
                    f"vtep-withdraw:{vtep}",
                    f"Suppressed as a symptom of current/recent control-plane restart(s): {', '.join(control_plane_nodes)}.",
                )
                continue
            # A withdrawn path can point to a healthy third-party VTEP.  Only call
            # it a VTEP failure when the VTEP's own Type-3 IMET presence is gone.
            if self._vtep_present(vtep):
                self.store.resolve_incident(
                    f"vtep-withdraw:{vtep}",
                    "VTEP still has Type-3 IMET routes in the current fabric RIB; only an alternate path disappeared.",
                )
                continue
            devices = sorted({row["device"] for row, _ in items})
            severity = "CRITICAL" if count >= self.mass_withdraw_threshold * 3 or 3 in types else "HIGH"
            confidence = "HIGH" if len(devices) >= 2 or 3 in types else "MEDIUM"
            self.store.upsert_incident(
                fingerprint=f"vtep-withdraw:{vtep}", severity=severity, category="VTEP_FAILURE",
                title=f"Probable VTEP failure: {vtep}",
                summary=f"{count} EVPN routes withdrawn; route types {types}; observed on {len(devices)} device(s).",
                confidence=confidence,
                details={"vtep": vtep, "withdrawn_routes": count, "route_types": types,
                         "observed_by": devices, "sample_prefixes": [r.prefix for _, r in items[:20]]},
            )
            if owner:
                self.store.resolve_incident(
                    f"vni-coverage:{owner}",
                    f"Suppressed as per-VNI symptoms of the aggregate VTEP failure for {vtep}.",
                )

    def _mac_mobility(self, rows: list[dict[str, Any]]) -> None:
        movements: dict[str, dict[str, Any]] = {}
        for row in rows:
            if row["event_type"] == "UPDATE":
                old, new = parse_route(self.value(row, True)), parse_route(self.value(row))
                if (new.route_type == 2 and new.mac and old.next_hop and new.next_hop
                        and old.next_hop != new.next_hop):
                    movements[new.mac] = {
                        "old": {old.next_hop}, "new": {new.next_hop},
                        "observers": {row["device"]}, "route": new,
                        "mobility_community": "MM:" in json.dumps(self.value(row)),
                    }
                continue
            if row["event_type"] not in ("ANNOUNCE", "WITHDRAW"):
                continue
            route = parse_route(self.value(row))
            if route.route_type != 2 or not route.mac or not route.next_hop:
                continue
            movement = movements.setdefault(route.mac, {
                "old": set(), "new": set(), "observers": set(), "route": route,
                "mobility_community": False,
            })
            movement["old" if row["event_type"] == "WITHDRAW" else "new"].add(route.next_hop)
            movement["observers"].add(row["device"])
            movement["mobility_community"] = (movement["mobility_community"]
                                                or "MM:" in json.dumps(self.value(row)))
            if row["event_type"] == "ANNOUNCE":
                movement["route"] = route

        for mac, movement in movements.items():
            old_vteps = movement["old"] - movement["new"]
            new_vteps = movement["new"] - movement["old"]
            if not old_vteps or not new_vteps or not movement["mobility_community"]:
                continue
            old_vtep, new_vtep = sorted(old_vteps)[0], sorted(new_vteps)[0]
            fingerprint = f"mac-mobility:{mac}"
            existing = self.store.rows(
                "SELECT details_json FROM incidents WHERE fingerprint=?", (fingerprint,)
            )
            previous_count = (json.loads(existing[0]["details_json"]).get("movement_count", 0)
                              if existing else 0)
            movement_count = previous_count + 1
            severity = "HIGH" if movement_count >= self.mac_flap_threshold else "INFO"
            category = "MAC_FLAPPING" if severity == "HIGH" else "MAC_MOBILITY"
            route = movement["route"]
            self.store.upsert_incident(
                fingerprint=fingerprint, severity=severity,
                category=category, title=f"MAC moved: {mac}",
                summary=(f"Type-2 route moved from VTEP {old_vtep} to {new_vtep}; "
                         f"observed by {len(movement['observers'])} device(s)."),
                confidence="HIGH",
                details={"mac": mac, "old_vtep": old_vtep, "new_vtep": new_vtep,
                         "rd": route.rd, "prefix": route.prefix,
                         "observers": sorted(movement["observers"]),
                         "movement_count": movement_count},
            )

    def _esi_withdraw(self, rows: list[dict[str, Any]]) -> None:
        for row in rows:
            if row["event_type"] != "WITHDRAW":
                continue
            route = parse_route(self.value(row))
            if route.route_type != 4:
                continue
            if self._control_plane_context():
                self.store.resolve_incident(
                    f"esi-withdraw:{route.prefix}:{route.next_hop}",
                    f"Suppressed as a symptom of current/recent Spine restart(s): {', '.join(self._control_plane_context())}.",
                )
                continue
            if self._route_present(route.prefix, route.next_hop):
                self.store.resolve_incident(
                    f"esi-withdraw:{route.prefix}:{route.next_hop}",
                    "An equivalent Type-4 route remains in the current fabric RIB.",
                )
                continue
            # A configured ES attachment state is stronger evidence than a raw
            # Type-4 symptom. Avoid showing two active incidents for one fault.
            topology_match = next((segment for segment in self.ethernet_segments
                                   if segment.get("esi") and segment["esi"] in route.prefix), None)
            if topology_match and any(
                self._interface_state(item["device"], item["interface"]).get("oper-status") != "UP"
                for item in topology_match.get("attachments", [])
            ):
                self.store.resolve_incident(
                    f"esi-withdraw:{route.prefix}:{route.next_hop}",
                    "Suppressed by topology-aware Ethernet Segment attachment incident."
                )
                continue
            self.store.upsert_incident(
                fingerprint=f"esi-withdraw:{route.prefix}:{route.next_hop}", severity="HIGH",
                category="ESI_DEGRADED", title="EVPN Ethernet Segment membership withdrawn",
                summary=f"Type-4 route from {route.next_hop or 'unknown VTEP'} disappeared on {row['device']}.",
                confidence="HIGH",
                details={"prefix": route.prefix, "rd": route.rd, "vtep": route.next_hop,
                         "observer": row["device"]},
            )

    def _current_routes(self) -> list[EvpnRoute]:
        rows = self.store.rows("SELECT value_json FROM current_state WHERE dataset='evpn_loc_rib'")
        return [parse_route(json.loads(row["value_json"])) for row in rows]

    def _vtep_present(self, vtep: str) -> bool:
        return any(route.route_type == 3 and
                   (route.next_hop == vtep or f"[32]:[{vtep}]" in route.prefix)
                   for route in self._current_routes())

    def _route_present(self, prefix: str, next_hop: str | None) -> bool:
        return any(route.prefix == prefix and (not next_hop or route.next_hop == next_hop)
                   for route in self._current_routes())

    def _reconcile_active_incidents(self) -> None:
        down_spines = self._control_plane_context()
        for row in self.store.rows("SELECT fingerprint,category,details_json FROM incidents WHERE status='ACTIVE'"):
            details = json.loads(row["details_json"])
            if row["category"] in ("VTEP_FAILURE", "ESI_DEGRADED") and down_spines:
                self.store.resolve_incident(
                    row["fingerprint"],
                    f"Suppressed as a downstream symptom of unreachable Spine node(s): {', '.join(down_spines)}.",
                )
            elif row["category"] == "VTEP_FAILURE" and self._down_attachment_for_vtep(
                str(details.get("vtep", ""))
            ):
                attachment = self._down_attachment_for_vtep(str(details.get("vtep", "")))
                self.store.resolve_incident(
                    row["fingerprint"],
                    f"Device remains reachable; symptom is explained by down ES attachment "
                    f"{attachment['device']}/{attachment['interface']}.",
                )
            elif row["category"] == "VTEP_FAILURE" and self._vtep_present(str(details.get("vtep", ""))):
                self.store.resolve_incident(
                    row["fingerprint"],
                    "VTEP Type-3 IMET presence is visible again or never disappeared fabric-wide.",
                )
            elif row["category"] == "ESI_DEGRADED" and self._route_present(
                str(details.get("prefix", "")), details.get("vtep")
            ):
                self.store.resolve_incident(
                    row["fingerprint"], "Equivalent Type-4 membership is present in the current fabric RIB."
                )
            elif row["category"] == "ESI_DEGRADED" and any(
                segment.get("esi") and segment["esi"] in str(details.get("prefix", ""))
                for segment in self.ethernet_segments
            ):
                self.store.resolve_incident(
                    row["fingerprint"], "Superseded by topology-aware Ethernet Segment attachment incident."
                )
            elif row["category"] in ("MAC_MOBILITY", "MAC_FLAPPING"):
                incident = self.store.rows(
                    "SELECT updated_at FROM incidents WHERE fingerprint=?", (row["fingerprint"],)
                )[0]
                updated = datetime.fromisoformat(incident["updated_at"])
                if (datetime.now(timezone.utc) - updated).total_seconds() >= 120:
                    self.store.resolve_incident(
                        row["fingerprint"], "No additional MAC movement observed for 120 seconds."
                    )

    def _down_spines(self) -> list[str]:
        return [row["device"] for row in self.store.rows(
            "SELECT device FROM device_status WHERE status='DOWN' AND lower(device) LIKE 'spine%'"
        )]

    def _control_plane_context(self, grace_period_seconds: int = 300) -> list[str]:
        """Include a recently recovered Spine while BGP GR stale paths may be expiring."""
        devices = set(self._down_spines())
        now = datetime.now(timezone.utc)
        rows = self.store.rows(
            "SELECT updated_at,details_json FROM incidents "
            "WHERE category IN ('DEVICE_UNREACHABLE','BGP_SESSION_RESET')"
        )
        for row in rows:
            details = json.loads(row["details_json"])
            device = str(details.get("device", ""))
            if not device.lower().startswith("spine"):
                continue
            updated = datetime.fromisoformat(row["updated_at"])
            if (now - updated).total_seconds() <= grace_period_seconds:
                devices.add(device)
        return sorted(devices)

    def _analyze_ethernet_segments(self) -> None:
        for segment in self.ethernet_segments:
            attachments = []
            for attachment in segment.get("attachments", []):
                state = self._interface_state(attachment["device"], attachment["interface"])
                attachments.append({**attachment, "admin_status": state.get("admin-status", "UNKNOWN"),
                                    "oper_status": state.get("oper-status", "UNKNOWN")})
            down = [item for item in attachments if item["oper_status"] != "UP"]
            fingerprint = f"ethernet-segment:{segment['esi']}"
            vlan_fingerprint = f"ethernet-segment-vlans:{segment['esi']}"
            vlan_gaps = []
            for attachment in segment.get("attachments", []):
                expected = {int(vlan) for vlan in attachment.get("vlans", [])}
                actual = self._interface_vlans(attachment["device"], attachment["interface"])
                missing = sorted(expected - actual)
                if missing:
                    vlan_gaps.append({"device": attachment["device"],
                                      "interface": attachment["interface"],
                                      "missing_vlans": missing,
                                      "actual_vlans": sorted(actual)})
            if down or any(self._device_status(item["device"]) != "UP" for item in attachments):
                self.store.resolve_incident(
                    vlan_fingerprint, "VLAN coverage check deferred while an attachment/device is unavailable."
                )
            elif vlan_gaps:
                self.store.upsert_incident(
                    fingerprint=vlan_fingerprint, severity="HIGH", category="ES_VLAN_COVERAGE_LOSS",
                    title=f"Ethernet Segment VLAN coverage incomplete: {segment['name']}",
                    summary="; ".join(f"{item['device']}/{item['interface']} missing VLAN(s) "
                                      f"{','.join(map(str, item['missing_vlans']))}"
                                      for item in vlan_gaps),
                    confidence="HIGH", details={"esi": segment["esi"], "gaps": vlan_gaps},
                )
            else:
                self.store.resolve_incident(
                    vlan_fingerprint, "All expected VLANs are present on every Ethernet Segment attachment."
                )
            current_routes = self._current_routes()
            missing_members = [item for item in attachments if not any(
                route.route_type == 4 and segment["esi"] in route.prefix
                and (route.next_hop == str(item["vtep"]) or f"[32]:[{item['vtep']}]" in route.prefix)
                for route in current_routes
            )]
            membership_check_valid = all(
                self._device_status(item["device"]) == "UP"
                and not self._evpn_afi_incident_active(item["device"])
                for item in attachments
            )
            if not down and missing_members and membership_check_valid:
                self.store.upsert_incident(
                    fingerprint=fingerprint, severity="HIGH", category="ESI_MEMBERSHIP_LOSS",
                    title=f"Ethernet Segment membership missing: {segment['name']}",
                    summary=(f"PortChannel attachments are UP, but expected Type-4 membership is missing for: "
                             f"{', '.join(item['device'] + '/' + str(item['vtep']) for item in missing_members)}."),
                    confidence="HIGH", details={"esi": segment["esi"], "attachments": attachments,
                                                 "missing_members": missing_members},
                )
                continue
            if not down:
                self.store.resolve_incident(fingerprint, "All configured Ethernet Segment attachments are operationally UP.")
                continue
            all_down = len(down) == len(attachments)
            self.store.upsert_incident(
                fingerprint=fingerprint,
                severity="CRITICAL" if all_down else "HIGH",
                category="ESI_DOWN" if all_down else "ESI_DEGRADED",
                title=f"Ethernet Segment {'down' if all_down else 'redundancy degraded'}: {segment['name']}",
                summary=(f"{len(down)} of {len(attachments)} attachment(s) are down; "
                         f"affected: {', '.join(x['device'] + '/' + x['interface'] for x in down)}."),
                confidence="HIGH",
                details={"esi": segment["esi"], "attachments": attachments,
                         "remaining_active": [x for x in attachments if x["oper_status"] == "UP"]},
            )

    def _interface_vlans(self, device: str, interface: str) -> set[int]:
        rows = self.store.rows(
            "SELECT value_json FROM current_state WHERE device=? AND dataset='interfaces' "
            "AND route_key LIKE ? AND route_key LIKE '%switched-vlan/state'",
            (device, f"%[name={interface}]%"),
        )
        if not rows:
            return set()
        value = json.loads(rows[0]["value_json"])
        return {int(vlan) for vlan in value.get("trunk-vlans", [])}

    def _interface_state(self, device: str, interface: str) -> dict[str, Any]:
        points = self.store.rows(
            "SELECT value_json FROM telemetry_points WHERE device=? AND dataset='interface_oper_status' "
            "AND point_key=?", (device, interface),
        )
        streamed_oper = json.loads(points[0]["value_json"]) if points else None
        suffix = f"interface[name={interface}]/state"
        rows = self.store.rows(
            "SELECT value_json FROM current_state WHERE device=? AND dataset='interfaces' AND route_key LIKE ?",
            (device, f"%{suffix}"),
        )
        state = json.loads(rows[0]["value_json"]) if rows else {}
        if streamed_oper is not None:
            state["oper-status"] = streamed_oper
        return state

    def analyze_ethernet_segments(self) -> None:
        """Public entry point used by interface ON_CHANGE listeners."""
        self._analyze_ethernet_segments()

    def _down_attachment_for_vtep(self, vtep: str) -> dict[str, Any] | None:
        for segment in self.ethernet_segments:
            for attachment in segment.get("attachments", []):
                if str(attachment.get("vtep")) != vtep:
                    continue
                state = self._interface_state(attachment["device"], attachment["interface"])
                device = self.store.rows("SELECT status FROM device_status WHERE device=?", (attachment["device"],))
                if state.get("oper-status") != "UP" and device and device[0]["status"] != "DOWN":
                    return attachment
        return None
