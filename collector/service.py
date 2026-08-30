from __future__ import annotations

import logging
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import Device, Settings
from .analytics import Analyzer
from .gnmi import get_dataset, on_change_updates
from .inventory import InventoryManager, SecretsManager
from .store import Store

LOG = logging.getLogger(__name__)


class Collector:
    def __init__(self, settings: Settings, store: Store):
        self.settings = settings
        self.store = store
        self.stop_event = threading.Event()
        self.analyzer = Analyzer(store, ethernet_segments=settings.ethernet_segments,
                                 bgp_links=settings.bgp_links, vtep_devices=settings.vtep_devices)
        self.analyzer.expected_vnis = settings.expected_vnis
        self.last_maintenance = 0.0
        self.inventory = InventoryManager(settings.inventory_path)
        self.inventory_mtime = settings.inventory_path.stat().st_mtime_ns
        self.secrets = SecretsManager(settings.inventory_path.parent / "device-secrets.yaml")
        self.secrets_mtime = self.secrets.path.stat().st_mtime_ns if self.secrets.path.exists() else 0
        self._bgp_poller_names: set[str] = set()
        self._onchange_keys: set[tuple[str, str]] = set()
        self._listener_lock = threading.Lock()

    def poll_device(self, device: Device) -> None:
        successes, errors = 0, []
        for dataset, path in self.settings.paths.items():
            try:
                records = get_dataset(self.settings, device, path)
                if dataset == "lldp_neighbors":
                    records = {key: value for key, value in records.items()
                               if "/neighbors/neighbor[" in key and key.endswith("/state")
                               and isinstance(value, dict) and value.get("system-name")}
                stats = self.store.apply_snapshot(device.name, dataset, records)
                successes += 1
                LOG.info("%s %-16s %s", device.name, dataset, stats)
            except Exception as exc:  # isolate unsupported paths and devices
                message = f"{dataset}: {type(exc).__name__}: {exc}"
                errors.append(message)
                LOG.warning("%s %s", device.name, message)
        management_reachable = successes > 0 or self._tcp_reachable(device.address, 22)
        status = ("DEGRADED" if errors and management_reachable else
                  "UP" if successes else "DOWN")
        previous = self.store.set_status(device.name, device.address, status, "; ".join(errors) or None)
        fingerprint = f"device-down:{device.name}"
        if status == "DOWN":
            self.store.upsert_incident(
                fingerprint=fingerprint, severity="CRITICAL", category="DEVICE_UNREACHABLE",
                title=f"Device unreachable: {device.name}",
                summary=f"All configured gNMI datasets failed for {device.address}.",
                confidence="HIGH",
                details={"device": device.name, "address": device.address, "previous_status": previous,
                         "errors": errors},
            )
        elif status == "DEGRADED" and not successes:
            self.store.upsert_incident(
                fingerprint=fingerprint, severity="HIGH", category="TELEMETRY_UNAVAILABLE",
                title=f"gNMI telemetry unavailable: {device.name}",
                summary=(f"All configured gNMI datasets failed, but management SSH remains "
                         f"reachable at {device.address}."), confidence="HIGH",
                details={"device": device.name, "address": device.address,
                         "management_ssh_reachable": True, "errors": errors},
            )
        elif status == "DEGRADED":
            self.store.upsert_incident(
                fingerprint=fingerprint, severity="HIGH", category="DEVICE_DEGRADED",
                title=f"Device telemetry degraded: {device.name}",
                summary=f"Some gNMI datasets failed for {device.address}.", confidence="HIGH",
                details={"device": device.name, "address": device.address, "errors": errors},
            )
        else:
            self.store.resolve_incident(fingerprint, "All configured gNMI datasets are reachable again.")

    @staticmethod
    def _tcp_reachable(address: str, port: int, timeout: float = 1.0) -> bool:
        try:
            with socket.create_connection((address, port), timeout=timeout):
                return True
        except OSError:
            return False

    def poll_once(self) -> None:
        self._reload_inventory_if_changed()
        devices = list(self.settings.devices)
        if not devices:
            LOG.warning("Inventory contains no devices; collection skipped")
            return
        with ThreadPoolExecutor(max_workers=len(devices)) as executor:
            futures = [executor.submit(self.poll_device, device) for device in devices]
            for future in as_completed(futures):
                future.result()
        analyzed = self.analyzer.run()
        LOG.info("analytics processed %d new EVPN event(s)", analyzed)
        interval = self.settings.maintenance_interval_hours * 3600
        if time.monotonic() - self.last_maintenance >= interval:
            result = self.store.maintain(self.settings.event_retention_days,
                                         self.settings.incident_retention_days)
            self.last_maintenance = time.monotonic()
            LOG.info("retention maintenance deleted %d event(s), %d incident(s)",
                     result["events"], result["incidents"])

    def run(self) -> None:
        self._start_on_change_listeners()
        self._start_bgp_fast_pollers()
        while not self.stop_event.is_set():
            self.poll_once()
            self.stop_event.wait(self.settings.poll_interval)

    def _start_bgp_fast_pollers(self) -> None:
        """BGP ON_CHANGE is disabled by this SONiC release; poll only the
        relatively small neighbor state at a faster cadence than full RIBs."""
        for device in self.settings.devices:
            with self._listener_lock:
                if device.name in self._bgp_poller_names:
                    continue
                self._bgp_poller_names.add(device.name)
            threading.Thread(target=self._watch_bgp, args=(device,),
                             name=f"bgp-fast-{device.name}", daemon=True).start()

    def _watch_bgp(self, device: Device) -> None:
        path = self.settings.paths["bgp_neighbors"]
        while not self.stop_event.is_set():
            if device.name not in {item.name for item in self.settings.devices}:
                with self._listener_lock:
                    self._bgp_poller_names.discard(device.name)
                return
            try:
                records = get_dataset(self.settings, device, path)
                stats = self.store.apply_snapshot(device.name, "bgp_neighbors", records)
                if stats["added"] or stats["removed"] or stats["changed"]:
                    LOG.info("%s BGP fast poll %s", device.name, stats)
            except Exception as exc:
                LOG.debug("%s BGP fast poll failed: %s", device.name, exc)
            self.stop_event.wait(self.settings.bgp_fast_poll_interval)

    def _start_on_change_listeners(self) -> None:
        """Use ON_CHANGE only for paths verified on this SONiC release."""
        devices = {device.name: device for device in self.settings.devices}
        for segment in self.settings.ethernet_segments:
            for attachment in segment.get("attachments", []):
                key = (attachment["device"], attachment["interface"])
                if attachment["device"] not in devices:
                    continue
                with self._listener_lock:
                    already_started = key in self._onchange_keys
                    if not already_started:
                        self._onchange_keys.add(key)
                if already_started:
                    continue
                thread = threading.Thread(
                    target=self._watch_interface,
                    args=(devices[attachment["device"]], attachment["interface"]),
                    name=f"on-change-{attachment['device']}-{attachment['interface']}", daemon=True,
                )
                thread.start()

    def _reload_inventory_if_changed(self) -> None:
        try:
            mtime = self.settings.inventory_path.stat().st_mtime_ns
            secrets_mtime = self.secrets.path.stat().st_mtime_ns if self.secrets.path.exists() else 0
            if mtime == self.inventory_mtime and secrets_mtime == self.secrets_mtime:
                return
            data = self.inventory.read()
            secrets = self.secrets.read()
            self.settings.devices[:] = [Device(**item, **secrets.get(item["name"], {}))
                                        for item in data["devices"]]
            self.settings.paths.clear()
            self.settings.paths.update(data["paths"])
            self.settings.ethernet_segments[:] = data.get("ethernet_segments", [])
            self.settings.bgp_links[:] = data.get("bgp_links", [])
            self.settings.expected_vnis[:] = data.get("expected_vnis", [])
            self.settings.vtep_devices.clear()
            self.settings.vtep_devices.update({str(k): v for k, v in data.get("vtep_devices", {}).items()})
            self.analyzer.ethernet_segments = self.settings.ethernet_segments
            self.analyzer.bgp_links = self.settings.bgp_links
            self.analyzer.expected_vnis = self.settings.expected_vnis
            self.analyzer.vtep_devices = self.settings.vtep_devices
            self.inventory_mtime = mtime
            self.secrets_mtime = secrets_mtime
            self._start_bgp_fast_pollers()
            self._start_on_change_listeners()
            LOG.info("Reloaded inventory.yaml: %d device(s)", len(self.settings.devices))
        except Exception as exc:
            LOG.error("Inventory reload rejected; keeping last valid configuration: %s", exc)

    def _watch_interface(self, device: Device, interface: str) -> None:
        path = self.settings.paths["interfaces"] + f"[name={interface}]/state/oper-status"
        while not self.stop_event.is_set():
            if device.name not in {item.name for item in self.settings.devices}:
                with self._listener_lock:
                    self._onchange_keys.discard((device.name, interface))
                return
            try:
                LOG.info("%s %s starting ON_CHANGE subscription", device.name, interface)
                for update in on_change_updates(self.settings, device, path):
                    value = update["value"]
                    self.store.set_point(device.name, "interface_oper_status", interface, value)
                    LOG.info("%s %s ON_CHANGE oper-status=%s", device.name, interface, value)
                    self.analyzer.analyze_ethernet_segments()
                    if self.stop_event.is_set():
                        return
            except Exception as exc:
                LOG.warning("%s %s ON_CHANGE failed: %s; retrying", device.name, interface, exc)
                self.stop_event.wait(5)
