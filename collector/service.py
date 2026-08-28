from __future__ import annotations

import logging
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import Device, Settings
from .analytics import Analyzer
from .gnmi import get_dataset, on_change_updates
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

    def poll_device(self, device: Device) -> None:
        successes, errors = 0, []
        for dataset, path in self.settings.paths.items():
            try:
                records = get_dataset(self.settings, device, path)
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
        with ThreadPoolExecutor(max_workers=len(self.settings.devices)) as executor:
            futures = [executor.submit(self.poll_device, device) for device in self.settings.devices]
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
            threading.Thread(target=self._watch_bgp, args=(device,),
                             name=f"bgp-fast-{device.name}", daemon=True).start()

    def _watch_bgp(self, device: Device) -> None:
        path = self.settings.paths["bgp_neighbors"]
        while not self.stop_event.is_set():
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
        seen: set[tuple[str, str]] = set()
        for segment in self.settings.ethernet_segments:
            for attachment in segment.get("attachments", []):
                key = (attachment["device"], attachment["interface"])
                if key in seen or attachment["device"] not in devices:
                    continue
                seen.add(key)
                thread = threading.Thread(
                    target=self._watch_interface,
                    args=(devices[attachment["device"]], attachment["interface"]),
                    name=f"on-change-{attachment['device']}-{attachment['interface']}", daemon=True,
                )
                thread.start()

    def _watch_interface(self, device: Device, interface: str) -> None:
        path = self.settings.paths["interfaces"] + f"[name={interface}]/state/oper-status"
        while not self.stop_event.is_set():
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
