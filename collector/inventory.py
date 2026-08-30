from __future__ import annotations

import ipaddress
import os
import re
import threading
from pathlib import Path
from typing import Any

import yaml

NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def validate_device(name: str, address: str) -> tuple[str, str]:
    name, address = name.strip(), address.strip()
    if not NAME.fullmatch(name):
        raise ValueError("Device name must be 1-64 letters, digits, dot, dash, or underscore.")
    try:
        address = str(ipaddress.ip_address(address))
    except ValueError as exc:
        raise ValueError("Management address must be a valid IPv4 or IPv6 address.") from exc
    return name, address


class InventoryManager:
    """Thread-safe, atomic access to inventory.yaml. Credentials never live here."""

    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.RLock()

    def read(self) -> dict[str, Any]:
        with self.lock, self.path.open(encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        devices = data.get("devices")
        if not isinstance(devices, list):
            raise ValueError("inventory.yaml must contain a devices list.")
        seen_names, seen_addresses = set(), set()
        normalized = []
        for item in devices:
            if not isinstance(item, dict):
                raise ValueError("Each device must be an object with name and address.")
            name, address = validate_device(str(item.get("name", "")), str(item.get("address", "")))
            if name.lower() in seen_names:
                raise ValueError(f"Duplicate device name: {name}")
            if address in seen_addresses:
                raise ValueError(f"Duplicate management address: {address}")
            seen_names.add(name.lower()); seen_addresses.add(address)
            normalized.append({"name": name, "address": address,
                               "notes": str(item.get("notes", "")).strip()})
        data["devices"] = normalized
        return data

    def _write(self, data: dict[str, Any]) -> None:
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        text = yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(self.path)

    def add_device(self, name: str, address: str, notes: str = "") -> dict[str, str]:
        name, address = validate_device(name, address)
        with self.lock:
            data = self.read()
            if any(item["name"].lower() == name.lower() for item in data["devices"]):
                raise ValueError(f"Device already exists: {name}")
            if any(item["address"] == address for item in data["devices"]):
                raise ValueError(f"Management address already exists: {address}")
            item = {"name": name, "address": address, "notes": notes.strip()[:256]}
            data["devices"].append(item)
            self._write(data)
            return item

    def remove_device(self, name: str) -> dict[str, str]:
        with self.lock:
            data = self.read()
            match = next((item for item in data["devices"] if item["name"] == name), None)
            if not match:
                raise KeyError(name)
            referenced = []
            for link in data.get("bgp_links", []):
                if name in (link.get("a_device"), link.get("b_device")):
                    referenced.append(f"BGP link {link.get('name', '')}")
            for segment in data.get("ethernet_segments", []):
                if any(item.get("device") == name for item in segment.get("attachments", [])):
                    referenced.append(f"Ethernet Segment {segment.get('name', '')}")
            if referenced:
                raise ValueError("Device is still referenced by " + ", ".join(referenced))
            data["devices"] = [item for item in data["devices"] if item["name"] != name]
            self._write(data)
            return match


class SecretsManager:
    """Atomic per-device credentials store. Its contents must never reach an API response."""

    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.RLock()

    def read(self) -> dict[str, dict[str, str]]:
        with self.lock:
            if not self.path.exists():
                return {}
            with self.path.open(encoding="utf-8") as handle:
                data = yaml.safe_load(handle) or {}
        devices = data.get("devices", {})
        if not isinstance(devices, dict):
            raise ValueError("device-secrets.yaml must contain a devices mapping.")
        result = {}
        for name, item in devices.items():
            if not isinstance(item, dict) or not item.get("username") or not item.get("password"):
                raise ValueError(f"Invalid credentials entry for {name}")
            result[str(name)] = {"username": str(item["username"]), "password": str(item["password"])}
        return result

    def _write(self, devices: dict[str, dict[str, str]]) -> None:
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            yaml.safe_dump({"devices": devices}, handle, sort_keys=False, allow_unicode=True)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(self.path)

    def set(self, name: str, username: str, password: str) -> None:
        if not username or not password:
            raise ValueError("Username and password are required.")
        with self.lock:
            devices = self.read()
            devices[name] = {"username": username, "password": password}
            self._write(devices)

    def remove(self, name: str) -> None:
        with self.lock:
            devices = self.read()
            if devices.pop(name, None) is not None:
                self._write(devices)
