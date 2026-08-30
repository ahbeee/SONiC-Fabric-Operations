from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from .inventory import InventoryManager, SecretsManager


@dataclass(frozen=True)
class Device:
    name: str
    address: str
    notes: str = ""
    username: str | None = None
    password: str | None = None


@dataclass(frozen=True)
class Settings:
    inventory_path: Path
    devices: list[Device]
    paths: dict[str, str]
    username: str
    password: str
    port: int
    skip_verify: bool
    timeout: int
    poll_interval: int
    bgp_fast_poll_interval: int
    database_path: Path
    web_host: str
    web_port: int
    ethernet_segments: list[dict]
    bgp_links: list[dict]
    event_retention_days: int
    incident_retention_days: int
    maintenance_interval_hours: int
    vtep_devices: dict[str, str]
    expected_vnis: list[dict]


def load_settings(root: Path) -> Settings:
    load_dotenv(root / ".env")
    inventory_path = root / "inventory.yaml"
    inventory = InventoryManager(inventory_path).read()
    secrets = SecretsManager(root / "device-secrets.yaml").read()
    devices = [Device(**item, **secrets.get(item["name"], {})) for item in inventory["devices"]]
    return Settings(
        inventory_path=inventory_path,
        devices=devices,
        paths=inventory["paths"],
        username=os.getenv("GNMI_USERNAME", "admin"),
        password=os.environ["GNMI_PASSWORD"],
        port=int(os.getenv("GNMI_PORT", "8080")),
        skip_verify=os.getenv("GNMI_SKIP_VERIFY", "true").lower() == "true",
        timeout=int(os.getenv("GNMI_TIMEOUT", "20")),
        poll_interval=int(os.getenv("POLL_INTERVAL", "10")),
        bgp_fast_poll_interval=int(os.getenv("BGP_FAST_POLL_INTERVAL", "2")),
        database_path=root / os.getenv("DATABASE_PATH", "data/collector.db"),
        web_host=os.getenv("WEB_HOST", "127.0.0.1"),
        web_port=int(os.getenv("WEB_PORT", "8000")),
        ethernet_segments=inventory.get("ethernet_segments", []),
        bgp_links=inventory.get("bgp_links", []),
        event_retention_days=int(os.getenv("EVENT_RETENTION_DAYS", "14")),
        incident_retention_days=int(os.getenv("INCIDENT_RETENTION_DAYS", "180")),
        maintenance_interval_hours=int(os.getenv("MAINTENANCE_INTERVAL_HOURS", "6")),
        vtep_devices={str(key): value for key, value in inventory.get("vtep_devices", {}).items()},
        expected_vnis=inventory.get("expected_vnis", []),
    )
