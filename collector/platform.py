from __future__ import annotations

from typing import Any

from .config import Device, Settings
from .gnmi import get_dataset

PLATFORM_PATH = "/openconfig-platform:components/component"


def collect_platform_inventory(settings: Settings, device: Device) -> dict[str, str | None]:
    return parse_platform_inventory(get_dataset(settings, device, PLATFORM_PATH))


def parse_platform_inventory(records: dict[str, Any]) -> dict[str, str | None]:
    state = next((value for path, value in records.items()
                  if "component[name=System Eeprom]/state" in path and isinstance(value, dict)), None)
    if not state:
        raise ValueError("System Eeprom component is not available through OpenConfig platform telemetry.")
    return {
        "description": field(state, "description"),
        "serial_number": field(state, "serial-no", "serial-number"),
        "base_mac": field(state, "base-mac-address"),
        "software_version": field(state, "software-version"),
    }


def field(data: dict[str, Any], *names: str) -> str | None:
    for key, value in data.items():
        unqualified = key.rsplit(":", 1)[-1]
        if unqualified in names and value not in (None, ""):
            return str(value).strip("'")
    return None
