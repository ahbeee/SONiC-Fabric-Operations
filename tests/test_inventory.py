from pathlib import Path

import pytest
import yaml

from collector.inventory import InventoryManager


def write_inventory(path: Path) -> None:
    path.write_text(yaml.safe_dump({
        "devices": [{"name": "Leaf-1", "address": "10.0.0.1"}],
        "paths": {"interfaces": "/interfaces"},
        "bgp_links": [],
        "ethernet_segments": [],
    }, sort_keys=False), encoding="utf-8")


def test_add_and_remove_device_is_atomic_and_preserves_config(tmp_path):
    path = tmp_path / "inventory.yaml"
    write_inventory(path)
    manager = InventoryManager(path)

    assert manager.add_device("Spine-1", "10.0.0.2", "Core device") == {
        "name": "Spine-1", "address": "10.0.0.2", "notes": "Core device"
    }
    saved = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert saved["paths"] == {"interfaces": "/interfaces"}
    assert all("username" not in item and "password" not in item for item in saved["devices"])
    assert not (tmp_path / "inventory.yaml.tmp").exists()

    assert manager.remove_device("Spine-1")["address"] == "10.0.0.2"
    assert [item["name"] for item in manager.read()["devices"]] == ["Leaf-1"]


@pytest.mark.parametrize("name,address", [
    ("bad name", "10.0.0.2"), ("Leaf-2", "not-an-ip"),
])
def test_rejects_invalid_device(name, address, tmp_path):
    path = tmp_path / "inventory.yaml"
    write_inventory(path)
    with pytest.raises(ValueError):
        InventoryManager(path).add_device(name, address)


def test_duplicate_and_referenced_device_are_rejected(tmp_path):
    path = tmp_path / "inventory.yaml"
    write_inventory(path)
    manager = InventoryManager(path)
    with pytest.raises(ValueError, match="already exists"):
        manager.add_device("leaf-1", "10.0.0.2")

    data = manager.read()
    data["ethernet_segments"] = [{"name": "ES-1", "attachments": [{"device": "Leaf-1"}]}]
    manager._write(data)
    with pytest.raises(ValueError, match="still referenced"):
        manager.remove_device("Leaf-1")
