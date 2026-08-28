from types import SimpleNamespace

from collector.config import Device
from collector.service import Collector
from collector.store import Store


def test_all_gnmi_failed_but_ssh_up_is_telemetry_unavailable(tmp_path, monkeypatch):
    collector = Collector.__new__(Collector)
    collector.store = Store(tmp_path / "test.db")
    collector.settings = SimpleNamespace(paths={"bgp": "/bgp", "evpn": "/evpn"})
    monkeypatch.setattr("collector.service.get_dataset",
                        lambda *_: (_ for _ in ()).throw(TimeoutError("gNMI down")))
    monkeypatch.setattr(collector, "_tcp_reachable", lambda *_: True)
    collector.poll_device(Device("Leaf-1", "10.0.0.1"))
    status = collector.store.rows("SELECT status FROM device_status")[0]
    incident = collector.store.rows("SELECT category,severity FROM incidents")[0]
    assert status["status"] == "DEGRADED"
    assert incident == {"category": "TELEMETRY_UNAVAILABLE", "severity": "HIGH"}


def test_all_gnmi_and_ssh_failed_is_device_unreachable(tmp_path, monkeypatch):
    collector = Collector.__new__(Collector)
    collector.store = Store(tmp_path / "test.db")
    collector.settings = SimpleNamespace(paths={"bgp": "/bgp"})
    monkeypatch.setattr("collector.service.get_dataset",
                        lambda *_: (_ for _ in ()).throw(TimeoutError("device down")))
    monkeypatch.setattr(collector, "_tcp_reachable", lambda *_: False)
    collector.poll_device(Device("Leaf-1", "10.0.0.1"))
    assert collector.store.rows("SELECT status FROM device_status")[0]["status"] == "DOWN"
    assert collector.store.rows("SELECT category FROM incidents")[0]["category"] == "DEVICE_UNREACHABLE"
