from __future__ import annotations

import json
import logging
import time
from typing import Any

from pygnmi.client import gNMIclient

from .config import Device, Settings

LOG = logging.getLogger(__name__)


def get_dataset(settings: Settings, device: Device, path: str) -> dict[str, Any]:
    target = (device.address, settings.port)
    with gNMIclient(
        target=target,
        username=settings.username,
        password=settings.password,
        insecure=False,
        skip_verify=settings.skip_verify,
        timeout=settings.timeout,
    ) as client:
        response = client.get(path=[path], encoding="json_ietf")
    return normalize_get(response)


def capabilities(settings: Settings, device: Device) -> dict[str, Any]:
    with gNMIclient(
        target=(device.address, settings.port), username=settings.username,
        password=settings.password, insecure=False, skip_verify=settings.skip_verify,
        timeout=settings.timeout,
    ) as client:
        return client.capabilities()


def probe_on_change(settings: Settings, device: Device, path: str,
                    wait_seconds: int = 4) -> dict[str, Any]:
    """Test whether a concrete path accepts STREAM/ON_CHANGE.

    Capabilities does not advertise subscription mode per path, so the only
    reliable check is an actual Subscribe request.  A supported path returns
    an initial update/sync; a rejected path exposes the RPC error on the
    subscriber object.
    """
    with gNMIclient(
        target=(device.address, settings.port), username=settings.username,
        password=settings.password, insecure=False, skip_verify=settings.skip_verify,
        timeout=settings.timeout,
    ) as client:
        subscriber = client.subscribe2(subscribe={
            "subscription": [{"path": path, "mode": "on_change"}],
            "mode": "stream", "encoding": "json_ietf", "updates_only": False,
        })
        try:
            response = subscriber.get_update(timeout=wait_seconds)
            return {"supported": True, "initial_response": response}
        except TimeoutError:
            # pygnmi receives RPC errors in its subscriber thread. Give it a
            # moment to publish that error before classifying a silent path.
            time.sleep(0.2)
            error = getattr(subscriber, "error", None)
            return {"supported": False, "error": str(error or "no initial update/sync")}
        finally:
            subscriber.close()


def on_change_updates(settings: Settings, device: Device, path: str):
    """Yield parsed updates from a long-lived STREAM/ON_CHANGE subscription."""
    with gNMIclient(
        target=(device.address, settings.port), username=settings.username,
        password=settings.password, insecure=False, skip_verify=settings.skip_verify,
        timeout=settings.timeout,
    ) as client:
        subscriber = client.subscribe2(subscribe={
            "subscription": [{"path": path, "mode": "on_change"}],
            "mode": "stream", "encoding": "json_ietf", "updates_only": False,
        })
        try:
            while True:
                try:
                    response = subscriber.get_update(timeout=30)
                except TimeoutError:
                    error = getattr(subscriber, "error", None)
                    if error:
                        raise error
                    continue
                notification = response.get("update", {})
                prefix = notification.get("prefix", "")
                for update in notification.get("update", []):
                    yield {"path": join_path(prefix, update.get("path", "")),
                           "value": update.get("val"),
                           "timestamp": notification.get("timestamp")}
        finally:
            subscriber.close()


def normalize_get(response: dict[str, Any]) -> dict[str, Any]:
    """Turn arbitrary gNMI notifications into stable path/value records for diffing."""
    records: dict[str, Any] = {}
    for notification in response.get("notification", []):
        prefix = notification.get("prefix", "")
        for update in notification.get("update", []):
            path = join_path(prefix, update.get("path", ""))
            value = update.get("val")
            if isinstance(value, str):
                try:
                    value = json.loads(value)
                except json.JSONDecodeError:
                    pass
            flatten_value(path, value, records)
    return records


def join_path(prefix: Any, path: Any) -> str:
    left, right = path_text(prefix).rstrip("/"), path_text(path).lstrip("/")
    return f"{left}/{right}" if left else f"/{right}"


def path_text(path: Any) -> str:
    if isinstance(path, str):
        return path
    if isinstance(path, dict) and "elem" in path:
        parts = []
        for elem in path["elem"]:
            keys = "".join(f"[{k}={v}]" for k, v in sorted(elem.get("key", {}).items()))
            parts.append(f"{elem.get('name', '')}{keys}")
        return "/" + "/".join(parts)
    return str(path or "")


def flatten_value(path: str, value: Any, records: dict[str, Any]) -> None:
    """Keep list entries independently addressable so deletes become withdrawals."""
    if isinstance(value, dict):
        # A route/neighbor object is the diffing unit; retain all of its attributes.
        if any(key in value for key in ("route-distinguisher", "neighbor-address", "mac-address")):
            records[path] = value
            return
        child_found = False
        for name, child in value.items():
            if isinstance(child, list) and any(isinstance(item, dict) for item in child):
                child_found = True
                for index, item in enumerate(child):
                    key = list_identity(item, index)
                    flatten_value(f"{path}/{name}[{key}]", item, records)
            elif isinstance(child, dict):
                child_found = True
                flatten_value(f"{path}/{name}", child, records)
        if not child_found:
            records[path] = value
    elif isinstance(value, list):
        for index, item in enumerate(value):
            flatten_value(f"{path}[{list_identity(item, index)}]", item, records)
    else:
        records[path] = value


def list_identity(item: Any, index: int) -> str:
    if not isinstance(item, dict):
        return f"index={index}"
    preferred = (
        "route-distinguisher", "prefix", "origin", "path-id", "neighbor-address",
        "name", "afi-safi-name", "mac-address", "ip-address", "esi",
    )
    keys = [(name, item[name]) for name in preferred if name in item]
    if not keys and "state" in item and isinstance(item["state"], dict):
        keys = [(name, item["state"][name]) for name in preferred if name in item["state"]]
    return "][".join(f"{name}={value}" for name, value in keys) if keys else f"index={index}"
