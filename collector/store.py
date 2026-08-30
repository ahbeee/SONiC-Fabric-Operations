from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.lock = threading.Lock()
        self._init()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def _init(self) -> None:
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS current_state (
                    device TEXT NOT NULL, dataset TEXT NOT NULL, route_key TEXT NOT NULL,
                    value_json TEXT NOT NULL, observed_at TEXT NOT NULL,
                    PRIMARY KEY(device, dataset, route_key));
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, observed_at TEXT NOT NULL,
                    device TEXT NOT NULL, dataset TEXT NOT NULL, event_type TEXT NOT NULL,
                    route_key TEXT NOT NULL, summary TEXT NOT NULL, value_json TEXT,
                    previous_value_json TEXT);
                CREATE TABLE IF NOT EXISTS device_status (
                    device TEXT PRIMARY KEY, address TEXT NOT NULL, status TEXT NOT NULL,
                    last_poll TEXT NOT NULL, last_error TEXT);
                CREATE TABLE IF NOT EXISTS telemetry_points (
                    device TEXT NOT NULL, dataset TEXT NOT NULL, point_key TEXT NOT NULL,
                    value_json TEXT NOT NULL, observed_at TEXT NOT NULL, source TEXT NOT NULL,
                    PRIMARY KEY(device, dataset, point_key));
                CREATE TABLE IF NOT EXISTS platform_inventory (
                    device TEXT PRIMARY KEY, description TEXT, serial_number TEXT,
                    base_mac TEXT, software_version TEXT, collected_at TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS event_time_idx ON events(observed_at DESC);
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT NOT NULL UNIQUE,
                    opened_at TEXT NOT NULL, updated_at TEXT NOT NULL, severity TEXT NOT NULL,
                    status TEXT NOT NULL, category TEXT NOT NULL, title TEXT NOT NULL,
                    summary TEXT NOT NULL, confidence TEXT NOT NULL, details_json TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS analytics_state (
                    name TEXT PRIMARY KEY, value TEXT NOT NULL);
            """)
            columns = {row[1] for row in db.execute("PRAGMA table_info(events)")}
            if "previous_value_json" not in columns:
                db.execute("ALTER TABLE events ADD COLUMN previous_value_json TEXT")
            incident_columns = {row[1] for row in db.execute("PRAGMA table_info(incidents)")}
            if "peak_severity" not in incident_columns:
                db.execute("ALTER TABLE incidents ADD COLUMN peak_severity TEXT")
            if "peak_category" not in incident_columns:
                db.execute("ALTER TABLE incidents ADD COLUMN peak_category TEXT")
            db.execute("UPDATE incidents SET peak_severity=COALESCE(peak_severity,severity), "
                       "peak_category=COALESCE(peak_category,category)")

    @staticmethod
    def now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="milliseconds")

    def apply_snapshot(self, device: str, dataset: str, records: dict[str, Any]) -> dict[str, int]:
        now = self.now()
        with self.lock, self.connect() as db:
            old_rows = db.execute(
                "SELECT route_key,value_json FROM current_state WHERE device=? AND dataset=?",
                (device, dataset),
            ).fetchall()
            old = {row["route_key"]: json.loads(row["value_json"]) for row in old_rows}
            added = records.keys() - old.keys()
            removed = old.keys() - records.keys()
            changed = {key for key in records.keys() & old.keys()
                       if meaningful_change(dataset, key, old[key], records[key])}
            event_added = set() if dataset == "interfaces" and old else added
            event_removed = set() if dataset == "interfaces" else removed
            for event_type, keys, source in (
                ("ANNOUNCE", event_added, records), ("WITHDRAW", event_removed, old),
                ("UPDATE", changed, records)
            ):
                for key in keys:
                    value = source[key]
                    stored_value = event_value(dataset, value)
                    previous = (event_value(dataset, old[key])
                                if event_type == "UPDATE" and key in old else None)
                    db.execute(
                        "INSERT INTO events(observed_at,device,dataset,event_type,route_key,summary,value_json,previous_value_json) VALUES(?,?,?,?,?,?,?,?)",
                        (now, device, dataset, event_type, key, summarize(key, stored_value),
                         json.dumps(stored_value, sort_keys=True),
                         json.dumps(previous, sort_keys=True) if previous is not None else None),
                    )
            db.execute("DELETE FROM current_state WHERE device=? AND dataset=?", (device, dataset))
            db.executemany(
                "INSERT INTO current_state(device,dataset,route_key,value_json,observed_at) VALUES(?,?,?,?,?)",
                [(device, dataset, key, json.dumps(value, sort_keys=True), now) for key, value in records.items()],
            )
        return {"added": len(added), "removed": len(removed), "changed": len(changed), "total": len(records)}

    def set_status(self, device: str, address: str, status: str, error: str | None = None) -> str | None:
        with self.connect() as db:
            previous_row = db.execute("SELECT status FROM device_status WHERE device=?", (device,)).fetchone()
            db.execute(
                "INSERT INTO device_status(device,address,status,last_poll,last_error) VALUES(?,?,?,?,?) "
                "ON CONFLICT(device) DO UPDATE SET address=excluded.address,status=excluded.status,last_poll=excluded.last_poll,last_error=excluded.last_error",
                (device, address, status, self.now(), error),
            )
        return previous_row[0] if previous_row else None

    def set_point(self, device: str, dataset: str, point_key: str,
                  value: Any, source: str = "ON_CHANGE") -> None:
        with self.connect() as db:
            db.execute(
                "INSERT INTO telemetry_points(device,dataset,point_key,value_json,observed_at,source) "
                "VALUES(?,?,?,?,?,?) ON CONFLICT(device,dataset,point_key) DO UPDATE SET "
                "value_json=excluded.value_json,observed_at=excluded.observed_at,source=excluded.source",
                (device, dataset, point_key, json.dumps(value, sort_keys=True), self.now(), source),
            )

    def remove_device_state(self, device: str) -> None:
        """Forget live state for a removed device while preserving audit history."""
        with self.lock, self.connect() as db:
            db.execute("DELETE FROM current_state WHERE device=?", (device,))
            db.execute("DELETE FROM telemetry_points WHERE device=?", (device,))
            db.execute("DELETE FROM device_status WHERE device=?", (device,))
            db.execute("DELETE FROM platform_inventory WHERE device=?", (device,))
        self.resolve_incident(f"device-down:{device}", "Device removed from inventory.")

    def set_platform_inventory(self, device: str, inventory: dict[str, Any]) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT INTO platform_inventory(device,description,serial_number,base_mac,software_version,collected_at) "
                "VALUES(?,?,?,?,?,?) ON CONFLICT(device) DO UPDATE SET description=excluded.description,"
                "serial_number=excluded.serial_number,base_mac=excluded.base_mac,"
                "software_version=excluded.software_version,collected_at=excluded.collected_at",
                (device, inventory.get("description"), inventory.get("serial_number"),
                 inventory.get("base_mac"), inventory.get("software_version"), self.now()),
            )

    def has_platform_inventory(self, device: str) -> bool:
        return bool(self.rows("SELECT 1 FROM platform_inventory WHERE device=?", (device,)))

    def rows(self, query: str, args: tuple = ()) -> list[dict[str, Any]]:
        with self.connect() as db:
            return [dict(row) for row in db.execute(query, args).fetchall()]

    def analytics_cursor(self) -> int:
        rows = self.rows("SELECT value FROM analytics_state WHERE name='event_cursor'")
        return int(rows[0]["value"]) if rows else 0

    def set_analytics_cursor(self, value: int) -> None:
        with self.connect() as db:
            db.execute("INSERT INTO analytics_state(name,value) VALUES('event_cursor',?) "
                       "ON CONFLICT(name) DO UPDATE SET value=excluded.value", (str(value),))

    def upsert_incident(self, *, fingerprint: str, severity: str, category: str,
                        title: str, summary: str, confidence: str, details: dict[str, Any]) -> None:
        now = self.now()
        with self.connect() as db:
            existing = db.execute(
                "SELECT * FROM incidents WHERE fingerprint=?", (fingerprint,)
            ).fetchone()
            # Keep current phase and peak impact separately.  This lets an active
            # ES incident show DEGRADED after one side recovers while retaining
            # that it reached CRITICAL/ESI_DOWN earlier in the same episode.
            rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "WARNING": 2,
                    "HIGH": 3, "CRITICAL": 4}
            peak_severity, peak_category = severity, category
            if existing and existing["status"] == "ACTIVE":
                old_peak = existing["peak_severity"] or existing["severity"]
                if rank.get(old_peak, 0) > rank.get(severity, 0):
                    peak_severity = old_peak
                    peak_category = existing["peak_category"] or existing["category"]
            opened_at = existing["opened_at"] if existing and existing["status"] == "ACTIVE" else now
            db.execute("""
                INSERT INTO incidents(fingerprint,opened_at,updated_at,severity,status,category,title,summary,confidence,details_json,peak_severity,peak_category)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(fingerprint) DO UPDATE SET opened_at=excluded.opened_at,updated_at=excluded.updated_at,
                  severity=excluded.severity,status='ACTIVE',category=excluded.category,title=excluded.title,
                  summary=excluded.summary,confidence=excluded.confidence,details_json=excluded.details_json,
                  peak_severity=excluded.peak_severity,peak_category=excluded.peak_category
            """, (fingerprint, opened_at, now, severity, "ACTIVE", category, title, summary,
                  confidence, json.dumps(details, sort_keys=True), peak_severity, peak_category))

    def resolve_incident(self, fingerprint: str, reason: str) -> None:
        with self.connect() as db:
            row = db.execute("SELECT details_json FROM incidents WHERE fingerprint=? AND status='ACTIVE'",
                             (fingerprint,)).fetchone()
            if not row:
                return
            details = json.loads(row[0])
            details["resolution_reason"] = reason
            db.execute("UPDATE incidents SET status='RESOLVED',updated_at=?,details_json=? WHERE fingerprint=?",
                       (self.now(), json.dumps(details, sort_keys=True), fingerprint))

    def maintain(self, event_retention_days: int, incident_retention_days: int) -> dict[str, int]:
        now = datetime.now(timezone.utc)
        event_cutoff = (now - timedelta(days=event_retention_days)).isoformat(timespec="milliseconds")
        incident_cutoff = (now - timedelta(days=incident_retention_days)).isoformat(timespec="milliseconds")
        with self.lock, self.connect() as db:
            event_result = db.execute("DELETE FROM events WHERE observed_at < ?", (event_cutoff,))
            incident_result = db.execute(
                "DELETE FROM incidents WHERE status='RESOLVED' AND updated_at < ?", (incident_cutoff,)
            )
            deleted_events, deleted_incidents = event_result.rowcount, incident_result.rowcount
        with self.connect() as db:
            db.execute("PRAGMA wal_checkpoint(PASSIVE)")
        return {"events": deleted_events, "incidents": deleted_incidents}


def summarize(key: str, value: Any) -> str:
    text = json.dumps(value, sort_keys=True, separators=(",", ":"))
    interesting = []
    for token in ("next-hop", "route-distinguisher", "prefix", "ext-community", "neighbor-address", "session-state"):
        if token in text:
            interesting.append(token)
    suffix = f" ({', '.join(interesting)})" if interesting else ""
    return f"{key}{suffix}"


def comparable(value: Any) -> Any:
    """Remove timestamps that some SONiC releases mutate on every gNMI GET."""
    if isinstance(value, dict):
        return {key: comparable(child) for key, child in value.items() if key != "last-modified"}
    if isinstance(value, list):
        return [comparable(child) for child in value]
    return value


def _number(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def bgp_event_value(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    state = value.get("state", {}) if isinstance(value.get("state"), dict) else {}
    selected = {key: state[key] for key in (
        "neighbor-address", "session-state", "established-transitions",
        "connections-dropped", "last-established", "last-reset-reason",
    ) if key in state}
    result: dict[str, Any] = {"state": selected}
    if "neighbor-address" in value:
        result["neighbor-address"] = value["neighbor-address"]
    afi_values = []
    for afi in value.get("afi-safis", {}).get("afi-safi", []):
        afi_state = afi.get("state", {}) if isinstance(afi, dict) else {}
        afi_values.append({key: afi_state[key] for key in
                           ("afi-safi-name", "active", "enabled") if key in afi_state})
    if afi_values:
        result["afi-safis"] = afi_values
    return result


def event_value(dataset: str, value: Any) -> Any:
    if dataset == "bgp_neighbors":
        return bgp_event_value(value)
    if dataset == "lldp_neighbors":
        return lldp_event_value(value)
    return value


def meaningful_change(dataset: str, key: str, old: Any, new: Any) -> bool:
    if dataset == "bgp_neighbors":
        old_event, new_event = bgp_event_value(old), bgp_event_value(new)
        # Normal uptime growth is not an event; a backwards jump is a reset.
        old_uptime = _number(old_event.get("state", {}).pop("last-established", None))
        new_uptime = _number(new_event.get("state", {}).pop("last-established", None))
        return (comparable(old_event) != comparable(new_event)
                or (old_uptime is not None and new_uptime is not None and new_uptime < old_uptime))
    if dataset == "interfaces":
        lowered = key.lower()
        if any(token in lowered for token in ("/counters", "/statistics", "last-change")):
            return False
        return interface_event_value(old) != interface_event_value(new)
    if dataset == "lldp_neighbors":
        return lldp_event_value(old) != lldp_event_value(new)
    return comparable(old) != comparable(new)


def lldp_event_value(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    return {key: value[key] for key in (
        "system-name", "chassis-id", "port-id", "port-description", "management-address"
    ) if key in value}


def interface_event_value(value: Any) -> Any:
    noise = {"counters", "statistics", "last-change", "last-clear", "timestamp"}
    if isinstance(value, dict):
        return {key: interface_event_value(child) for key, child in value.items()
                if key.lower() not in noise
                and not key.lower().endswith(("pkt-rcvd", "pkt-sent"))}
    if isinstance(value, list):
        normalized = [interface_event_value(child) for child in value]
        return sorted(normalized) if all(isinstance(item, (str, int, float)) for item in normalized) else normalized
    return value
