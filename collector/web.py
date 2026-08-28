from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse

from .analytics import parse_route
from .store import Store


def create_app(store: Store, root: Path) -> FastAPI:
    app = FastAPI(title="SONiC gNMI EVPN Collector", version="0.1.0")

    @app.get("/")
    def index():
        return FileResponse(root / "static" / "index.html")

    @app.get("/api/devices")
    def devices():
        return store.rows("SELECT * FROM device_status ORDER BY device")

    @app.get("/api/events")
    def events(limit: int = Query(100, ge=1, le=2000), event_type: str | None = None):
        if event_type:
            rows = store.rows("SELECT * FROM events WHERE event_type=? ORDER BY id DESC LIMIT ?", (event_type, limit))
        else:
            rows = store.rows("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
        for row in rows:
            row["value"] = json.loads(row.pop("value_json")) if row.get("value_json") else None
        return rows

    @app.get("/api/routes")
    def routes(limit: int = Query(500, ge=1, le=5000), search: str = ""):
        rows = store.rows(
            "SELECT * FROM current_state WHERE route_key LIKE ? OR value_json LIKE ? ORDER BY observed_at DESC LIMIT ?",
            (f"%{search}%", f"%{search}%", limit),
        )
        for row in rows:
            row["value"] = json.loads(row.pop("value_json"))
        return rows

    @app.get("/api/summary")
    def summary():
        return {
            "routes": store.rows("SELECT device,dataset,COUNT(*) AS count FROM current_state GROUP BY device,dataset ORDER BY device,dataset"),
            "events": store.rows("SELECT event_type,COUNT(*) AS count FROM events GROUP BY event_type"),
        }

    @app.get("/api/health")
    def health():
        device_counts = {row["status"]: row["count"] for row in store.rows(
            "SELECT status,COUNT(*) AS count FROM device_status GROUP BY status"
        )}
        incident_counts = {row["severity"]: row["count"] for row in store.rows(
            "SELECT severity,COUNT(*) AS count FROM incidents WHERE status='ACTIVE' GROUP BY severity"
        )}
        freshness = store.rows(
            "SELECT MIN(last_poll) AS oldest_poll,MAX(last_poll) AS newest_poll FROM device_status"
        )[0]
        route_counts = store.rows(
            "SELECT dataset,COUNT(*) AS count FROM current_state GROUP BY dataset ORDER BY dataset"
        )
        db_size = store.path.stat().st_size if store.path.exists() else 0
        return {"devices": device_counts, "active_incidents": incident_counts,
                "freshness": freshness, "route_counts": route_counts,
                "database_bytes": db_size, "server_time": datetime.now(timezone.utc).isoformat()}

    @app.get("/api/incidents")
    def incidents(limit: int = Query(100, ge=1, le=1000), status: str = "ACTIVE"):
        where, args = ("", ()) if status.upper() == "ALL" else ("WHERE status=?", (status.upper(),))
        rows = store.rows(f"SELECT * FROM incidents {where} ORDER BY "
                          "CASE status WHEN 'ACTIVE' THEN 1 ELSE 2 END,"
                          "CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'WARNING' THEN 3 ELSE 4 END, "
                          "updated_at DESC LIMIT ?", (*args, limit))
        for row in rows:
            row["details"] = json.loads(row.pop("details_json"))
        return rows

    @app.get("/api/incidents/{incident_id}")
    def incident_detail(incident_id: int, event_limit: int = Query(200, ge=1, le=1000)):
        rows = store.rows("SELECT * FROM incidents WHERE id=?", (incident_id,))
        if not rows:
            raise HTTPException(status_code=404, detail="Incident not found")
        incident = rows[0]
        incident["details"] = json.loads(incident.pop("details_json"))
        # The incident window is the safest generic correlation boundary. The UI
        # marks these as nearby evidence rather than claiming every row is causal.
        events = store.rows(
            "SELECT id,observed_at,device,dataset,event_type,summary FROM events "
            "WHERE observed_at>=? AND observed_at<=? ORDER BY id DESC LIMIT ?",
            (incident["opened_at"], incident["updated_at"], event_limit),
        )
        incident["events"] = events
        return incident

    @app.get("/api/evpn/routes")
    def evpn_routes(limit: int = Query(500, ge=1, le=5000), search: str = "",
                    route_type: int | None = Query(None, ge=1, le=5), device: str = ""):
        rows = store.rows(
            "SELECT device,route_key,value_json,observed_at FROM current_state "
            "WHERE dataset='evpn_loc_rib' AND (?='' OR device=?) "
            "AND (route_key LIKE ? OR value_json LIKE ?) ORDER BY observed_at DESC LIMIT ?",
            (device, device, f"%{search}%", f"%{search}%", limit),
        )
        result = []
        for row in rows:
            value = json.loads(row.pop("value_json"))
            route = parse_route(value)
            if route_type is not None and route.route_type != route_type:
                continue
            result.append({**row, "route_type": route.route_type, "prefix": route.prefix,
                           "rd": route.rd, "vtep": route.next_hop, "mac": route.mac})
        return result

    return app
