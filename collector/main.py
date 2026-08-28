from __future__ import annotations

import argparse
import json
import logging
import threading
from pathlib import Path

import uvicorn

from .config import load_settings
from .gnmi import capabilities, probe_on_change
from .service import Collector
from .store import Store
from .web import create_app


def main() -> None:
    parser = argparse.ArgumentParser(description="SONiC gNMI EVPN collector")
    parser.add_argument("command", choices=("run", "poll-once", "capabilities", "probe-on-change"),
                        nargs="?", default="run")
    parser.add_argument("--device", default="Leaf-1", help="Device used by probe-on-change")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    settings = load_settings(root)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    store = Store(settings.database_path)
    collector = Collector(settings, store)

    if args.command == "capabilities":
        for device in settings.devices:
            try:
                result = capabilities(settings, device)
                print(device.name, json.dumps(result, indent=2))
            except Exception as exc:
                print(device.name, "ERROR", exc)
        return
    if args.command == "poll-once":
        collector.poll_once()
        return
    if args.command == "probe-on-change":
        device = next((item for item in settings.devices if item.name == args.device), None)
        if not device:
            raise SystemExit(f"Unknown device: {args.device}")
        bgp = settings.paths["bgp_neighbors"]
        candidates = {
            "interface_oper_status": settings.paths["interfaces"] +
                "[name=PortChannel1]/state/oper-status",
            "bgp_session_state": bgp +
                "/neighbor[neighbor-address=Ethernet72]/state/session-state",
            "bgp_last_established": bgp +
                "/neighbor[neighbor-address=Ethernet72]/state/last-established",
            "bgp_established_transitions": bgp +
                "/neighbor[neighbor-address=Ethernet72]/state/established-transitions",
            "evpn_loc_rib": settings.paths["evpn_loc_rib"],
            "evpn_neighbors": settings.paths["evpn_neighbors"],
        }
        # pygnmi reports subscription rejection from a worker thread; results
        # are read from subscriber.error below, so suppress duplicate traceback.
        old_hook = threading.excepthook
        threading.excepthook = lambda _args: None
        try:
            for name, path in candidates.items():
                try:
                    result = probe_on_change(settings, device, path)
                    status = "SUPPORTED" if result["supported"] else "UNSUPPORTED"
                    print(f"{name}: {status} - {result.get('error', 'initial sync received')}")
                except Exception as exc:
                    print(f"{name}: ERROR - {type(exc).__name__}: {exc}")
        finally:
            threading.excepthook = old_hook
        return

    thread = threading.Thread(target=collector.run, name="collector", daemon=True)
    thread.start()
    app = create_app(store, root)
    uvicorn.run(app, host=settings.web_host, port=settings.web_port)


if __name__ == "__main__":
    main()
