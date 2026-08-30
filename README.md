# SONiC Fabric Operations

SONiC Fabric Operations is a deployable gNMI-based monitoring and incident-correlation service for SONiC fabrics. It monitors BGP neighbor state, EVPN RIB state, Ethernet Segment attachments, VTEPs, VNIs, and device availability without requiring BMP support on the switch.

The project is not tied to a fixed topology or lab. Devices, OpenConfig paths, BGP links, Ethernet Segments, VTEPs, and expected VNIs are supplied at deployment time through local configuration.

## What it provides

- A live device and fabric health dashboard.
- A topology view labeled with hostnames learned from device telemetry and optional operator notes.
- Per-device gNMI credentials that are never returned by the API or displayed after submission.
- Current EVPN Loc-RIB state and searchable Type-1 through Type-5 routes.
- Snapshot-derived announce, update, and withdrawal events.
- Correlated incidents for device loss, telemetry loss, BGP resets, adjacency loss, fabric isolation, VTEP mass withdrawal, Type-2 MAC mobility/flapping, Type-4 ESI membership loss, multihoming degradation, and VNI coverage loss.
- Root-cause suppression and recovery-aware incident lifecycle handling.
- Bounded event and resolved-incident retention with SQLite WAL maintenance.

## Architecture

The collector polls supported OpenConfig paths independently, stores only the latest state in `current_state`, and records meaningful changes in the event history. A faster BGP neighbor poll supplements the full collection cycle. Interface operational state can use gNMI `STREAM/ON_CHANGE` when the SONiC implementation supports it. OpenConfig LLDP neighbor state automatically discovers physical links between managed devices.

The analyzer correlates evidence across devices and datasets. A confirmed device or control-plane outage can suppress derivative route-withdrawal noise, while an independent service-impacting failure remains visible.

This is not a packet-complete BGP update archive. gNMI snapshots can miss a route that appears and disappears between polls. See [BMP_COMPARISON.md](BMP_COMPARISON.md) for the complete capability comparison.

## Requirements

- Python 3.11 or newer
- Network reachability to each SONiC gNMI endpoint
- A SONiC image exposing the required OpenConfig paths

## Installation

```powershell
git clone https://github.com/ahbeee/SONiC-Fabric-Operations.git
cd SONiC-Fabric-Operations
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
Copy-Item inventory.yaml.example inventory.yaml
```

Set the shared fallback credentials and runtime options in `.env`. Both `.env` and `inventory.yaml` are excluded from Git.

```dotenv
GNMI_USERNAME=admin
GNMI_PASSWORD=replace-me
GNMI_PORT=8080
GNMI_SKIP_VERIFY=true
POLL_INTERVAL=10
BGP_FAST_POLL_INTERVAL=2
WEB_HOST=127.0.0.1
WEB_PORT=8000
```

Start the service:

```powershell
python -m collector.main run
```

Open <http://127.0.0.1:8000>. Interactive API documentation is available at <http://127.0.0.1:8000/docs>.

## Device management and credentials

Use **Manage devices** to enter:

- Management IPv4 or IPv6 address
- Username
- Password
- Optional operator notes

The internal device ID is generated from the management address. The UI does not ask for an operator-defined device name. Fabric topology uses the hostname advertised by the device through BGP telemetry; until a hostname is learned, the management address is shown.

The management address and notes are written atomically to `inventory.yaml`. Per-device credentials are written to the Git-ignored `device-secrets.yaml`; the API never returns them. Devices without a per-device entry use the shared `.env` credentials. Inventory write operations are restricted to localhost because the application does not provide user authentication.

Both files can also be edited manually. Use [inventory.yaml.example](inventory.yaml.example) and [device-secrets.yaml.example](device-secrets.yaml.example) as templates. The running collector hot-reloads valid changes and keeps its last valid configuration if a file is temporarily invalid.

> `device-secrets.yaml` is local plaintext configuration. Protect it with operating-system file permissions or integrate a secret manager before exposing this service in a multi-user production environment.

## Topology configuration

Physical fabric links are discovered automatically from `lldp_neighbors`. The collector maps LLDP neighbor system names to hostnames learned from managed-device telemetry, accepts either FQDN or short-name matches, combines observations from both ends, and removes duplicate links. Only current neighbor state is retained; LLDP age and counter churn does not create historical events.

When a configured BGP adjacency connects the same device pair, its session health is overlaid on the LLDP physical link. This lets the UI show a physically discovered connection in red when its BGP control plane is down.

Optional `bgp_links` entries correlate the two observed sides of each adjacency. A link is marked UP only when both ends report `ESTABLISHED`; incomplete evidence is shown as UNKNOWN.

Optional `ethernet_segments` entries associate an ESI with its device/interface attachments. This enables immediate multihoming degradation and outage analysis when interface `ON_CHANGE` is supported.

Optional `vtep_devices` and `expected_vnis` entries enable VTEP ownership and VNI coverage correlation. See [inventory.yaml.example](inventory.yaml.example) for the schema and adapt it to the target fabric.

## SONiC model compatibility

OpenConfig coverage differs by SONiC release. Each configured path is probed independently, so one unsupported dataset degrades a device rather than stopping all collection. Edit the `paths` section in `inventory.yaml` when a release uses different network-instance, protocol, or AFI/SAFI identifiers.

Useful diagnostics:

```powershell
python -m collector.main capabilities
python -m collector.main poll-once
python -m collector.main probe-on-change --device <internal-device-id>
```

Broadcom SONiC releases tested during development accepted interface operational-state `ON_CHANGE` but rejected `ON_CHANGE` for BGP and EVPN RIB paths. Those datasets therefore use polling unless the target release proves otherwise.

## Data retention

- `current_state` and telemetry points are replacements, not unbounded history.
- Meaningful events are retained for 14 days by default.
- Resolved incidents are retained for 180 days by default.
- Maintenance runs every six hours and checkpoints the SQLite WAL.

Adjust `EVENT_RETENTION_DAYS`, `INCIDENT_RETENTION_DAYS`, and `MAINTENANCE_INTERVAL_HOURS` in `.env` for the deployment size and compliance requirements.

## Validation

Run the automated test suite:

```powershell
python -m pytest -q
```

Operational fault-injection scenarios and acceptance criteria are documented in [VALIDATION.md](VALIDATION.md).

## Security and deployment notes

- The default web listener is localhost only.
- TLS certificate verification is configurable; `GNMI_SKIP_VERIFY=true` is intended for controlled environments.
- There is no built-in UI authentication or role-based access control.
- Use a reverse proxy with TLS and authentication before exposing the UI remotely.
- Back up configuration and the SQLite database according to local operational requirements.
