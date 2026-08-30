# gNMI collector compared with BMP

BMP and this collector observe BGP through fundamentally different interfaces. BMP streams BGP monitoring messages from the routing process. This project reads operational state through gNMI and derives changes by comparing snapshots. It is a practical alternative where SONiC does not expose BMP, but it is not a protocol-equivalent replacement.

## Capability matrix

| Capability | BMP collector | SONiC Fabric Operations |
| --- | --- | --- |
| Pre-policy and post-policy route monitoring | Native when exported by the router | Only the RIB views exposed by the configured gNMI model |
| Every BGP update in sequence | Designed for update-level streaming | No; transient changes between polls can be missed |
| Peer up/down and termination reasons | Native BMP messages | Inferred from BGP state, timers, counters, and snapshot changes |
| Route Monitoring / Route Mirroring | Native BMP functions | Not available as raw BGP messages or mirrored packets |
| Per-peer Adj-RIB-In visibility | Native when configured/exported | Available only if SONiC exposes the corresponding per-neighbor EVPN RIB path |
| Timestamp fidelity | Router/BMP message timestamps | Collector observation time, bounded by polling/subscription latency |
| Interface and device operational state | Outside BMP scope | Native gNMI strength |
| Ethernet Segment attachment state | Requires another telemetry source | Correlated directly with EVPN Type-4 and interface state |
| VNI/VLAN intent validation | Requires external configuration/integration | Built-in expected-VNI correlation |
| Root-cause incident analysis | Usually a separate analytics layer | Built in for the supported scenarios |
| Configuration/model portability | Standard protocol, vendor export differences remain | Depends on OpenConfig model coverage and path compatibility |
| Network overhead | Continuous route-monitoring stream; can be large | Tunable polling, current-state replacement, filtered event retention |

## What remains weaker than BMP

1. **No lossless update history.** A route announced and withdrawn inside one polling interval is invisible.
2. **No exact BGP message ordering.** Events observed in the same polling cycle cannot be claimed to have wire-order accuracy.
3. **No raw UPDATE attributes beyond the exposed model.** Unsupported attributes, policy stages, and rejected routes are unavailable.
4. **No BMP Route Mirroring, Statistics Report, Initiation, or Termination messages.** Similar conclusions may sometimes be inferred, but the original protocol evidence is absent.
5. **Model dependence.** AFI/SAFI and RIB coverage vary by SONiC release, platform, and OpenConfig implementation.
6. **Polling load.** Large RIB snapshots can consume switch CPU, bandwidth, collector CPU, and SQLite write I/O. Capacity testing is required before broad deployment.
7. **Collector-side timestamps.** Clock and collection latency are less authoritative than router-originated monitoring timestamps.

## What is better for operations

1. **Works without BMP support.** It uses the management interface already exposed by many SONiC deployments.
2. **Cross-domain evidence.** BGP, EVPN, interfaces, device reachability, Ethernet Segments, and intended VNI coverage are analyzed together.
3. **Actionable incidents instead of a raw feed.** Repeated observations are deduplicated and grouped into root causes with severity, confidence, impact, and recovery state.
4. **Noise suppression.** Route withdrawals caused by a confirmed device or route-reflector outage can be treated as symptoms while independent service failures remain visible.
5. **Controlled data growth.** Current state is replaced in place, low-value counter churn is filtered, and retained events/incidents have independent lifetimes.
6. **Topology and health UI.** Operators can see device, adjacency, multihoming, route, and incident state without deploying a separate BMP analytics frontend.
7. **Intent-aware validation.** Expected VNIs and configured Ethernet Segment attachments can identify missing coverage that a raw BGP feed alone does not define as incorrect.

## Recommended production position

Use BMP when packet-complete BGP history, policy-stage visibility, compliance evidence, or precise update ordering is required and the platform supports it. Use this collector for operational health and incident correlation where gNMI is available, especially when BMP is unavailable.

When both are available, they are complementary: BMP supplies authoritative BGP event history, while gNMI supplies device, interface, and service-state context. A mature deployment should correlate both rather than force one to replace the other.
