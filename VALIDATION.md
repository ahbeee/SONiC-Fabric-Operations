# Validation scenarios

This catalog is vendor- and topology-neutral. Run only scenarios that are safe for the target environment, and use unsaved configuration changes when automatic rollback after reboot is required.

## Device and telemetry availability

- Reboot one managed device and verify a single `DEVICE_UNREACHABLE` root incident.
- Stop the telemetry service while SSH remains available and verify `TELEMETRY_UNAVAILABLE`, not a device outage.
- Restore service and verify the incident resolves without stale active findings.

## BGP control plane

- Clear one BGP adjacency and verify the affected link while alternate paths remain visible.
- Clear all BGP sessions on one device and verify reset events are aggregated by root cause.
- Disable only the EVPN AFI/SAFI and verify it is distinguished from total BGP failure.
- Shut all fabric-facing links on one edge device and verify fabric isolation detection.

## EVPN data plane signals

- Withdraw a VTEP's EVPN routes and verify mass-withdrawal aggregation.
- Move a MAC between VTEPs and verify Type-2 mobility correlation and deduplication across observers.
- Remove a Type-4 route or multihoming configuration and verify Ethernet Segment membership loss.
- Remove one VLAN-to-VNI mapping and verify the finding is scoped to that device and VNI.

## Ethernet Segment resilience

- Disable one multihoming attachment and verify redundancy degradation.
- Disable every attachment in the same segment and verify escalation to service down.
- Restore one side and verify the incident transitions back to degraded before resolving fully.

## Compound failures

- Combine a route-reflector reset with an independent attachment failure and verify both root causes remain visible without route-withdrawal alert storms.
- Combine one edge-device outage with loss of the remaining multihoming attachment and verify the service outage is not hidden by device-level suppression.

## Acceptance criteria

- Incidents identify the affected device, adjacency, VTEP, ESI, MAC, or VNI.
- Symptom incidents are suppressed only when a stronger root cause is supported by evidence.
- Recovery resolves active incidents and retains historical evidence.
- Polling limitations and confidence are represented honestly; inferred events are never presented as packet-complete BGP history.
