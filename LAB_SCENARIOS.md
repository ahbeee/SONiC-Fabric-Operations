# SONiC gNMI Collector — LAB fault scenarios

所有案例只修改 running state，不執行 `config save`。每個案例依序執行：baseline → 注入 → 等待 incident → 驗證證據 → 還原 → 等待 resolved。若 SSH/management reachability 受影響，以 reboot 回復已保存設定。

## A. Device lifecycle

1. Reboot Leaf-1/2/3：預期 `DEVICE_UNREACHABLE` 為根因；VTEP/ESI 為衍生影響。
2. Reboot Spine-1/2：預期 Spine device incident；抑制 fabric-wide VTEP 誤報及 GR stale cleanup。
3. 暫停單一 telemetry service（若平台命令確認安全）：預期 `DEVICE_DEGRADED`，不是 device down。

## B. EVPN multihoming / data plane

4. Shutdown Leaf-1 的 PortChannel member：預期 `ESI_DEGRADED`，Leaf-2 維持服務。
5. 再 shutdown Leaf-2 member：預期同一 incident 升級為 `ESI_DOWN/CRITICAL`。
6. 依序恢復兩側 member：預期 `ESI_DOWN → ESI_DEGRADED → RESOLVED`，並保留 peak severity。
7. 暫時錯配 ESI 或移除單側 ES membership：預期 Type-4 withdrawal 並定位 attachment。
8. 暫時錯配 PortChannel/VLAN membership：預期 attachment down 或 EVPN Type-2/Type-3 影響。

## C. BGP control plane

9. Leaf `clear bgp all *`：預期單一 Leaf `BGP_SESSION_RESET`，關聯 VTEP route churn。
10. Spine `clear bgp all *`：預期聚合為單一 Spine root cause，列出所有 reset sessions。
11. Clear 單一 neighbor：預期只影響指定 adjacency，alternate Spine path 保留。
12. 暫時 shutdown 單一 Leaf uplink：預期 BGP adjacency loss，但設備 gNMI 仍 UP。
13. 暫時 shutdown Leaf 的兩條 uplink：預期 Leaf control-plane isolation、VTEP withdrawals。
14. 暫時停用單一 neighbor 的 L2VPN EVPN AFI/SAFI：預期 IPv4 BGP 可維持，但 EVPN NLRI 消失。
15. 暫時配置錯誤 remote-AS/peer-group（只限可由另一條路徑恢復者）：預期 session failure 與局部 route loss。

## D. EVPN route behavior

16. 觸發已知 MAC 在 Leaf-1/Leaf-2 間移動：預期 `MAC_MOBILITY`；反覆移動升級 `MAC_FLAPPING`。
17. 關閉單一 VTEP/NVE source（平台命令確認後）：預期 Type-3 與該 VTEP routes mass withdraw。
18. 移除/錯配單側 VNI 或 route-target：預期只影響指定 VNI/RD，不應判成整台 VTEP failure。
19. 移除單側 Type-4 advertisement：預期 ESI membership degraded，另一 PE 仍有效。

## E. Compound and recovery

20. Spine BGP reset 同時單側 ES attachment down：預期 Spine control-plane 與真實 ES degraded 分開呈現。
21. Leaf reboot 同時另一側 ES member down：預期 ES service down，不能只歸因 reboot 而隱藏服務中斷。
22. 注入錯誤後 reboot：驗證未保存設定消失、所有 incidents resolved、current state 回到 baseline。

## Safety gates

- 不 shutdown management interface，不修改 management VRF/default route。
- 不同時重啟兩台 Spine；不在沒有存活替代路徑時修改遠端 BGP recovery path。
- 每個案例保存 exact rollback command；超時或結果不符立即 rollback/reboot。
- 下一案例開始前，五台 device status 必須為 UP、ES attachment 必須恢復、active incident 必須清空或有已知理由。

## Execution log

Coverage: all 22 scenario classes have been exercised. Scenario 17 used an equivalent
fabric-wide L2 VNI withdrawal because this SONiC CLI prevents deleting the NVO/tunnel
while L2 and VRF VNI dependencies exist; direct NVE oper-down remains a platform-limited
variant rather than a claimed test result.

- PASS — Leaf-1 ES member down: one `ESI_DEGRADED`, ON_CHANGE observed in about 1 second.
- PASS — Leaf-1 + Leaf-2 ES members down: one `ESI_DOWN/CRITICAL`; partial and full recovery correct.
- PASS — Leaf-3 single uplink Ethernet72 down: one topology `BGP_SESSION_DOWN` for Spine-2--Leaf-3.
- PASS — Leaf-3 both uplinks down: one `FABRIC_ISOLATION/CRITICAL`; after one link recovered it transitioned to the remaining `BGP_SESSION_DOWN`, then resolved.
- PASS — Spine-1 clear BGP neighbor Ethernet4: only Spine-1--Leaf-2 adjacency incident; alternate Spine path remained available and incident resolved.
- FIXED — Raw Type-4 incident no longer duplicates a topology-aware ES incident.
- FIXED — BGP counters encoded as JSON strings are parsed correctly.
- FIXED — Endpoint reset incidents are suppressed when they are recovery evidence for a known BGP link outage.
- PASS — Leaf-2 reboot: `DEVICE_UNREACHABLE/CRITICAL` root cause plus ES degraded; recovered without active leftovers.
- PASS — Spine-1 reboot: only `DEVICE_UNREACHABLE/CRITICAL` active during outage; Leaf/VTEP symptoms suppressed.
- PASS — Leaf-3 EVPN AFI disabled while IPv4 BGP remained established: `EVPN_AFI_INACTIVE/CRITICAL`; resolved after exact rollback.
- PASS — Leaf-3 VNI 1040 mapping removed: one device/VNI-scoped `VNI_COVERAGE_LOSS`; resolved after restoring the exact CONFIG_DB entry.
- PASS — Leaf-1 ES `system_mac` mismatch: physical attachment loss was the root incident and derivative per-VNI losses were suppressed; resolved after restoring `00:00:00:00:11:11`.
- PASS — MAC `80:a2:35:81:9a:ab` moved Leaf-3 → Leaf-1 and back: paired Type-2 announce/withdraw events from five observers produced one deduplicated `MAC_MOBILITY` with correct old/new VTEPs.
- PASS — Repeated movement of MAC `80:a2:35:81:9a:ab`: movement count 3 remained `MAC_MOBILITY/INFO`; count 4 escalated to `MAC_FLAPPING/HIGH`, then resolved after stability.
- PASS — Leaf-3 `telemetry.service` stopped: management SSH probe kept the device `DEGRADED` and produced one `TELEMETRY_UNAVAILABLE/HIGH`, not `DEVICE_UNREACHABLE`; resolved after service start.
- PASS — Compound Spine-2 BGP clear plus Leaf-1 ES member down: one aggregated Spine `BGP_SESSION_RESET/HIGH` (3 sessions and correlated EVPN withdrawals) plus one independent `ESI_DEGRADED/HIGH`; per-link symptoms suppressed.
- PASS — Compound Leaf-1 reboot plus Leaf-2 ES member down: `ESI_DOWN/CRITICAL` remained visible as a service outage while the Leaf device/telemetry incident represented the reboot; peer-side Spine resets were suppressed and both recovered cleanly.
- PASS — Deleted Leaf-3 VNI 1040 mapping without saving, then rebooted: startup CONFIG_DB restored `vni=1040,vlan=Vlan40`, the local Type-3 route returned, and all incidents resolved.
- PASS — Removed VLAN 40 from Leaf-1 PortChannel1: one `ES_VLAN_COVERAGE_LOSS/HIGH` identified the exact attachment/VLAN while the PortChannel remained UP; derivative VNI 1040 loss was suppressed and the incident resolved after restoring the tagged member.
- PASS — Replaced only Leaf-3 Ethernet72 runtime peer-group with incorrect remote-AS 65000: one `BGP_SESSION_DOWN/HIGH` for Spine-2--Leaf-3 while the Spine-1 path stayed Established; resolved after restoring `neighbor Ethernet72 interface peer-group SPINE` without saving.
- PASS (functional equivalent) — Removed all four Leaf-3 L2 VLAN–VNI mappings: 63 Type-2/3 withdrawals were observed across all five devices and aggregated into one `VTEP_FAILURE/CRITICAL`; per-VNI symptoms were suppressed. Reboot restored all six mappings, NVO binding, and four local Type-3 routes.
- PLATFORM LIMIT — Direct `config vxlan evpn_nvo del nvo1` and `config vxlan del vtep1` are rejected until every L2 and VRF VNI dependency is removed; CONFIG_DB tunnel/source deletion alone leaves operational FRR/ASIC state intact and is not considered a valid NVE-down test.
- PASS — Removed only `evpn mh es-id 1` from Leaf-1 PortChannel1 runtime: PortChannel stayed UP and one `ESI_MEMBERSHIP_LOSS/HIGH` identified the missing Leaf-1 Type-4 member; resolved after restoring the exact FRR line.
- FIXED — Aggregate VTEP failure now suppresses matching per-device VNI coverage incidents in the same and subsequent analysis cycles.
- FIXED — Active device root incidents now suppress same-batch peer-side BGP reset symptoms without suppressing an independent Ethernet Segment service outage.
- FIXED — Device recovery context remains valid for 5 minutes so delayed peer-side reset events are still attributed to the recent reboot.
- FIXED — Expected ES trunk VLANs and VLAN-to-VNI mappings are topology inventory, allowing a missing VLAN root cause to suppress its matching Type-3 VNI symptom.
- FIXED — MAC mobility detection now handles the SONiC behavior where RD/origin changes create separate announce and withdraw records instead of an in-place route update.
- FIXED — Type-2 best-path convergence without an EVPN `MM:` community is no longer classified as MAC mobility.
- FIXED — A 2-second lightweight BGP neighbor probe fills the gap left by unsupported BGP ON_CHANGE without increasing stable event storage.
- UI — Added fabric health summary, collection freshness, Active/Resolved/All incident views, peak impact and resolution details, correlated telemetry timeline, structured EVPN route filters, and local/UTC time switching.
- FIXED — ON_CHANGE streams detect reboot disconnects and reconnect instead of blocking forever.
- FIXED — Device outage/degradation suppresses BGP link and fabric-isolation derivative incidents.
- FIXED — Active EVPN AFI incident suppresses adjacency churn during configuration recovery.
- STORAGE — Stable polling no longer records BGP uptime/message counters, interface counters, IPv6 RA counters, VLAN list ordering, or transient interface snapshot omissions.
- STORAGE — 35-second stable validation produced zero new events; retention and WAL checkpoint maintenance added.
