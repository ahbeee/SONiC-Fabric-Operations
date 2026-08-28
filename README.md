# SONiC gNMI EVPN Collector

這是一個 LAB 用的 BMP 替代工具。它以 gNMI 讀取 Broadcom SONiC 的 BGP neighbor、EVPN Loc-RIB 與 per-neighbor EVPN RIB，將目前狀態保存到 SQLite，並由相鄰快照推導 `ANNOUNCE`、`UPDATE`、`WITHDRAW` 事件。

首頁優先呈現分析後的 incident，而非原始資料：VTEP mass withdrawal、Type-2 MAC mobility/flapping，以及 Type-4 ESI membership withdrawal。每個 incident 都包含 severity、confidence、影響範圍與判斷證據。

BGP neighbor 的 `last-established` 回到較小值或 `established-transitions` 增加時，會建立 `BGP_SESSION_RESET`；即使 reset 在兩次 polling 間完成，也能利用 timer/counter 證據辨識，並關聯同一輪的 EVPN withdrawals。

根因有優先順序：若 Spine/RR 本身確認不可達，同一時間發生的 VTEP/ESI route withdrawals 會視為控制平面路徑消失的症狀並抑制，避免告警風暴。
Spine 恢復後仍保留 300 秒的 Graceful Restart correlation window，避免 stale route timer 到期時誤判成新的 VTEP failure。

`inventory.yaml` 可定義 EVPN Ethernet Segment、ESI 與各 Leaf 的 PortChannel attachment。分析器會直接交叉驗證介面 operational state：單側 down 為 `ESI_DEGRADED`，所有 attachment down 才是 `ESI_DOWN`。

## 能力與限制

- 顯示五台設備的可達狀態與 gNMI 錯誤。
- 保存目前 RIB 和歷史事件，支援 MAC、VTEP、ESI、RD、prefix 搜尋。
- 每個 gNMI path 獨立探測；某一條路徑不支援不會中止整台設備。
- 預設每 10 秒輪詢，因此事件時間精度為輪詢週期，且在同一週期內出現又消失的 route 不會被看見。
- gNMI 是 RIB state telemetry，不是 BMP UPDATE message feed；本工具推導的事件不能宣稱為逐封包、無遺漏的 BGP 歷史。
- 某些版本在每次 GET 都會改寫 `last-modified`；分析器刻意忽略這個欄位，避免產生假的 route UPDATE。
- 同一 incident 在 DOWN -> DEGRADED 的恢復階段會保留 peak severity 與原始 root cause，直到完全恢復才 resolve。
- BGP uptime/message counters、interface counters、IPv6 RA counters 與無語意的 VLAN list ordering 不會產生歷史事件；current state 仍會更新。
- Retention maintenance 預設每 6 小時執行，events 保留 14 天、resolved incidents 保留 180 天，並執行 WAL checkpoint。
- Broadcom SONiC 僅對部分 path 支援 `ON_CHANGE`。本版先採可靠的 GET snapshot diff；確認 EVPN path 的 subscription capability 後可再切換成串流。
- LAB 實測具體介面的 `state/oper-status` 支援 `STREAM/ON_CHANGE`，ES attachment 因此會即時觸發分析；BGP state/counter 與 EVPN RIB 明確回覆 `on change disabled`，仍使用 polling。

## 安裝與執行（PowerShell）

```powershell
cd C:\Users\yeile\Documents\codex\NOS_info\sonic-gnmi-collector
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m collector.main capabilities
python -m collector.main probe-on-change --device Leaf-1
python -m collector.main poll-once
python -m collector.main run
```

開啟 <http://127.0.0.1:8000>。API 文件位於 <http://127.0.0.1:8000/docs>。

帳密位於被 `.gitignore` 排除的 `.env`。可提交的範本是 `.env.example`。

## 若設備回報 path 不存在

不同版本可能使用不同的 network-instance、protocol name 或 AFI/SAFI identity。修改 `inventory.yaml` 中的 path 即可，不需要改程式。先用 `capabilities` 確認 model，再以單次 `poll-once` 檢視每條 path 的錯誤。

Broadcom SONiC 4.5.1 文件所定義的 EVPN root：

```text
/openconfig-network-instance:network-instances/network-instance[name=default]
 /protocols/protocol[identifier=BGP][name=bgp]/bgp/rib/afi-safis
 /afi-safi[afi-safi-name=L2VPN_EVPN]
 /openconfig-bgp-evpn-ext:l2vpn-evpn
```
