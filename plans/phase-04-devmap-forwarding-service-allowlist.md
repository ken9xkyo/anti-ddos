# Phase 04 - DEVMAP Forwarding va Service Allowlist

## Muc tieu

Dam bao gateway chi redirect traffic sach toi backend/service da khai bao bang L2 MAC rewrite va `XDP_REDIRECT` qua `BPF_MAP_TYPE_DEVMAP`. Packet ngoai allowlist hoac redirect target loi phai fail-closed bang `XDP_DROP`, tang counter ro reason va tao du input cho dashboard/alert.

## Pham vi

- Implement `service_allowlist` lookup trong XDP theo dst IPv4, protocol va dst port.
- Agent resolve output ifindex va next-hop/backend MAC tu routing/ARP/neighbor table truoc khi publish policy.
- Agent populate `tx_devmap` va `service_allowlist` tu snapshot da validate.
- XDP rewrite Ethernet source/destination MAC va goi `bpf_redirect_map(&tx_devmap, service.devmap_key, XDP_DROP)`.
- Backend return path co the asymmetric; MVP khong NAT/DNAT va khong proxy.
- Control API CRUD service implement day du o Phase 05; phase nay dung config/mock snapshot de verify data path.

## Cong viec

| ID | Cong viec | Muc dich | Ket qua ban giao | Phu thuoc |
|---|---|---|---|---|
| P04-T01 | Dinh nghia final `service_key` va `service_value` | Dong bo XDP map voi snapshot/API | Key dst_v4/proto/dst_port; value service_id, policy_id, action, output_ifindex, devmap_key, neighbor_status, dst_mac, src_mac | Phase 03 |
| P04-T02 | Implement Agent route/neighbor resolver | Biet redirect packet ra interface nao va MAC nao | Resolver doc route, ifindex, interface MAC, ARP/neighbor MAC, status resolved/unresolved | P04-T01 |
| P04-T03 | Validate output interface va neighbor state | Khong publish policy redirect sai path | Validation error cho interface missing/down, MAC missing, neighbor unresolved | P04-T02 |
| P04-T04 | Populate `tx_devmap` | Tao target output interface cho `XDP_REDIRECT` | Agent update `BPF_MAP_TYPE_DEVMAP` theo devmap_key/output_ifindex | P04-T03 |
| P04-T05 | Populate `service_allowlist` active/inactive slot | Dua service registry thanh hot-path policy | Map entries co dst/proto/port va resolved redirect metadata | P04-T04 |
| P04-T06 | Implement service lookup trong XDP | Chan traffic ngoai allowlist som | Logic lookup active service slot sau parse/source checks | P04-T05 |
| P04-T07 | Implement `REASON_NOT_ALLOWED_SERVICE` | Visibility cho service miss | Counter/drop/event cho packet khong match service allowlist | P04-T06 |
| P04-T08 | Implement neighbor unresolved fail-closed drop | Khong redirect khi MAC/neighbor khong tin cay | XDP drop `REASON_NEIGHBOR_UNRESOLVED`, counter va sampled event | P04-T06 |
| P04-T09 | Implement Ethernet source/destination MAC rewrite | Chuan bi packet cho backend-facing NIC | Helper rewrite `eth->h_dest` bang backend/next-hop MAC va `eth->h_source` bang output interface MAC | P04-T08 |
| P04-T10 | Implement DEVMAP redirect return path | Chuyen traffic sach toi backend | XDP return `bpf_redirect_map(&tx_devmap, service.devmap_key, XDP_DROP)` | P04-T09 |
| P04-T11 | Implement redirect/error counters | Quan sat duoc success/failure forwarding | Counters `redirected`, `redirect_error`, `neighbor_unresolved`, `not_allowed_service` theo service/proto/interface | P04-T10 |
| P04-T12 | Expose redirect va neighbor metrics | Dashboard/Prometheus thay forwarding state | Metrics `anti_ddos_redirected_packets_total`, `anti_ddos_redirect_errors_total`, `anti_ddos_neighbor_resolution_status` | P04-T11 |
| P04-T13 | Test non-allowlisted traffic | Xac nhan khong forward nham | Packet toi port/proto/dst khong cho phep bi drop/count | P04-T12 |
| P04-T14 | Test end-to-end VETH/namespace DEVMAP forwarding | Xac nhan redirect path hoat dong that | Client namespace -> WAN veth -> XDP -> DEVMAP -> backend namespace | P04-T10 |
| P04-T15 | Document redirect failure behavior | Van hanh biet khi nao can canh bao/rollback | Runbook ngan cho output interface down, DEVMAP missing, neighbor unresolved, return path sai | P04-T12 |

## Tieu chi chap nhan

- Packet toi backend IP/protocol/port da khai bao duoc L2 rewrite va return `XDP_REDIRECT` qua `tx_devmap`.
- Packet khong match service allowlist bi `XDP_DROP` voi reason `not_allowed_service`.
- Neighbor unresolved, output interface loi hoac DEVMAP target loi fail-closed bang drop voi counter/metric rieng.
- `service_allowlist` va `tx_devmap` cap nhat qua snapshot khong can restart Agent hay XDP program.
- Prometheus scrape duoc redirect success, redirect error, neighbor unresolved va neighbor resolution status.
- E2E namespace/VETH test chung minh backend chi nhan traffic allowlisted.

## Kiem chung

- Packet fixture cho allowed TCP/UDP/ICMP service tra `XDP_REDIRECT` va khong di theo diagnostic/fallback return path.
- Negative tests cho port khong cho phep, protocol khong cho phep va dst IP khong thuoc service.
- Test unresolved neighbor: policy bi reject hoac packet bi drop `REASON_NEIGHBOR_UNRESOLVED` theo mode da thiet ke.
- Test missing DEVMAP entry: `bpf_redirect_map(..., XDP_DROP)` fail-closed va tang redirect error metrics.
- Network namespace/VETH integration test xac nhan backend chi thay traffic da allowlist va MAC headers duoc rewrite dung.
- Prometheus scrape redirect/neighbor metrics va dashboard Phase 06 co du input hien thi.

## Truy vet PRD

- PRD-002: forwarding status, redirect counters va neighbor health tren metrics/dashboard.
- PRD-003: packet sach match allowlist duoc rewrite L2 va `XDP_REDIRECT`; target loi drop fail-closed.
- PRD-007: dashboard protected backend service registry sinh `service_allowlist` va `tx_devmap`.
- PRD-008: redirect/neighbor failure la input cho Telegram alerting.
- PRD-010: apply loi giu policy snapshot gan nhat.
- PRD-011: route/link/neighbor evidence phuc vu ISP escalation khi can.

## Ghi chu va rui ro

- MVP giu nguyen IP, khong NAT/DNAT; moi thay doi sang kernel routing/proxy la ngoai scope phase nay.
- Diagnostic/fallback return path chi duoc bat bang policy rieng, khong phai success path P1.
- Backend return path asymmetric lam troubleshooting phuc tap hon; runbook phai ghi ro.
- Neighbor/MAC sai co the redirect nham hoac drop traffic hop le; validation va alert phai uu tien fail-closed.
