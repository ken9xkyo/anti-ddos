# Phase 01 - XDP Data Plane Skeleton

## Muc tieu

Xay dung chuong trinh XDP toi thieu nhung verifier-safe: parse Ethernet/IPv4/TCP/UDP/ICMP, khai bao map contracts, dem pass/drop/redirect, xu ly malformed/fragment theo policy va load duoc bang libbpf. Phase nay tao packet path nen tang cho blacklist, service allowlist, DEVMAP redirect va rate limit.

## Pham vi

- Viet XDP C/libbpf object voi `SEC("xdp") xdp_entry`.
- Dinh nghia shared structs: `packet_meta`, action, reason, runtime config, LPM key, service key/value, rule/rate/counter/event records.
- Khai bao maps dung LLD: whitelist/blacklist LPM, service allowlist A/B, `tx_devmap`, rate state, rule config, per-CPU counters, ringbuf, runtime config.
- Parser support IPv4 trong MVP; IPv6 chi reserve type/schema, chua enforce.
- Chua implement Agent full lifecycle; load/verifier test co the dung harness/toy loader.

## Cong viec

| ID | Cong viec | Muc dich | Ket qua ban giao | Phu thuoc |
|---|---|---|---|---|
| P01-T01 | Tao source layout cho data plane | Tach ro kernel eBPF code va shared headers | Thu muc data plane, shared headers, build target XDP object | Phase 00 |
| P01-T02 | Dinh nghia enum action/reason/protocol | Dam bao counters/events thong nhat voi API sau nay | Header co `ACTION_*`, `REASON_*`, `L4_*` theo LLD | P01-T01 |
| P01-T03 | Dinh nghia `packet_meta` zero-initialized | Tranh verifier loi uninitialized stack | Struct compact co src/dst, ports, proto, flags, action, reason | P01-T02 |
| P01-T04 | Khai bao maps voi max entries mac dinh | Co contract kernel/userspace ro rang | Map definitions cho runtime, LPM, service, `tx_devmap`, rules, rate, counters, events | P01-T02 |
| P01-T05 | Implement Ethernet va IPv4 parser bounds-check | Doc header an toan truoc `data_end` | Function parse L2/L3 tra ok/malformed/fragment | P01-T03 |
| P01-T06 | Implement TCP/UDP/ICMP parser bounds-check | Lay dst port, src port, SYN flags an toan | Function parse L4, handle fragments/unknown protocol | P01-T05 |
| P01-T07 | Implement malformed va fragment default drop | Fail-closed khi khong du header match service | Logic `REASON_MALFORMED`, `REASON_FRAGMENT`, counter va `XDP_DROP` | P01-T06 |
| P01-T08 | Implement counter update per-CPU | Giam contention tren hot path | Helper count packets/bytes theo reason/action/proto/service/rule | P01-T04 |
| P01-T09 | Implement sampled ringbuf event stub | Dat nen cho sampled security events | `maybe_sample` co ringbuf reserve/submit va dropped-event counter | P01-T08 |
| P01-T10 | Add safe runtime-config missing behavior | Tranh chay voi policy khong hop le | Thieu `runtime_config` thi count `REASON_MAP_ERROR` va `XDP_DROP` | P01-T08 |
| P01-T11 | Build va verifier log gate | Bat loi verifier som | Build command, verbose verifier output, xlated dump neu can | P01-T10 |
| P01-T12 | Packet unit tests bang fixture | Chong regression parser | Tests malformed Ethernet/IP, TCP/UDP/ICMP, fragments, unknown protocol | P01-T11 |

## Tieu chi chap nhan

- XDP object build duoc bang clang target BPF va load duoc trong lab.
- Moi packet pointer access deu co bounds check truoc khi doc.
- Tat ca stack structs duoc zero-init; khong co verifier loi uninitialized stack.
- Neu `runtime_config` thieu, XDP fail-closed bang `XDP_DROP` voi counter `REASON_MAP_ERROR`.
- Malformed va fragment packet bi drop mac dinh va tang counter rieng.
- Ringbuf failure chi tang dropped-event counter, khong thay doi packet decision.

## Kiem chung

- Build XDP object voi debug symbols va BTF.
- Load object voi verbose verifier log; khong co `invalid mem access`, `R0 !read_ok`, `unreachable insn`.
- Replay fixture malformed va valid packets qua XDP test harness hoac network namespace.
- Inspect maps bang `bpftool map` de xac nhan type va max entries dung contract.
- Inspect program bang `bpftool prog dump xlated` neu can de xac nhan khong co loop khong bounded.

## Truy vet PRD

- PRD-002: tao counters va ringbuf lam nguon metrics/events.
- PRD-003: XDP/eBPF packet filtering, malformed handling, verifier-safe data plane.
- PRD-007: dat nen `service_allowlist` va `tx_devmap` maps cho forwarding policy.
- PRD-010: fail-safe khi runtime config/policy khong hop le.

## Ghi chu va rui ro

- Khong dua logic phuc tap vao XDP skeleton neu lam tang rui ro verifier; rate limit va feed policy nam o phase sau.
- LPM trie va per-CPU maps can uoc luong memory truoc khi load capacity lon.
- Fragment handling giu ro: MVP drop default, khong reassembly.
- Top-source exact accounting khong nam trong XDP hot path; dung sampled events va counters de tranh cardinality/memory cao.

