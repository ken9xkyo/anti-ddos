# Phase 00 Benchmark Matrix

Date: 2026-05-28

This matrix defines benchmark inputs for later phases. No XDP program was attached and no benchmark was executed in Phase 0.

## Benchmark Principles

- Native XDP is the target mode for performance gates.
- Generic XDP is acceptable only for functional fallback checks and must be labeled as a performance limitation.
- DEVMAP redirect must be benchmarked with filtering, not only as a drop-only test.
- Backend service allowlist and neighbor/MAC resolution must be explicit before redirect tests.
- All tests must report interface, driver, firmware, queue count, CPU count, XDP mode, packet size mix, pps, bps, drops, redirects, CPU utilization, and error counters.

## Current Lab Inputs

| Input | Current value |
|---|---|
| Host | `cyberrange02` |
| Kernel | `6.8.0-106-generic` |
| BTF | `/sys/kernel/btf/vmlinux` present |
| 10G candidates | `enp94s0f0`, `enp134s0f1` |
| Driver | `ixgbe` |
| Queue count | Combined `63` on both 10G candidates |
| CPU count | `96` logical processors |
| Preferred default route | `enp134s0f1` via `118.107.78.1`, metric `100` |
| Secondary default route | `enp94s0f0` via `118.107.64.249`, metric `200` |
| Backend inventory | TODO from Network/SRE |

## Matrix

| ID | Scenario | Traffic input | Expected XDP path | Required metrics | Pass criteria | Dependencies |
|---|---|---|---|---|---|---|
| BM-01 | Drop-only malformed packets | Truncated Ethernet/IP/TCP/UDP frames and invalid headers | Bounds-checked parse, `XDP_DROP`, reason `malformed` | pps, bps, drop reason counters, verifier logs, CPU | No verifier errors; no kernel stack crash; malformed counter increases; backend receives zero packets | Phase 01 parser and counters |
| BM-02 | Fragment/default drop | IPv4 fragments and packets without enough L4 header to match service | `XDP_DROP`, reason `fragment` or `malformed` | fragment counters, sampled events, CPU | Fragmented traffic is dropped by default and counted separately | Phase 01 parser and runtime config |
| BM-03 | Service allowlist miss | Valid TCP/UDP/ICMP to unregistered backend IP/protocol/port | Service lookup miss, `XDP_DROP`, reason `not_allowed_service` | not-allowed-service counter by proto/interface, backend receive count | Backend receives zero packets; miss counter increases | Phase 04 service allowlist |
| BM-04 | Blacklist hit | Source IP/CIDR present in blacklist LPM sends valid traffic to allowlisted service | Blacklist lookup, `XDP_DROP`, reason `blacklist` unless whitelisted | blacklist counters, rule id, sampled events | Blacklisted traffic is dropped; whitelist precedence cases tested separately | Phase 03 map sync, Phase 08 feed/manual blacklist input |
| BM-05 | UDP flood | High-rate UDP to protected service and to non-allowlisted ports | Allowlisted traffic evaluated by rate policy; non-allowlisted traffic dropped | pps, bps, drops, redirects, not-allowed-service, rate-limit counters | No traffic outside allowlist reaches backend; rate/drop behavior matches configured rule | Phase 04 and Phase 07 |
| BM-06 | TCP SYN flood | High-rate SYN packets to protected TCP service | CPS approximation and rate/drop decision | cps, pps, rule counters, SYN-specific evidence | SYN flood is detected/rate-limited/dropped according to rule mode; backend receives only in-policy traffic | Phase 07 |
| BM-07 | ICMP flood | High-rate ICMP to protected and unprotected destinations | Service allowlist and rate policy for ICMP | ICMP pps/bps, drop/redirect counters | Only explicitly allowlisted ICMP policy can redirect; all other ICMP is dropped | Phase 04 and Phase 07 |
| BM-08 | Neighbor unresolved | Service policy target with unresolved next-hop/backend MAC | Fail-closed before redirect, reason `neighbor_unresolved` | neighbor status, unresolved counter, alert input | Packet is dropped; no redirect to unknown MAC; metric/alert input emitted | Phase 04 resolver and metrics |
| BM-09 | Missing DEVMAP target | Service value references absent or invalid DEVMAP key | `bpf_redirect_map(..., XDP_DROP)` fallback path and redirect error accounting | redirect errors, devmap entries, backend receive count | Redirect failure is counted and backend receives no packet via wrong path | Phase 04 |
| BM-10 | Full DEVMAP redirect path | Valid traffic to allowlisted backend service with resolved MAC and output interface | L2 source/destination MAC rewrite plus `XDP_REDIRECT` | redirected packets/bytes, backend receive count, MAC headers, pps, bps, CPU | Backend receives only allowlisted traffic; MAC rewrite is correct; no service miss leaks | Phase 04 |
| BM-11 | Mixed attack and clean traffic | Blend of clean allowlisted traffic, blacklist hits, service misses, UDP/SYN/ICMP flood | Full policy decision order | all action/reason counters, top sources, alert inputs | Clean traffic stays within accepted loss/latency target; attack classes are counted by reason | Phase 07 and Phase 10 |

## Throughput Gates

| Gate | Required evidence |
|---|---|
| Functional gate | XDP object loads, verifier passes, packet fixtures match expected decision and counters. |
| 10 Gbps MVP gate | Sustained 10 Gbps on target hardware for representative drop path and DEVMAP redirect path, with CPU and error counters recorded. |
| 40 Gbps report | Benchmark report on suitable NIC/hardware before any 40 Gbps SLA commitment. This is a report requirement, not an MVP pass/fail gate. |

## Required Report Fields

Each executed benchmark report must include:

- Host, kernel, BTF status, XDP mode, NIC model, driver, firmware, queue/RSS count, CPU count.
- WAN/input interface and backend/output interface.
- Backend service inventory used for the test.
- Traffic generator, packet size distribution, protocol mix, duration, warmup, and offered load.
- Observed pps, bps, drops, redirects, redirect errors, neighbor unresolved, not-allowed-service, blacklist, malformed, fragment, and rate-limit counters.
- CPU utilization, softirq pressure, packet loss at generator/backend, and link saturation notes.
- Whether generic fallback was used; if so, mark the result as functional-only.

