# Project State

Last updated: 2026-05-28

Current work: Phase 02 - Agent Lifecycle completed; Phase 03 - Policy Snapshot Map Sync is next.

## Decisions

- Current host `cyberrange02` is the Phase 0 lab target.
- Backend services are not inferred from route or neighbor entries. The official service list must come from Network/SRE.
- Phase 0 creates project memory and lab readiness documentation only. It does not attach XDP, create runtime source directories, or implement Agent/API/dashboard code.
- Runtime source tree conventions are documented in Phase 0, but actual runtime directories start in Phase 01 or later.
- Secrets are represented as references only; raw DB DSNs, Telegram tokens, and feed API keys must not appear in config, logs, audit entries, or docs.
- Phase 01 valid IPv4 traffic without a service policy fails closed with `XDP_DROP` and `REASON_NOT_ALLOWED_SERVICE`.
- Phase 01 verification is build/load/verifier/`BPF_PROG_TEST_RUN` only; no XDP program was attached to a real or veth interface.
- Phase 02 Agent is implemented in Go with `github.com/cilium/ebpf v0.17.3` and `github.com/prometheus/client_golang v1.22.0` to stay compatible with Go `1.22.2`.
- Phase 02 verification attaches XDP only to temporary VETH/netns lab interfaces; no production or lab NIC attach was performed.
- BPF maps/programs/links are pinned in bpffs; JSON program metadata is stored beside the last-valid snapshot because bpffs does not support regular JSON files.

## Phase Progress

| Phase | Status | Evidence |
|---|---|---|
| 00 - Foundation Lab Readiness | Ready for Phase 01 with gaps carried | Lab readiness docs exist; backend inventory, interface roles, PostgreSQL, Prometheus, native attach and benchmarks remain open. |
| 01 - XDP Data Plane Skeleton | Done | `make phase1-verify` PASS on 2026-05-28; report `reports/phase-01-xdp-data-plane-skeleton.md`; verifier log `build/bpf/verifier.log`. |
| 02 - Agent Lifecycle | Done | `make phase2-verify` PASS on 2026-05-28; report `reports/phase-02-agent-lifecycle.md`; VETH lifecycle test attached XDP to a temporary veth, scraped `/metrics`, verified pinned link restart behavior, and cleaned up with safe detach. |

## Current Host Facts

- OS: Ubuntu 24.04.3 LTS (`noble`).
- Kernel: `6.8.0-106-generic` on `x86_64`.
- BTF: `/sys/kernel/btf/vmlinux` exists.
- CPU: `96` logical processors.
- eBPF toolchain present: `clang 18.1.3`, `llvm-strip`, `bpftool v7.4.0`, `libbpf v1.3.0` as observed through `pkg-config`.
- Go present: `go1.22.2 linux/amd64`.
- Node toolchain present: Node `v18.19.1`, npm `9.2.0`.
- Runtime gaps: `psql` and `prometheus` commands are missing.
- 10G NIC candidates: `enp94s0f0` and `enp134s0f1`, both `ixgbe`, link `10000Mb/s`, combined queues `63`.
- Default route priority currently favors `enp134s0f1` with metric `100`; `enp94s0f0` is secondary with metric `200`.

## Open Blockers

- Protected backend service inventory is missing: service name, backend IP/CIDR, protocol, allowed ports, owner, criticality, output interface, and return path.
- WAN/LAN roles are not formally assigned for `enp94s0f0` and `enp134s0f1`.
- PostgreSQL and Prometheus binaries are not installed on the lab target.
- Native XDP attach capability on real NICs has not been tested; no XDP program should be attached to `enp94s0f0`, `enp134s0f1`, or any production/lab NIC without explicit execution approval and confirmed interface roles.
- 10 Gbps and 40 Gbps benchmark results are not available yet.

## Next Actions

- Start Phase 03 Policy Snapshot Map Sync using the Phase 02 Agent loader, pinned maps and last-valid snapshot baseline.
- Network/SRE confirms protected backend service inventory and final WAN/LAN/output interface roles before any redirect policy work.
- Install PostgreSQL client/server components and Prometheus according to the deployment decision for the lab.
- Keep real NIC XDP attach disabled until explicit execution approval and interface roles are confirmed; VETH-only lifecycle testing is available through `make phase2-veth-test`.
- Run benchmark matrix only after Agent attach flow and service redirect path exist.
