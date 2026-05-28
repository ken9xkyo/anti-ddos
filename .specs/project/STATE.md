# Project State

Last updated: 2026-05-28

Current work: Phase 08 - Threat Feed Sync completed; Phase 09 - Telegram ISP Runbook is next.

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
- Phase 04 forwarding resolution uses `github.com/vishvananda/netlink v1.3.1` for route/link/neighbor discovery.
- Phase 04 VETH DEVMAP lab attaches a minimal `xdp_pass` program to the backend veth peer so native XDP redirect frames are accepted by the peer-side veth; this is lab support, not a production datapath change.
- Phase 05 Control Plane is implemented in Go with `github.com/jackc/pgx/v5 v5.7.2` for PostgreSQL access and `golang.org/x/crypto/bcrypt` for local password hashing.
- Phase 05 Agent-Control sync is optional and only activates when `ANTI_DDOS_CONTROL_URL` is set; otherwise the existing local/bootstrap snapshot behavior remains unchanged.
- Phase 05 active service snapshots support IPv4 host destinations only because the current XDP `service_key` matches exact destination IPv4, protocol and port.
- Phase 06 dashboard frontend is a React/Vite TypeScript app under `web/dashboard` and uses Control API auth/RBAC.
- Phase 06 dashboard timeseries flow goes through Control API Prometheus proxy/status using `ANTI_DDOS_PROMETHEUS_URL`; when unset, UI reports Prometheus as unconfigured rather than failing.
- Phase 06 sampled security events are best-effort from Agent ringbuf to Control API; raw source IP/CIDR stays in PostgreSQL `security_events`, not Prometheus labels.
- Phase 06 verification keeps real NIC XDP attach disabled and uses PostgreSQL Docker container plus UI unit/build gates.
- Phase 07 XDP applies at most one selected rule per service: highest-priority enabled, unexpired service-specific rule first, otherwise the highest-priority global rule.
- Phase 07 rate limiting uses token buckets keyed by configured rule dimension (`source`, `service`, or `source_service`), defaults manual and auto rules to `source_service`, and counts CPS from TCP SYN packets without ACK only.
- Phase 07 auto-enforce is conservative by default: minimum confidence `0.90`, minimum score `85`, at least two evidence signals, default action `rate_limit`, TTL `15m` clamped to `5m..60m`, and low-confidence baselines are observe-only.
- Phase 07 scheduler runs in-process with `control-api serve`; anomaly evaluation ticks every `10s`, TTL expiry ticks every `30s`, and missing Prometheus configuration is reported/skipped cleanly.
- Phase 07 verification keeps real NIC XDP attach disabled and uses packet fixtures, a temporary PostgreSQL database, and temporary VETH namespaces only.
- Phase 08 Threat Feed Sync stays entirely in the Control Plane and reuses existing `PolicySnapshot.BlacklistV4`; no eBPF ABI or XDP C changes are required for feed enforcement.
- Phase 08 feed credentials are references only. `env://VAR_NAME` resolves from that exact environment variable; `secret://anti-ddos/name` resolves to lab env `ANTI_DDOS_SECRET_NAME`; missing values fail the run without logging plaintext.
- Phase 08 Team Cymru HTTP feeds are IPv4-only and enforce a minimum 4-hour interval; IPv6 remains rejected because active policy supports IPv4 only.
- Phase 08 feed failures record `feed_runs`/source status and keep the last valid reputation entries and policy snapshot unchanged. Telegram alert delivery for prolonged feed failures remains Phase 09.
- Phase 08 verification keeps real NIC XDP attach disabled and uses packet fixtures, a temporary PostgreSQL database, and dashboard unit/build gates only.

## Phase Progress

| Phase | Status | Evidence |
|---|---|---|
| 00 - Foundation Lab Readiness | Ready for Phase 01 with gaps carried | Lab readiness docs exist; backend inventory, interface roles, PostgreSQL, Prometheus, native attach and benchmarks remain open. |
| 01 - XDP Data Plane Skeleton | Done | `make phase1-verify` PASS on 2026-05-28; report `reports/phase-01-xdp-data-plane-skeleton.md`; verifier log `build/bpf/verifier.log`. |
| 02 - Agent Lifecycle | Done | `make phase2-verify` PASS on 2026-05-28; report `reports/phase-02-agent-lifecycle.md`; VETH lifecycle test attached XDP to a temporary veth, scraped `/metrics`, verified pinned link restart behavior, and cleaned up with safe detach. |
| 03 - Policy Snapshot Map Sync | Done | `make phase3-verify` PASS on 2026-05-28; report `reports/phase-03-policy-snapshot-map-sync.md`; policy snapshot validation, A/B map apply, devmap update, runtime flip, rollback and last-valid persistence passed. |
| 04 - DEVMAP Forwarding and Service Allowlist | Done | `make phase4-verify` PASS on 2026-05-28; report `reports/phase-04-devmap-forwarding-service-allowlist.md`; packet fixtures and VETH namespace test verified allowlisted DEVMAP redirect with MAC rewrite and fail-closed service miss. |
| 05 - Control Plane Core | Done | `make phase5-verify` PASS on 2026-05-28; report `reports/phase-05-control-plane-core.md`; Control API/Admin CLI, PostgreSQL migrations, local auth/RBAC, audit, policy CRUD, snapshot builder, rollback and Agent register/heartbeat/fetch/ack were verified. |
| 06 - Observability Dashboard | Done | `make phase6-verify` PASS on 2026-05-28; report `reports/phase-06-observability-dashboard.md`; Control/Agent metrics, sampled event ingestion/query, Prometheus-backed dashboard APIs, React/Vite dashboard, Grafana JSON and scrape config were verified. |
| 07 - Rate Limit Baseline Auto-Enforce | Done | `make phase7-verify` PASS on 2026-05-28; report `reports/phase-07-rate-limit-baseline-auto-enforce.md`; XDP token buckets, rule selection, SYN CPS counters, baseline/anomaly APIs, conservative auto-enforce, TTL expiry, rollback, VETH lab and dashboard visibility were verified. |
| 08 - Threat Feed Sync | Done | `make phase8-verify` PASS on 2026-05-28; report `reports/phase-08-threat-feed-sync.md`; feed source schema/API, parser pipeline, scheduler, safe aggregation, whitelist conflict suppression, snapshot inclusion, last-valid retention, metrics and dashboard visibility were verified. |

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

- Production protected backend service inventory is missing: service name, backend IP/CIDR, protocol, allowed ports, owner, criticality, output interface, resolved forwarding metadata and return path.
- WAN/LAN roles are not formally assigned for `enp94s0f0` and `enp134s0f1`.
- PostgreSQL and Prometheus binaries are not installed on the lab target.
- Native XDP attach capability on real NICs has not been tested; no XDP program should be attached to `enp94s0f0`, `enp134s0f1`, or any production/lab NIC without explicit execution approval and confirmed interface roles.
- 10 Gbps and 40 Gbps benchmark results are not available yet.

## Next Actions

- Start Phase 09 Telegram ISP Runbook using Phase 08 feed failure status as one alert producer input.
- Network/SRE confirms production protected backend service inventory and final WAN/LAN/output interface roles before real service policy rollout.
- Install PostgreSQL client/server components and Prometheus according to the deployment decision for the lab.
- Keep real NIC XDP attach disabled until explicit execution approval and interface roles are confirmed; VETH-only lifecycle and forwarding tests are available through `make phase2-veth-test` and `make phase4-veth-test`.
- Run benchmark matrix after production interface roles and backend service inventory are confirmed.
