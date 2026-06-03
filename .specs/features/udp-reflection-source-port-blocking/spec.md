# UDP Reflection Source-Port Blocking

## Summary

UDP Reflection Source-Port Blocking adds a global, admin-managed UDP source-port blocklist to the protected-service XDP path. Whitelist precedence remains first; non-whitelisted UDP packets that match an enabled source-port block are dropped with `REASON_UDP_AMP_SOURCE_PORT = 11` before normal forwarding and rule processing.

## Requirements

- URSPB-001: `udp_source_port_blocks` stores unique UDP source ports with `ebpf_id`, label, reason, owner, enabled state, expiry and timestamps.
- URSPB-002: Migration seeds disabled entries for common reflection/amplification ports: `0`, `19`, `53`, `69`, `111`, `123`, `137`, `161`, `162`, `389`, `427`, `520`, `1194`, `1900`, `3702`, `5353`, `10001`, `11211`, `20800`, `27005`.
- URSPB-003: Viewer can read and filter entries; Operator/Admin can create, update and soft-disable with an audit reason.
- URSPB-004: Effective snapshots include only enabled, non-expired entries in `udp_source_port_blocks` and include feature flag `udp_src_port_block` only when active entries exist.
- URSPB-005: Agent validates capacity, duplicates and expiry; old snapshots without `udp_source_port_blocks` continue to apply.
- URSPB-006: BPF exposes A/B maps `udp_src_port_blocks_a/b` keyed by UDP source port as `u32`, with max entries `4096`.
- URSPB-007: XDP order is service match, whitelist applicability, blacklist drop precedence, UDP source-port block drop for non-whitelisted UDP, then forwarding/rules as before.
- URSPB-008: Dashboard exposes Configuration > UDP Ports with filters, create/edit drawer, soft-disable confirmation and Viewer read-only behavior.
- URSPB-009: Rollout deploys the new BPF object and Agent before enabling any block entries beyond the disabled seeds.

## Interfaces

- `GET /v1/udp-source-port-blocks?q=&state=&expiry=`
- `POST /v1/udp-source-port-blocks`
- `PATCH /v1/udp-source-port-blocks/{id}`
- `DELETE /v1/udp-source-port-blocks/{id}`

`DELETE` is a soft-disable and requires `X-Audit-Reason`.

## Verification

- `make bpf-build`
- `make bpf-test`
- `go test ./internal/agent ./internal/control`
- `go test ./...`
- `npm --prefix web/dashboard test -- --run`
- `npm --prefix web/dashboard run build`

No real NIC attach is part of verification; packet coverage uses fixture/prog-test or VETH-only lab gates.
