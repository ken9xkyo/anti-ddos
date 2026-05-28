# Forwarding Failure Behavior

Phase 04 forwarding is fail-closed. A packet is redirected only after it matches `service_allowlist`, has resolved neighbor metadata, receives L2 source/destination MAC rewrite, and `bpf_redirect_map(&tx_devmap, key, XDP_DROP)` returns `XDP_REDIRECT`.

## Failure Cases

| Failure | Behavior | Operator check |
|---|---|---|
| Service not allowlisted | XDP drops with `REASON_NOT_ALLOWED_SERVICE`; backend must receive nothing. | Check `anti_ddos_not_allowed_service_total` by protocol and confirm service registry/snapshot input. |
| Output interface missing or down | Agent resolver rejects the service before policy publish; active snapshot stays unchanged. | Check Agent apply error, link state, ifindex, and intended WAN/LAN/output role. |
| Neighbor unresolved or MAC missing | Resolver rejects publish; if stale/corrupt map value reaches XDP, packet drops with `REASON_NEIGHBOR_UNRESOLVED`. | Check `ip neigh`, backend/next-hop reachability, and `anti_ddos_neighbor_resolution_status`. |
| Missing or wrong DEVMAP target | Redirect helper falls back to `XDP_DROP`; XDP increments `REASON_REDIRECT_ERROR`. | Check `tx_devmap` entry, output ifindex, map capacity, and `anti_ddos_redirect_errors_total`. |
| Backend return path asymmetric | Forward packet keeps original source/destination IP; return traffic may bypass the gateway. | Confirm backend routing and upstream ACLs; do not troubleshoot this as NAT failure. |

## Rollback

- Do not attach to real NICs until interface roles are confirmed.
- If a new snapshot fails validation or map population, Agent keeps the previous active slot and last-valid policy.
- If redirect errors rise after a snapshot apply, roll back to the prior policy version in Phase 05 Control Plane once rollback API exists; until then, restart with the previous last-valid snapshot.

## VETH Lab Note

`make phase4-veth-test` attaches the production XDP program only to a temporary WAN veth. The backend peer uses a minimal `xdp_pass` program so native XDP redirect through veth is observable in the namespace lab. This helper is not part of the production forwarding path.
