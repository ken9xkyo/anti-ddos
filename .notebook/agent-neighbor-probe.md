# Agent Neighbor Probe
> Forwarding resolver asks kernel to resolve ARP before fail-closed apply

Entry: `internal/agent/forwarding_resolver.go:NetlinkForwardingResolver.ResolveService()`

Flow: unresolved service snapshot -> `policy_apply.go:resolvePolicySnapshotServices()` -> resolver
- Route lookup chooses gateway, or backend IP for directly connected route
- Resolver checks neighbor cache first; resolved entries avoid probe
- Missing/failed/incomplete neighbor -> `probeNeighbor()` sends netlink `NeighSet` with `NTF_USE`, `NUD_NONE`
- Resolver polls briefly for non-zero 6-byte MAC in accepted NUD states
- If still unresolved, apply fails in `resolve_forwarding`; active slot and last-valid stay unchanged

Context: `PolicyApplyOptions.Context`
- Control polling passes request context; bootstrap defaults to background context
- Cancellation stops probe polling before map population

Updated: 2026-06-02
