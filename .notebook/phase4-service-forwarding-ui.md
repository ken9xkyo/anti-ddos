# Phase 4 Service Forwarding UI
> Add/Edit service flow for output interface metadata

Entry: `web/dashboard/src/App.tsx:ServicesView()`
Flow: `ServicesView()` -> `ApiClient.createService()` -> `internal/control/policy_store.go:CreateService()` -> `internal/control/snapshot.go:makePolicyService()`

Interface source: `internal/agent/control_client.go:hostInterfaces()` -> heartbeat/register `interfaces` -> `internal/control/agent_store.go:replaceAgentInterfaces()` -> dashboard `agents[].interfaces`

Gotcha: Control API runs in compose container and cannot netlink-lookup host NIC names such as `enp134s0f1`.
- UI defaults new service disabled
- Selecting an Agent-reported interface fills `resolved_ifindex` and `resolved_src_mac`
- Enabling a service requires `resolved_ifindex` and `resolved_src_mac`; `resolved_next_hop_mac` is not a manual dashboard field
- `snapshot.go:makePolicyService()` falls back to the forwarding resolver when next-hop MAC is missing, while still requiring complete metadata for legacy pre-resolved next-hop inputs

Updated: 2026-05-29
