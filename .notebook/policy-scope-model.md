# Policy Scope Model
> Admin-global, user-global, and service policy scopes

Entry: `internal/control/policy_scope.go`

Scopes:
- `admin_global` - admin-created; applies to all users; user views see read-only rows
- `user_global` - user-created; applies to all services owned by that user
- `service` - user-created; applies to one user-owned service

Policy families:
- Whitelist: `internal/control/policy_store.go`, `internal/control/snapshot.go`
- Rules: `internal/control/policy_store.go`, `internal/control/snapshot.go`
- Manual blacklist: `internal/control/policy_store.go`, `internal/control/snapshot.go`
- UDP source-port blocks: `internal/control/policy_store.go`, `internal/control/snapshot.go`

Owner:
- Create ignores client owner and stores actor user ID/name
- Update preserves existing owner
- Admin-global owner is the admin creator, but normal admins can manage all admin-global rows

Effective reads:
- Normal admin -> admin-global rows
- User -> admin-global read-only + own user-global/service rows
- Admin view-user -> viewed user's effective union, read-only

Dataplane:
- Service-scoped blacklist -> `blacklist_service_v4_a/b`
- Service-scoped UDP source-port blocks -> `udp_src_port_service_blocks_a/b`
- XDP checks service-scoped blacklist/UDP before global maps

Dashboard:
- Policy tabs use `scope_type` selectors: `web/dashboard/src/views/*AdminView.tsx`
- Services/Snapshots/Telegram remain user-owned mutation only

Updated: 2026-06-12
