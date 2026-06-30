# Allocated CIDR Management Tasks

**Design**: `.specs/features/allocated-cidr-management/design.md`
**Status**: Draft

---

## Execution Plan

### Phase 1: Database Foundation (Sequential)
We set up the data models, tables, and run migrations.

```
T1 ──→ T2
```

### Phase 2: Core Storage & API logic (Sequential)
Database integration tests in Go share a single PostgreSQL database instance and are not parallel-safe, so these must run sequentially.

```
T2 ──→ T3 ──→ T4 ──→ T5 ──→ T6
```

### Phase 3: Frontend Integration (Parallelizable)
Once the API is fully verified, we implement the frontend interfaces. The Vitest UI tests run independently in parallel-safe worker threads.

```
Phase 3 (Parallel):
  T6 complete, then:
    ├── T7 (Types & API Client) [P]
    └── T7 complete, then:
          ├── T8 (Admin UI Drawer) [P]
          └── T9 (Service Forms) [P]
```

---

## Task Breakdown

### T1: Create Allocated CIDR Table Migration
- **What**: Add Database Migration Version 8 to create `allocated_cidrs` table and auto-allocate existing service CIDRs to owners.
- **Where**: [migrations.go](file:///root/anti-ddos/internal/control/migrations.go)
- **Depends on**: None
- **Reuses**: existing database migration array syntax.
- **Requirement**: CIDR-ALLOC-05
- **Tools**:
  - MCP: `filesystem`
  - Skill: `golang-pro`
- **Done when**:
  - [ ] Migration Version 8 is added to the migration slice in Go.
  - [ ] Running integration tests applies the migration cleanly.
  - [ ] Database contains the `allocated_cidrs` table with unique constraint and GIST indices.
  - [ ] Pre-existing services have their CIDR allocated automatically to their owners.
- **Tests**: Go Database Integration
- **Gate**: Full (`make test-all`)

**Verify**:
```bash
make integration-test
```
Verify that all migration logs report success and that the database schema compiles.

---

### T2: Define AllocatedCIDR Go Structs
- **What**: Declare the type structures for `AllocatedCIDR` and input formats in `types.go`.
- **Where**: [types.go](file:///root/anti-ddos/internal/control/types.go)
- **Depends on**: T1
- **Reuses**: None
- **Requirement**: CIDR-ALLOC-01
- **Tools**:
  - MCP: `filesystem`
- **Done when**:
  - [ ] Struct `AllocatedCIDR` is defined with json mappings for JSON Marshalling/Unmarshalling.
  - [ ] Backend Go code compiles cleanly without syntax errors.
- **Tests**: none
- **Gate**: Build (`make build`)

**Verify**:
```bash
go build ./cmd/control-api/...
```

---

### T3: Implement Storage Layer CRUD for Allocated CIDRs
- **What**: Add database CRUD methods `ListUserAllocatedCIDRs`, `CreateAllocatedCIDR` (checks overlaps with other users), and `DeleteAllocatedCIDR` to policy storage.
- **Where**: [policy_store.go](file:///root/anti-ddos/internal/control/policy_store.go)
- **Depends on**: T2
- **Reuses**: Transaction wrappers (`beginActorOwnerTx`, `beginUnscopedTx`) and audit trail logger (`insertAudit`).
- **Requirement**: CIDR-ALLOC-01, CIDR-ALLOC-02
- **Tools**:
  - MCP: `filesystem`
  - Skill: `golang-pro`
- **Done when**:
  - [ ] Storage methods are implemented.
  - [ ] `CreateAllocatedCIDR` rejects overlapping allocations for other users.
  - [ ] Unit/Integration tests are written in Go covering lists, overlap conflicts, and creation.
- **Tests**: Go Database Integration
- **Gate**: Full (`make test-all`)

**Verify**:
```bash
go test -run TestAllocatedCIDRStorage ./internal/control/...
```

---

### T4: Enforce Service Configuration Containment Validation
- **What**: Create helper method `ValidateServiceCIDR` and call it within `CreateService` and `UpdateService` transactions to enforce backend CIDR containment.
- **Where**: [policy_store.go](file:///root/anti-ddos/internal/control/policy_store.go)
- **Depends on**: T3
- **Reuses**: SQL containment operator `<<=`.
- **Requirement**: CIDR-ALLOC-03
- **Tools**:
  - MCP: `filesystem`
  - Skill: `golang-pro`
- **Done when**:
  - [ ] `ValidateServiceCIDR` checks that service CIDR is contained inside owner's allocations.
  - [ ] Service creation/update is rejected with bad request error if containment check fails.
  - [ ] Go tests cover valid, invalid, and admin configurations.
- **Tests**: Go Database Integration
- **Gate**: Full (`make test-all`)

**Verify**:
```bash
go test -run TestServiceCIDRValidation ./internal/control/...
```

---

### T5: Block Allocation Deletion in Use
- **What**: Update `DeleteAllocatedCIDR` to check if active services reside within the target allocation and block deletion if true.
- **Where**: [policy_store.go](file:///root/anti-ddos/internal/control/policy_store.go)
- **Depends on**: T4
- **Reuses**: None
- **Requirement**: CIDR-ALLOC-02
- **Tools**:
  - MCP: `filesystem`
  - Skill: `golang-pro`
- **Done when**:
  - [ ] Deletion of allocation is blocked when containing active services.
  - [ ] Database returns error listing blocking services.
  - [ ] Integration tests verify blocked and successful deletions.
- **Tests**: Go Database Integration
- **Gate**: Full (`make test-all`)

**Verify**:
```bash
go test -run TestDeleteAllocationBlocked ./internal/control/...
```

---

### T6: Implement API Endpoints & Routes
- **What**: Expose endpoints `GET /v1/users/{userId}/allocated-cidrs`, `POST /v1/users/{userId}/allocated-cidrs`, `DELETE /v1/users/{userId}/allocated-cidrs/{id}`, and `GET /v1/me/allocated-cidrs`.
- **Where**: [server.go](file:///root/anti-ddos/internal/control/server.go)
- **Depends on**: T5
- **Reuses**: Router handlers and role check functions.
- **Requirement**: CIDR-ALLOC-01, CIDR-ALLOC-04
- **Tools**:
  - MCP: `filesystem`
- **Done when**:
  - [ ] Routing endpoints are registered in server initialization.
  - [ ] Admins are permitted to perform user allocation CRUD, non-admins receive 403.
  - [ ] Standard user can list their own allocations.
  - [ ] HTTP API integration tests verify these requirements.
- **Tests**: Go Database Integration
- **Gate**: Full (`make test-all`)

**Verify**:
```bash
go test -run TestAllocatedCIDRAPI ./internal/control/...
```

---

### T7: Add Frontend Types and API Methods [P]
- **What**: Add `AllocatedCIDR` interface to dashboard UI types and API wrappers.
- **Where**: `web/dashboard/src/types.ts` & `web/dashboard/src/api.ts`
- **Depends on**: T6
- **Reuses**: `api.request` patterns.
- **Requirement**: CIDR-ALLOC-01, CIDR-ALLOC-04
- **Tools**:
  - MCP: `filesystem`
- **Done when**:
  - [ ] TypeScript types are compiled.
  - [ ] Client requests compile and pass vitest unit checks.
- **Tests**: Vitest React Testing
- **Gate**: Quick (`make test`)

**Verify**:
```bash
npm --prefix web/dashboard run build
```

---

### T8: Implement Admin Drawer in AccessView [P]
- **What**: Create visual interface (button in accounts grid, drawer list, add form, delete trigger) to manage user allocations.
- **Where**: `web/dashboard/src/views/AccessView.tsx`
- **Depends on**: T7
- **Reuses**: `AdminDrawer` and styling guidelines.
- **Requirement**: CIDR-ALLOC-01
- **Tools**:
  - MCP: `filesystem`
- **Done when**:
  - [ ] Accounts grid shows a "CIDRs" action button for user accounts.
  - [ ] Drawer loads and displays active user allocations, permits creating and deleting with confirmation.
- **Tests**: Vitest React Testing
- **Gate**: Quick (`make test`)

**Verify**:
```bash
npm --prefix web/dashboard test -- --run
```

---

### T9: Add Allocation Selection and Guide in ServicesView [P]
- **What**: Update service form to retrieve active user allocations, display them, and perform frontend input validation before submit.
- **Where**: `web/dashboard/src/views/ServicesView.tsx`
- **Depends on**: T7
- **Reuses**: existing select inputs.
- **Requirement**: CIDR-ALLOC-04
- **Tools**:
  - MCP: `filesystem`
- **Done when**:
  - [ ] Service creation UI pulls allocations for the active target owner.
  - [ ] Active allocations are shown as guidance text.
  - [ ] Input validates format and displays containment warnings.
- **Tests**: Vitest React Testing
- **Gate**: Quick (`make test`)

**Verify**:
```bash
npm --prefix web/dashboard test -- --run
```

---

## Parallel Execution Map

```

Phase 1 (Sequential):
  T1 ──→ T2

Phase 2 (Sequential):
  T2 ──→ T3 ──→ T4 ──→ T5 ──→ T6

Phase 3 (Parallel):
  T6 complete, then:
    T7 complete, then:
      ├── T8 [P] (Admin Access UI Drawer)
      └── T9 [P] (Service Config Form Helper)

```

---

## Task Granularity Check

| Task | Scope | Status |
| --- | --- | --- |
| T1: DB migration & populating seeds | Schema migration | ✅ Granular |
| T2: Define structures | Type declaration | ✅ Granular |
| T3: Implement Storage Logic | DB query layer | ✅ Granular |
| T4: Validation integration | Service handler check | ✅ Granular |
| T5: Blocking deletion logic | Delete handler rule | ✅ Granular |
| T6: API Endpoints | REST routes | ✅ Granular |
| T7: Frontend Client methods | API wrapper | ✅ Granular |
| T8: UI drawer | Layout/actions component | ✅ Granular |
| T9: UI service guides | Form enhancement | ✅ Granular |

---

## Diagram-Definition Cross-Check

| Task | Depends On (task body) | Diagram Shows | Status |
| --- | --- | --- | --- |
| T1 | None | None | ✅ Match |
| T2 | T1 | T1 -> T2 | ✅ Match |
| T3 | T2 | T2 -> T3 | ✅ Match |
| T4 | T3 | T3 -> T4 | ✅ Match |
| T5 | T4 | T4 -> T5 | ✅ Match |
| T6 | T5 | T5 -> T6 | ✅ Match |
| T7 | T6 | T6 -> T7 | ✅ Match |
| T8 | T7 | T7 -> T8 | ✅ Match |
| T9 | T7 | T7 -> T9 | ✅ Match |

---

## Test Co-location Validation

| Task | Code Layer Created/Modified | Matrix Requires | Task Says | Status |
| --- | --- | --- | --- | --- |
| T1 | DB Schema / Migration | Go Database Integration | Go Database Integration | ✅ OK |
| T2 | Go Types | none | none | ✅ OK |
| T3 | Go Storage | Go Database Integration | Go Database Integration | ✅ OK |
| T4 | Go Validation | Go Database Integration | Go Database Integration | ✅ OK |
| T5 | Go Storage / Delete | Go Database Integration | Go Database Integration | ✅ OK |
| T6 | Go HTTP Handlers | Go Database Integration | Go Database Integration | ✅ OK |
| T7 | TypeScript API client | Vitest React Testing | Vitest React Testing | ✅ OK |
| T8 | React Component | Vitest React Testing | Vitest React Testing | ✅ OK |
| T9 | React Component | Vitest React Testing | Vitest React Testing | ✅ OK |

---

## Success Criteria

- [ ] Existing backend services have their CIDRs automatically registered to their owners.
- [ ] Database contains disjoint allocated CIDRs per user.
- [ ] Control Plane rejects service modifications out of owner allocations.
- [ ] Deletion of allocated CIDRs is prevented when active services reside inside.
- [ ] UI visual panels allow admins to manage user allocations and guide users during service creation.
