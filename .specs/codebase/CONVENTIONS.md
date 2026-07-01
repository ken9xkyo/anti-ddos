# Code Conventions

## Naming Conventions

**Files:**
- Go: `snake_case.go` (e.g., `policy_snapshot.go`, `control_client.go`, `event_forwarder.go`)
- Go tests: `*_test.go` same package (white-box), collocated with source
- C/BPF: `snake_case.bpf.c` (e.g., `xdp_data_plane.bpf.c`)
- TypeScript/React: `PascalCase.tsx` for views (e.g., `ServicesView.tsx`, `FleetView.tsx`), `camelCase.ts` for utilities (e.g., `api.ts`, `format.ts`)

**Functions/Methods:**
- Go: `PascalCase` for exported, `camelCase` for unexported
- Handler methods: `handle<Resource>` or `handle<Resource>ByID` (e.g., `handleServices`, `handleServiceByID`)
- Constructor: `New<Type>` (e.g., `NewServer`, `NewStore`, `NewMetrics`)
- Config loader: `LoadConfigFromEnv()` (consistent across agent and control)
- Examples: `LoadAndAttach()`, `SignPolicySnapshot()`, `CollectDropCounters()`, `resolveOwner()`

**Variables:**
- Go: `camelCase` (e.g., `objectChecksum`, `eventSink`, `feedLocks`)
- Env vars: `ANTI_DDOS_` prefix, `UPPER_SNAKE_CASE` (e.g., `ANTI_DDOS_WAN_IFACE`, `ANTI_DDOS_DB_DSN`)
- BPF maps: `snake_case` with `_a`/`_b` suffix for A/B slots (e.g., `whitelist_v4_a`, `blacklist_v4_b`)

**Constants:**
- Go agent: unexported `camelCase` (e.g., `actionDrop`, `reasonBlacklist`, `l4TCP`)
- Go control: exported `PascalCase` (e.g., `RoleAdmin`, `ActionDrop`, `StatusActive`)
- C/BPF: `UPPER_SNAKE_CASE` enums + `ANTI_DDOS_` prefixed macros (e.g., `ACTION_DROP`, `ANTI_DDOS_MAX_RULES`)

**Types:**
- Go structs: `PascalCase` (e.g., `PolicySnapshot`, `ServiceKey`, `RuntimeConfigValue`)
- C structs: `snake_case` (e.g., `struct packet_meta`, `struct service_value`)
- BPF/Go contract types mirror each other (C `struct service_key` ↔ Go `ServiceKey`)

## Code Organization

**Import/Dependency Declaration:**
- Go: stdlib → third-party → internal packages, separated by blank lines
```go
import (
	"context"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/ken9xkyo/anti-ddos/internal/agent"
)
```

**File Structure (Go):**
- Package declaration → imports → constants → types → constructors → methods → helpers
- One major concept per file (e.g., `store.go` for Store, `server.go` for Server/HTTP handlers)
- Test helpers in `test_helpers_test.go` within the same package

**File Structure (C/BPF):**
- Includes → macros → helper enums → map definitions → helper functions → SEC programs

## Type Safety/Documentation

**Go:** Minimal inline docs. No godoc-style comments on most functions. Types are self-documenting via struct field names + JSON tags. Validation done in `Validate()` methods.

**TypeScript:** Extensive type definitions in `types.ts`. React components are functional with typed props.

**BPF/Go Contract:** Shared `bpf_contract.h` header defines the ABI between C and Go. Go mirrors these as Go structs with matching field layout (manually verified).

## Error Handling

**Go pattern:** `errors.Join()` for multi-field validation, `fmt.Errorf("verb: %w", err)` for wrapping.
- Config validation accumulates all errors before returning
- HTTP handlers use `writeError(w, statusCode, err)` helper
- Agent logs use `RedactString(err.Error())` to prevent credential leaks
```go
var errs []error
if strings.TrimSpace(c.Addr) == "" {
	errs = append(errs, errors.New("ANTI_DDOS_CONTROL_ADDR is required"))
}
return errors.Join(errs...)
```

**BPF:** Returns XDP verdicts (`XDP_PASS`, `XDP_DROP`, `XDP_REDIRECT`). No error returns; failures counted in `drop_counters` map.

## Logging

- Standard library `log/slog` throughout (JSON handler to stderr)
- Logger injected via constructor, falls back to `slog.Default()` if nil
- Sensitive values wrapped with `agent.RedactString()` before logging
```go
logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
```

## HTTP API Conventions

- JSON request/response bodies
- `Authorization: Bearer <token>` header for session auth
- Agent endpoints use `X-Owner-Username` / `X-Owner-User-ID` headers
- Session cookie: `anti_ddos_session` (HttpOnly, SameSite=Strict)
- `Content-Type: application/json` required for POST/PUT
- Health checks: `/healthz` returning `text/plain` "ok"
- Metrics: `/metrics` returning Prometheus exposition format
- Audit: `X-Audit-Reason` header and `reason` JSON field for audit trail

## Comments/Documentation

- Minimal inline comments in Go code (code is self-documenting)
- BPF C code has section comments for major logic blocks
- README.md in Vietnamese with detailed operational instructions
- Makefile includes comprehensive `help` target with all variables documented
