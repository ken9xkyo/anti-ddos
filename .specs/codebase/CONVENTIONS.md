# Code Conventions

## Naming Conventions

### Go (Backend & Node Agent)
* **Packages:** Lowercase single-word names (`agent`, `control`). Avoid underscores or mixed capitalization.
* **Files:** snake_case filenames (e.g., `admin_console.go`, `policy_apply.go`).
* **Types / Structs:** PascalCase (UpperCamelCase) (e.g., `Server`, `Config`, `Actor`).
* **Functions / Methods:** PascalCase (e.g., `NewServer`, `ServeHTTP`, `routes`).
* **Receiver Variables:** Short (1 or 2 characters) matching the type name (e.g., `s *Server`, `a *Agent`, `c Config`). Avoid `this` or `self`.
* **Variables / Constants:** camelCase for local variables. Database column tags in structs use `json` snake_case mappings.

**Example from [store.go](file:///root/anti-ddos/internal/control/store.go#L27-L42):**
```go
type Store struct {
	pool           *pgxpool.Pool
	cfg            Config
	logger         *slog.Logger
	feedHTTPClient *http.Client
	telegramClient *TelegramClient
	alertRetryBase time.Duration
	feedMu         sync.Mutex
	feedLocks      map[string]*sync.Mutex
	metrics        *ControlMetrics
}

type Actor struct {
	User
	ViewOwnerUserID string
}
```

### TypeScript / React (Frontend)
* **Directories:** kebab-case or lower-case directories.
* **Component Files / Views:** PascalCase (e.g., `FleetView.tsx`, `OverviewView.tsx`).
* **Utility Files:** camelCase (e.g., `api.ts`, `muiTheme.ts`).
* **Classes / Types:** PascalCase (e.g., `ApiClient`, `BlacklistEntry`).
* **Methods / Variables:** camelCase (e.g., `setToken`, `clearToken`).

---

## Code Organization

### Go Import Ordering
Go imports must be grouped into three blocks separated by empty lines:
1. Standard Library packages.
2. Third-Party packages (e.g., `github.com/jackc/pgx`).
3. Local project modules (e.g., `github.com/ken9xkyo/anti-ddos/internal/agent`).

**Example from [migrations.go](file:///root/anti-ddos/internal/control/migrations.go#L3-L9):**
```go
import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)
```

### Go File Layout
Files generally follow a top-down order:
1. Package declaration & imports.
2. Main Struct/Interface declarations.
3. Constructor functions (e.g., `New`, `NewServer`).
4. Public methods.
5. Private helper methods.

---

## Type Safety & Documentation

### Go Type Safety
* Enforce explicit typing. Avoid `interface{}` or `any` except when strictly required (e.g., JSON unmarshaling, database scanner parameters).
* Map inputs to strong structs (e.g. `UserUpdateInput`, `PasswordResetInput`).

### TypeScript Type Safety
* No usage of the `any` type. Define interfaces or types in `types.ts` for all request/response models.
* Use `import type` for type-only imports to aid bundler tree-shaking.

**Example from [api.ts](file:///root/anti-ddos/web/dashboard/src/api.ts#L1-L10):**
```typescript
import type {
  Agent,
  Alert,
  AuditEvent,
  BlacklistEntriesPage,
  BlacklistEntry,
...
} from './types';
```

---

## Error Handling

### Go Patterns
* Errors should be returned as the last parameter of functions and handled immediately.
* Return errors rather than logging and crashing (use `log/slog` warnings/errors only at the top level or background jobs).
* Wrap database or integration errors with contextual details using `fmt.Errorf("context message: %w", err)`.
* Database transaction errors should roll back correctly using a deferred rollback strategy.

**Example from [admin_console.go](file:///root/anti-ddos/internal/control/admin_console.go#L21-L29):**
```go
tx, err := s.beginUnscopedTx(ctx)
if err != nil {
	return User{}, err
}
defer tx.Rollback(ctx)
before, err := s.getUser(ctx, tx, id)
if err != nil {
	return User{}, err
}
```

---

## Comments & Documentation

### Comment Style
* Use double-slash comments (`//`) for single-line comments.
* Exported variables, structs, and functions should have a documentation comment block starting with the symbol's name.
* Annotate complex eBPF parser helper assertions or verifier workarounds in `xdp_data_plane.bpf.c` inline.
