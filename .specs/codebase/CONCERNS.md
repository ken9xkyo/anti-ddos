# Codebase Concerns

**Analysis Date:** 2026-06-30

## Tech Debt

**Hardcoded Database Connection Pool Size:**
* **Issue:** The PostgreSQL connection pool is initialized with a hardcoded `MaxConns = 8`.
* **Files:** `internal/control/store.go` (L49)
* **Impact:** In high-concurrency environments (e.g. numerous agents sending logs or multiple dashboard sessions), database connections will quickly block or time out.
* **Fix approach:** Expose connection pool limits as configuration variables (e.g. `ANTI_DDOS_DB_MAX_CONNS` env var).

**Database Integration Test Shared State:**
* **Issue:** The test helper drops the public schema cascadingly on every run.
* **Files:** `internal/control/test_helpers_test.go` (L28)
* **Impact:** Go integration tests cannot be run in parallel (`t.Parallel()` must be avoided). If two tests reset the database concurrently, they will corrupt each other's schemas.
* **Fix approach:** Use dynamic schemas (e.g. `CREATE SCHEMA test_xxxx`) or separate databases per test run if concurrent execution is needed.

---

## Known Bugs

**Admin User Bootstrap Failure:**
* **Symptoms:** Running `make admin-bootstrap` fails with exit code 2 and prints `{"level":"ERROR","msg":"bootstrap failed","error":"admin user already exists"}` if the database already has an admin user.
* **Trigger:** Calling the bootstrap CLI twice or after the lab has already been initialized once.
* **Files:** `internal/control/store.go` (L150-L152) and `Makefile` (L528)
* **Workaround:** Manually inspect the database or skip running bootstrap on subsequent runs.
* **Root cause:** The store returns an error if count of admins is greater than 0, causing the CLI tool to exit with code 2.

**ixgbe Driver DEVMAP Pass-through Requirement:**
* **Symptoms:** Forwarding/Redirect actions fail to transit packets out output interfaces.
* **Trigger:** Running on network cards using the `ixgbe` driver.
* **Files:** Documented in `.notebook/ixgbe-devmap-target-xdp-pass.md`.
* **Root cause:** The driver requires pass-through XDP queues configured before DEVMAP redirection is operational.

---

## Security Considerations

**Plaintext Database Connections:**
* **Risk:** The default docker-compose environments configure the database connection with `sslmode=disable`.
* **Files:** `docker-compose.yml` (L46)
* **Current mitigation:** None (insecure transit).
* **Recommendations:** Enable SSL validation (`sslmode=require` or `sslmode=verify-full`) for all staging and production deployments.

**No API Login Rate Limiting:**
* **Risk:** The `/v1/auth/login` endpoint does not restrict authentication attempts.
* **Files:** `internal/control/server.go` (L118)
* **Recommendations:** Implement a rate-limiting middleware or integrate IP lockout for authentication attempts.

---

## Performance Bottlenecks

**Ring Buffer Event Drops Under Heavy DDoS:**
* **Problem:** Security events are submitted to a 64MB `events` ring buffer.
* **Files:** `include/anti_ddos/bpf_contract.h` (L17)
* **Cause:** During a high-pps DDoS attack, the volume of alert and sample events might overwhelm the user-space agent, filling the 64MB ring buffer and causing kernel drops.
* **Improvement path:** Implement higher kernel-side sampling, dynamic ringbuf sizes, or multi-cpu ring buffer allocations if high pps alerts are expected.

---

## Fragile Areas

**Dual-slot Policy Map Population:**
* **Files:** `internal/agent/policy_apply.go` (L119-L150)
* **Why fragile:** If the agent fails or crashes halfway through populating the inactive slot, it rolls back by clearing the inactive slot. However, if the rollback itself fails (e.g. BPF subsystem call error), the inactive maps are left dirty, leading to potential corrupt state on the next policy flip.
* **Safe modification:** Ensure map cleans are fully validated and add strict checks that the inactive slot is completely empty before population.

---

## Scaling Limits

**Static Capacity Limits in BPF Contract:**
* **Limit:** The limits for Whitelist entries (65,536), Rules (4,096), and Blacklist entries (1,000,000) are hardcoded macros.
* **Files:** `include/anti_ddos/bpf_contract.h` (L4-L18)
* **Symptoms at limit:** BPF map updates will fail with `ENOSPC` / map capacity overflows.
* **Scaling path:** Limits require editing the header, re-compiling the eBPF object, and re-building the agent binaries.

---

## Test Coverage Gaps

**Complex Playwright Setup Requirements:**
* **What's not tested automatically:** Playwright tests are skipped unless the user has manually prepared the python virtual environment and installed chromium browsers.
* **Risk:** Frontend dashboard interactions could break unnoticed in standard CI pipelines.
* **Priority:** Medium.
