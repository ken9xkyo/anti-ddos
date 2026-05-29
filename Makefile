CLANG ?= clang
CC ?= gcc
BPFTOOL ?= bpftool
PKG_CONFIG ?= pkg-config
PYTHON ?= python3

BUILD_DIR := build
BPF_BUILD_DIR := $(BUILD_DIR)/bpf
TEST_BUILD_DIR := $(BUILD_DIR)/tests
REPORT_DIR := reports

VMLINUX := $(BPF_BUILD_DIR)/vmlinux.h
BPF_OBJ := $(BPF_BUILD_DIR)/xdp_data_plane.bpf.o
BPF_PASS_OBJ := $(BPF_BUILD_DIR)/xdp_pass.bpf.o
PHASE1_TEST := $(TEST_BUILD_DIR)/xdp_fixture_test
PHASE1_REPORT := $(REPORT_DIR)/phase-01-xdp-data-plane-skeleton.md
AGENT_BUILD_DIR := $(BUILD_DIR)/agent
AGENT_BIN := $(AGENT_BUILD_DIR)/anti-ddos-agent
PHASE2_REPORT := $(REPORT_DIR)/phase-02-agent-lifecycle.md
PHASE3_REPORT := $(REPORT_DIR)/phase-03-policy-snapshot-map-sync.md
PHASE4_REPORT := $(REPORT_DIR)/phase-04-devmap-forwarding-service-allowlist.md
PHASE4_POLICYGEN := $(BUILD_DIR)/phase4-policygen
PHASE5_REPORT := $(REPORT_DIR)/phase-05-control-plane-core.md
PHASE6_REPORT := $(REPORT_DIR)/phase-06-observability-dashboard.md
PHASE7_REPORT := $(REPORT_DIR)/phase-07-rate-limit-baseline-auto-enforce.md
PHASE8_REPORT := $(REPORT_DIR)/phase-08-threat-feed-sync.md
PHASE9_REPORT := $(REPORT_DIR)/phase-09-telegram-isp-runbook.md

BPF_CFLAGS := -g -O2 -Wall -Werror -target bpf -D__TARGET_ARCH_x86 \
	-I$(BPF_BUILD_DIR) -Iinclude
USER_CFLAGS := -g -O2 -Wall -Wextra -Werror -Iinclude
LIBBPF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf 2>/dev/null)
LIBBPF_LIBS := $(shell $(PKG_CONFIG) --libs libbpf 2>/dev/null || printf '%s' '-lbpf -lelf -lz')

.PHONY: phase1-build phase1-test phase1-verify phase2-build phase2-test phase2-veth-test phase2-verify phase3-test phase3-verify phase4-policygen phase4-test phase4-veth-test phase4-ui-e2e phase4-verify phase5-test phase5-postgres-test phase5-verify phase6-test phase6-postgres-test phase6-ui-test phase6-verify phase7-test phase7-postgres-test phase7-veth-test phase7-ui-test phase7-verify phase8-test phase8-postgres-test phase8-ui-test phase8-verify phase9-test phase9-postgres-test phase9-ui-test phase9-verify admin-dashboard-postgres-test admin-dashboard-ui-test admin-dashboard-test clean

phase1-build: $(BPF_OBJ)

phase1-test: $(BPF_OBJ) $(PHASE1_TEST)
	$(PHASE1_TEST) $(BPF_OBJ)

phase1-verify: phase1-test
	@mkdir -p $(REPORT_DIR)
	@printf '# Phase 01 Verification Report\n\n' > $(PHASE1_REPORT)
	@printf 'Date: %s\n\n' "$$(date -u +%F)" >> $(PHASE1_REPORT)
	@printf 'Command: `make phase1-verify`\n\n' >> $(PHASE1_REPORT)
	@printf 'Result: PASS\n\n' >> $(PHASE1_REPORT)
	@printf -- '- BPF object built with clang target BPF.\n' >> $(PHASE1_REPORT)
	@printf -- '- Object loaded through libbpf without attaching to any interface.\n' >> $(PHASE1_REPORT)
	@printf -- '- Required map contracts validated for type and max entries.\n' >> $(PHASE1_REPORT)
	@printf -- '- Packet fixtures passed with BPF_PROG_TEST_RUN: missing runtime config, truncated Ethernet payload, malformed IPv4/IHL, IPv4 fragment, valid TCP SYN, valid UDP, valid ICMP, unknown IPv4 protocol, non-IPv4 pass.\n' >> $(PHASE1_REPORT)
	@printf -- '- Verifier log captured at `build/bpf/verifier.log`.\n' >> $(PHASE1_REPORT)

phase2-build: $(BPF_OBJ)
	@mkdir -p $(AGENT_BUILD_DIR)
	go build -o $(AGENT_BIN) ./cmd/agent

phase2-test: phase1-test
	go test ./...

phase2-veth-test: phase2-build
	scripts/lab/phase2-veth-test.sh

phase2-verify: phase2-test phase2-veth-test
	@mkdir -p $(REPORT_DIR)
	@printf '# Phase 02 Verification Report\n\n' > $(PHASE2_REPORT)
	@printf 'Date: %s\n\n' "$$(date -u +%F)" >> $(PHASE2_REPORT)
	@printf 'Command: `make phase2-verify`\n\n' >> $(PHASE2_REPORT)
	@printf 'Result: PASS\n\n' >> $(PHASE2_REPORT)
	@printf -- '- Phase 01 fixture baseline passed before Agent verification.\n' >> $(PHASE2_REPORT)
	@printf -- '- Go Agent built with pinned dependencies compatible with Go 1.22.2.\n' >> $(PHASE2_REPORT)
	@printf -- '- Unit tests covered config validation, redaction, snapshot checksum, map contract validation, counter aggregation, and metric registration.\n' >> $(PHASE2_REPORT)
	@printf -- '- VETH lifecycle test attached XDP to a temporary veth interface, scraped `/metrics`, verified pinned link restart behavior, and cleaned up with safe detach.\n' >> $(PHASE2_REPORT)

phase3-test: phase2-test

phase3-verify: phase3-test
	@mkdir -p $(REPORT_DIR)
	@printf '# Phase 03 Verification Report\n\n' > $(PHASE3_REPORT)
	@printf 'Date: %s\n\n' "$$(date -u +%F)" >> $(PHASE3_REPORT)
	@printf 'Command: `make phase3-verify`\n\n' >> $(PHASE3_REPORT)
	@printf 'Result: PASS\n\n' >> $(PHASE3_REPORT)
	@printf -- '- Phase 01 verifier and packet fixture baseline passed, including blacklist drop and whitelist-over-blacklist precedence before service allowlist.\n' >> $(PHASE3_REPORT)
	@printf -- '- Go unit tests covered canonical policy snapshot checksum, validation failures, capacity checks, TTL rejection, atomic map apply, runtime flip, rollback, and last-valid persistence.\n' >> $(PHASE3_REPORT)
	@printf -- '- Phase 02 Agent test baseline passed with the phase 03 policy snapshot and map sync code compiled into the Agent.\n' >> $(PHASE3_REPORT)

phase4-policygen:
	@mkdir -p $(BUILD_DIR)
	go build -o $(PHASE4_POLICYGEN) ./cmd/phase4-policygen

phase4-test: phase1-test
	go test ./...

phase4-veth-test: phase2-build phase4-policygen $(BPF_PASS_OBJ)
	scripts/lab/phase4-devmap-veth-test.sh

phase4-ui-e2e:
	$(PYTHON) scripts/e2e/phase4_services_forwarding.py

phase4-verify: phase4-test phase4-veth-test
	@mkdir -p $(REPORT_DIR)
	@printf '# Phase 04 Verification Report\n\n' > $(PHASE4_REPORT)
	@printf 'Date: %s\n\n' "$$(date -u +%F)" >> $(PHASE4_REPORT)
	@printf 'Command: `make phase4-verify`\n\n' >> $(PHASE4_REPORT)
	@printf 'Result: PASS\n\n' >> $(PHASE4_REPORT)
	@printf -- '- XDP packet fixtures covered service allowlist miss, TCP/UDP/ICMP allowlisted redirect, MAC rewrite, missing DEVMAP fail-closed, unresolved neighbor drop, blacklist after service match, and whitelist after service match.\n' >> $(PHASE4_REPORT)
	@printf -- '- Go unit tests covered forwarding resolver route/link/neighbor validation, tightened service snapshot validation, policy apply, and forwarding metrics.\n' >> $(PHASE4_REPORT)
	@printf -- '- VETH namespace test attached XDP only to temporary interfaces and verified client -> WAN XDP -> DEVMAP -> backend forwarding with rewritten Ethernet headers.\n' >> $(PHASE4_REPORT)

phase5-test: phase4-test

phase5-postgres-test:
	scripts/lab/phase5-postgres-test.sh

phase5-verify: phase5-test phase5-postgres-test
	@mkdir -p $(REPORT_DIR)
	@printf '# Phase 05 Verification Report\n\n' > $(PHASE5_REPORT)
	@printf 'Date: %s\n\n' "$$(date -u +%F)" >> $(PHASE5_REPORT)
	@printf 'Command: `make phase5-verify`\n\n' >> $(PHASE5_REPORT)
	@printf 'Result: PASS\n\n' >> $(PHASE5_REPORT)
	@printf -- '- Existing Go tests and XDP packet fixture baseline passed through `phase4-test`.\n' >> $(PHASE5_REPORT)
	@printf -- '- Control API, Admin CLI and Agent optional Control sync compiled with PostgreSQL `pgx/v5` and bcrypt dependencies.\n' >> $(PHASE5_REPORT)
	@printf -- '- PostgreSQL integration test ran migrations twice on a clean database, bootstrapped Admin, verified local session auth/RBAC, denied Viewer mutation, and checked audit reason capture.\n' >> $(PHASE5_REPORT)
	@printf -- '- Policy mutations created deterministic Agent-compatible snapshots using the Phase 03/04 `PolicySnapshot` contract, and unchanged rebuild skipped a redundant version.\n' >> $(PHASE5_REPORT)
	@printf -- '- Rollback created a new snapshot with `rollback_from`; Agent register, heartbeat, snapshot fetch and apply ack endpoints were exercised.\n' >> $(PHASE5_REPORT)

phase6-test: phase5-test

phase6-postgres-test:
	scripts/lab/phase6-postgres-test.sh

phase6-ui-test:
	npm --prefix web/dashboard test -- --run
	npm --prefix web/dashboard run build

phase6-verify: phase6-test phase6-postgres-test phase6-ui-test
	@mkdir -p $(REPORT_DIR)
	@printf '# Phase 06 Verification Report\n\n' > $(PHASE6_REPORT)
	@printf 'Date: %s\n\n' "$$(date -u +%F)" >> $(PHASE6_REPORT)
	@printf 'Command: `make phase6-verify`\n\n' >> $(PHASE6_REPORT)
	@printf 'Result: PASS\n\n' >> $(PHASE6_REPORT)
	@printf -- '- Existing Go tests and XDP packet fixture baseline passed through `phase5-test`.\n' >> $(PHASE6_REPORT)
	@printf -- '- Control API exposed `/metrics`, bounded request labels, dashboard APIs, Prometheus proxy status and PostgreSQL-backed sampled security event ingestion/query APIs.\n' >> $(PHASE6_REPORT)
	@printf -- '- Agent ringbuf consumer forwarded sampled events to Control API best-effort with bounded queue, drop metrics and forwarding error metrics.\n' >> $(PHASE6_REPORT)
	@printf -- '- PostgreSQL integration test ran phase 06 migrations, ingested sampled events, queried events/summary/dashboard and audited metrics label safety.\n' >> $(PHASE6_REPORT)
	@printf -- '- React/Vite dashboard tests verified Viewer read-only behavior, Operator actions, freshness indicators and event investigation rendering; production build succeeded.\n' >> $(PHASE6_REPORT)
	@printf -- '- Grafana dashboard and Prometheus scrape example were added under `deploy/`.\n' >> $(PHASE6_REPORT)

phase7-test: phase1-test
	go test ./...

phase7-postgres-test:
	scripts/lab/phase7-postgres-test.sh

phase7-veth-test: phase4-veth-test

phase7-ui-test:
	npm --prefix web/dashboard test -- --run
	npm --prefix web/dashboard run build

phase7-verify: phase7-test phase7-postgres-test phase7-veth-test phase7-ui-test
	@mkdir -p $(REPORT_DIR)
	@printf '# Phase 07 Verification Report\n\n' > $(PHASE7_REPORT)
	@printf 'Date: %s\n\n' "$$(date -u +%F)" >> $(PHASE7_REPORT)
	@printf 'Command: `make phase7-verify`\n\n' >> $(PHASE7_REPORT)
	@printf 'Result: PASS\n\n' >> $(PHASE7_REPORT)
	@printf -- '- XDP packet fixtures covered rate-limit under/over threshold, refill, byte bucket, SYN CPS bucket, observe mode, drop rule and whitelist bypass.\n' >> $(PHASE7_REPORT)
	@printf -- '- Go tests covered policy snapshot rule selection, rule dimension contract, baseline/anomaly APIs, low-confidence observe-only behavior, whitelist conflict gate, auto-enforce TTL rule creation, rollback and TTL expiry.\n' >> $(PHASE7_REPORT)
	@printf -- '- PostgreSQL integration test ran phase 07 migrations, baseline approve/recalibrate, anomaly evaluation and auto-enforce lifecycle against a temporary database.\n' >> $(PHASE7_REPORT)
	@printf -- '- VETH lab forwarding baseline remained valid through `phase7-veth-test`; no real NIC attach was performed.\n' >> $(PHASE7_REPORT)
	@printf -- '- React/Vite dashboard tests verified anomaly score, active auto-rule, TTL, baseline confidence and viewer read-only behavior; production build succeeded.\n' >> $(PHASE7_REPORT)

phase8-test: phase1-test
	go test ./...

phase8-postgres-test:
	scripts/lab/phase8-postgres-test.sh

phase8-ui-test:
	npm --prefix web/dashboard test -- --run
	npm --prefix web/dashboard run build

phase8-verify: phase8-test phase8-postgres-test phase8-ui-test
	@mkdir -p $(REPORT_DIR)
	@printf '# Phase 08 Verification Report\n\n' > $(PHASE8_REPORT)
	@printf 'Date: %s\n\n' "$$(date -u +%F)" >> $(PHASE8_REPORT)
	@printf 'Command: `make phase8-verify`\n\n' >> $(PHASE8_REPORT)
	@printf 'Result: PASS\n\n' >> $(PHASE8_REPORT)
	@printf -- '- Existing Go tests and XDP packet fixture baseline passed through `phase8-test`.\n' >> $(PHASE8_REPORT)
	@printf -- '- Feed parser tests covered Spamhaus/plaintext, internal JSON, invalid IPv4/IPv6 rejection, dedupe, safe aggregation and whitelist merge prevention.\n' >> $(PHASE8_REPORT)
	@printf -- '- PostgreSQL integration test ran Phase 08 migrations, feed source CRUD/RBAC, manual sync, run history, conflict report, snapshot inclusion and last-valid retention on fetch failure.\n' >> $(PHASE8_REPORT)
	@printf -- '- Control metrics expose bounded feed sync success/error counters and active entry/conflict gauges without raw IP/CIDR labels.\n' >> $(PHASE8_REPORT)
	@printf -- '- React/Vite dashboard tests verified feed status, run history, conflict visibility and viewer read-only behavior; production build succeeded.\n' >> $(PHASE8_REPORT)

phase9-test: phase1-test
	go test ./...

phase9-postgres-test:
	scripts/lab/phase9-postgres-test.sh

phase9-ui-test:
	npm --prefix web/dashboard test -- --run
	npm --prefix web/dashboard run build

phase9-verify: phase9-test phase9-postgres-test phase9-ui-test
	@mkdir -p $(REPORT_DIR)
	@printf '# Phase 09 Verification Report\n\n' > $(PHASE9_REPORT)
	@printf 'Date: %s\n\n' "$$(date -u +%F)" >> $(PHASE9_REPORT)
	@printf 'Command: `make phase9-verify`\n\n' >> $(PHASE9_REPORT)
	@printf 'Result: PASS\n\n' >> $(PHASE9_REPORT)
	@printf -- '- Existing Go tests and XDP packet fixture baseline passed through `phase9-test`.\n' >> $(PHASE9_REPORT)
	@printf -- '- Alert schema, Telegram config/API, dedupe window, retry backoff, delivery logs and secret redaction were covered by unit and PostgreSQL integration tests.\n' >> $(PHASE9_REPORT)
	@printf -- '- Telegram mock server verified success, 4xx no-retry, 5xx retry, malformed response handling and dedupe without duplicate send.\n' >> $(PHASE9_REPORT)
	@printf -- '- Producers created alert records for test alert, anomaly/manual alert, feed failure, neighbor/redirect failure and ISP escalation runbook payload.\n' >> $(PHASE9_REPORT)
	@printf -- '- React/Vite dashboard tests verified Alerts tab, Telegram status, delivery log visibility, ISP manual runbook and viewer read-only behavior; production build succeeded.\n' >> $(PHASE9_REPORT)

admin-dashboard-postgres-test:
	scripts/lab/admin-dashboard-postgres-test.sh

admin-dashboard-ui-test:
	npm --prefix web/dashboard test -- --run
	npm --prefix web/dashboard run build

admin-dashboard-test:
	go vet ./...
	go test -race ./...
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found; skipping optional lint gate"; \
	fi
	scripts/lab/admin-dashboard-postgres-test.sh
	npm --prefix web/dashboard test -- --run
	npm --prefix web/dashboard run build

$(VMLINUX):
	@mkdir -p $(BPF_BUILD_DIR)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): bpf/xdp_data_plane.bpf.c include/anti_ddos/bpf_contract.h $(VMLINUX)
	@mkdir -p $(BPF_BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BPF_PASS_OBJ): bpf/xdp_pass.bpf.c $(VMLINUX)
	@mkdir -p $(BPF_BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(PHASE1_TEST): tests/phase01/xdp_fixture_test.c include/anti_ddos/bpf_contract.h
	@mkdir -p $(TEST_BUILD_DIR)
	$(CC) $(USER_CFLAGS) $(LIBBPF_CFLAGS) $< -o $@ $(LIBBPF_LIBS)

clean:
	rm -rf $(BUILD_DIR)
