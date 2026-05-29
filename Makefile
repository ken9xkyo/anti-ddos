CLANG ?= clang
CC ?= gcc
BPFTOOL ?= bpftool
PKG_CONFIG ?= pkg-config
PYTHON ?= python3
CURL ?= curl
NPM ?= npm
GO ?= go
COMPOSE ?= docker compose
SUDO ?= $(shell if [ "$$(id -u)" = 0 ]; then printf ''; else printf sudo; fi)
ADMIN_USERNAME ?= admin
ADMIN_PASSWORD ?=
AGENT_PROCESS ?= anti-ddos-agent
AGENT_STOP_TIMEOUT ?= 10
AGENT_FORCE ?= 0
AGENT_WAN_IFACE ?= $(ANTI_DDOS_WAN_IFACE)
AGENT_BPF_PIN_DIR ?= $(if $(ANTI_DDOS_BPF_PIN_DIR),$(ANTI_DDOS_BPF_PIN_DIR),/sys/fs/bpf/anti-ddos)
AGENT_LOG_FILE ?= $(AGENT_BUILD_DIR)/anti-ddos-agent.log
AGENT_PID_FILE ?= $(AGENT_BUILD_DIR)/anti-ddos-agent.pid
AGENT_START_WAIT ?= 2
AGENT_METRICS_ADDR ?=
AGENT_CONTROL_URL ?=
AGENT_XDP_MODE ?=
AGENT_ALLOW_GENERIC_FALLBACK ?=
AGENT_SAFE_DETACH_ON_EXIT ?=
AGENT_TOKEN ?=
export ADMIN_PASSWORD AGENT_TOKEN

BUILD_DIR := build
BPF_BUILD_DIR := $(BUILD_DIR)/bpf
TEST_BUILD_DIR := $(BUILD_DIR)/tests
AGENT_BUILD_DIR := $(BUILD_DIR)/agent

VMLINUX := $(BPF_BUILD_DIR)/vmlinux.h
BPF_OBJ := $(BPF_BUILD_DIR)/xdp_data_plane.bpf.o
BPF_TEST := $(TEST_BUILD_DIR)/xdp_fixture_test
BPF_TEST_SRC := $(firstword $(wildcard tests/*/xdp_fixture_test.c))
AGENT_BIN := $(AGENT_BUILD_DIR)/anti-ddos-agent
CONTROL_API_BIN := $(BUILD_DIR)/control-api
CONTROL_ADMIN_BIN := $(BUILD_DIR)/control-admin
SERVICES_UI_E2E := $(firstword $(wildcard scripts/e2e/*services_forwarding.py))

BPF_CFLAGS := -g -O2 -Wall -Werror -target bpf -D__TARGET_ARCH_x86 \
	-I$(BPF_BUILD_DIR) -Iinclude
USER_CFLAGS := -g -O2 -Wall -Wextra -Werror -Iinclude
LIBBPF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf 2>/dev/null)
LIBBPF_LIBS := $(shell $(PKG_CONFIG) --libs libbpf 2>/dev/null || printf '%s' '-lbpf -lelf -lz')

COMPOSE_BUILD_SERVICES := control-api admin-dashboard
COMPOSE_LOG_SERVICES := postgres control-api prometheus grafana admin-dashboard

.PHONY: help usage
.PHONY: bpf-build bpf-test agent-build agent-start agent-stop agent-remove go-build ui-build build
.PHONY: go-test go-vet go-race ui-test lint integration-test admin-dashboard-postgres-test admin-dashboard-ui-test admin-dashboard-test services-ui-e2e test test-all
.PHONY: env-init compose-config compose-build dev-up dev-down dev-reset dev-ps dev-logs dev-health admin-bootstrap
.PHONY: deploy deploy-down deploy-logs clean

help:
	@printf 'Anti-DDoS Make command guide\n\n'
	@printf 'Usage:\n'
	@printf '  make help                         Show this guide\n'
	@printf '  make usage                        Same as make help\n'
	@printf '  make <target>                     Run one target\n'
	@printf '  make VAR=value <target>           Override one Make/env value for a run\n'
	@printf '  make -n <target>                  Dry-run commands without executing them\n\n'
	@printf 'Common workflows:\n'
	@printf '  Local lab bootstrap:\n'
	@printf '    make env-init\n'
	@printf '    make compose-config\n'
	@printf '    make dev-up\n'
	@printf '    make admin-bootstrap\n'
	@printf '    make dev-health\n\n'
	@printf '  Host Agent lifecycle:\n'
	@printf '    make agent-build\n'
	@printf '    make AGENT_WAN_IFACE=<approved-lab-or-wan-iface> agent-start\n'
	@printf '    tail -f $(AGENT_LOG_FILE)\n'
	@printf '    make agent-stop\n'
	@printf '    make AGENT_WAN_IFACE=<approved-lab-or-wan-iface> agent-remove\n\n'
	@printf '  Test gates:\n'
	@printf '    make test                       Fast local gate: BPF, Go, UI tests/build\n'
	@printf '    make test-all                   Full local gate with lint, race and integration tests\n'
	@printf '    make go-race                    Run Go tests with race detector\n\n'
	@printf '  Deploy lab stack:\n'
	@printf '    make deploy                     Build BPF/images and start compose stack\n'
	@printf '    make deploy-logs                Follow compose service logs\n'
	@printf '    make deploy-down                Stop compose stack\n\n'
	@printf 'Build targets:\n'
	@printf '  make bpf-build                    Build/update build/bpf/xdp_data_plane.bpf.o\n'
	@printf '  make bpf-test                     Run XDP fixture test against the BPF object\n'
	@printf '  make agent-build                  Build build/agent/anti-ddos-agent for host execution\n'
	@printf '  make go-build                     Build control-api, control-admin and host Agent\n'
	@printf '  make ui-build                     Build Admin Dashboard assets\n'
	@printf '  make compose-build                Build control-api and admin-dashboard images\n'
	@printf '  make build                        Build BPF object, Go binaries and UI assets\n\n'
	@printf 'Host Agent targets:\n'
	@printf '  make agent-start                  Start host Agent in background; requires AGENT_WAN_IFACE\n'
	@printf '  make agent-stop                   Send SIGTERM to background Agent and wait for exit\n'
	@printf '  make AGENT_FORCE=1 agent-stop     Send SIGKILL if Agent does not stop in time\n'
	@printf '  make agent-remove                 Stop Agent, unpin BPF link, detach legacy XDP, remove pins\n\n'
	@printf 'Test targets:\n'
	@printf '  make go-test                      Run go test ./...\n'
	@printf '  make go-vet                       Run go vet ./...\n'
	@printf '  make ui-test                      Run dashboard unit tests\n'
	@printf '  make lint                         Run go vet and optional golangci-lint\n'
	@printf '  make integration-test             Run PostgreSQL admin dashboard integration test\n'
	@printf '  make services-ui-e2e              Run protected services dashboard E2E test\n'
	@printf '  make admin-dashboard-test         Run dashboard backend/UI verification bundle\n\n'
	@printf 'Dev and deploy targets:\n'
	@printf '  make env-init                     Create .env from .env.example when missing\n'
	@printf '  make compose-config               Validate docker-compose.yml\n'
	@printf '  make dev-up                       Build BPF/images and start lab stack\n'
	@printf '  make dev-health                   Check local health endpoints\n'
	@printf '  make dev-ps                       Show compose service status\n'
	@printf '  make dev-logs                     Follow compose service logs\n'
	@printf '  make dev-down                     Stop lab stack\n'
	@printf '  make dev-reset                    Stop stack and remove lab volumes\n'
	@printf '  make admin-bootstrap              Bootstrap first admin user, reading password from TTY\n'
	@printf '  make ADMIN_USERNAME=<user> admin-bootstrap\n'
	@printf '  make ADMIN_PASSWORD=<password> admin-bootstrap\n\n'
	@printf 'Important variables:\n'
	@printf '  COMPOSE                           Compose command, default: docker compose\n'
	@printf '  GO, NPM, CLANG, CC, BPFTOOL       Tool overrides for build/test targets\n'
	@printf '  ADMIN_USERNAME                    Admin bootstrap username, default: admin\n'
	@printf '  ADMIN_PASSWORD                    Non-interactive admin bootstrap password\n'
	@printf '  AGENT_WAN_IFACE                   Interface for XDP attach/detach\n'
	@printf '  ANTI_DDOS_WAN_IFACE               Env fallback for AGENT_WAN_IFACE\n'
	@printf '  AGENT_TOKEN                       Host Agent token; falls back to .env values\n'
	@printf '  AGENT_METRICS_ADDR                Host Agent metrics bind, default: 0.0.0.0:9091\n'
	@printf '  AGENT_CONTROL_URL                 Control API URL, default: http://127.0.0.1:8080\n'
	@printf '  AGENT_XDP_MODE                    XDP mode, default: native\n'
	@printf '  AGENT_ALLOW_GENERIC_FALLBACK      Allow generic XDP fallback, default: false\n'
	@printf '  AGENT_SAFE_DETACH_ON_EXIT         Detach XDP on Agent exit, default: false\n'
	@printf '  AGENT_BPF_PIN_DIR                 BPF pin dir, default: /sys/fs/bpf/anti-ddos\n'
	@printf '  AGENT_LOG_FILE                    Background Agent log, default: $(AGENT_LOG_FILE)\n'
	@printf '  AGENT_PID_FILE                    Background Agent PID file, default: $(AGENT_PID_FILE)\n'
	@printf '  AGENT_START_WAIT                  Startup check wait seconds, default: 2\n'
	@printf '  AGENT_STOP_TIMEOUT                Agent stop wait seconds, default: 10\n'
	@printf '  AGENT_FORCE                       Use 1 to SIGKILL after stop timeout\n\n'
	@printf 'Safety notes:\n'
	@printf '  - Compose starts management/control services only; the Node Agent runs on host.\n'
	@printf '  - agent-start runs in the background and can attach XDP. Use only an approved lab/WAN interface.\n'
	@printf '  - agent-remove removes the pinned BPF link before using ip link xdp off.\n'
	@printf '  - Use make -n <target> to inspect commands before running risky operations.\n'

usage: help

bpf-build: $(BPF_OBJ)
	@printf 'BPF object ready: %s\n' "$(BPF_OBJ)"

bpf-test: $(BPF_OBJ) $(BPF_TEST)
	$(BPF_TEST) $(BPF_OBJ)

agent-build: $(BPF_OBJ)
	@mkdir -p $(AGENT_BUILD_DIR)
	$(GO) build -o $(AGENT_BIN) ./cmd/agent

agent-start: agent-build
	@set -eu; \
	if [ -f .env ]; then \
		set -a; . ./.env; set +a; \
	fi; \
	iface="$(AGENT_WAN_IFACE)"; \
	if [ -z "$$iface" ]; then iface="$${ANTI_DDOS_WAN_IFACE:-}"; fi; \
	if [ -z "$$iface" ]; then \
		echo "AGENT_WAN_IFACE or ANTI_DDOS_WAN_IFACE is required for XDP attach" >&2; \
		exit 1; \
	fi; \
	if ! ip link show dev "$$iface" >/dev/null 2>&1; then \
		echo "interface $$iface not found" >&2; \
		exit 1; \
	fi; \
	existing="$$(pgrep -x "$(AGENT_PROCESS)" || true)"; \
	if [ -n "$$existing" ]; then \
		echo "$(AGENT_PROCESS) is already running: $$existing" >&2; \
		exit 1; \
	fi; \
	metrics_addr="$(AGENT_METRICS_ADDR)"; \
	if [ -z "$$metrics_addr" ]; then metrics_addr="$${ANTI_DDOS_METRICS_ADDR:-0.0.0.0:9091}"; fi; \
	control_url="$(AGENT_CONTROL_URL)"; \
	if [ -z "$$control_url" ]; then control_url="$${ANTI_DDOS_CONTROL_URL:-http://127.0.0.1:8080}"; fi; \
	token="$${AGENT_TOKEN:-}"; \
	if [ -z "$$token" ]; then token="$${ANTI_DDOS_AGENT_TOKEN:-$${ANTI_DDOS_AGENT_SHARED_TOKEN:-}}"; fi; \
	xdp_mode="$(AGENT_XDP_MODE)"; \
	if [ -z "$$xdp_mode" ]; then xdp_mode="$${ANTI_DDOS_XDP_MODE:-native}"; fi; \
	allow_fallback="$(AGENT_ALLOW_GENERIC_FALLBACK)"; \
	if [ -z "$$allow_fallback" ]; then allow_fallback="$${ANTI_DDOS_XDP_ALLOW_GENERIC_FALLBACK:-false}"; fi; \
	safe_detach="$(AGENT_SAFE_DETACH_ON_EXIT)"; \
	if [ -z "$$safe_detach" ]; then safe_detach="$${ANTI_DDOS_SAFE_DETACH_ON_EXIT:-false}"; fi; \
	pin_dir="$(AGENT_BPF_PIN_DIR)"; \
	if [ -z "$$pin_dir" ]; then pin_dir="$${ANTI_DDOS_BPF_PIN_DIR:-/sys/fs/bpf/anti-ddos}"; fi; \
	log_file="$(AGENT_LOG_FILE)"; \
	pid_file="$(AGENT_PID_FILE)"; \
	start_wait="$(AGENT_START_WAIT)"; \
	mkdir -p "$$(dirname "$$log_file")" "$$(dirname "$$pid_file")"; \
	if [ -n "$$control_url" ] && [ -z "$$token" ]; then \
		echo "warning: ANTI_DDOS_AGENT_TOKEN is empty; Control API sync may be rejected" >&2; \
	fi; \
	echo "starting $(AGENT_PROCESS) on $$iface in background"; \
	printf '\n[%s] starting $(AGENT_PROCESS) on %s\n' "$$(date -Is)" "$$iface" >> "$$log_file"; \
	nohup $(SUDO) env \
		ANTI_DDOS_WAN_IFACE="$$iface" \
		ANTI_DDOS_XDP_OBJECT="$(BPF_OBJ)" \
		ANTI_DDOS_XDP_MODE="$$xdp_mode" \
		ANTI_DDOS_XDP_ALLOW_GENERIC_FALLBACK="$$allow_fallback" \
		ANTI_DDOS_METRICS_ADDR="$$metrics_addr" \
		ANTI_DDOS_BPF_PIN_DIR="$$pin_dir" \
		ANTI_DDOS_CONTROL_URL="$$control_url" \
		ANTI_DDOS_AGENT_TOKEN="$$token" \
		ANTI_DDOS_SAFE_DETACH_ON_EXIT="$$safe_detach" \
		"$(AGENT_BIN)" >> "$$log_file" 2>&1 & \
	launcher_pid="$$!"; \
	sleep "$$start_wait"; \
	pids="$$(pgrep -x "$(AGENT_PROCESS)" || true)"; \
	if [ -z "$$pids" ]; then \
		echo "$(AGENT_PROCESS) failed to stay running; launcher pid $$launcher_pid" >&2; \
		echo "last log lines from $$log_file:" >&2; \
		tail -n 40 "$$log_file" >&2 || true; \
		rm -f -- "$$pid_file"; \
		exit 1; \
	fi; \
	printf '%s\n' "$$pids" > "$$pid_file"; \
	echo "$(AGENT_PROCESS) started: $$pids"; \
	echo "log: $$log_file"; \
	echo "pid file: $$pid_file"

agent-stop:
	@set -eu; \
	pids="$$(pgrep -x "$(AGENT_PROCESS)" || true)"; \
	if [ -z "$$pids" ]; then \
		echo "$(AGENT_PROCESS) is not running"; \
		rm -f -- "$(AGENT_PID_FILE)"; \
		exit 0; \
	fi; \
	echo "stopping $(AGENT_PROCESS): $$pids"; \
	$(SUDO) kill -TERM $$pids; \
	timeout="$(AGENT_STOP_TIMEOUT)"; \
	while [ "$$timeout" -gt 0 ]; do \
		sleep 1; \
		remaining="$$(pgrep -x "$(AGENT_PROCESS)" || true)"; \
		if [ -z "$$remaining" ]; then \
			echo "$(AGENT_PROCESS) stopped"; \
			rm -f -- "$(AGENT_PID_FILE)"; \
			exit 0; \
		fi; \
		timeout=$$((timeout - 1)); \
	done; \
	remaining="$$(pgrep -x "$(AGENT_PROCESS)" || true)"; \
	if [ "$(AGENT_FORCE)" = "1" ] && [ -n "$$remaining" ]; then \
		echo "force stopping $(AGENT_PROCESS): $$remaining"; \
		$(SUDO) kill -KILL $$remaining; \
		rm -f -- "$(AGENT_PID_FILE)"; \
	else \
		echo "$(AGENT_PROCESS) still running after $(AGENT_STOP_TIMEOUT)s; rerun with AGENT_FORCE=1 to send SIGKILL" >&2; \
		exit 1; \
	fi

agent-remove: agent-stop
	@set -eu; \
	iface="$(AGENT_WAN_IFACE)"; \
	pin_dir="$(AGENT_BPF_PIN_DIR)"; \
	detach_output=""; \
	if [ -f .env ]; then \
		set -a; . ./.env; set +a; \
		if [ -z "$$iface" ]; then iface="$${ANTI_DDOS_WAN_IFACE:-}"; fi; \
		pin_dir="$${ANTI_DDOS_BPF_PIN_DIR:-$$pin_dir}"; \
	fi; \
	case "$$pin_dir" in \
		""|"/"|"/sys"|"/sys/"|"/sys/fs"|"/sys/fs/"|"/sys/fs/bpf"|"/sys/fs/bpf/") \
			echo "refusing to remove unsafe BPF pin dir: $$pin_dir" >&2; \
			exit 1; \
			;; \
	esac; \
	if [ -n "$$iface" ]; then \
		if ! ip link show dev "$$iface" >/dev/null 2>&1; then \
			echo "interface $$iface not found" >&2; \
			exit 1; \
		fi; \
		link_pin="$$pin_dir/links/xdp_$$iface"; \
		if [ -e "$$link_pin" ]; then \
			echo "removing pinned XDP link $$link_pin"; \
			$(SUDO) rm -f -- "$$link_pin"; \
		else \
			echo "pinned XDP link does not exist: $$link_pin"; \
		fi; \
		echo "detaching legacy/netlink XDP from $$iface if present"; \
		if detach_output="$$( $(SUDO) ip link set dev "$$iface" xdp off 2>&1 )"; then \
			:; \
		else \
			status="$$?"; \
			if printf '%s\n' "$$detach_output" | grep -q "Can't replace active BPF XDP link"; then \
				echo "$$detach_output" >&2; \
				echo "XDP is still owned by an active BPF link after removing $$link_pin" >&2; \
				echo "Check for another process or pin with: $(BPFTOOL) link show" >&2; \
			else \
				echo "$$detach_output" >&2; \
			fi; \
			exit "$$status"; \
		fi; \
	else \
		echo "AGENT_WAN_IFACE/ANTI_DDOS_WAN_IFACE is not set; skipping explicit XDP detach"; \
		echo "removing pinned BPF links can detach the Agent-managed XDP program"; \
	fi; \
	if [ -e "$$pin_dir" ]; then \
		echo "removing BPF pins under $$pin_dir"; \
		$(SUDO) rm -rf -- "$$pin_dir"; \
	else \
		echo "BPF pin dir does not exist: $$pin_dir"; \
	fi

go-build: agent-build
	@mkdir -p $(BUILD_DIR)
	$(GO) build -o $(CONTROL_API_BIN) ./cmd/control-api
	$(GO) build -o $(CONTROL_ADMIN_BIN) ./cmd/control-admin

ui-build:
	$(NPM) --prefix web/dashboard run build

build: bpf-build go-build ui-build

go-test:
	$(GO) test ./...

go-vet:
	$(GO) vet ./...

go-race:
	$(GO) test -race ./...

ui-test:
	$(NPM) --prefix web/dashboard test -- --run

lint: go-vet
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found; skipping optional lint gate"; \
	fi

integration-test:
	scripts/lab/admin-dashboard-postgres-test.sh

admin-dashboard-postgres-test: integration-test

admin-dashboard-ui-test: ui-test ui-build

admin-dashboard-test: lint go-race integration-test ui-test ui-build

services-ui-e2e:
	@if [ -z "$(SERVICES_UI_E2E)" ]; then \
		echo "services dashboard E2E script not found" >&2; \
		exit 1; \
	fi
	$(PYTHON) $(SERVICES_UI_E2E)

test: bpf-test go-test ui-test ui-build

test-all: test lint go-race integration-test

env-init:
	@if [ -f .env ]; then \
		echo ".env already exists"; \
	else \
		cp .env.example .env; \
		echo "created .env from .env.example"; \
		echo "edit change-me-* values before using this stack outside a local lab"; \
	fi

compose-config:
	$(COMPOSE) config --quiet

compose-build:
	$(COMPOSE) build $(COMPOSE_BUILD_SERVICES)

dev-up: bpf-build compose-build
	$(COMPOSE) up -d

dev-down:
	$(COMPOSE) down

dev-reset:
	$(COMPOSE) down -v

dev-ps:
	$(COMPOSE) ps

dev-logs:
	$(COMPOSE) logs -f $(COMPOSE_LOG_SERVICES)

dev-health:
	@set -eu; \
	control_addr="$$($(COMPOSE) port control-api 8080)"; \
	prometheus_addr="$$($(COMPOSE) port prometheus 9090)"; \
	grafana_addr="$$($(COMPOSE) port grafana 3000)"; \
	dashboard_addr="$$($(COMPOSE) port admin-dashboard 8080)"; \
	check() { \
		name="$$1"; \
		url="$$2"; \
		printf '%-16s %s\n' "$$name" "$$url"; \
		$(CURL) -fsS "$$url" >/dev/null; \
	}; \
	check control-api "http://$$control_addr/healthz"; \
	check prometheus "http://$$prometheus_addr/-/ready"; \
	check grafana "http://$$grafana_addr/api/health"; \
	check admin-dashboard "http://$$dashboard_addr/healthz"

admin-bootstrap:
	@if [ -n "$${ADMIN_PASSWORD:-}" ]; then \
		printf '%s\n' "$$ADMIN_PASSWORD" | $(COMPOSE) run --rm --no-deps --entrypoint control-admin control-api bootstrap --username "$(ADMIN_USERNAME)" --password-stdin; \
	else \
		if [ ! -r /dev/tty ]; then \
			echo "ADMIN_PASSWORD is required when no TTY is available" >&2; \
			exit 1; \
		fi; \
		printf 'Admin password for %s: ' "$(ADMIN_USERNAME)" > /dev/tty; \
		stty -echo < /dev/tty; \
		trap 'stty echo < /dev/tty; printf "\n" > /dev/tty' EXIT INT TERM; \
		IFS= read -r password < /dev/tty; \
		stty echo < /dev/tty; \
		trap - EXIT INT TERM; \
		printf '\n' > /dev/tty; \
		if [ -z "$$password" ]; then \
			echo "admin password cannot be empty" >&2; \
			exit 1; \
		fi; \
		printf '%s\n' "$$password" | $(COMPOSE) run --rm --no-deps --entrypoint control-admin control-api bootstrap --username "$(ADMIN_USERNAME)" --password-stdin; \
	fi

deploy: dev-up

deploy-down: dev-down

deploy-logs: dev-logs

$(VMLINUX):
	@mkdir -p $(BPF_BUILD_DIR)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): bpf/xdp_data_plane.bpf.c include/anti_ddos/bpf_contract.h $(VMLINUX)
	@mkdir -p $(BPF_BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BPF_TEST): $(BPF_TEST_SRC) include/anti_ddos/bpf_contract.h
	@if [ -z "$(BPF_TEST_SRC)" ]; then \
		echo "XDP fixture test source not found" >&2; \
		exit 1; \
	fi
	@mkdir -p $(TEST_BUILD_DIR)
	$(CC) $(USER_CFLAGS) $(LIBBPF_CFLAGS) $(BPF_TEST_SRC) -o $@ $(LIBBPF_LIBS)

clean:
	rm -rf $(BUILD_DIR)
