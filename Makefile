CLANG ?= clang
CC ?= gcc
BPFTOOL ?= bpftool
PKG_CONFIG ?= pkg-config
PYTHON ?= python3
CURL ?= curl
NPM ?= npm
GO ?= go
COMPOSE ?= docker compose
ADMIN_USERNAME ?= admin
ADMIN_PASSWORD ?=
export ADMIN_PASSWORD

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

.PHONY: help
.PHONY: bpf-build bpf-test agent-build go-build ui-build build
.PHONY: go-test go-vet go-race ui-test lint integration-test admin-dashboard-postgres-test admin-dashboard-ui-test admin-dashboard-test services-ui-e2e test test-all
.PHONY: env-init compose-config compose-build dev-up dev-down dev-reset dev-ps dev-logs dev-health admin-bootstrap
.PHONY: deploy deploy-down deploy-logs clean

help:
	@printf 'Anti-DDoS Make targets\n\n'
	@printf 'Build:\n'
	@printf '  make bpf-build         Build XDP/eBPF object\n'
	@printf '  make agent-build       Build host Agent binary\n'
	@printf '  make go-build          Build control-api, control-admin and Agent\n'
	@printf '  make ui-build          Build Admin Dashboard assets\n'
	@printf '  make compose-build     Build local Docker images\n'
	@printf '  make build             Build BPF, Go binaries and UI assets\n\n'
	@printf 'Test:\n'
	@printf '  make bpf-test          Run XDP fixture tests\n'
	@printf '  make go-test           Run Go tests\n'
	@printf '  make go-vet            Run go vet\n'
	@printf '  make go-race           Run Go race tests\n'
	@printf '  make ui-test           Run dashboard tests\n'
	@printf '  make integration-test  Run PostgreSQL admin dashboard integration test\n'
	@printf '  make services-ui-e2e   Run protected services dashboard E2E\n'
	@printf '  make test              Run BPF, Go and UI tests/build\n'
	@printf '  make test-all          Run full local gate\n\n'
	@printf 'Dev and deploy:\n'
	@printf '  make env-init          Create .env from .env.example when missing\n'
	@printf '  make compose-config    Validate docker-compose.yml\n'
	@printf '  make dev-up            Build BPF/images and start lab stack\n'
	@printf '  make dev-health        Check local health endpoints\n'
	@printf '  make dev-ps            Show compose service status\n'
	@printf '  make dev-logs          Follow compose service logs\n'
	@printf '  make dev-down          Stop lab stack\n'
	@printf '  make dev-reset         Stop stack and remove lab volumes\n'
	@printf '  make admin-bootstrap   Bootstrap first admin user\n'
	@printf '  make deploy            Alias for dev-up\n'
	@printf '  make deploy-down       Alias for dev-down\n'
	@printf '  make deploy-logs       Alias for dev-logs\n'

bpf-build: $(BPF_OBJ)

bpf-test: $(BPF_OBJ) $(BPF_TEST)
	$(BPF_TEST) $(BPF_OBJ)

agent-build: $(BPF_OBJ)
	@mkdir -p $(AGENT_BUILD_DIR)
	$(GO) build -o $(AGENT_BIN) ./cmd/agent

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
