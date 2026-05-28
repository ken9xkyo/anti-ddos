CLANG ?= clang
CC ?= gcc
BPFTOOL ?= bpftool
PKG_CONFIG ?= pkg-config

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

BPF_CFLAGS := -g -O2 -Wall -Werror -target bpf -D__TARGET_ARCH_x86 \
	-I$(BPF_BUILD_DIR) -Iinclude
USER_CFLAGS := -g -O2 -Wall -Wextra -Werror -Iinclude
LIBBPF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf 2>/dev/null)
LIBBPF_LIBS := $(shell $(PKG_CONFIG) --libs libbpf 2>/dev/null || printf '%s' '-lbpf -lelf -lz')

.PHONY: phase1-build phase1-test phase1-verify phase2-build phase2-test phase2-veth-test phase2-verify phase3-test phase3-verify phase4-policygen phase4-test phase4-veth-test phase4-verify clean

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

phase4-verify: phase4-test phase4-veth-test
	@mkdir -p $(REPORT_DIR)
	@printf '# Phase 04 Verification Report\n\n' > $(PHASE4_REPORT)
	@printf 'Date: %s\n\n' "$$(date -u +%F)" >> $(PHASE4_REPORT)
	@printf 'Command: `make phase4-verify`\n\n' >> $(PHASE4_REPORT)
	@printf 'Result: PASS\n\n' >> $(PHASE4_REPORT)
	@printf -- '- XDP packet fixtures covered service allowlist miss, TCP/UDP/ICMP allowlisted redirect, MAC rewrite, missing DEVMAP fail-closed, unresolved neighbor drop, blacklist after service match, and whitelist after service match.\n' >> $(PHASE4_REPORT)
	@printf -- '- Go unit tests covered forwarding resolver route/link/neighbor validation, tightened service snapshot validation, policy apply, and forwarding metrics.\n' >> $(PHASE4_REPORT)
	@printf -- '- VETH namespace test attached XDP only to temporary interfaces and verified client -> WAN XDP -> DEVMAP -> backend forwarding with rewritten Ethernet headers.\n' >> $(PHASE4_REPORT)

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
