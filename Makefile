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
PHASE1_TEST := $(TEST_BUILD_DIR)/xdp_fixture_test
PHASE1_REPORT := $(REPORT_DIR)/phase-01-xdp-data-plane-skeleton.md

BPF_CFLAGS := -g -O2 -Wall -Werror -target bpf -D__TARGET_ARCH_x86 \
	-I$(BPF_BUILD_DIR) -Iinclude
USER_CFLAGS := -g -O2 -Wall -Wextra -Werror -Iinclude
LIBBPF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf 2>/dev/null)
LIBBPF_LIBS := $(shell $(PKG_CONFIG) --libs libbpf 2>/dev/null || printf '%s' '-lbpf -lelf -lz')

.PHONY: phase1-build phase1-test phase1-verify clean

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

$(VMLINUX):
	@mkdir -p $(BPF_BUILD_DIR)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): bpf/xdp_data_plane.bpf.c include/anti_ddos/bpf_contract.h $(VMLINUX)
	@mkdir -p $(BPF_BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(PHASE1_TEST): tests/phase01/xdp_fixture_test.c include/anti_ddos/bpf_contract.h
	@mkdir -p $(TEST_BUILD_DIR)
	$(CC) $(USER_CFLAGS) $(LIBBPF_CFLAGS) $< -o $@ $(LIBBPF_LIBS)

clean:
	rm -rf $(BUILD_DIR)
