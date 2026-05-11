# antiddos - XDP Anti-DDoS 100G mitigator
#
# Targets:
#   make bpf       - compile eBPF object and generate Go bindings via bpf2go
#   make build     - build antiddosd binary
#   make install   - install binary + systemd unit
#   make clean
#
# Requires: clang >= 14, llvm, libbpf headers, go >= 1.22

GO          ?= go
CLANG       ?= clang
STRIP       ?= llvm-strip
ARCH        ?= $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')
KERNEL_REL  ?= $(shell uname -r)
KHEADERS    ?= /usr/src/linux-headers-$(KERNEL_REL)

BPF_SRC     := bpf/xdp_antiddos.c
BPF_OUT     := pkg/loader/bpf_bpfel.o
GENERATED   := pkg/loader/bpf_bpfel.go pkg/loader/bpf_bpfel.o

BPF_CFLAGS  := -O2 -g -Wall -Werror \
               -target bpf \
               -D__TARGET_ARCH_$(ARCH) \
               -D__KERNEL__ \
               -I./bpf \
               -I/usr/include/$(shell uname -m)-linux-gnu \
               -mcpu=v3

GO_PKG      := ./...
LDFLAGS     := -s -w -X main.version=$(shell git describe --always --dirty 2>/dev/null || echo dev)

.PHONY: all bpf build generate test clean install fmt vet lint tidy

all: build

generate: bpf

bpf:
	$(GO) generate ./pkg/loader/...

build: bpf
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/antiddosd ./cmd/antiddosd
	cp pkg/loader/bpf_bpfel.o bin/xdp_antiddos.o 2>/dev/null || true

test:
	$(GO) test -race -count=1 $(GO_PKG)

fmt:
	$(GO) fmt $(GO_PKG)

vet:
	$(GO) vet $(GO_PKG)

tidy:
	$(GO) mod tidy

clean:
	rm -rf bin/ $(GENERATED)

install: build
	install -D -m0755 bin/antiddosd /usr/local/bin/antiddosd
	install -D -m0644 bin/xdp_antiddos.o /usr/local/lib/antiddos/xdp_antiddos.o
	install -D -m0644 deploy/antiddosd.service /etc/systemd/system/antiddosd.service
	install -D -m0644 deploy/config.example.yaml /etc/antiddosd/config.yaml
	install -D -m0755 deploy/tuning.sh /usr/local/sbin/antiddos-tuning
	install -D -m0755 deploy/set_irq_affinity.sh /usr/local/sbin/antiddos-irq
	systemctl daemon-reload
