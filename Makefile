BINARY := execguard
CMD_DIR := ./cmd
BUILD_DIR := ./bin
BPF_GEN := pkg/bpf/guard_bpfel.go pkg/bpf/guard_bpfeb.go
BPF_OBJECT = guard.o
GO ?= go
CLANG ?= clang

.PHONY: all
all: build

.PHONY: generate
generate:
	$(GO) generate ./...

$(BPF_GEN): bpf/src/guard.bpf.c bpf/include/vmlinux.h
	$(GO) generate ./...

.PHONY: bpf
bpf:
	$(CLANG) -target bpf -O2 -g -Wall -I bpf/include -c bpf/src/guard.bpf.c -o $(BUILD_DIR)/$(BPF_OBJECT)

.PHONY: build
build: $(BPF_GEN)
	mkdir -p $(BUILD_DIR)
	$(GO) build -o $(BUILD_DIR)/$(BINARY) $(CMD_DIR)

.PHONY: run
run: build
	sudo $(BUILD_DIR)/$(BINARY) $(ARGS)

.PHONY: fmt
fmt:
	./scripts/fmt.sh

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	rm -f pkg/bpf/guard_bpfel.go pkg/bpf/guard_bpfel.o
	rm -f pkg/bpf/guard_bpfeb.go pkg/bpf/guard_bpfeb.o

.PHONY: help
help:
	@echo "targets:"
	@echo "  generate  - run go generate (bpf2go) to build eBPF skeletons"
	@echo "  bpf       - compile the eBPF C source only, for testing"
	@echo "  build     - generate + compile the execguard binary into $(BUILD_DIR)"
	@echo "  run       - build and run execguard (requires root, ARGS=... to pass flags)"
	@echo "  fmt       - format Go and C sources via scripts/fmt.sh"
	@echo "  clean     - remove build output and generated bpf files"
