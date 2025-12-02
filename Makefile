# Makefile for RAPL Stats BPF Program
CLANG ?= clang
LLC ?= llc
CC ?= gcc

KERNEL_VERSION := $(shell uname -r)
UNAME_M := $(shell uname -m)

ifeq ($(BPF_TARGET_ARCH),)
  ifeq ($(UNAME_M),x86_64)
    BPF_TARGET_ARCH := x86
  else ifeq ($(UNAME_M),aarch64)
    BPF_TARGET_ARCH := arm64
  else
    $(error Unsupported architecture $(UNAME_M). Set BPF_TARGET_ARCH manually)
  endif
endif

ifeq ($(SYS_INCLUDE_DIR),)
  ifeq ($(UNAME_M),x86_64)
    SYS_INCLUDE_DIR := /usr/include/x86_64-linux-gnu
  else ifeq ($(UNAME_M),aarch64)
    SYS_INCLUDE_DIR := /usr/include/aarch64-linux-gnu
  else
    SYS_INCLUDE_DIR := /usr/include
  endif
endif

SCX_INCLUDE ?= $(HOME)/scx/scheds/include

SRC_DIR = src/bpf-stats-updater
INCLUDE_DIR = src/include
BUILD_DIR = build

BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_$(BPF_TARGET_ARCH) \
	-I$(INCLUDE_DIR) \
	-I$(SYS_INCLUDE_DIR) \
	-I/usr/src/linux-headers-$(KERNEL_VERSION)/tools/lib/bpf \
	-I/usr/src/linux-headers-$(KERNEL_VERSION)/tools/bpf/resolve_btfids/libbpf/include

BPF_SCX_CFLAGS = $(BPF_CFLAGS) -I$(SCX_INCLUDE)

CFLAGS = -O2 -Wall -I$(INCLUDE_DIR)
LDFLAGS = -lbpf -lelf -lz

BPF_OBJ = $(BUILD_DIR)/repl_stats_interval.bpf.o
USER_BIN = $(BUILD_DIR)/rapl_stats_updater
SCX_READER = $(BUILD_DIR)/scx_reader
SCX_FIFO_BPF = $(BUILD_DIR)/scx_fifo.bpf.o
SCX_FIFO_BIN = $(BUILD_DIR)/scx_fifo
ENERGY_BPF_OBJ = $(BUILD_DIR)/scx_energy_aware.bpf.o
ENERGY_LOADER = $(BUILD_DIR)/scx_energy_aware
RAPL_CONSOLE = $(BUILD_DIR)/rapl_console_reader

.PHONY: all clean

all: $(BUILD_DIR) $(BPF_OBJ) $(USER_BIN) $(SCX_READER) $(SCX_FIFO_BPF) $(SCX_FIFO_BIN) $(ENERGY_BPF_OBJ) $(ENERGY_LOADER) $(RAPL_CONSOLE)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BPF_OBJ): $(SRC_DIR)/repl_stats_interval.bpf.c $(INCLUDE_DIR)/rapl_stats.h
	$(CLANG) $(BPF_CFLAGS) -c $(SRC_DIR)/repl_stats_interval.bpf.c -o $(BPF_OBJ)
	@echo "BPF object built: $(BPF_OBJ)"

$(USER_BIN): $(SRC_DIR)/loader.c $(INCLUDE_DIR)/rapl_stats.h $(BPF_OBJ)
	$(CC) $(CFLAGS) $(SRC_DIR)/loader.c -o $(USER_BIN) $(LDFLAGS)
	@echo "Userspace program built: $(USER_BIN)"

$(SCX_READER): $(SRC_DIR)/scx_reader.c $(INCLUDE_DIR)/rapl_stats.h
	$(CC) $(CFLAGS) $(SRC_DIR)/scx_reader.c -o $(SCX_READER) $(LDFLAGS)
	@echo "SCX reader built: $(SCX_READER)"

$(SCX_FIFO_BPF): src/scx_fifo.bpf.c
	$(CLANG) $(BPF_SCX_CFLAGS) -c src/scx_fifo.bpf.c -o $(SCX_FIFO_BPF)
	@echo "FIFO scheduler BPF object built: $(SCX_FIFO_BPF)"

$(SCX_FIFO_BIN): src/scx_fifo_loader.c $(SCX_FIFO_BPF)
	$(CC) $(CFLAGS) src/scx_fifo_loader.c -o $(SCX_FIFO_BIN) $(LDFLAGS)
	@echo "FIFO scheduler loader built: $(SCX_FIFO_BIN)"

$(ENERGY_BPF_OBJ): src/scx_energy_aware.bpf.c $(INCLUDE_DIR)/rapl_stats.h
	$(CLANG) $(BPF_SCX_CFLAGS) -c src/scx_energy_aware.bpf.c -o $(ENERGY_BPF_OBJ)
	@echo "Energy-Aware scheduler BPF object built: $(ENERGY_BPF_OBJ)"

$(ENERGY_LOADER): src/scx_energy_aware_loader.c $(ENERGY_BPF_OBJ)
	$(CC) $(CFLAGS) src/scx_energy_aware_loader.c -o $(ENERGY_LOADER) $(LDFLAGS)
	@echo "Energy-Aware scheduler loader built: $(ENERGY_LOADER)"

$(RAPL_CONSOLE): src/rapl_console_reader.c
	$(CC) $(CFLAGS) src/rapl_console_reader.c -o $(RAPL_CONSOLE)
	@echo "RAPL console reader built: $(RAPL_CONSOLE)"

run: all
	@echo "Running RAPL stats updater..."
	@cd $(BUILD_DIR) && sudo ./rapl_stats_updater

test-scx: all
	@echo "Testing SCX reader (make sure rapl_stats_updater is running in another terminal)..."
	@cd $(BUILD_DIR) && sudo ./scx_reader

run-fifo: all
	@echo "Running FIFO scheduler..."
	@cd $(BUILD_DIR) && sudo ./scx_fifo

run-energy: all
	@echo "Running Energy-Aware scheduler..."
	@cd $(BUILD_DIR) && sudo ./scx_energy_aware

clean:
	rm -rf $(BUILD_DIR)
	@echo "Clean complete"

install-deps:
	@echo "Installing dependencies..."
	@echo "On Ubuntu/Debian: sudo apt-get install clang llvm libbpf-dev libelf-dev"
	@echo "On Fedora: sudo dnf install clang llvm libbpf-devel elfutils-libelf-devel"
	@echo "On Arch: sudo pacman -S clang llvm libbpf elfutils"
