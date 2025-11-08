# Makefile for RAPL Stats BPF Program

# Compiler and flags
CLANG ?= clang
LLC ?= llc
CC ?= gcc

# Detect kernel version
KERNEL_VERSION := $(shell uname -r)

# Directories
SRC_DIR = src/bpf-stats-updater
INCLUDE_DIR = src/include
BUILD_DIR = build

# BPF flags
BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_arm64 \
	-I$(INCLUDE_DIR) \
	-I/usr/include/aarch64-linux-gnu \
	-I/usr/src/linux-headers-$(KERNEL_VERSION)/tools/lib/bpf \
	-I/usr/src/linux-headers-$(KERNEL_VERSION)/tools/bpf/resolve_btfids/libbpf/include

# User space flags
CFLAGS = -O2 -Wall -I$(INCLUDE_DIR)
LDFLAGS = -lbpf -lelf -lz

# Targets
BPF_OBJ = $(BUILD_DIR)/repl_stats_interval.bpf.o
USER_BIN = $(BUILD_DIR)/rapl_stats_updater
SCX_READER = $(BUILD_DIR)/scx_reader

.PHONY: all clean

all: $(BUILD_DIR) $(BPF_OBJ) $(USER_BIN) $(SCX_READER)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Build BPF object file
$(BPF_OBJ): $(SRC_DIR)/repl_stats_interval.bpf.c $(INCLUDE_DIR)/rapl_stats.h
	$(CLANG) $(BPF_CFLAGS) -c $(SRC_DIR)/repl_stats_interval.bpf.c -o $(BPF_OBJ)
	@echo "BPF object built: $(BPF_OBJ)"

# Build userspace loader
$(USER_BIN): $(SRC_DIR)/loader.c $(INCLUDE_DIR)/rapl_stats.h $(BPF_OBJ)
	$(CC) $(CFLAGS) $(SRC_DIR)/loader.c -o $(USER_BIN) $(LDFLAGS)
	@echo "Userspace program built: $(USER_BIN)"

# Build SCX reader example
$(SCX_READER): $(SRC_DIR)/scx_reader.c $(INCLUDE_DIR)/rapl_stats.h
	$(CC) $(CFLAGS) $(SRC_DIR)/scx_reader.c -o $(SCX_READER) $(LDFLAGS)
	@echo "SCX reader built: $(SCX_READER)"

# Run the program
run: all
	@echo "Running RAPL stats updater..."
	@cd $(BUILD_DIR) && sudo ./rapl_stats_updater

# Test reading from SCX
test-scx: all
	@echo "Testing SCX reader (make sure rapl_stats_updater is running in another terminal)..."
	@cd $(BUILD_DIR) && sudo ./scx_reader

clean:
	rm -rf $(BUILD_DIR)
	@echo "Clean complete"

install-deps:
	@echo "Installing dependencies..."
	@echo "On Ubuntu/Debian: sudo apt-get install clang llvm libbpf-dev libelf-dev"
	@echo "On Fedora: sudo dnf install clang llvm libbpf-devel elfutils-libelf-devel"
	@echo "On Arch: sudo pacman -S clang llvm libbpf elfutils"
