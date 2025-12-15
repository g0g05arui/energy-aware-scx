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

HOT ?= 60
WARM ?= 55
THROTTLE ?= 85

TEMP_HEADER = $(INCLUDE_DIR)/temp_thresholds.h
STATS_HEADERS = $(INCLUDE_DIR)/rapl_stats.h $(TEMP_HEADER)

BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_$(BPF_TARGET_ARCH) \
	-I$(INCLUDE_DIR) \
	-I$(SYS_INCLUDE_DIR) \
	-I/usr/src/linux-headers-$(KERNEL_VERSION)/tools/lib/bpf \
	-I/usr/src/linux-headers-$(KERNEL_VERSION)/tools/bpf/resolve_btfids/libbpf/include

BPF_SCX_CFLAGS = $(BPF_CFLAGS) -I$(SCX_INCLUDE)

CFLAGS = -O2 -Wall -I$(INCLUDE_DIR) -I$(SCX_INCLUDE)
LDFLAGS = -lbpf -lelf -lz

BPF_OBJ = $(BUILD_DIR)/repl_stats_interval.bpf.o
HWMON_BPF_OBJ = $(BUILD_DIR)/hwmon_stats_interval.bpf.o
USER_BIN = $(BUILD_DIR)/rapl_stats_updater
HWMON_LOADER = $(BUILD_DIR)/hwmon_stats_updater
SCX_READER = $(BUILD_DIR)/scx_reader
SCX_FIFO_BPF = $(BUILD_DIR)/scx_fifo.bpf.o
SCX_FIFO_BIN = $(BUILD_DIR)/scx_fifo
ENERGY_BPF_OBJ = $(BUILD_DIR)/scx_energy_aware.bpf.o
ENERGY_LOADER = $(BUILD_DIR)/scx_energy_aware
RAPL_CONSOLE = $(BUILD_DIR)/rapl_console_reader
HWMON_READER = $(BUILD_DIR)/hwmon_console_reader

TOPO_OBJ = $(BUILD_DIR)/topology.o

.PHONY: all clean FORCE

all: $(BUILD_DIR) $(TEMP_HEADER) $(BPF_OBJ) $(HWMON_BPF_OBJ) $(USER_BIN) $(HWMON_LOADER) $(SCX_READER) $(SCX_FIFO_BPF) $(SCX_FIFO_BIN) $(ENERGY_BPF_OBJ) $(ENERGY_LOADER) $(RAPL_CONSOLE) $(HWMON_READER)

FORCE:

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TEMP_HEADER): Makefile FORCE | $(INCLUDE_DIR)
	@echo "Generating $(TEMP_HEADER) (HOT=$(HOT), WARM=$(WARM), THROTTLE=$(THROTTLE))"
	@tmp_file="$@.tmp"; \
	{ \
		printf "#ifndef TEMP_THRESHOLDS_H\n"; \
		printf "#define TEMP_THRESHOLDS_H\n\n"; \
		printf "#define TEMP_THRESHOLD_WARM %s\n" "$(WARM)"; \
		printf "#define TEMP_THRESHOLD_HOT %s\n" "$(HOT)"; \
		printf "#define TEMP_THRESHOLD_THROTTLE %s\n\n" "$(THROTTLE)"; \
		printf "#endif\n"; \
	} > "$$tmp_file"; \
	if [ ! -f "$@" ] || ! cmp -s "$$tmp_file" "$@"; then \
		mv "$$tmp_file" "$@"; \
	else \
		rm -f "$$tmp_file"; \
	fi

$(BPF_OBJ): $(SRC_DIR)/repl_stats_interval.bpf.c $(STATS_HEADERS)
	$(CLANG) $(BPF_CFLAGS) -c $(SRC_DIR)/repl_stats_interval.bpf.c -o $(BPF_OBJ)
	@echo "BPF object built: $(BPF_OBJ)"

$(HWMON_BPF_OBJ): $(SRC_DIR)/hwmon_stats_interval.bpf.c $(STATS_HEADERS)
	$(CLANG) $(BPF_CFLAGS) -c $(SRC_DIR)/hwmon_stats_interval.bpf.c -o $(HWMON_BPF_OBJ)
	@echo "HWMON BPF object built: $(HWMON_BPF_OBJ)"

$(TOPO_OBJ): src/topology.c $(INCLUDE_DIR)/topology.h $(INCLUDE_DIR)/topology_defs.h
	$(CC) $(CFLAGS) -c src/topology.c -o $(TOPO_OBJ)

$(USER_BIN): $(SRC_DIR)/loader.c $(STATS_HEADERS) $(BPF_OBJ) $(TOPO_OBJ)
	$(CC) $(CFLAGS) $(SRC_DIR)/loader.c $(TOPO_OBJ) -o $(USER_BIN) $(LDFLAGS)
	@echo "Userspace program built: $(USER_BIN)"

$(HWMON_LOADER): $(SRC_DIR)/hwmon_loader.c $(STATS_HEADERS) $(HWMON_BPF_OBJ) $(TOPO_OBJ)
	$(CC) $(CFLAGS) $(SRC_DIR)/hwmon_loader.c $(TOPO_OBJ) -o $(HWMON_LOADER) $(LDFLAGS)
	@echo "HWMON stats loader built: $(HWMON_LOADER)"

$(SCX_READER): $(SRC_DIR)/scx_reader.c $(STATS_HEADERS)
	$(CC) $(CFLAGS) $(SRC_DIR)/scx_reader.c -o $(SCX_READER) $(LDFLAGS)
	@echo "SCX reader built: $(SCX_READER)"

$(SCX_FIFO_BPF): src/scx_fifo.bpf.c
	$(CLANG) $(BPF_SCX_CFLAGS) -c src/scx_fifo.bpf.c -o $(SCX_FIFO_BPF)
	@echo "FIFO scheduler BPF object built: $(SCX_FIFO_BPF)"

$(SCX_FIFO_BIN): src/scx_fifo_loader.c $(SCX_FIFO_BPF)
	$(CC) $(CFLAGS) src/scx_fifo_loader.c -o $(SCX_FIFO_BIN) $(LDFLAGS)
	@echo "FIFO scheduler loader built: $(SCX_FIFO_BIN)"

$(ENERGY_BPF_OBJ): src/scx_energy_aware.bpf.c $(STATS_HEADERS)
	$(CLANG) $(BPF_SCX_CFLAGS) -c src/scx_energy_aware.bpf.c -o $(ENERGY_BPF_OBJ)
	@echo "Energy-Aware scheduler BPF object built: $(ENERGY_BPF_OBJ)"

$(ENERGY_LOADER): src/scx_energy_aware_loader.c $(ENERGY_BPF_OBJ) $(TOPO_OBJ)
	$(CC) $(CFLAGS) src/scx_energy_aware_loader.c $(TOPO_OBJ) -o $(ENERGY_LOADER) $(LDFLAGS)
	@echo "Energy-Aware scheduler loader built: $(ENERGY_LOADER)"

$(RAPL_CONSOLE): src/rapl_console_reader.c
	$(CC) $(CFLAGS) src/rapl_console_reader.c -o $(RAPL_CONSOLE)
	@echo "RAPL console reader built: $(RAPL_CONSOLE)"

$(HWMON_READER): src/hwmon_console_reader.c
	$(CC) $(CFLAGS) src/hwmon_console_reader.c -o $(HWMON_READER)
	@echo "HWMON console reader built: $(HWMON_READER)"

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
	rm -f $(TEMP_HEADER)
	@echo "Clean complete"

install-deps:
	@echo "Installing dependencies..."
	@echo "On Ubuntu/Debian: sudo apt-get install clang llvm libbpf-dev libelf-dev"
	@echo "On Fedora: sudo dnf install clang llvm libbpf-devel elfutils-libelf-devel"
	@echo "On Arch: sudo pacman -S clang llvm libbpf elfutils"
