# Energy-Aware sched_ext Scheduler

A custom Linux scheduler using sched_ext (BPF) with RAPL (Running Average Power Limit) energy monitoring integration.

## Features

- **RAPL Stats Monitor**: BPF-based energy and temperature monitoring with kernel timer (100ms intervals)
- **FIFO Scheduler**: Simple First-In-First-Out scheduler implementation using sched_ext
- **BPF Map Integration**: Pinned BPF maps for inter-process communication of energy stats
- **Round-Robin Scheduler (demo)**: Minimal sched_ext scheduler that time-slices tasks while steering new work toward the coldest CPUs using the synthetic RAPL stats

## Prerequisites

### System Requirements
- Linux kernel 6.12+ with sched_ext support
- BPF/BTF enabled kernel
- Root/sudo access

### Dependencies

```bash
# Ubuntu/Debian
sudo apt-get install clang llvm libbpf-dev libelf-dev bpftool

# Fedora
sudo dnf install clang llvm libbpf-devel elfutils-libelf-devel bpftool

# Arch
sudo pacman -S clang llvm libbpf elfutils bpf
```

## Setup

### 1. Clone sched_ext Headers

The project requires sched_ext headers for building schedulers:

```bash
cd ~
git clone https://github.com/sched-ext/scx.git
```

The Makefile expects the headers at `~/scx/scheds/include`. If you clone to a different location, update the `SCX_INCLUDE` variable in the Makefile.

### 2. Generate vmlinux.h

Generate the kernel BTF (BPF Type Format) header:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/include/vmlinux.h
```

This creates a header with all kernel data structures needed for BPF programs.

## Building

```bash
# Build all components
make

# Clean build artifacts
make clean
```

Built binaries will be in the `build/` directory:
- `rapl_stats_updater` - RAPL stats collector
- `scx_reader` - Read RAPL stats from BPF map
- `scx_fifo` - FIFO scheduler

## Usage

### RAPL Stats Monitor

Start the energy monitoring daemon (updates every 100ms using BPF timer):

```bash
# Terminal 1: Start the updater
sudo make run
```

The stats are written to a pinned BPF map at `/sys/fs/bpf/rapl_stats`.

Read current energy stats:

```bash
# Terminal 2: Read stats
sudo make test-scx
```

### FIFO Scheduler

**⚠️ WARNING**: This replaces your system's scheduler. Test in a safe environment!

```bash
sudo make run-fifo
```

Press Ctrl+C to stop and restore the default scheduler.

### Round-Robin Scheduler with RAPL Display

This scheduler is a minimal Round-Robin policy (same time slice for every runnable task) that steers wakeups toward the coldest CPUs at the time of scheduling. It logs the synthetic RAPL stats so you can see which CPUs were considered coldest.

```bash
sudo make run-energy
```

Make sure `rapl_stats_updater` is running so the loader can attach to the pinned `/sys/fs/bpf/rapl_stats` and `/sys/fs/bpf/rapl_temps` maps. The stats are logged from the kernel via `bpf_printk`, so monitor them with:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

Press Ctrl+C in the scheduler terminal to stop and detach.

## Architecture

### RAPL Stats (src/bpf-stats-updater/)

- `repl_stats_interval.bpf.c` - BPF program with kernel timer for stats generation
- `loader.c` - Userspace loader that pins the BPF map
- `scx_reader.c` - Example reader for accessing pinned stats

Stats collected:
- Package/Core power (watts)
- Package/Core energy (joules)
- Package/Core temperature (°C)
- TDP (Thermal Design Power)

### FIFO Scheduler (src/)

- `scx_fifo.bpf.c` - Simple FIFO scheduling policy using sched_ext
- `scx_fifo_loader.c` - Loader to attach the scheduler

### Round-Robin Scheduler (src/)

- `scx_energy_aware.bpf.c` - Cold-aware Round-Robin sched_ext policy that chooses the coolest CPU using the RAPL maps and logs the decision stream
- `scx_energy_aware_loader.c` - Loader that attaches the scheduler and links the pinned RAPL stats and temperature maps so the kernel can read them

## Development

### Project Structure

```
.
├── Makefile
├── README.md
├── src/
│   ├── bpf-stats-updater/
│   │   ├── loader.c
│   │   ├── repl_stats_interval.bpf.c
│   │   └── scx_reader.c
│   ├── include/
│   │   ├── rapl_stats.h
│   │   └── vmlinux.h (generated)
│   ├── scx_fifo.bpf.c
│   ├── scx_fifo_loader.c
│   ├── scx_energy_aware.bpf.c
│   └── scx_energy_aware_loader.c
└── build/
```

### Adding Energy-Aware Scheduling

To integrate RAPL stats into scheduling decisions:

1. Open the pinned map in your scheduler:
```c
int map_fd = bpf_obj_get("/sys/fs/bpf/rapl_stats");
```

2. Read stats in your BPF program:
```c
struct rapl_stats stats;
__u32 key = 0;
bpf_map_lookup_elem(map_fd, &key, &stats);
```

3. Use `stats.package_power`, `stats.core_count`, etc. from the stats map, and fetch per-core temperatures from `/sys/fs/bpf/rapl_temps` (keys are core indices) for scheduling decisions

## Troubleshooting

### "scx/common.bpf.h not found"
Make sure you've cloned the scx repository and the path in Makefile is correct.

### "vmlinux.h not found"
Generate it using the bpftool command in Setup step 2.

### "non-existent DSQ" errors
Check kernel logs with `sudo dmesg` for detailed BPF scheduler errors.

## License

GPL-2.0

## References

- [sched_ext Documentation](https://github.com/sched-ext/scx)
- [BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
- [RAPL Interface](https://www.kernel.org/doc/html/latest/power/powercap/powercap.html)
