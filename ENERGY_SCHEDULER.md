# Cold-Aware Round-Robin Scheduler Demo

The current scheduler remains intentionally minimal, but it now demonstrates how to consume the synthetic RAPL telemetry: every time a task wakes up, the scheduler selects the coldest CPU (round-robin among ties) before inserting the task into the per-CPU DSQ. All stats continue to be streamed from the kernel via `bpf_printk` so you can validate the plumbing.

## Components

1. **BPF Scheduler (`src/scx_energy_aware.bpf.c`)**
   - Implements a per-CPU Round-Robin queue by inserting runnable tasks into the local DSQ with the default sched_ext slice.
   - Reads the shared `rapl_stats` map plus the `/sys/fs/bpf/rapl_temps` per-core temperature map, selects the coldest allowed CPU, and emits the stats via `bpf_printk`.

2. **Userspace Loader (`src/scx_energy_aware_loader.c`)**
   - Loads the BPF object, attaches the struct_ops scheduler, and reuses the pinned `/sys/fs/bpf/rapl_stats` and `/sys/fs/bpf/rapl_temps` maps so the kernel program can see the data.
   - No longer prints stats itself; instead it just keeps the scheduler attached while you watch the kernel log (e.g., `trace_pipe`).

## Prerequisites

1. Linux kernel 6.12+ with sched_ext enabled.
2. `rapl_stats_updater` running so the pinned stats and temps maps exist and receive fresh random values.
3. Root privileges (required for sched_ext and map access).

## Building

```bash
make
```

Relevant build artifacts:

- `build/scx_energy_aware.bpf.o` – Round-Robin sched_ext program.
- `build/scx_energy_aware` – Loader/monitor binary.

## Usage

1. **Start the RAPL stats updater**

   ```bash
   sudo ./build/rapl_stats_updater
   ```

   This pins the shared maps at `/sys/fs/bpf/rapl_stats` and `/sys/fs/bpf/rapl_temps`, refreshing them every 100 ms with random data.

2. **Attach the Round-Robin scheduler**

   ```bash
   sudo ./build/scx_energy_aware
   # or
   sudo make run-energy
   ```

   The loader:
   - Attaches the Round-Robin sched_ext policy.
   - Connects the BPF program to the pinned map so it can read stats in kernel space.
   - Leaves actual logging to `bpf_printk`. Watch it via:

     ```bash
     sudo cat /sys/kernel/debug/tracing/trace_pipe
     ```

3. **Stop the scheduler**

   Press `Ctrl+C`. The loader detaches the scheduler, closes the map FD, and exits cleanly.

### Sample Output

```
Round-Robin scheduler loaded and attached successfully.
Pinned RAPL stats map: /sys/fs/bpf/rapl_stats
Pinned RAPL temps map: /sys/fs/bpf/rapl_temps
Stats are emitted from the kernel via bpf_printk.
Run 'sudo cat /sys/kernel/debug/tracing/trace_pipe' to monitor them.
Press Ctrl+C to stop.

<trace_pipe output>
...
            scx_energy_aware: RAPL ts=433223512445 delta=100000000 pkg=79W/66C core=48W/60C tdp=102W
            scx_energy_aware: RAPL ts=433323512679 delta=100000000 pkg=65W/62C core=40W/57C tdp=115W
```

## Next Steps

With the Round-Robin baseline working, we can begin experimenting with policies that consume the map data—e.g., dynamic slices or task throttling based on package power/temperature.

## Files of Interest

- `src/scx_energy_aware.bpf.c`
- `src/scx_energy_aware_loader.c`
- `src/include/rapl_stats.h`
- `Makefile`

## Further Reading

- [sched_ext Documentation](https://docs.kernel.org/scheduler/sched-ext.html)
- [RAPL Interface](https://www.kernel.org/doc/html/latest/power/powercap/powercap.html)
- [BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
