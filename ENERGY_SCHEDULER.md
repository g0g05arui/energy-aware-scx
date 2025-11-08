# Energy-Aware Scheduler

An energy-aware CPU scheduler built with sched_ext that dynamically adjusts scheduling decisions based on real-time power consumption and temperature measurements from RAPL (Running Average Power Limit).

## Features

- **Dynamic Time Slice Adjustment**: Adapts CPU time slices based on current power and thermal state
- **Three Operating Modes**:
  - **Normal Mode**: Full performance (temp < 75°C, power < 80% TDP)
  - **Power Save Mode**: Reduced time slices (temp ≥ 75°C OR power ≥ 80% TDP)
  - **Aggressive Save Mode**: Minimal time slices (temp ≥ 85°C)
- **Real-time RAPL Integration**: Uses BPF maps to read power/temperature stats
- **Live Monitoring**: Displays current energy state and scheduler statistics every 5 seconds

## Architecture

The energy-aware scheduler consists of two main components:

1. **BPF Scheduler** (`scx_energy_aware.bpf.c`):
   - Implements the sched_ext scheduling policy
   - Reads RAPL stats from shared BPF map
   - Adjusts time slices based on power/thermal state
   - Tracks scheduling decisions

2. **Userspace Loader** (`scx_energy_aware_loader.c`):
   - Loads and attaches the BPF scheduler
   - Monitors and displays energy state
   - Shows real-time statistics

## Prerequisites

1. Linux kernel with sched_ext support (6.12+)
2. RAPL stats updater running (provides energy measurements)
3. Root privileges

## Building

```bash
make
```

This builds:
- `build/scx_energy_aware.bpf.o` - BPF scheduler object
- `build/scx_energy_aware` - Userspace loader

## Usage

### Step 1: Start RAPL Stats Updater

In one terminal:
```bash
sudo ./build/rapl_stats_updater
```

This will continuously update power/temperature measurements in a BPF map at `/sys/fs/bpf/rapl_stats`.

### Step 2: Run Energy-Aware Scheduler

In another terminal:
```bash
sudo ./build/scx_energy_aware
```

Or use the make target:
```bash
make run-energy
```

### Expected Output

```
======================================
Energy-Aware Scheduler Loaded!
======================================

This scheduler adjusts task scheduling based on:
  - Current power consumption
  - Temperature
  - TDP limits

Power/Temperature Thresholds:
  Normal:     Temp < 75°C, Power < 80% TDP
  Power Save: Temp >= 75°C OR Power >= 80% TDP
  Aggressive: Temp >= 85°C

Press Ctrl+C to stop and unload the scheduler

=== Current Energy State ===
Package Power: 5 W  (TDP: 15 W, 33.3%)
Package Temp:  55 °C
Core Power:    3 W
Core Temp:     52 °C
Scheduler Mode: NORMAL - Performance Mode

=== Scheduler Statistics ===
Normal decisions:     1234567
Power save decisions: 0
Aggressive save:      0
```

## How It Works

### Scheduling Policy

The scheduler makes decisions in the `energy_aware_enqueue()` function:

1. **Read RAPL Stats**: Fetch current power/temperature from BPF map
2. **Evaluate State**:
   - Check if temperature is critical (≥ 85°C) → Aggressive save mode
   - Check if temperature is high (≥ 75°C) → Power save mode
   - Check if power consumption is high (≥ 80% TDP) → Power save mode
   - Otherwise → Normal mode
3. **Assign Time Slice**:
   - Normal: Full time slice (`SCX_SLICE_DFL`)
   - Power Save: Half time slice (`SCX_SLICE_DFL / 2`)
   - Aggressive: Quarter time slice (`SCX_SLICE_DFL / 4`)

### Time Slice Impact

- **Shorter time slices** = More context switches = Lower CPU frequency = Less power
- **Longer time slices** = Fewer context switches = Higher CPU frequency = Better performance

### Statistics Tracking

The scheduler tracks:
- Number of normal scheduling decisions
- Number of power-saving decisions
- Number of aggressive power-saving decisions

These help evaluate how often the scheduler is in power-saving mode.

## Tuning

You can adjust the thresholds in `src/scx_energy_aware.bpf.c`:

```c
#define TEMP_THRESHOLD_HIGH 75        // °C - start power saving
#define TEMP_THRESHOLD_CRITICAL 85    // °C - aggressive power saving
#define POWER_THRESHOLD_PERCENT 80    // % of TDP
```

You can also modify the time slice ratios:

```c
#define SLICE_NORMAL SCX_SLICE_DFL           // Normal slice
#define SLICE_POWER_SAVE (SCX_SLICE_DFL / 2)    // Power save
#define SLICE_AGGRESSIVE_SAVE (SCX_SLICE_DFL / 4) // Aggressive save
```

After changes, rebuild with `make`.

## Stopping the Scheduler

Press `Ctrl+C` in the terminal running the scheduler. It will:
1. Print final statistics
2. Detach from the system
3. Restore default scheduling

## Testing

You can stress test the scheduler to see it react to high power/temperature:

```bash
# Generate CPU load
stress-ng --cpu 4 --timeout 60s
```

Watch the scheduler output to see it switch between modes as temperature/power increases.

## Comparison with FIFO Scheduler

The repository also includes a simple FIFO scheduler for comparison:

```bash
sudo ./build/scx_fifo
```

The FIFO scheduler doesn't consider energy - it always uses the same time slice regardless of power/temperature.

## Troubleshooting

### "RAPL stats map not found"
- Make sure `rapl_stats_updater` is running first
- Check that `/sys/fs/bpf/rapl_stats` exists

### "Failed to attach struct_ops"
- Ensure your kernel has sched_ext support
- Check `dmesg` for kernel errors
- Verify no other sched_ext scheduler is running

### "Permission denied"
- Run with `sudo`
- Check that BPF is enabled in your kernel

## Files

- `src/scx_energy_aware.bpf.c` - BPF scheduler implementation
- `src/scx_energy_aware_loader.c` - Userspace loader
- `src/include/rapl_stats.h` - Shared RAPL stats structure
- `Makefile` - Build configuration

## Further Reading

- [sched_ext Documentation](https://docs.kernel.org/scheduler/sched-ext.html)
- [RAPL Interface](https://www.kernel.org/doc/html/latest/power/powercap/powercap.html)
- [BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
