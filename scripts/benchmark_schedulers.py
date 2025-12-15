#!/usr/bin/env python3
"""
Benchmark helper that compares the default eeVDF scheduler against the
scx_energy_aware scheduler.  It runs a handful of workloads, records
runtime, estimates energy by sampling RAPL counters, and computes a
simple fairness metric based on how evenly CPU time was distributed
across logical CPUs.  Results are plotted with matplotlib so it is easy
to see where the schedulers differ.

Usage:
    sudo python3 scripts/benchmark_schedulers.py \
        --scx ./build/scx_energy_aware \
        --workdir ./build \
        --prefer-primary 1 \
        --output ./build/benchmark_results.png

The script requires root so it can start/stop the scx scheduler and
read RAPL counters.  Workloads are defined near the top of the file; add
or remove entries to match your benchmarking needs.
"""

from __future__ import annotations


import argparse
import json
import math
import os
import shutil
import signal
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import matplotlib.pyplot as plt


WORKLOADS = [
    {
        "name": "hackbench",
        "cmd": ["hackbench", "-l", "100", "-g", "20", "-f", "25"],
        "description": "scheduler latency/IPC benchmark",
        "ops_scale": 1.0,
    },
    {
        "name": "stress-ng-matrix",
        "cmd": ["stress-ng", "--matrix", "40", "--timeout", "60"],
        "description": "floating point heavy workload",
        "ops_scale": 1.0,
    },
    {
        "name": "stress-ng-io",
        "cmd": ["stress-ng", "--hdd", "8", "--timeout", "45"],
        "description": "I/O heavy tasks",
        "ops_scale": 1.0,
    },
]

METRIC_CONFIG = {
    "runtime_s": "Runtime (s)",
    "throughput_ops": "Throughput (ops/s)",
    "energy_j": "Energy (J)",
    "fairness_cv": "Fairness CoV",
    "avg_power_w": "Avg Power (W)",
}


class SchedulerMode:
    def __init__(self, name: str, mode_type: str, cmd: Optional[List[str]] = None):
        self.name = name
        self.mode_type = mode_type
        self.cmd = cmd or []

    def __repr__(self) -> str:
        return f"SchedulerMode(name={self.name}, mode_type={self.mode_type})"


SCHEDULERS = [
    SchedulerMode(name="eevdf", mode_type="baseline"),
    SchedulerMode(name="scx_energy_aware", mode_type="scx"),
]


def read_rapl_energy() -> Tuple[int, Dict[str, int]]:
    """Read energy_uj from all RAPL package domains."""
    root = Path("/sys/class/powercap")
    energies = {}
    ts = time.monotonic_ns()
    if not root.exists():
        return ts, energies

    for pkg in root.glob("intel-rapl:*"):
        energy_file = pkg / "energy_uj"
        if not energy_file.exists():
            continue
        try:
            energies[pkg.name] = int(energy_file.read_text().strip())
        except OSError:
            continue
    return ts, energies


def rapl_delta(
    start: Tuple[int, Dict[str, int]], end: Tuple[int, Dict[str, int]]
) -> Tuple[float, float]:
    """Return (energy_joules, avg_power_watts) based on RAPL readings."""
    t0, e0 = start
    t1, e1 = end
    if not e0 or not e1:
        return 0.0, 0.0
    dt = (t1 - t0) / 1e9
    if dt <= 0:
        return 0.0, 0.0
    total_uj = 0
    for domain, val in e1.items():
        prev = e0.get(domain)
        if prev is None:
            continue
        delta = val - prev
        if delta < 0:
            continue
        total_uj += delta
    energy_j = total_uj / 1_000_000.0
    avg_power = energy_j / dt if dt else 0.0
    return energy_j, avg_power


def read_proc_stat() -> Dict[str, List[int]]:
    stats = {}
    with open("/proc/stat", "r", encoding="utf-8") as f:
        for line in f:
            if not line.startswith("cpu"):
                continue
            parts = line.split()
            key = parts[0]
            values = list(map(int, parts[1:]))
            stats[key] = values
    return stats


def cpu_busy_ticks(snapshot: Dict[str, List[int]]) -> Dict[str, int]:
    busy = {}
    for cpu, vals in snapshot.items():
        if cpu == "cpu":
            continue
        if len(vals) < 4:
            continue
        busy[cpu] = sum(vals[:3])  # user + nice + system ticks
    return busy


def fairness_score(before: Dict[str, List[int]], after: Dict[str, List[int]]) -> float:
    busy_before = cpu_busy_ticks(before)
    busy_after = cpu_busy_ticks(after)
    deltas = []
    for cpu, val in busy_after.items():
        prev = busy_before.get(cpu)
        if prev is None:
            continue
        delta = val - prev
        if delta > 0:
            deltas.append(delta)
    if len(deltas) <= 1:
        return 0.0
    mean = statistics.mean(deltas)
    if mean == 0:
        return 0.0
    return statistics.stdev(deltas) / mean


def run_command(cmd: List[str], env: Optional[Dict[str, str]] = None) -> Tuple[int, str, str]:
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env
    )
    out, err = proc.communicate()
    return proc.returncode, out, err


def start_scheduler(sched: SchedulerMode, args: argparse.Namespace) -> Optional[subprocess.Popen]:
    if sched.mode_type == "baseline":
        return None

    cmd = [args.scx_loader, f"--prefer-primary={args.prefer_primary}"]
    if args.scx_extra_args:
        cmd.extend(args.scx_extra_args)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    # Give the loader a moment to attach
    time.sleep(2)
    return proc


def stop_scheduler(proc: Optional[subprocess.Popen]) -> None:
    if not proc:
        return
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


def run_workload(cmd: List[str], workdir: Optional[str] = None) -> Tuple[int, str, str, float]:
    start = time.monotonic()
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=workdir
    )
    out, err = proc.communicate()
    end = time.monotonic()
    return proc.returncode, out, err, end - start


def ensure_tools() -> None:
    for tool in ("hackbench", "stress-ng"):
        if not shutil.which(tool):
            raise RuntimeError(f"{tool} not found in PATH")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare eeVDF vs scx_energy_aware with fairness/energy/perf graphs."
    )
    parser.add_argument("--scx-loader", default="./build/scx_energy_aware", help="Path to scx loader binary")
    parser.add_argument("--prefer-primary", type=int, default=1, help="Prefer primary SMT threads (1=yes,0=no)")
    parser.add_argument("--scx-extra-args", nargs="*", help="Additional args for the scx loader")
    parser.add_argument("--output", default="./build/benchmark_results.png", help="Output graph path")
    parser.add_argument("--results-json", default="./build/benchmark_results.json", help="Raw results JSON")
    parser.add_argument("--workdir", default=".", help="Working directory for workloads")
    parser.add_argument(
        "--cooldown-seconds",
        type=int,
        default=10,
        help="Sleep between scheduler runs so cores can cool (seconds)",
    )
    args = parser.parse_args()

    ensure_tools()

    results: Dict[str, Dict[str, Dict[str, float]]] = {}

    for sched in SCHEDULERS:
        print(f"\n=== Running benchmarks under {sched.name} ===")
        loader_proc = start_scheduler(sched, args)
        try:
            for workload in WORKLOADS:
                print(f"  -> {workload['name']}: {workload['description']}")
                before_stat = read_proc_stat()
                rapl_before = read_rapl_energy()
                rc, out, err, runtime = run_workload(workload["cmd"], workdir=args.workdir)
                rapl_after = read_rapl_energy()
                after_stat = read_proc_stat()

                if rc != 0:
                    print(f"     workload failed (rc={rc})\n{err}")
                    continue

                energy_j, avg_power = rapl_delta(rapl_before, rapl_after)
                fairness = fairness_score(before_stat, after_stat)

                throughput = 0.0
                if runtime > 0:
                    throughput = float(workload.get("ops_scale", 1.0)) / runtime

                workload_results = results.setdefault(workload["name"], {})
                results[workload["name"]][sched.name] = {
                    "runtime_s": runtime,
                    "throughput_ops": throughput,
                    "energy_j": energy_j,
                    "avg_power_w": avg_power,
                    "fairness_cv": fairness,
                }

                print(
                    f"     runtime={runtime:.2f}s energy={energy_j:.2f}J "
                    f"power={avg_power:.2f}W fairness_cv={fairness:.3f}"
                )

                workload_pause = max(args.cooldown_seconds / 2.0, 0.0)
                if workload_pause > 0:
                    print(f"     cooling before next workload for {workload_pause:.1f}s...")
                    time.sleep(workload_pause)
        finally:
            stop_scheduler(loader_proc)
            if args.cooldown_seconds > 0:
                print(f"Cooling down for {args.cooldown_seconds}s...")
                time.sleep(args.cooldown_seconds)

    if not results:
        print("No benchmark data collected.")
        return

    output_dir = Path(args.output).resolve().parent
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(args.results_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
        print(f"\nSaved raw results to {args.results_json}")

    plot_results(results, args.output)
    print(f"Graphs saved to {args.output}")


def plot_results(results: Dict[str, Dict[str, Dict[str, float]]], output_path: str) -> None:
    sched_names = [sched.name for sched in SCHEDULERS]
    workload_names = list(results.keys())
    metrics = ["runtime_s", "throughput_ops", "energy_j", "fairness_cv"]
    fig, axes = plt.subplots(len(metrics), 1, figsize=(12, 4 * len(metrics)))

    if len(metrics) == 1:
        axes = [axes]

    for ax, metric in zip(axes, metrics):
        width = 0.35
        x = range(len(results))
        for idx, sched in enumerate(sched_names):
            vals = []
            for workload in workload_names:
                vals.append(results[workload].get(sched, {}).get(metric, math.nan))
            offsets = [i + (idx - len(sched_names) / 2) * width for i in x]
            ax.bar(offsets, vals, width, label=sched)
        ax.set_xticks(list(x))
        ax.set_xticklabels(workload_names)
        ax.set_ylabel(METRIC_CONFIG.get(metric, metric))
        ax.set_title(METRIC_CONFIG.get(metric, metric))
        ax.legend()

    fig.tight_layout()
    fig.savefig(output_path)


if __name__ == "__main__":
    main()
