#!/bin/bash

set -e

# Update packages
sudo apt update

cd ~

# Clone sched-ext
git clone https://github.com/sched-ext/scx.git

# Install dependencies
sudo apt-get install -y clang llvm libbpf-dev libelf-dev
sudo apt install -y libssl-dev
sudo apt install -y make gcc zlib1g-dev flex bison

# Clone bpftool with submodules
git clone --depth=1 https://github.com/libbpf/bpftool
cd bpftool
git submodule update --init --recursive

# Build bpftool
cd src
make
sudo make install

# Generate vmlinux.h
cd ~/energy-aware-scx
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/include/vmlinux.h

sudo modprobe intel_rapl_msr intel_rapl_common