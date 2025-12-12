#!/usr/bin/env bash
set -euo pipefail

if ! command -v bpftool >/dev/null 2>&1; then
	exit 1
fi

btf_path="/sys/kernel/btf/vmlinux"

if [[ ! -r "${btf_path}" ]]; then
	exit 1
fi

if bpftool btf dump file "${btf_path}" name therm_read_ia32_therm_status >/dev/null 2>&1; then
	exit 0
fi

exit 1
