#!/usr/bin/env bash
set -euo pipefail

if ! command -v bpftool >/dev/null 2>&1; then
	exit 1
fi

symbol="therm_read_ia32_therm_status"
btf_dir="/sys/kernel/btf"
btf_paths=()

if [[ -r "${btf_dir}/vmlinux" ]]; then
	btf_paths+=("${btf_dir}/vmlinux")
fi

if [[ -d "${btf_dir}" ]]; then
	while IFS= read -r -d '' path; do
		[[ "${path}" == "${btf_dir}/vmlinux" ]] && continue
		btf_paths+=("${path}")
	done < <(find "${btf_dir}" -maxdepth 1 -type f -print0 2>/dev/null || true)
fi

for path in "${btf_paths[@]}"; do
	if bpftool btf dump file "${path}" name "${symbol}" >/dev/null 2>&1; then
		exit 0
	fi
done

exit 1
