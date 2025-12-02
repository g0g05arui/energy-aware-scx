#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CALLER_USER="${SUDO_USER:-$USER}"
CALLER_HOME="$(getent passwd "${CALLER_USER}" | cut -d: -f6)"
if [[ -z "${CALLER_HOME}" ]]; then
	echo "Unable to determine home directory for ${CALLER_USER}" >&2
	exit 1
fi

KERNEL_DIR="${KERNEL_DIR:-${CALLER_HOME}/scx}"
KERNEL_REF="${KERNEL_REF:-sched_ext-for-6.14}"
APT_PACKAGES=(build-essential bc flex bison libssl-dev libelf-dev libncurses-dev dwarves libcap-dev pkg-config fakeroot jq wget)

sudo apt update
sudo apt install -y "${APT_PACKAGES[@]}"

if [[ ! -d "${KERNEL_DIR}" ]]; then
	git clone https://git.kernel.org/pub/scm/linux/kernel/git/tj/sched_ext.git "${KERNEL_DIR}"
else
	git -C "${KERNEL_DIR}" fetch --all --tags
fi

echo "[*] Checking out ${KERNEL_REF}..."
git -C "${KERNEL_DIR}" checkout "${KERNEL_REF}"

BOOT_CONFIG="/boot/config-$(uname -r)"
SCX_CONFIG="${REPO_ROOT}/scx/kernel.config"

if [[ ! -f "${BOOT_CONFIG}" ]]; then
	echo "Missing ${BOOT_CONFIG}; aborting." >&2
	exit 1
fi

cp "${BOOT_CONFIG}" "${KERNEL_DIR}/.config"
cat "${SCX_CONFIG}" >> "${KERNEL_DIR}/.config"

pushd "${KERNEL_DIR}" >/dev/null
./scripts/config --set-str CONFIG_SYSTEM_TRUSTED_KEYS ""
./scripts/config --set-str CONFIG_SYSTEM_REVOCATION_KEYS ""
./scripts/config --enable CONFIG_DEBUG_INFO
./scripts/config --enable CONFIG_DEBUG_INFO_DWARF4
./scripts/config --enable CONFIG_DEBUG_INFO_BTF
make olddefconfig

make -j"$(nproc)" bindeb-pkg

KERNEL_RELEASE="$(make -s kernelrelease)"
IMAGE_DEB="$(ls "../linux-image-${KERNEL_RELEASE}"_*.deb | head -n1)"
HEADERS_DEB="$(ls "../linux-headers-${KERNEL_RELEASE}"_*.deb | head -n1)"

if [[ -z "${IMAGE_DEB}" || -z "${HEADERS_DEB}" ]]; then
	echo "Failed to locate generated deb packages" >&2
	exit 1
fi

sudo apt install -y --allow-downgrades "${IMAGE_DEB}" "${HEADERS_DEB}"

GRUB_ENTRY="Advanced options for Ubuntu>Ubuntu, with Linux ${KERNEL_RELEASE}"
sudo sed -i "s|^GRUB_DEFAULT=.*|GRUB_DEFAULT=\"${GRUB_ENTRY}\"|" /etc/default/grub
sudo update-grub

pushd tools/bpf/bpftool >/dev/null
make -j"$(nproc)"
sudo cp ./bpftool /usr/local/bin/bpftool
popd >/dev/null

VMLINUX_SRC="${KERNEL_DIR}/vmlinux"
VMLINUX_HDR="${REPO_ROOT}/src/include/vmlinux.h"
SCX_INCLUDE="${SCX_INCLUDE:-${CALLER_HOME}/scx/scheds/include}"
SCX_VMLINUX="${SCX_INCLUDE}/scx/vmlinux.h"
mkdir -p "$(dirname "${VMLINUX_HDR}")"

if [[ -f "${VMLINUX_SRC}" ]]; then
	/usr/local/bin/bpftool btf dump file "${VMLINUX_SRC}" format c > "${VMLINUX_HDR}"
	if [[ -d "$(dirname "${SCX_VMLINUX}")" ]]; then
		echo "[*] Syncing vmlinux.h into ${SCX_VMLINUX}"
		cp "${VMLINUX_HDR}" "${SCX_VMLINUX}"
	else
		echo "Warning: ${SCX_INCLUDE}/scx not found; skipped copying vmlinux.h for sched_ext headers." >&2
	fi
else
	echo "Warning: ${VMLINUX_SRC} not found; skipping vmlinux.h generation." >&2
fi

popd >/dev/null
