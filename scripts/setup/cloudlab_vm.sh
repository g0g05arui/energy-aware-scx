#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KERNEL_DIR="${KERNEL_DIR:-$HOME/scx-kernel}"
KERNEL_REF="${KERNEL_REF:-sched_ext-for-6.12}"
APT_PACKAGES=(build-essential bc flex bison libssl-dev libelf-dev libncurses-dev dwarves libcap-dev pkg-config fakeroot jq wget)

echo "[*] Installing build dependencies..."
sudo apt update
sudo apt install -y "${APT_PACKAGES[@]}"

echo "[*] Ensuring sched_ext kernel tree exists..."
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

echo "[*] Preparing kernel configuration..."
cp "${BOOT_CONFIG}" "${KERNEL_DIR}/.config"
cat "${SCX_CONFIG}" >> "${KERNEL_DIR}/.config"

pushd "${KERNEL_DIR}" >/dev/null
./scripts/config --set-str CONFIG_SYSTEM_TRUSTED_KEYS ""
./scripts/config --set-str CONFIG_SYSTEM_REVOCATION_KEYS ""
./scripts/config --enable CONFIG_DEBUG_INFO
./scripts/config --enable CONFIG_DEBUG_INFO_DWARF4
./scripts/config --enable CONFIG_DEBUG_INFO_BTF
make olddefconfig

echo "[*] Building kernel packages..."
make -j"$(nproc)" bindeb-pkg

KERNEL_RELEASE="$(make -s kernelrelease)"
IMAGE_DEB="$(ls "../linux-image-${KERNEL_RELEASE}"_*.deb | head -n1)"
HEADERS_DEB="$(ls "../linux-headers-${KERNEL_RELEASE}"_*.deb | head -n1)"

if [[ -z "${IMAGE_DEB}" || -z "${HEADERS_DEB}" ]]; then
	echo "Failed to locate generated deb packages" >&2
	exit 1
fi

echo "[*] Installing kernel packages..."
sudo apt install -y "${IMAGE_DEB}" "${HEADERS_DEB}"

GRUB_ENTRY="Advanced options for Ubuntu>Ubuntu, with Linux ${KERNEL_RELEASE}"
echo "[*] Setting GRUB default to ${GRUB_ENTRY}"
sudo sed -i "s|^GRUB_DEFAULT=.*|GRUB_DEFAULT=\"${GRUB_ENTRY}\"|" /etc/default/grub
sudo update-grub

echo "[*] Building bpftool from the kernel tree..."
pushd tools/bpf/bpftool >/dev/null
make -j"$(nproc)"
sudo cp ./bpftool /usr/local/bin/bpftool
popd >/dev/null

VMLINUX_SRC="${KERNEL_DIR}/vmlinux"
VMLINUX_HDR="${REPO_ROOT}/src/include/vmlinux.h"
mkdir -p "$(dirname "${VMLINUX_HDR}")"

echo "[*] Generating ${VMLINUX_HDR} from ${VMLINUX_SRC}..."
if [[ -f "${VMLINUX_SRC}" ]]; then
	/usr/local/bin/bpftool btf dump file "${VMLINUX_SRC}" format c > "${VMLINUX_HDR}"
else
	echo "Warning: ${VMLINUX_SRC} not found; skipping vmlinux.h generation." >&2
fi

popd >/dev/null

cat <<EOF

======================================================================
Kernel ${KERNEL_RELEASE} installed and src/include/vmlinux.h updated
from the built tree. Reboot to use it. After booting into the new
kernel, you can regenerate the header directly from /sys/kernel/btf to
keep it in sync:
  sudo /usr/local/bin/bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/include/vmlinux.h
======================================================================
EOF
