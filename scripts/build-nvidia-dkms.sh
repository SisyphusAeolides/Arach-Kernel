#!/usr/bin/env bash
set -euo pipefail

readonly source_root=${NVIDIA_SOURCE_ROOT:-target/nvidia-open}
readonly kernel_source=${ARACH_KBUILD_SOURCE:-target/arach-kbuild/source}
readonly kernel_output=${ARACH_KBUILD_OUTPUT:-target/arach-kbuild/output}

"$(dirname "$0")/audit-nvidia-source.sh" "$source_root"

required_paths=(
    "$kernel_source/Makefile"
    "$kernel_source/scripts/Makefile.modpost"
    "$kernel_output/.config"
    "$kernel_output/Module.symvers"
    "$kernel_output/include/generated/autoconf.h"
    "$kernel_output/include/generated/utsrelease.h"
)

for required in "${required_paths[@]}"; do
    if [[ ! -e "$required" ]]; then
        echo "Arach NVIDIA DKMS gate blocked: missing $required" >&2
        echo "The kernel must export a complete external-Kbuild tree before NVIDIA modules can be built." >&2
        exit 2
    fi
done

make -C "$source_root" modules \
    SYSSRC="$(realpath "$kernel_source")" \
    SYSOUT="$(realpath "$kernel_output")"

for module in nvidia nvidia-modeset nvidia-drm nvidia-uvm; do
    test -s "$source_root/kernel-open/$module.ko" || {
        echo "Arach NVIDIA DKMS gate failed: $module.ko was not produced" >&2
        exit 3
    }
done

echo "NVIDIA modules compiled; runtime qualification still requires Arach load/unload and GPU lifecycle tests."
