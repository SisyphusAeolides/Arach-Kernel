#!/usr/bin/env bash
set -euo pipefail

readonly source_root=${NVIDIA_SOURCE_ROOT:-target/nvidia-open}
readonly kernel_source=${ARACH_KBUILD_SOURCE:-target/arach-kbuild/source}
readonly kernel_output=${ARACH_KBUILD_OUTPUT:-target/arach-kbuild/output}
readonly jobs=${NVIDIA_BUILD_JOBS:-4}
readonly report=${NVIDIA_BUILD_REPORT:-target/nvidia-dkms/build-measurement.json}
readonly inspection=${NVIDIA_INSPECTION_OUTPUT:-target/nvidia-dkms/inspection}
readonly vermagic_file=${ARACH_KBUILD_VERMAGIC_FILE:-target/arach-kbuild/vermagic}

case "$jobs" in
    ''|*[!0-9]*|0) echo "NVIDIA_BUILD_JOBS must be a positive integer" >&2; exit 1 ;;
esac

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

make -j "$jobs" -C "$source_root" modules \
    SYSSRC="$(realpath "$kernel_source")" \
    SYSOUT="$(realpath "$kernel_output")"

for module in nvidia nvidia-modeset nvidia-drm nvidia-uvm; do
    test -s "$source_root/kernel-open/$module.ko" || {
        echo "Arach NVIDIA DKMS gate failed: $module.ko was not produced" >&2
        exit 3
    }
done

kernel_release=$(sed -n \
    's/^#define UTS_RELEASE "\(.*\)"/\1/p' \
    "$kernel_output/include/generated/utsrelease.h")
test -n "$kernel_release" || {
    echo "Arach NVIDIA DKMS gate failed: generated UTS release is empty" >&2
    exit 3
}
test -s "$vermagic_file" || {
    echo "Arach NVIDIA DKMS gate failed: missing measured vermagic file $vermagic_file" >&2
    exit 3
}
expected_vermagic=$(sed -n '1p' "$vermagic_file")
test -n "$expected_vermagic" || {
    echo "Arach NVIDIA DKMS gate failed: expected vermagic is empty" >&2
    exit 3
}

mkdir -p "$inspection"

for module in nvidia nvidia-modeset nvidia-drm nvidia-uvm; do
    artifact=$source_root/kernel-open/$module.ko
    sections=$inspection/$module.sections
    readelf --sections --wide "$artifact" >"$sections"
    grep -Fq .modinfo "$sections" || {
        echo "Arach NVIDIA DKMS gate failed: $module.ko lacks .modinfo" >&2
        exit 3
    }
    vermagic=$(modinfo -F vermagic "$artifact")
    case "$vermagic" in
        "$kernel_release"*) ;;
        *)
            echo "Arach NVIDIA DKMS gate failed: $module.ko vermagic '$vermagic' does not match $kernel_release" >&2
            exit 3
            ;;
    esac
    cargo run --quiet --manifest-path "$(dirname "$0")/../Cargo.toml" \
        --bin arach-ko-inspect -- "$artifact"
    cargo run --quiet --manifest-path "$(dirname "$0")/../Cargo.toml" \
        --bin arach-ko-admit -- \
        "$artifact" "$vermagic_file" \
        "$kernel_output/Module.symvers" \
        "$source_root/kernel-open/Module.symvers"
done

nvidia_digest=$(sha256sum "$source_root/kernel-open/nvidia.ko" | cut -d' ' -f1)
modeset_digest=$(sha256sum "$source_root/kernel-open/nvidia-modeset.ko" | cut -d' ' -f1)
drm_digest=$(sha256sum "$source_root/kernel-open/nvidia-drm.ko" | cut -d' ' -f1)
uvm_digest=$(sha256sum "$source_root/kernel-open/nvidia-uvm.ko" | cut -d' ' -f1)
mkdir -p "$(dirname "$report")"
cat >"$report" <<EOF
{
  "suite": "arach-nvidia-open-kbuild",
  "release": "610.43.03",
  "source_revision": "452cec62d827034798072827d3866d1881662b77",
  "kernel_release": "$kernel_release",
  "vermagic": "$expected_vermagic",
  "workers": $jobs,
  "nvidia_ko_sha256": "$nvidia_digest",
  "nvidia_modeset_ko_sha256": "$modeset_digest",
  "nvidia_drm_ko_sha256": "$drm_digest",
  "nvidia_uvm_ko_sha256": "$uvm_digest",
  "arach_structural_preflight": true,
  "exact_vermagic": true,
  "symbol_crc_admission": true,
  "export_policy_admission": true,
  "load_layout_planning": true,
  "wx_region_planning": true,
  "relocation_binding": true,
  "build_qualified": true,
  "runtime_qualified": false
}
EOF

echo "NVIDIA modules compiled and measured for $kernel_release"
echo "Runtime qualification still requires Arach load/unload and GPU lifecycle tests."
