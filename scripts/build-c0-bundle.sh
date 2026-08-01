#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
push_root="${ARACH_PUSH_ROOT:?set ARACH_PUSH_ROOT to the Push checkout}"
granite_root="${ARACH_GRANITE_ROOT:?set ARACH_GRANITE_ROOT to the Granite checkout}"
cargo_bin="${CARGO:-cargo}"
target="$root/x86_64-arach.json"
build_root="${ARACH_C0_BUILD_ROOT:-$root/target/c0}"
push_features="${ARACH_PUSH_FEATURES:-os-bin}"

test -f "$push_root/Cargo.toml"
test -f "$granite_root/Cargo.toml"
mkdir -p "$build_root"

build_none() {
    local manifest="$1"
    local target_dir="$2"
    shift 2
    CARGO_TARGET_DIR="$target_dir" "$cargo_bin" build \
        --locked --release --manifest-path "$manifest" --target "$target" \
        -Z json-target-spec -Z build-std=core,alloc,compiler_builtins \
        -Z build-std-features=compiler-builtins-mem "$@"
}

build_none "$push_root/Cargo.toml" "$build_root/push" --features "$push_features"
runtime_linker_image="$build_root/runtime-linker/arach-ld.so"
"$root/scripts/build-runtime-linker-probe.sh" "$runtime_linker_image"
build_none "$root/probes/exec-target/Cargo.toml" "$build_root/exec-target"

exec_target_image="$build_root/exec-target/x86_64-arach/release/arach-exec-target"
test -s "$exec_target_image"
ARACH_EXEC_TARGET_IMAGE="$exec_target_image" \
ARACH_RUNTIME_LINKER_IMAGE="$runtime_linker_image" \
    build_none "$root/probes/c0/Cargo.toml" "$build_root/probe"

push_image="$build_root/push/x86_64-arach/release/push"
probe_image="$build_root/probe/x86_64-arach/release/arach-c0-probe"
test -s "$push_image"
test -s "$probe_image"

"$root/scripts/bootstrap-formal-toolchains.sh"
ARACH_PUSH_IMAGE="$push_image" \
ARACH_BOOTSTRAP_IMAGE="$probe_image" \
ARACH_BOOTSTRAP_ABI="${ARACH_BOOTSTRAP_ABI:-linux}" \
CARGO_TARGET_DIR="$build_root/kernel" \
    "$cargo_bin" build --locked --release -p arach --bin arach \
        --no-default-features --features kernel-bin,reference-driver,fortran-control \
        --target "$target" -Z json-target-spec \
        -Z build-std=core,alloc,compiler_builtins \
        -Z build-std-features=compiler-builtins-mem

kernel_image="$build_root/kernel/x86_64-arach/release/arach"
test -s "$kernel_image"

ARACH_KERNEL_IMAGE="$kernel_image" \
ARACH_PUSH_IMAGE="$push_image" \
ARACH_CREST_IMAGE="$probe_image" \
CARGO_TARGET_DIR="$build_root/granite" \
    "$cargo_bin" build --locked --release --manifest-path "$granite_root/Cargo.toml" \
        --target x86_64-unknown-uefi --features uefi-bin,require-artifacts

granite_image="$build_root/granite/x86_64-unknown-uefi/release/granite.efi"
test -s "$granite_image"
sha256sum "$kernel_image" "$push_image" "$probe_image" "$exec_target_image" \
    "$runtime_linker_image" "$granite_image"
