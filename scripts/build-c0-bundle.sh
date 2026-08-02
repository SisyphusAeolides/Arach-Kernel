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
shared_object_image="$build_root/shared-object/libarach-probe.so"
shared_provider_image="$build_root/shared-object/libarach-provider.so"
shared_observer_image="$build_root/shared-object/libarach-observer.so"
shared_core_image="$build_root/shared-object/libarach-core.so"
"$root/scripts/build-shared-object-probe.sh" \
    "$shared_object_image" "$shared_provider_image" \
    "$shared_observer_image" "$shared_core_image"
runtime_linker_image="$build_root/runtime-linker/arach-ld.so"
"$root/scripts/build-runtime-linker-probe.sh" "$runtime_linker_image"
ARACH_SHARED_OBJECT_IMAGE="$shared_object_image" \
    build_none "$root/probes/exec-target/Cargo.toml" "$build_root/exec-target"

exec_target_image="$build_root/exec-target/x86_64-arach/release/arach-exec-target"
test -s "$exec_target_image"
test "$(stat -c %s -- "$exec_target_image")" -le 65536
test "$(readelf -hW "$exec_target_image" | awk '/Number of program headers:/ {print $5}')" -eq 6
test "$(readelf -lW "$exec_target_image" | awk '$1 == "LOAD" {count++} END {print count + 0}')" -eq 3
test -z "$(readelf -lW "$exec_target_image" | awk '$1 == "LOAD" && / W / && / E / {print}')"
test "$(readelf -lW "$exec_target_image" | awk '$1 == "PHDR" {count++} END {print count + 0}')" -eq 1
test "$(readelf -lW "$exec_target_image" | awk '$1 == "INTERP" {count++} END {print count + 0}')" -eq 1
readelf -lW "$exec_target_image" | grep -F '[Requesting program interpreter: /arach-ld.so]' >/dev/null
test "$(readelf -lW "$exec_target_image" | awk '$1 == "DYNAMIC" {count++} END {print count + 0}')" -eq 1
test "$(readelf -dW "$exec_target_image" | awk '$2 == "(NEEDED)" {print $5}')" = '[libarach-probe.so]'
test "$(readelf -dW "$exec_target_image" | awk '$2 == "(NEEDED)" {count++} END {print count + 0}')" -eq 1
test "$(readelf -dW "$exec_target_image" | awk '$2 == "(FLAGS_1)" && /PIE/ {count++} END {print count + 0}')" -eq 1
test "$(readelf -dW "$exec_target_image" | awk '$2 == "(VERSYM)" {count++} END {print count + 0}')" -eq 1
test "$(readelf -dW "$exec_target_image" | awk '$2 == "(VERNEEDNUM)" {print $3}')" -eq 1
test -z "$(readelf -dW "$exec_target_image" | awk '$2 == "(SONAME)" || $2 == "(RUNPATH)" || $2 == "(RPATH)" {print}')"
test "$(readelf -rW "$exec_target_image" | awk '$3 == "R_X86_64_COPY" {count++} END {print count + 0}')" -eq 1
test -z "$(readelf -rW "$exec_target_image" | awk '/^[0-9a-f]+/ && $3 != "R_X86_64_COPY" {print}')"
test "$(readelf -rW "$exec_target_image" | awk '$3 == "R_X86_64_COPY" && $5 ~ /^arach_copy_source@ARACH_PROBE_1[.]0$/ && $7 == "0" {count++} END {print count + 0}')" -eq 1
test "$(readelf --dyn-syms -W "$exec_target_image" | awk '$1 ~ /^[0-9]+:/ {count++} END {print count + 0}')" -eq 2
test "$(readelf --dyn-syms -W "$exec_target_image" | awk '$3 == 24 && $4 == "OBJECT" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 ~ /^arach_copy_source@ARACH_PROBE_1[.]0$/ {count++} END {print count + 0}')" -eq 1
ARACH_EXEC_TARGET_IMAGE="$exec_target_image" \
ARACH_RUNTIME_LINKER_IMAGE="$runtime_linker_image" \
ARACH_SHARED_OBJECT_IMAGE="$shared_object_image" \
ARACH_SHARED_PROVIDER_IMAGE="$shared_provider_image" \
ARACH_SHARED_OBSERVER_IMAGE="$shared_observer_image" \
ARACH_SHARED_CORE_IMAGE="$shared_core_image" \
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
    "$root/scripts/build-reproducible-granite.sh" \
        "$granite_root" "$build_root/granite" "$build_root/granite-repeat" \
        uefi-bin,require-artifacts

granite_image="$build_root/granite/x86_64-unknown-uefi/release/granite.efi"
test -s "$granite_image"
sha256sum "$kernel_image" "$push_image" "$probe_image" "$exec_target_image" \
    "$runtime_linker_image" "$shared_object_image" "$shared_provider_image" \
    "$shared_observer_image" "$shared_core_image" \
    "$granite_image"
