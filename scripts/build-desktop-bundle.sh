#!/usr/bin/env bash
set -euo pipefail

# Build the production measured bundle. C0 remains available through
# build-c0-bundle.sh; this path is the only one that enables native COSMIC.
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
push_root="${ARACH_PUSH_ROOT:?set ARACH_PUSH_ROOT to the Push checkout}"
granite_root="${ARACH_GRANITE_ROOT:?set ARACH_GRANITE_ROOT to the Granite checkout}"
cosmic_root="${ARACH_COSMIC_SERVICES_DIR:?set ARACH_COSMIC_SERVICES_DIR to eight target-compatible COSMIC seat, audio, D-Bus, and desktop ELF images}"
cargo_bin="${CARGO:-cargo}"
target="$root/x86_64-arach.json"
build_root="${ARACH_DESKTOP_BUILD_ROOT:-$root/target/desktop}"
output_root="${ARACH_DESKTOP_BUNDLE_ROOT:-$build_root/bundle}"
push_features="${ARACH_PUSH_FEATURES:-os-bin,cosmic-boot}"

test -f "$push_root/Cargo.toml"
test -f "$granite_root/Cargo.toml"
test -d "$cosmic_root"
[[ ",$push_features," == *,os-bin,* && ",$push_features," == *,cosmic-boot,* ]] || {
    echo 'production bundle requires Push features os-bin and cosmic-boot' >&2
    exit 1
}

cosmic_artifacts=(
    seatd
    pipewire
    wireplumber
    dbus-broker
    cosmic-comp
    cosmic-greeter
    cosmic-session
    xdg-desktop-portal-cosmic
)
for artifact in "${cosmic_artifacts[@]}"; do
    path="$cosmic_root/$artifact"
    [[ -f "$path" && ! -L "$path" ]] || {
        echo "missing native COSMIC service: $path" >&2
        exit 1
    }
    size=$(stat -c '%s' -- "$path")
    [[ "$size" -gt 0 && "$size" -le $((16 * 1024 * 1024)) ]] || {
        echo "native COSMIC service has an invalid size: $path" >&2
        exit 1
    }
    head -c 4 -- "$path" | cmp -s - <(printf '\177ELF') || {
        echo "native COSMIC service is not an ELF image: $path" >&2
        exit 1
    }
done

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
build_none "$root/probes/c0/Cargo.toml" "$build_root/probe"

push_image="$build_root/push/x86_64-arach/release/push"
probe_image="$build_root/probe/x86_64-arach/release/arach-c0-probe"
test -s "$push_image"
test -s "$probe_image"

"$root/scripts/bootstrap-formal-toolchains.sh"
ARACH_COSMIC_SERVICES_DIR="$cosmic_root" \
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

ARACH_COSMIC_SERVICES_DIR="$cosmic_root" \
ARACH_KERNEL_IMAGE="$kernel_image" \
ARACH_PUSH_IMAGE="$push_image" \
ARACH_CREST_IMAGE="$probe_image" \
CARGO_TARGET_DIR="$build_root/granite" \
    "$cargo_bin" build --locked --release --manifest-path "$granite_root/Cargo.toml" \
        --target x86_64-unknown-uefi --features uefi-bin,require-artifacts,cosmic-boot

granite_image="$build_root/granite/x86_64-unknown-uefi/release/granite.efi"
test -s "$granite_image"

stage="$output_root.tmp.$$"
rm -rf -- "$stage"
mkdir -p -- "$stage"
install -m 0644 -- "$granite_image" "$stage/granite.efi"
install -m 0644 -- "$kernel_image" "$stage/arach"
install -m 0644 -- "$push_image" "$stage/push"
install -m 0644 -- "$probe_image" "$stage/crest"
for artifact in "${cosmic_artifacts[@]}"; do
    install -m 0644 -- "$cosmic_root/$artifact" "$stage/$artifact"
done
mkdir -p -- "$(dirname -- "$output_root")"
rm -rf -- "$output_root"
mv -- "$stage" "$output_root"
sha256sum "$output_root"/*
