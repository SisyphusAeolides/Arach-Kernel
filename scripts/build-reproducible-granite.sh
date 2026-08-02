#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
    echo "usage: $0 GRANITE_ROOT FIRST_TARGET SECOND_TARGET FEATURES" >&2
    exit 64
fi

granite_root=$1
first_target=$2
second_target=$3
features=$4
cargo_bin=${CARGO:-cargo}
config="$granite_root/.cargo/config.toml"
verifier="$granite_root/scripts/verify-uefi-image.sh"

[[ "$first_target" != "$second_target" ]] || {
    echo "Granite target directories must be distinct" >&2
    exit 64
}
[[ -f "$granite_root/Cargo.toml" && ! -L "$granite_root/Cargo.toml" ]] || {
    echo "invalid Granite manifest" >&2
    exit 66
}
[[ -f "$config" && ! -L "$config" ]] || {
    echo "Granite Cargo configuration is required" >&2
    exit 66
}
[[ -x "$verifier" && ! -L "$verifier" ]] || {
    echo "Granite UEFI verifier is required" >&2
    exit 66
}

for target_dir in "$first_target" "$second_target"; do
    CARGO_TARGET_DIR="$target_dir" \
        "$cargo_bin" --config "$config" build --locked --release \
            --manifest-path "$granite_root/Cargo.toml" \
            --target x86_64-unknown-uefi \
            --features "$features"
done

first="$first_target/x86_64-unknown-uefi/release/granite.efi"
second="$second_target/x86_64-unknown-uefi/release/granite.efi"
[[ -s "$first" && -s "$second" ]] || {
    echo "Granite did not produce both UEFI images" >&2
    exit 1
}
cmp --silent "$first" "$second" || {
    echo "Granite production UEFI builds differ" >&2
    exit 1
}
"$verifier" "$first" "$second"
sha256sum "$first" "$second"
