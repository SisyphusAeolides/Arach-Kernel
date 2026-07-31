#!/usr/bin/env bash
set -euo pipefail

# Build the deterministic FAT volume consumed by Granite.  The four input
# files are already measured by Granite at compile time; this script only
# performs bounded layout and never modifies a target installation.

if [[ $# -ne 5 ]]; then
    echo "usage: $0 GRANITE_EFI ARACH_KERNEL PUSH CREST OUTPUT_IMG" >&2
    exit 64
fi

granite=$1
arach=$2
push=$3
crest=$4
output=$5
[[ "$output" = /* ]] || { echo "output image must be absolute" >&2; exit 64; }
[[ ! -e "$output" ]] || { echo "output image already exists" >&2; exit 1; }

max_bytes=$((32 * 1024 * 1024))
check_file() {
    local path=$1
    [[ -f "$path" && ! -L "$path" ]] || { echo "invalid artifact: $path" >&2; exit 1; }
    local size
    size=$(stat -c '%s' -- "$path")
    [[ "$size" -gt 0 && "$size" -le "$max_bytes" ]] || {
        echo "artifact exceeds the bounded image contract: $path" >&2
        exit 1
    }
}
check_file "$granite"
check_file "$arach"
check_file "$push"
check_file "$crest"
head -c 2 "$granite" | cmp -s - <(printf 'MZ') || {
    echo "Granite is not a PE/COFF image" >&2
    exit 1
}
for path in "$arach" "$push" "$crest"; do
    head -c 4 "$path" | cmp -s - <(printf '\177ELF') || {
        echo "ELF header missing from $path" >&2
        exit 1
    }
done

parent=$(dirname -- "$output")
mkdir -p -- "$parent"
stage=$(mktemp "$parent/.c0-image.XXXXXX")
cleanup() {
    rm -f -- "$stage"
}
trap cleanup EXIT

# 64 MiB is large enough for the bounded Granite inputs and deterministic
# across builders.  mtools operates on the regular file without root access.
truncate -s $((64 * 1024 * 1024)) "$stage"
mkfs.fat -F 32 -n ARACHC0 "$stage" >/dev/null
mmd -i "$stage" ::/EFI
mmd -i "$stage" ::/EFI/BOOT
mmd -i "$stage" ::/BOOT
mcopy -i "$stage" "$granite" ::/EFI/BOOT/BOOTX64.EFI
mcopy -i "$stage" "$arach" ::/BOOT/ARACH
mcopy -i "$stage" "$push" ::/BOOT/PUSH
mcopy -i "$stage" "$crest" ::/BOOT/CREST
sync -f "$stage"
mv -- "$stage" "$output"
trap - EXIT
sync -f "$parent"
sha256sum "$output"
