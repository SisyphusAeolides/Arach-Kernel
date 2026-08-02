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
source_date_epoch=${SOURCE_DATE_EPOCH:-315532800}
if [[ ! "$source_date_epoch" =~ ^[0-9]+$ ]] \
    || ((${#source_date_epoch} > 10)) \
    || ((source_date_epoch < 315532800 || source_date_epoch > 4354819199)); then
    echo "SOURCE_DATE_EPOCH must fit the FAT timestamp range" >&2
    exit 64
fi
export LC_ALL=C TZ=UTC

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
stage=$(mktemp -d "$parent/.c0-image.XXXXXXXX")
cleanup() {
    rm -rf -- "$stage"
}
trap cleanup EXIT

# 64 MiB is large enough for the bounded Granite inputs and deterministic
# across builders.  mtools operates on the regular file without root access.
image="$stage/arach-c0.img"
tree="$stage/root"
truncate -s $((64 * 1024 * 1024)) "$image"
mkfs.fat --invariant -F 32 -i 00000000 -n ARACHC0 "$image" >/dev/null
mkdir -p -- "$tree/EFI/BOOT" "$tree/BOOT"
install -m 0644 -- "$granite" "$tree/EFI/BOOT/BOOTX64.EFI"
install -m 0644 -- "$arach" "$tree/BOOT/ARACH"
install -m 0644 -- "$push" "$tree/BOOT/PUSH"
install -m 0644 -- "$crest" "$tree/BOOT/CREST"
find "$tree" -xdev -exec touch -h -d "@$source_date_epoch" -- {} +
mcopy -smp -i "$image" "$tree"/* ::/
sync -f "$image"
mv -- "$image" "$output"
rm -rf -- "$stage"
trap - EXIT
sync -f "$parent"
sha256sum "$output"
