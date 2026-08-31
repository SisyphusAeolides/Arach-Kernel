#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kernel=${ARACH_KERNEL_IMAGE:?set ARACH_KERNEL_IMAGE to the measured Arach ELF}
rustd=${ARACH_RUSTD_IMAGE:?set ARACH_RUSTD_IMAGE to the measured RustD PID 1 ELF}
bootstrap=${ARACH_BOOTSTRAP_IMAGE:?set ARACH_BOOTSTRAP_IMAGE to the measured bootstrap ELF}
resolved=${ARACH_RESOLVED_IMAGE:-}
output=${ARACH_GRUB_ISO:-$root/target/arachos-grub/Arach-Kernel-ArachOS.iso}

fail() { printf 'ArachOS GRUB bundle: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"; }
for command in xorriso readelf sha256sum install sed; do need "$command"; done
if command -v grub-file >/dev/null 2>&1; then
    grub_file=grub-file
elif command -v grub2-file >/dev/null 2>&1; then
    grub_file=grub2-file
else
    fail 'missing command: grub-file or grub2-file'
fi
if command -v grub-mkrescue >/dev/null 2>&1; then
    grub_mkrescue=grub-mkrescue
elif command -v grub2-mkrescue >/dev/null 2>&1; then
    grub_mkrescue=grub2-mkrescue
else
    fail 'missing command: grub-mkrescue or grub2-mkrescue'
fi

for artifact in "$kernel" "$rustd" "$bootstrap"; do
    [[ -s $artifact ]] || fail "artifact is missing or empty: $artifact"
done
[[ -z $resolved || -s $resolved ]] || fail "resolver artifact is missing or empty: $resolved"

"$grub_file" --is-x86-multiboot2 "$kernel" \
    || fail 'kernel does not expose a valid x86 Multiboot2 header'
for artifact in "$rustd" "$bootstrap"; do
    readelf -hW "$artifact" | grep -Fq 'Class:                             ELF64' \
        || fail "artifact is not ELF64: $artifact"
done

stage=$(mktemp -d "${TMPDIR:-/tmp}/arachos-grub.XXXXXX")
cleanup() { rm -rf -- "$stage"; }
trap cleanup EXIT
mkdir -p "$stage/boot/grub"
install -m 0644 "$kernel" "$stage/boot/arach"
install -m 0644 "$rustd" "$stage/boot/rustd"
install -m 0644 "$bootstrap" "$stage/boot/bootstrap"
if [[ -n $resolved ]]; then
    install -m 0644 "$resolved" "$stage/boot/rustd-resolved"
fi

resolved_entry=
if [[ -n $resolved ]]; then
    resolved_entry='    module2 /boot/rustd-resolved rustd-resolved'
fi
sed \
    -e "s|@RESOLVED_MODULE@|$resolved_entry|" \
    "$root/packaging/grub/arachos.cfg.in" > "$stage/boot/grub/grub.cfg"

mkdir -p "$(dirname "$output")"
"$grub_mkrescue" -o "$output" "$stage" >/dev/null
"$grub_file" --is-x86-multiboot2 "$stage/boot/arach" \
    || fail 'staged kernel lost its Multiboot2 contract'
sha256sum "$output" "$kernel" "$rustd" "$bootstrap"
if [[ -n $resolved ]]; then sha256sum "$resolved"; fi
printf 'ArachOS GRUB bundle written to %s\n' "$output"
