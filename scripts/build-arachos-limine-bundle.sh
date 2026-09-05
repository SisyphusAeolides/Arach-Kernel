#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kernel=${ARACH_KERNEL_IMAGE:?set ARACH_KERNEL_IMAGE to the measured Arach ELF}
rustd=${ARACH_RUSTD_IMAGE:?set ARACH_RUSTD_IMAGE to the measured RustD PID 1 ELF}
bootstrap=${ARACH_BOOTSTRAP_IMAGE:?set ARACH_BOOTSTRAP_IMAGE to the measured bootstrap ELF}
resolved=${ARACH_RESOLVED_IMAGE:-}
output=${ARACH_LIMINE_ISO:-$root/target/arachos-limine/Arach-Kernel-ArachOS.iso}

fail() { printf 'ArachOS Limine bundle: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"; }

for command in limine xorriso readelf sha256sum install find awk od; do
    need "$command"
done

for artifact in "$kernel" "$rustd" "$bootstrap"; do
    [[ -s $artifact ]] || fail "artifact is missing or empty: $artifact"
done
[[ -z $resolved || -s $resolved ]] || fail "resolver artifact is missing or empty: $resolved"

for artifact in "$rustd" "$bootstrap"; do
    readelf -hW "$artifact" | grep -Fq 'Class:                             ELF64' \
        || fail "artifact is not ELF64: $artifact"
done

# grub-file is useful when the GRUB tools are installed, but the kernel's
# Multiboot2 header can also be checked directly. Keeping the fallback makes
# this qualification script usable on a clean Arch host that only has Limine.
if command -v grub-file >/dev/null 2>&1; then
    grub-file --is-x86-multiboot2 "$kernel" \
        || fail 'kernel does not expose a valid x86 Multiboot2 header'
elif command -v grub2-file >/dev/null 2>&1; then
    grub2-file --is-x86-multiboot2 "$kernel" \
        || fail 'kernel does not expose a valid x86 Multiboot2 header'
else
    header_offset=$(readelf -SW "$kernel" \
        | awk '$3 == ".multiboot_header" {print $6; exit}')
    [[ -n $header_offset ]] || fail 'kernel has no .multiboot_header section'
    header_magic=$(od -An -tx4 -N4 -j "$((16#$header_offset))" "$kernel" \
        | tr -d '[:space:]')
    [[ $header_magic == e85250d6 ]] \
        || fail 'kernel Multiboot2 header has the wrong magic'
fi

limine_data=$(limine --print-datadir)
[[ -d $limine_data ]] || fail "Limine data directory is missing: $limine_data"
for asset in limine-bios.sys limine-bios-cd.bin limine-uefi-cd.bin BOOTX64.EFI; do
    [[ -s $limine_data/$asset ]] || fail "Limine asset is missing: $limine_data/$asset"
done

stage=$(mktemp -d "${TMPDIR:-/tmp}/arachos-limine.XXXXXX")
cleanup() { find "$stage" -depth -delete 2>/dev/null || :; }
trap cleanup EXIT

mkdir -p "$stage/boot" "$stage/EFI/BOOT"
install -m 0644 "$kernel" "$stage/boot/arach"
install -m 0644 "$rustd" "$stage/boot/rustd"
install -m 0644 "$bootstrap" "$stage/boot/bootstrap"
if [[ -n $resolved ]]; then
    install -m 0644 "$resolved" "$stage/boot/rustd-resolved"
fi
install -m 0644 "$limine_data/limine-bios.sys" "$stage/boot/limine-bios.sys"
install -m 0644 "$limine_data/limine-bios-cd.bin" "$stage/boot/limine-bios-cd.bin"
install -m 0644 "$limine_data/limine-uefi-cd.bin" "$stage/boot/limine-uefi-cd.bin"
install -m 0644 "$limine_data/BOOTX64.EFI" "$stage/EFI/BOOT/BOOTX64.EFI"

cat > "$stage/limine.conf" <<'CONFIG'
timeout: 0
serial: yes
serial_baudrate: 115200
verbose: yes
measured_boot: yes

/ArachOS — Arach Kernel (qualification)
    protocol: multiboot2
    kernel_path: boot():/boot/arach
    cmdline: arachos=1 init=/usr/lib/rustd/rustd
    module_path: boot():/boot/rustd
    module_string: rustd
    module_path: boot():/boot/bootstrap
    module_string: arachos-bootstrap
    module_path: boot():/boot/rustd-resolved
    module_string: rustd-resolved
CONFIG
if [[ -z $resolved ]]; then
    sed -i '/module_path: boot():\/boot\/rustd-resolved/,+1d' "$stage/limine.conf"
fi

mkdir -p "$(dirname "$output")"
# xorriso needs an alternate El Torito record for the UEFI image. The
# partition offset leaves the ISO's protective MBR compatible with Limine's
# BIOS installer while retaining a hybrid image for ordinary USB media.
xorriso -as mkisofs -R -r -J \
    -b boot/limine-bios-cd.bin \
    -no-emul-boot -boot-load-size 4 -boot-info-table \
    -hfsplus -apm-block-size 2048 \
    -eltorito-alt-boot --efi-boot boot/limine-uefi-cd.bin \
    -efi-boot-part --efi-boot-image \
    -isohybrid-gpt-basdat -isohybrid-apm-hfsplus \
    -partition_offset 16 --protective-msdos-label \
    "$stage" -o "$output" >/dev/null
limine bios-install "$output" >/dev/null

sha256sum "$output" "$kernel" "$rustd" "$bootstrap"
if [[ -n $resolved ]]; then sha256sum "$resolved"; fi
printf 'ArachOS Limine bundle written to %s\n' "$output"
