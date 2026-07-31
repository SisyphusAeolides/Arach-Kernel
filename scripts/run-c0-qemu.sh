#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "usage: $0 C0_IMAGE [SERIAL_LOG]" >&2
    exit 64
fi

image=$1
log=${2:-${image}.serial.log}
qemu=${QEMU:-qemu-system-x86_64}
ovmf_code=${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE.fd}
ovmf_vars=${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS.fd}
[[ -f "$image" && ! -L "$image" ]] || { echo "C0 image is not a regular file" >&2; exit 1; }
command -v "$qemu" >/dev/null || { echo "QEMU is required for C0 execution" >&2; exit 69; }
[[ -f "$ovmf_code" && -f "$ovmf_vars" ]] || {
    echo "OVMF_CODE and OVMF_VARS are required for C0 execution" >&2
    exit 69
}

vars=$(mktemp /tmp/arach-c0-vars.XXXXXX)
cleanup() {
    rm -f -- "$vars"
}
trap cleanup EXIT
cp -- "$ovmf_vars" "$vars"

timeout_seconds=${ARACH_C0_TIMEOUT_SECONDS:-30}
set +e
timeout --kill-after=5s "${timeout_seconds}s" "$qemu" \
    -machine q35 \
    -m 512M \
    -display none \
    -no-reboot \
    -no-shutdown \
    -serial "file:$log" \
    -drive "if=pflash,format=raw,readonly=on,file=$ovmf_code" \
    -drive "if=pflash,format=raw,file=$vars" \
    -drive "format=raw,if=virtio,file=$image"
status=$?
set -e
if [[ "$status" -ne 0 ]]; then
    echo "C0 QEMU exited with status $status" >&2
    exit "$status"
fi

for marker in \
    "Granite: bounded Arach/Push/Crest preflight passed" \
    "ARACH_C0_RING3_SYSCALL_PASS"; do
    grep -F -- "$marker" "$log" >/dev/null || {
        echo "C0 serial evidence missing: $marker" >&2
        exit 1
    }
done
echo "C0 execution gate passed: $log"
