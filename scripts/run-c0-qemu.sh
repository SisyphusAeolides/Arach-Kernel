#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "usage: $0 C0_IMAGE [SERIAL_LOG]" >&2
    exit 64
fi

image=$1
log=${2:-${image}.serial.log}
qemu=${QEMU:-qemu-system-x86_64}
[[ -f "$image" && ! -L "$image" ]] || { echo "C0 image is not a regular file" >&2; exit 1; }
command -v "$qemu" >/dev/null || { echo "QEMU is required for C0 execution" >&2; exit 69; }

first_existing() {
    local candidate
    for candidate in "$@"; do
        if [[ -f "$candidate" && ! -L "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

# Fedora, Debian, and Ubuntu package the same firmware under different names.
# An explicit override remains authoritative; otherwise select only a regular,
# non-symlinked firmware file so the execution gate is reproducible and cannot
# silently boot with a host-controlled link.
ovmf_code=${OVMF_CODE:-}
ovmf_vars=${OVMF_VARS:-}
if [[ -z "$ovmf_code" ]]; then
    ovmf_code=$(first_existing \
        /usr/share/OVMF/OVMF_CODE_4M.fd \
        /usr/share/OVMF/OVMF_CODE.fd \
        /usr/share/edk2/ovmf/OVMF_CODE_4M.fd \
        /usr/share/edk2/ovmf/OVMF_CODE.fd) || true
fi
if [[ -z "$ovmf_vars" ]]; then
    ovmf_vars=$(first_existing \
        /usr/share/OVMF/OVMF_VARS_4M.fd \
        /usr/share/OVMF/OVMF_VARS.fd \
        /usr/share/edk2/ovmf/OVMF_VARS_4M.fd \
        /usr/share/edk2/ovmf/OVMF_VARS.fd) || true
fi
[[ -n "$ovmf_code" && -n "$ovmf_vars" \
    && -f "$ovmf_code" && ! -L "$ovmf_code" \
    && -f "$ovmf_vars" && ! -L "$ovmf_vars" ]] || {
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
# Do not let a previous serial transcript satisfy the marker check if QEMU
# exits before this invocation reaches the measured userspace probe.
: >"$log"
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
if [[ "$status" -ne 0 && "$status" -ne 124 ]]; then
    echo "C0 QEMU exited with status $status" >&2
    exit "$status"
fi

for marker in \
    "Granite: bounded Arach/Push/Crest preflight passed" \
    "ARACH_C0_RING3_SYSCALL_PASS" \
    "ARACH_C1_THREAD_FUTEX_PASS" \
    "ARACH_C1_ROBUST_FUTEX_PASS" \
    "ARACH_C1_SIGNAL_RETURN_PASS" \
    "ARACH_C1_LINUX_SYSCALL_PASS" \
    "ARACH_C1_EXIT_GROUP_ARMED" \
    "[PID 1] child 2 exited with status 0"; do
    grep -F -- "$marker" "$log" >/dev/null || {
        echo "C0 serial evidence missing: $marker" >&2
        exit 1
    }
done
if [[ "$status" -eq 124 ]]; then
    echo "C0 execution gate passed before bounded QEMU timeout: $log"
else
    echo "C0 execution gate passed: $log"
fi
