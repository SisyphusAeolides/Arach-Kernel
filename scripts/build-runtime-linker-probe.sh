#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
output="${1:?usage: build-runtime-linker-probe.sh OUTPUT}"
build_directory="$(dirname -- "$output")/runtime-linker-objects"
cc_bin="${CC:-cc}"
ld_bin="${LD:-ld}"

mkdir -p "$build_directory" "$(dirname -- "$output")"

common_flags=(
    -ffreestanding
    -fPIC
    -fno-asynchronous-unwind-tables
    -fno-builtin
    -fno-jump-tables
    -fno-stack-protector
    -fcf-protection=none
    -mno-red-zone
    -mno-mmx
    -mno-sse
    -mno-sse2
)

"$cc_bin" "${common_flags[@]}" -std=c11 -O2 -Wall -Wextra -Wconversion \
    -Werror -Wmissing-prototypes -Wpointer-arith -Wshadow -Wsign-conversion \
    -Wstrict-prototypes \
    -c "$root/probes/runtime-linker/runtime_linker.c" \
    -o "$build_directory/runtime_linker.o"
"$cc_bin" "${common_flags[@]}" \
    -c "$root/probes/runtime-linker/entry.S" \
    -o "$build_directory/entry.o"
"$ld_bin" -pie --no-dynamic-linker -nostdlib -Bsymbolic -z noexecstack \
    -T "$root/probes/runtime-linker/linker.ld" \
    -o "$output" \
    "$build_directory/entry.o" "$build_directory/runtime_linker.o"

test -s "$output"
test "$(readelf -h "$output" | awk '/Type:/{print $2}')" = DYN
test -z "$(readelf -lW "$output" | awk '$1 == "INTERP" {print}')"
test -z "$(readelf -rW "$output" | awk '/^[0-9a-f]+/{print}')"
