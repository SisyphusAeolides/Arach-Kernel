#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
output="${1:?usage: build-shared-object-probe.sh OUTPUT}"
build_directory="$(dirname -- "$output")/shared-object-objects"
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
    -fvisibility=hidden
    -fcf-protection=none
    -mno-red-zone
    -mno-mmx
    -mno-sse
    -mno-sse2
)

"$cc_bin" "${common_flags[@]}" -std=c11 -O2 -Wall -Wextra -Wconversion \
    -Werror -Wmissing-prototypes -Wpointer-arith -Wshadow -Wsign-conversion \
    -Wstrict-prototypes \
    -c "$root/probes/shared-object/shared_object.c" \
    -o "$build_directory/shared_object.o"
"$ld_bin" -shared -nostdlib -Bsymbolic --hash-style=sysv -z noexecstack \
    -soname libarach-probe.so \
    -T "$root/probes/shared-object/linker.ld" \
    -o "$output" \
    "$build_directory/shared_object.o"

test -s "$output"
test "$(readelf -hW "$output" | awk '/Type:/{print $2}')" = DYN
test -z "$(readelf -lW "$output" | awk '$1 == "INTERP" {print}')"
test "$(readelf -dW "$output" | awk '$2 == "(SONAME)" {print $5}')" = '[libarach-probe.so]'
test "$(readelf -rW "$output" | awk '$3 == "R_X86_64_RELATIVE" {count++} END {print count + 0}')" -eq 1
test -z "$(readelf -rW "$output" | awk '/^[0-9a-f]+/ && $3 != "R_X86_64_RELATIVE" {print}')"
test -z "$(readelf -dW "$output" | awk '$2 == "(NEEDED)" {print}')"
test "$(readelf -sW "$output" | awk '$8 == "arach_shared_probe" && $7 != "UND" {count++} END {print count + 0}')" -ge 1
