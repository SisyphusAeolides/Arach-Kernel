#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
output="${1:?usage: build-shared-object-probe.sh CONSUMER PROVIDER OBSERVER CORE}"
provider_output="${2:?usage: build-shared-object-probe.sh CONSUMER PROVIDER OBSERVER CORE}"
observer_output="${3:?usage: build-shared-object-probe.sh CONSUMER PROVIDER OBSERVER CORE}"
core_output="${4:?usage: build-shared-object-probe.sh CONSUMER PROVIDER OBSERVER CORE}"
build_directory="$(dirname -- "$output")/shared-object-objects"
cc_bin="${CC:-cc}"
ld_bin="${LD:-ld}"

mkdir -p "$build_directory" "$(dirname -- "$output")" \
    "$(dirname -- "$provider_output")" "$(dirname -- "$observer_output")" \
    "$(dirname -- "$core_output")"

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
"$cc_bin" "${common_flags[@]}" -std=c11 -O2 -Wall -Wextra -Wconversion \
    -Werror -Wmissing-prototypes -Wpointer-arith -Wshadow -Wsign-conversion \
    -Wstrict-prototypes \
    -c "$root/probes/shared-object/provider.c" \
    -o "$build_directory/provider.o"
"$cc_bin" "${common_flags[@]}" -std=c11 -O2 -Wall -Wextra -Wconversion \
    -Werror -Wmissing-prototypes -Wpointer-arith -Wshadow -Wsign-conversion \
    -Wstrict-prototypes \
    -c "$root/probes/shared-object/observer.c" \
    -o "$build_directory/observer.o"
"$cc_bin" "${common_flags[@]}" -std=c11 -O2 -Wall -Wextra -Wconversion \
    -Werror -Wmissing-prototypes -Wpointer-arith -Wshadow -Wsign-conversion \
    -Wstrict-prototypes \
    -c "$root/probes/shared-object/core.c" \
    -o "$build_directory/core.o"
"$ld_bin" -shared -nostdlib -Bsymbolic --hash-style=sysv -z noexecstack \
    -soname libarach-core.so \
    -T "$root/probes/shared-object/provider.ld" \
    -o "$core_output" \
    "$build_directory/core.o"
"$ld_bin" -shared -nostdlib -Bsymbolic --hash-style=sysv -z noexecstack \
    -z now -soname libarach-provider.so \
    -T "$root/probes/shared-object/linker.ld" \
    -o "$provider_output" \
    "$build_directory/provider.o" \
    -L"$(dirname -- "$core_output")" --no-as-needed \
    -l:libarach-core.so
"$ld_bin" -shared -nostdlib -Bsymbolic --hash-style=sysv -z noexecstack \
    -z now -soname libarach-observer.so \
    -T "$root/probes/shared-object/linker.ld" \
    -o "$observer_output" \
    "$build_directory/observer.o" \
    -L"$(dirname -- "$core_output")" --no-as-needed \
    -l:libarach-core.so
"$ld_bin" -shared -nostdlib -Bsymbolic --hash-style=sysv -z noexecstack \
    -z now -soname libarach-probe.so \
    -T "$root/probes/shared-object/linker.ld" \
    -o "$output" \
    "$build_directory/shared_object.o" \
    -L"$(dirname -- "$provider_output")" --no-as-needed \
    -l:libarach-provider.so -l:libarach-observer.so

test -s "$output" && test -s "$provider_output" \
    && test -s "$observer_output" && test -s "$core_output"
test "$(readelf -hW "$output" | awk '/Type:/{print $2}')" = DYN
test -z "$(readelf -lW "$output" | awk '$1 == "INTERP" {print}')"
test "$(readelf -dW "$output" | awk '$2 == "(SONAME)" {print $5}')" = '[libarach-probe.so]'
mapfile -t root_dependencies < <(readelf -dW "$output" | awk '$2 == "(NEEDED)" {print $5}')
test "${root_dependencies[*]}" = '[libarach-provider.so] [libarach-observer.so]'
test "$(readelf -rW "$output" | awk '$3 == "R_X86_64_JUMP_SLOT" {count++} END {print count + 0}')" -eq 2
test -z "$(readelf -rW "$output" | awk '/^[0-9a-f]+/ && $3 != "R_X86_64_JUMP_SLOT" {print}')"
test "$(readelf -sW "$output" | awk '$8 == "arach_shared_probe" && $7 != "UND" {count++} END {print count + 0}')" -ge 1

test "$(readelf -hW "$provider_output" | awk '/Type:/{print $2}')" = DYN
test -z "$(readelf -lW "$provider_output" | awk '$1 == "INTERP" {print}')"
test "$(readelf -dW "$provider_output" | awk '$2 == "(SONAME)" {print $5}')" = '[libarach-provider.so]'
test "$(readelf -dW "$provider_output" | awk '$2 == "(NEEDED)" {print $5}')" = '[libarach-core.so]'
test "$(readelf -rW "$provider_output" | awk '$3 == "R_X86_64_JUMP_SLOT" {count++} END {print count + 0}')" -eq 1
test -z "$(readelf -rW "$provider_output" | awk '/^[0-9a-f]+/ && $3 != "R_X86_64_JUMP_SLOT" {print}')"
test "$(readelf -sW "$provider_output" | awk '$8 == "arach_provider_value" && $7 != "UND" {count++} END {print count + 0}')" -ge 1

test "$(readelf -hW "$observer_output" | awk '/Type:/{print $2}')" = DYN
test -z "$(readelf -lW "$observer_output" | awk '$1 == "INTERP" {print}')"
test "$(readelf -dW "$observer_output" | awk '$2 == "(SONAME)" {print $5}')" = '[libarach-observer.so]'
test "$(readelf -dW "$observer_output" | awk '$2 == "(NEEDED)" {print $5}')" = '[libarach-core.so]'
test "$(readelf -rW "$observer_output" | awk '$3 == "R_X86_64_JUMP_SLOT" {count++} END {print count + 0}')" -eq 1
test -z "$(readelf -rW "$observer_output" | awk '/^[0-9a-f]+/ && $3 != "R_X86_64_JUMP_SLOT" {print}')"
test "$(readelf -sW "$observer_output" | awk '$8 == "arach_observer_value" && $7 != "UND" {count++} END {print count + 0}')" -ge 1

test "$(readelf -hW "$core_output" | awk '/Type:/{print $2}')" = DYN
test -z "$(readelf -lW "$core_output" | awk '$1 == "INTERP" {print}')"
test "$(readelf -dW "$core_output" | awk '$2 == "(SONAME)" {print $5}')" = '[libarach-core.so]'
test "$(readelf -rW "$core_output" | awk '$3 == "R_X86_64_RELATIVE" {count++} END {print count + 0}')" -eq 1
test -z "$(readelf -rW "$core_output" | awk '/^[0-9a-f]+/ && $3 != "R_X86_64_RELATIVE" {print}')"
test -z "$(readelf -dW "$core_output" | awk '$2 == "(NEEDED)" {print}')"
test "$(readelf -sW "$core_output" | awk '$8 == "arach_core_value" && $7 != "UND" {count++} END {print count + 0}')" -ge 1
