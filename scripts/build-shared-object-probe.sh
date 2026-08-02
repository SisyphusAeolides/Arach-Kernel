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
    -mtls-dialect=gnu
)
runpath_flags=(
    --enable-new-dtags
    -rpath
    /runpath
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
    -soname libarach-core.so -fini arach_core_finish \
    --version-script="$root/probes/shared-object/core.map" \
    -T "$root/probes/shared-object/core.ld" \
    -o "$core_output" \
    "$build_directory/core.o"
"$ld_bin" -shared -nostdlib -Bsymbolic --hash-style=sysv -z noexecstack \
    -z now "${runpath_flags[@]}" -soname libarach-provider.so \
    -fini arach_provider_finish \
    --version-script="$root/probes/shared-object/provider.map" \
    -T "$root/probes/shared-object/linker.ld" \
    -o "$provider_output" \
    "$build_directory/provider.o" \
    -L"$(dirname -- "$core_output")" --no-as-needed \
    -l:libarach-core.so
"$ld_bin" -shared -nostdlib -Bsymbolic --hash-style=sysv -z noexecstack \
    -z now "${runpath_flags[@]}" -soname libarach-observer.so \
    -fini arach_observer_finish \
    --version-script="$root/probes/shared-object/observer.map" \
    -T "$root/probes/shared-object/linker.ld" \
    -o "$observer_output" \
    "$build_directory/observer.o" \
    -L"$(dirname -- "$core_output")" --no-as-needed \
    -l:libarach-core.so
"$ld_bin" -shared -nostdlib -Bsymbolic --hash-style=sysv -z noexecstack \
    -z now "${runpath_flags[@]}" -soname libarach-probe.so \
    -fini arach_root_finish \
    --version-script="$root/probes/shared-object/root.map" \
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
test "$(readelf -dW "$output" | awk '$2 == "(RUNPATH)" {print $5}')" = '[/runpath]'
test "$(readelf -dW "$output" | awk '$2 == "(RUNPATH)" {count++} END {print count + 0}')" -eq 1
test -z "$(readelf -dW "$output" | awk '$2 == "(RPATH)" {print}')"
mapfile -t root_dependencies < <(readelf -dW "$output" | awk '$2 == "(NEEDED)" {print $5}')
test "${root_dependencies[*]}" = '[libarach-provider.so] [libarach-observer.so]'
test "$(readelf -rW "$output" | awk '$3 == "R_X86_64_JUMP_SLOT" {count++} END {print count + 0}')" -eq 5
test "$(readelf -rW "$output" | awk '$3 == "R_X86_64_RELATIVE" {count++} END {print count + 0}')" -eq 2
test "$(readelf -rW "$output" | awk '$3 == "R_X86_64_GLOB_DAT" {count++} END {print count + 0}')" -eq 3
test -z "$(readelf -rW "$output" | awk '/^[0-9a-f]+/ && $3 != "R_X86_64_JUMP_SLOT" && $3 != "R_X86_64_RELATIVE" && $3 != "R_X86_64_GLOB_DAT" {print}')"
test "$(readelf -dW "$output" | awk '$2 == "(INIT_ARRAYSZ)" {print $3}')" -eq 8
test "$(readelf -dW "$output" | awk '$2 == "(FINI_ARRAYSZ)" {print $3}')" -eq 8
test "$(readelf -dW "$output" | awk '$2 == "(FINI)" {count++} END {print count + 0}')" -eq 1
test "$(readelf -dW "$output" | awk '$2 == "(VERDEFNUM)" {print $3}')" -eq 2
test "$(readelf -dW "$output" | awk '$2 == "(VERNEEDNUM)" {print $3}')" -eq 2
test "$(readelf -dW "$output" | awk '$2 == "(VERSYM)" {count++} END {print count + 0}')" -eq 1
test -z "$(readelf -lW "$output" | awk '$1 == "TLS" {print}')"
test "$(readelf --dyn-syms -W "$output" | awk '$8 ~ /^arach_shared_probe@@ARACH_PROBE_1[.]0$/ && $7 != "UND" {count++} END {print count + 0}')" -eq 1
test "$(readelf -rW "$output" | awk '$3 == "R_X86_64_JUMP_SLOT" && $5 ~ /@ARACH_/ {count++} END {print count + 0}')" -eq 3
test "$(readelf --dyn-syms -W "$output" | awk '$4 == "FUNC" && $5 == "WEAK" && $7 == "UND" && $8 == "arach_scope_choice" {count++} END {print count + 0}')" -eq 1
test "$(readelf --dyn-syms -W "$output" | awk '$4 == "NOTYPE" && $5 == "WEAK" && $7 == "UND" && $8 == "arach_optional_hook" {count++} END {print count + 0}')" -eq 1
test "$(readelf -rW "$output" | awk '$3 == "R_X86_64_JUMP_SLOT" && ($5 == "arach_scope_choice" || $5 == "arach_optional_hook") {count++} END {print count + 0}')" -eq 2
test "$(readelf --dyn-syms -W "$output" | awk '$4 == "OBJECT" && $5 == "GLOBAL" && $7 == "UND" && $8 ~ /^arach_provider_data@ARACH_PROVIDER_1[.]0$/ {count++} END {print count + 0}')" -eq 1
test "$(readelf --dyn-syms -W "$output" | awk '$4 == "OBJECT" && $5 == "WEAK" && $7 == "UND" && $8 == "arach_data_choice" {count++} END {print count + 0}')" -eq 1
test "$(readelf --dyn-syms -W "$output" | awk '$4 == "NOTYPE" && $5 == "WEAK" && $7 == "UND" && $8 == "arach_optional_data" {count++} END {print count + 0}')" -eq 1
test "$(readelf -rW "$output" | awk '$3 == "R_X86_64_GLOB_DAT" && $5 ~ /^arach_provider_data@ARACH_PROVIDER_1[.]0$/ {count++} END {print count + 0}')" -eq 1
test "$(readelf -rW "$output" | awk '$3 == "R_X86_64_GLOB_DAT" && ($5 == "arach_data_choice" || $5 == "arach_optional_data") {count++} END {print count + 0}')" -eq 2

test "$(readelf -hW "$provider_output" | awk '/Type:/{print $2}')" = DYN
test -z "$(readelf -lW "$provider_output" | awk '$1 == "INTERP" {print}')"
test "$(readelf -dW "$provider_output" | awk '$2 == "(SONAME)" {print $5}')" = '[libarach-provider.so]'
test "$(readelf -dW "$provider_output" | awk '$2 == "(RUNPATH)" {print $5}')" = '[/runpath]'
test "$(readelf -dW "$provider_output" | awk '$2 == "(RUNPATH)" {count++} END {print count + 0}')" -eq 1
test -z "$(readelf -dW "$provider_output" | awk '$2 == "(RPATH)" {print}')"
test "$(readelf -dW "$provider_output" | awk '$2 == "(NEEDED)" {print $5}')" = '[libarach-core.so]'
test "$(readelf -rW "$provider_output" | awk '$3 == "R_X86_64_JUMP_SLOT" {count++} END {print count + 0}')" -eq 3
test "$(readelf -rW "$provider_output" | awk '$3 == "R_X86_64_RELATIVE" {count++} END {print count + 0}')" -eq 2
test "$(readelf -rW "$provider_output" | awk '$3 == "R_X86_64_DTPMOD64" && $5 ~ /^arach_core_tls@ARACH_CORE_1[.]0$/ {count++} END {print count + 0}')" -eq 1
test "$(readelf -rW "$provider_output" | awk '$3 == "R_X86_64_DTPOFF64" && $5 ~ /^arach_core_tls@ARACH_CORE_1[.]0$/ {count++} END {print count + 0}')" -eq 1
test -z "$(readelf -rW "$provider_output" | awk '/^[0-9a-f]+/ && $3 != "R_X86_64_JUMP_SLOT" && $3 != "R_X86_64_RELATIVE" && $3 != "R_X86_64_DTPMOD64" && $3 != "R_X86_64_DTPOFF64" {print}')"
test "$(readelf -dW "$provider_output" | awk '$2 == "(INIT_ARRAYSZ)" {print $3}')" -eq 8
test "$(readelf -dW "$provider_output" | awk '$2 == "(FINI_ARRAYSZ)" {print $3}')" -eq 8
test "$(readelf -dW "$provider_output" | awk '$2 == "(FINI)" {count++} END {print count + 0}')" -eq 1
test "$(readelf -dW "$provider_output" | awk '$2 == "(VERDEFNUM)" {print $3}')" -eq 2
test "$(readelf -dW "$provider_output" | awk '$2 == "(VERNEEDNUM)" {print $3}')" -eq 1
test "$(readelf -dW "$provider_output" | awk '$2 == "(VERSYM)" {count++} END {print count + 0}')" -eq 1
test -z "$(readelf -lW "$provider_output" | awk '$1 == "TLS" {print}')"
test -z "$(readelf -dW "$provider_output" | awk '$2 == "(FLAGS)" && /STATIC_TLS/ {print}')"
test "$(readelf --dyn-syms -W "$provider_output" | awk '$8 ~ /^arach_provider_value@@ARACH_PROVIDER_1[.]0$/ && $7 != "UND" {count++} END {print count + 0}')" -eq 1
test "$(readelf --dyn-syms -W "$provider_output" | awk '$4 == "FUNC" && $5 == "WEAK" && $6 == "DEFAULT" && $7 != "UND" && $8 == "arach_scope_choice" {count++} END {print count + 0}')" -eq 1
test "$(readelf --dyn-syms -W "$provider_output" | awk '$3 == 8 && $4 == "OBJECT" && $5 == "WEAK" && $6 == "DEFAULT" && $7 != "UND" && $8 == "arach_data_choice" {count++} END {print count + 0}')" -eq 1
test "$(readelf --dyn-syms -W "$provider_output" | awk '$3 == 8 && $4 == "OBJECT" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 ~ /^arach_provider_data@@ARACH_PROVIDER_1[.]0$/ {count++} END {print count + 0}')" -eq 1
test "$(readelf --dyn-syms -W "$provider_output" | awk '$4 == "TLS" && $5 == "GLOBAL" && $7 == "UND" && $8 ~ /^arach_core_tls@ARACH_CORE_1[.]0$/ {count++} END {print count + 0}')" -eq 1
test "$(readelf --dyn-syms -W "$provider_output" | awk '$4 == "NOTYPE" && $5 == "GLOBAL" && $7 == "UND" && $8 == "__tls_get_addr" {count++} END {print count + 0}')" -eq 1
test "$(readelf -rW "$provider_output" | awk '$3 == "R_X86_64_JUMP_SLOT" && $5 ~ /@ARACH_CORE_1[.]0/ {count++} END {print count + 0}')" -eq 2
test "$(readelf -rW "$provider_output" | awk '$3 == "R_X86_64_JUMP_SLOT" && $5 == "__tls_get_addr" {count++} END {print count + 0}')" -eq 1

test "$(readelf -hW "$observer_output" | awk '/Type:/{print $2}')" = DYN
test -z "$(readelf -lW "$observer_output" | awk '$1 == "INTERP" {print}')"
test "$(readelf -dW "$observer_output" | awk '$2 == "(SONAME)" {print $5}')" = '[libarach-observer.so]'
test "$(readelf -dW "$observer_output" | awk '$2 == "(RUNPATH)" {print $5}')" = '[/runpath]'
test "$(readelf -dW "$observer_output" | awk '$2 == "(RUNPATH)" {count++} END {print count + 0}')" -eq 1
test -z "$(readelf -dW "$observer_output" | awk '$2 == "(RPATH)" {print}')"
test "$(readelf -dW "$observer_output" | awk '$2 == "(NEEDED)" {print $5}')" = '[libarach-core.so]'
test "$(readelf -rW "$observer_output" | awk '$3 == "R_X86_64_JUMP_SLOT" {count++} END {print count + 0}')" -eq 2
test "$(readelf -rW "$observer_output" | awk '$3 == "R_X86_64_RELATIVE" {count++} END {print count + 0}')" -eq 2
test -z "$(readelf -rW "$observer_output" | awk '/^[0-9a-f]+/ && $3 != "R_X86_64_JUMP_SLOT" && $3 != "R_X86_64_RELATIVE" {print}')"
test "$(readelf -dW "$observer_output" | awk '$2 == "(INIT_ARRAYSZ)" {print $3}')" -eq 8
test "$(readelf -dW "$observer_output" | awk '$2 == "(FINI_ARRAYSZ)" {print $3}')" -eq 8
test "$(readelf -dW "$observer_output" | awk '$2 == "(FINI)" {count++} END {print count + 0}')" -eq 1
test "$(readelf -dW "$observer_output" | awk '$2 == "(VERDEFNUM)" {print $3}')" -eq 2
test "$(readelf -dW "$observer_output" | awk '$2 == "(VERNEEDNUM)" {print $3}')" -eq 1
test "$(readelf -dW "$observer_output" | awk '$2 == "(VERSYM)" {count++} END {print count + 0}')" -eq 1
test -z "$(readelf -lW "$observer_output" | awk '$1 == "TLS" {print}')"
test "$(readelf --dyn-syms -W "$observer_output" | awk '$8 ~ /^arach_observer_value@@ARACH_OBSERVER_1[.]0$/ && $7 != "UND" {count++} END {print count + 0}')" -eq 1
test "$(readelf --dyn-syms -W "$observer_output" | awk '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 == "arach_scope_choice" {count++} END {print count + 0}')" -eq 1
test "$(readelf --dyn-syms -W "$observer_output" | awk '$3 == 8 && $4 == "OBJECT" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 == "arach_data_choice" {count++} END {print count + 0}')" -eq 1
test "$(readelf -rW "$observer_output" | awk '$3 == "R_X86_64_JUMP_SLOT" && $5 ~ /@ARACH_CORE_1[.]0/ {count++} END {print count + 0}')" -eq 2

test "$(readelf -hW "$core_output" | awk '/Type:/{print $2}')" = DYN
test -z "$(readelf -lW "$core_output" | awk '$1 == "INTERP" {print}')"
test "$(readelf -dW "$core_output" | awk '$2 == "(SONAME)" {print $5}')" = '[libarach-core.so]'
test -z "$(readelf -dW "$core_output" | awk '$2 == "(RUNPATH)" || $2 == "(RPATH)" {print}')"
test "$(readelf -rW "$core_output" | awk '$3 == "R_X86_64_RELATIVE" {count++} END {print count + 0}')" -eq 3
test "$(readelf -rW "$core_output" | awk '$3 == "R_X86_64_TPOFF64" {count++} END {print count + 0}')" -eq 1
test -z "$(readelf -rW "$core_output" | awk '/^[0-9a-f]+/ && $3 != "R_X86_64_RELATIVE" && $3 != "R_X86_64_TPOFF64" {print}')"
test "$(readelf -dW "$core_output" | awk '$2 == "(INIT_ARRAYSZ)" {print $3}')" -eq 8
test "$(readelf -dW "$core_output" | awk '$2 == "(FINI_ARRAYSZ)" {print $3}')" -eq 8
test "$(readelf -dW "$core_output" | awk '$2 == "(FINI)" {count++} END {print count + 0}')" -eq 1
test "$(readelf -dW "$core_output" | awk '$2 == "(VERDEFNUM)" {print $3}')" -eq 2
test "$(readelf -dW "$core_output" | awk '$2 == "(VERSYM)" {count++} END {print count + 0}')" -eq 1
test -z "$(readelf -dW "$core_output" | awk '$2 == "(VERNEEDNUM)" {print}')"
test "$(readelf -lW "$core_output" | awk '$1 == "TLS" {count++} END {print count + 0}')" -eq 1
test "$(readelf -lW "$core_output" | awk '$1 == "TLS" {print $5, $6, $8}')" = '0x000008 0x000008 0x8'
test "$(readelf --dyn-syms -W "$core_output" | awk '$4 == "TLS" && $8 ~ /^arach_core_tls@@ARACH_CORE_1[.]0$/ && $7 != "UND" {count++} END {print count + 0}')" -eq 1
test "$(readelf -dW "$core_output" | awk '$2 == "(FLAGS)" && /STATIC_TLS/ {count++} END {print count + 0}')" -eq 1
test "$(objdump -d "$core_output" | awk '/%fs:/{count++} END {print count + 0}')" -ge 2
test -z "$(readelf -dW "$core_output" | awk '$2 == "(NEEDED)" {print}')"
test "$(readelf --dyn-syms -W "$core_output" | awk '$8 ~ /^arach_core_value@@ARACH_CORE_1[.]0$/ && $7 != "UND" {count++} END {print count + 0}')" -eq 1
