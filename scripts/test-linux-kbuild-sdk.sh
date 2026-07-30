#!/usr/bin/env bash
set -euo pipefail

readonly root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
readonly kernel_source=${ARACH_KBUILD_SOURCE:-/usr/src/kernels/$(uname -r)}
readonly kernel_output=${ARACH_KBUILD_OUTPUT:-$kernel_source}
readonly work=${ARACH_KBUILD_SMOKE_OUTPUT:-$root/target/linux-contract/smoke}
readonly report=${ARACH_KBUILD_REPORT:-$root/target/linux-contract/kbuild-measurement.json}
readonly vermagic_file=${ARACH_KBUILD_VERMAGIC_FILE:-$root/target/arach-kbuild/vermagic}

fail() {
    echo "Linux Kbuild contract: $*" >&2
    exit 1
}

case "$work" in
    "$root"/target/*) ;;
    *) fail "smoke output must remain below $root/target" ;;
esac

for required in \
    "$kernel_source/Makefile" \
    "$kernel_source/scripts/Makefile.modpost" \
    "$kernel_output/.config" \
    "$kernel_output/Module.symvers" \
    "$kernel_output/include/generated/autoconf.h" \
    "$kernel_output/include/generated/utsrelease.h"; do
    test -f "$required" || fail "missing $required"
done

rm -rf -- "$work"
mkdir -p -- "$work" "$(dirname -- "$report")"
cp -- "$root/compat/linux-module-smoke/Makefile" "$work/Makefile"
cp -- "$root/compat/linux-module-smoke/arach_contract_smoke.c" \
    "$work/arach_contract_smoke.c"

make -C "$kernel_source" \
    O="$kernel_output" \
    M="$work" \
    modules

readonly module=$work/arach_contract_smoke.ko
test -s "$module" || fail "Kbuild did not produce $module"

readonly sections=$work/sections.txt
readonly symbols=$work/symbols.txt
readelf --sections --wide "$module" >"$sections"
readelf --symbols --wide "$module" >"$symbols"

for section in .modinfo .gnu.linkonce.this_module; do
    grep -Fq "$section" "$sections" || \
        fail "$module lacks $section"
done

for symbol in init_module cleanup_module; do
    grep -Eq "[[:space:]]$symbol$" "$symbols" || \
        fail "$module lacks $symbol"
done

mkdir -p -- "$(dirname -- "$vermagic_file")"
cargo run --quiet --manifest-path "$root/Cargo.toml" \
    --bin arach-ko-inspect -- "$module" "$vermagic_file"

readonly vermagic=$(sed -n '1p' "$vermagic_file")
test -n "$vermagic" || fail "$module has empty vermagic"
cargo run --quiet --manifest-path "$root/Cargo.toml" \
    --bin arach-ko-admit -- \
    "$module" "$vermagic_file" "$kernel_output/Module.symvers"

readonly module_digest=$(sha256sum -- "$module" | cut -d' ' -f1)
readonly kernel_release=$(sed -n \
    's/^#define UTS_RELEASE "\(.*\)"/\1/p' \
    "$kernel_output/include/generated/utsrelease.h")
test -n "$kernel_release" || fail "generated UTS release is empty"

cat >"$report" <<EOF
{
  "suite": "arach-linux-external-kbuild-smoke",
  "passing_cases": 14,
  "artifact": "arach_contract_smoke.ko",
  "artifact_sha256": "$module_digest",
  "kernel_release": "$kernel_release",
  "vermagic": "$vermagic",
  "external_kbuild": true,
  "generated_configuration": true,
  "symbol_versions": true,
  "modpost": true,
  "module_linker_scripts": true,
  "linux_headers": true,
  "linux_module_elf": true,
  "arach_structural_preflight": true,
  "exact_vermagic": true,
  "symbol_crc_admission": true,
  "export_policy_admission": true,
  "load_layout_planning": true,
  "wx_region_planning": true,
  "relocation_binding": true
}
EOF

echo "Linux external-Kbuild contract passed for $kernel_release"
echo "$module_digest  $module"
