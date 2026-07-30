#!/usr/bin/env bash
set -euo pipefail

readonly root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
readonly input_source=${1:-/usr/src/kernels/$(uname -r)}
readonly input_output=${2:-$input_source}
readonly sdk=${ARACH_KBUILD_SDK_ROOT:-$root/target/arach-kbuild}

fail() {
    echo "Arach Linux-contract SDK: $*" >&2
    exit 1
}

source_real=$(realpath -- "$input_source") || fail "cannot resolve $input_source"
output_real=$(realpath -- "$input_output") || fail "cannot resolve $input_output"

for required in \
    "$source_real/Makefile" \
    "$source_real/scripts/Makefile.modpost" \
    "$output_real/.config" \
    "$output_real/Module.symvers" \
    "$output_real/include/generated/autoconf.h" \
    "$output_real/include/generated/utsrelease.h"; do
    test -f "$required" || fail "missing $required"
done

case "$sdk" in
    "$root"/target/*) ;;
    *) fail "SDK output must remain below $root/target" ;;
esac

mkdir -p -- "$sdk"
ln -sfn -- "$source_real" "$sdk/source"
ln -sfn -- "$output_real" "$sdk/output"

kernel_release=$(sed -n \
    's/^#define UTS_RELEASE "\(.*\)"/\1/p' \
    "$output_real/include/generated/utsrelease.h")
test -n "$kernel_release" || fail "generated UTS release is empty"

config_digest=$(sha256sum -- "$output_real/.config" | cut -d' ' -f1)
symvers_digest=$(sha256sum -- "$output_real/Module.symvers" | cut -d' ' -f1)
autoconf_digest=$(sha256sum -- "$output_real/include/generated/autoconf.h" | cut -d' ' -f1)

cat >"$sdk/manifest.json" <<EOF
{
  "contract": "arach-linux-kernel-module-sdk-v1",
  "architecture": "$(uname -m)",
  "kernel_release": "$kernel_release",
  "source": "$source_real",
  "output": "$output_real",
  "config_sha256": "$config_digest",
  "module_symvers_sha256": "$symvers_digest",
  "autoconf_sha256": "$autoconf_digest"
}
EOF

echo "Arach Linux-contract SDK materialized for $kernel_release"
cat "$sdk/manifest.json"
