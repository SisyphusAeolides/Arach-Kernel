#!/usr/bin/env bash
set -euo pipefail

readonly expected_revision=452cec62d827034798072827d3866d1881662b77
readonly expected_release=610.43.03
readonly source_root=${1:-target/nvidia-open}
readonly report_path=${2:-target/nvidia-dkms/source-contract.json}

fail() {
    echo "nvidia source contract: $*" >&2
    exit 1
}

test -d "$source_root/.git" || fail "not a git checkout: $source_root"
actual_revision=$(git -C "$source_root" rev-parse HEAD)
test "$actual_revision" = "$expected_revision" || \
    fail "expected $expected_revision, found $actual_revision"

top_makefile=$source_root/Makefile
module_makefile=$source_root/kernel-open/Makefile
kbuild=$source_root/kernel-open/Kbuild
conftest=$source_root/kernel-open/conftest.sh

for required in "$top_makefile" "$module_makefile" "$kbuild" "$conftest"; do
    test -f "$required" || fail "missing $required"
done

grep -Fq 'modules:' "$top_makefile" || fail "top-level modules target changed"
grep -Fq '$(MAKE) -C kernel-open modules' "$top_makefile" || \
    fail "top-level kernel-open handoff changed"
grep -Fq 'KBUILD_PARAMS += -C $(KERNEL_SOURCES) M=$(CURDIR)' "$module_makefile" || \
    fail "external Kbuild invocation changed"
grep -Fq 'include $(src)/$(_module)/$(_module).Kbuild' "$kbuild" || \
    fail "per-module Kbuild inclusion changed"
grep -Fq 'generated/autoconf.h' "$conftest" || \
    fail "generated configuration probe missing"
grep -Fq 'generated/utsrelease.h' "$conftest" || \
    fail "UTS release probe missing"
grep -Fq 'Module.symvers' "$conftest" || fail "symbol-version probe missing"
grep -Fq 'nvidia-drm' "$module_makefile" || fail "nvidia-drm target missing"
grep -Fq 'nvidia-modeset' "$module_makefile" || fail "nvidia-modeset target missing"
grep -Fq 'nvidia-uvm' "$module_makefile" || fail "nvidia-uvm target missing"
grep -Fq "NV_VERSION_STRING=\\\"$expected_release\\\"" "$kbuild" || \
    fail "release string changed"

c_sources=$(find "$source_root" -type f -name '*.c' | wc -l)
headers=$(find "$source_root" -type f -name '*.h' | wc -l)
module_kbuilds=$(find "$source_root/kernel-open" -type f -name '*.Kbuild' | wc -l)

mkdir -p "$(dirname "$report_path")"
cat >"$report_path" <<EOF
{
  "release": "$expected_release",
  "revision": "$actual_revision",
  "external_kbuild": true,
  "generated_configuration": true,
  "module_symvers": true,
  "modpost_required": true,
  "module_linker_scripts_required": true,
  "c_sources": $c_sources,
  "headers": $headers,
  "module_kbuilds": $module_kbuilds
}
EOF

echo "NVIDIA $expected_release source contract verified at $actual_revision"
echo "Inventory: $c_sources C sources, $headers headers, $module_kbuilds module Kbuild files"
echo "This verifies the pinned source contract; it does not qualify Arach build or runtime compatibility."
