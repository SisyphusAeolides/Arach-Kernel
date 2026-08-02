#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cc_bin="${CC:-cc}"
stage="$(mktemp -d)"
cleanup() {
    rm -r -- "$stage"
}
trap cleanup EXIT

"$cc_bin" -std=c11 -O2 -Wall -Wextra -Wconversion -Werror \
    -Wmissing-prototypes -Wpointer-arith -Wshadow -Wsign-conversion \
    -Wstrict-prototypes -ffunction-sections -fdata-sections \
    "$root/probes/runtime-linker/graph_test.c" \
    -Wl,--gc-sections -o "$stage/runtime-linker-graph-test"
"$stage/runtime-linker-graph-test"
