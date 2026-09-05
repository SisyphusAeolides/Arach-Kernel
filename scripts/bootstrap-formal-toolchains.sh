#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
tools="${FORMAL_TOOLCHAIN_ROOT:-$root/target/formal/toolchains}"
downloads="$tools/downloads"
idris_version="0.8.0"
idris_commit="5aaefadb587224eb44d3be0fbb7e2835b48bd7a6"
idris_source_sha256="b05e982313b7532be84f0482b808f222a2c5065a50d896690cce8f11a738753c"
idris_root="$tools/Idris2-$idris_version-$idris_commit"
agda_root="$tools/Agda-v2.8.0-linux"
mkdir -p "$downloads"

if command -v chezscheme >/dev/null 2>&1; then
    scheme="chezscheme"
elif command -v scheme >/dev/null 2>&1; then
    scheme="scheme"
elif command -v chez >/dev/null 2>&1; then
    # Arch's chez-scheme package installs the executable as `chez`.
    scheme="chez"
else
    printf '%s\n' 'Idris bootstrap requires Chez Scheme (chezscheme, scheme, or chez).' >&2
    exit 1
fi

if [[ ! -x "$idris_root/build/exec/idris2" ]]; then
    archive="$downloads/idris2-$idris_commit.tar.gz"
    curl --fail --location --retry 3 \
        --output "$archive" \
        "https://github.com/idris-lang/Idris2/archive/$idris_commit.tar.gz"
    printf '%s  %s\n' \
        "$idris_source_sha256" \
        "$archive" | sha256sum --check --strict
    staging="$(mktemp -d "$tools/.idris.XXXXXXXX")"
    trap 'find "$staging" -depth -delete 2>/dev/null || :' EXIT
    tar -xzf "$archive" --strip-components=1 -C "$staging"
    make -C "$staging" bootstrap SCHEME="$scheme"
    mv "$staging" "$idris_root"
    trap - EXIT
fi

if [[ ! -x "$agda_root/agda" ]]; then
    archive="$downloads/Agda-v2.8.0-linux.tar.xz"
    curl --fail --location --retry 3 --output "$archive" \
        https://github.com/agda/agda/releases/download/v2.8.0/Agda-v2.8.0-linux.tar.xz
    printf '%s  %s\n' \
        824081b8dcbe431289a50ac6bd83e451f390c51c3884ac7a8c4a5c0df2632faf \
        "$archive" | sha256sum --check --strict
    staging="$(mktemp -d "$tools/.agda.XXXXXXXX")"
    trap 'find "$staging" -depth -delete 2>/dev/null || :' EXIT
    tar -xJf "$archive" -C "$staging"
    mkdir "$agda_root"
    mv "$staging/agda" "$agda_root/agda"
    rmdir "$staging"
    trap - EXIT
fi

IDRIS2="$idris_root/build/exec/idris2" \
IDRIS2_PATH="$idris_root/libs/prelude/build/ttc:$idris_root/libs/base/build/ttc" \
AGDA="$agda_root/agda" \
    "$root/scripts/check-formal-models.sh"
