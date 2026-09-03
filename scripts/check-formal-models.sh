#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
idris="${IDRIS2:-idris2}"
agda="${AGDA:-agda}"

fail() {
    printf 'formal check failed: %s\n' "$1" >&2
    exit 1
}

[[ "$($idris --version)" == "Idris 2, version 0.8.0"* ]] ||
    fail "Idris2 0.8.0 is required"
[[ "$($agda --version | sed -n '1p')" == "Agda version 2.8.0" ]] ||
    fail "Agda 2.8.0 is required"

idris_sources=(
    DriverLifecycle.idr PackageTransaction.idr Crucible.idr
    AegisLifecycle.idr ArgusMarkup.idr ArachBoot.idr
    HermesAuthority.idr CrestShell.idr CosmicCompatibility.idr LinuxContract.idr
)
agda_sources=(
    PrivilegeRings.agda ArgusLayout.agda ArachLayout.agda
    HermesWire.agda CrestOverlay.agda CosmicStack.agda LinuxContract.agda
)

for name in "${idris_sources[@]}"; do
    source="$root/formal/idris2/$name"
    [[ -f "$source" ]] || fail "missing formal/idris2/$name"
    grep -Fxq '%default total' "$source" || fail "$name is not total by default"
done
for name in "${agda_sources[@]}"; do
    source="$root/formal/agda/$name"
    [[ -f "$source" ]] || fail "missing formal/agda/$name"
    grep -Fxq '{-# OPTIONS --safe --without-K #-}' "$source" ||
        fail "$name does not require safe, without-K checking"
done

if grep -En 'believe_me|assert_total|assert_smaller|unsafe|(^|[^[:alnum:]_])partial([^[:alnum:]_]|$)|[?][A-Za-z_]|[?][?][?]' \
    "$root"/formal/idris2/*.idr; then
    fail "Idris2 escape hatch or unresolved hole detected"
fi
if grep -En '^[[:space:]]*postulate\b|\{![^!]*!\}|TERMINATING|NON_TERMINATING|NO_TERMINATION_CHECK' \
    "$root"/formal/agda/*.agda; then
    fail "Agda postulate, escape hatch, or unresolved hole detected"
fi

scratch="$(mktemp -d "${TMPDIR:-/tmp}/arach-formal.XXXXXXXX")"
cleanup() { find "$scratch" -depth -delete 2>/dev/null || :; }
trap cleanup EXIT
mkdir -p "$scratch/idris2" "$scratch/agda" "$scratch/agda-data" "$scratch/agda-config"

for name in "${idris_sources[@]}"; do
    cp -- "$root/formal/idris2/$name" "$scratch/idris2/"
done
for name in "${agda_sources[@]}"; do
    cp -- "$root/formal/agda/$name" "$scratch/agda/"
done

for name in "${idris_sources[@]}"; do
    (cd -- "$scratch/idris2" && "$idris" --check "$name")
done
for name in "${agda_sources[@]}"; do
    (
        cd -- "$scratch/agda"
        XDG_DATA_HOME="$scratch/agda-data" \
        XDG_CONFIG_HOME="$scratch/agda-config" \
            "$agda" --no-libraries --safe --without-K "$name"
    )
done

digest() {
    sha256sum -- "$1" | cut -d' ' -f1
}

mkdir -p "$root/target/formal"
cat > "$root/target/formal/verified.lock" <<LOCK
format=1
idris2_version=0.8.0
agda_version=2.8.0
driver_lifecycle_sha256=$(digest "$root/formal/idris2/DriverLifecycle.idr")
package_transaction_sha256=$(digest "$root/formal/idris2/PackageTransaction.idr")
crucible_sha256=$(digest "$root/formal/idris2/Crucible.idr")
aegis_lifecycle_sha256=$(digest "$root/formal/idris2/AegisLifecycle.idr")
argus_markup_sha256=$(digest "$root/formal/idris2/ArgusMarkup.idr")
arach_boot_sha256=$(digest "$root/formal/idris2/ArachBoot.idr")
hermes_authority_sha256=$(digest "$root/formal/idris2/HermesAuthority.idr")
crest_shell_sha256=$(digest "$root/formal/idris2/CrestShell.idr")
privilege_rings_sha256=$(digest "$root/formal/agda/PrivilegeRings.agda")
argus_layout_sha256=$(digest "$root/formal/agda/ArgusLayout.agda")
arach_layout_sha256=$(digest "$root/formal/agda/ArachLayout.agda")
hermes_wire_sha256=$(digest "$root/formal/agda/HermesWire.agda")
crest_overlay_sha256=$(digest "$root/formal/agda/CrestOverlay.agda")
cosmic_compatibility_sha256=$(digest "$root/formal/idris2/CosmicCompatibility.idr")
cosmic_stack_sha256=$(digest "$root/formal/agda/CosmicStack.agda")
linux_contract_idris_sha256=$(digest "$root/formal/idris2/LinuxContract.idr")
linux_contract_agda_sha256=$(digest "$root/formal/agda/LinuxContract.agda")
LOCK

cmp -- "$root/formal/verified.lock" "$root/target/formal/verified.lock" ||
    fail "tracked formal attestation differs from the verified model set"

printf 'formal check passed: Idris2 0.8.0, Agda 2.8.0\n'
