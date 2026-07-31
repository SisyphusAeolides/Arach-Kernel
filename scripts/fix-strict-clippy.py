#!/usr/bin/env python3
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if text.count(old) != 1:
        raise SystemExit(f"{label}: expected one match, found {text.count(old)}")
    return text.replace(old, new)


build_path = Path("build.rs")
build = build_path.read_text(encoding="utf-8")

call_old = '''        verify_formal_attestation(
            &workspace,
            driver_digest,
            package_digest,
            crucible_digest,
            aegis_digest,
            argus_markup_digest,
            granite_boot_digest,
            hermes_authority_digest,
            crest_shell_digest,
            privilege_digest,
            argus_layout_digest,
            granite_layout_digest,
            hermes_wire_digest,
            crest_overlay_digest,
            cosmic_compatibility_digest,
            cosmic_stack_digest,
            linux_contract_idris_digest,
            linux_contract_agda_digest,
        );'''
call_new = '''        verify_formal_attestation(
            &workspace,
            FormalDigests {
                driver: driver_digest,
                package: package_digest,
                crucible: crucible_digest,
                aegis: aegis_digest,
                argus_markup: argus_markup_digest,
                granite_boot: granite_boot_digest,
                hermes_authority: hermes_authority_digest,
                crest_shell: crest_shell_digest,
                privilege: privilege_digest,
                argus_layout: argus_layout_digest,
                granite_layout: granite_layout_digest,
                hermes_wire: hermes_wire_digest,
                crest_overlay: crest_overlay_digest,
                cosmic_compatibility: cosmic_compatibility_digest,
                cosmic_stack: cosmic_stack_digest,
                linux_contract_idris: linux_contract_idris_digest,
                linux_contract_agda: linux_contract_agda_digest,
            },
        );'''
build = replace_once(build, call_old, call_new, "formal attestation call")

signature_old = '''fn verify_formal_attestation(
    workspace: &Path,
    driver_digest: [u8; 32],
    package_digest: [u8; 32],
    crucible_digest: [u8; 32],
    aegis_digest: [u8; 32],
    argus_markup_digest: [u8; 32],
    granite_boot_digest: [u8; 32],
    hermes_authority_digest: [u8; 32],
    crest_shell_digest: [u8; 32],
    privilege_digest: [u8; 32],
    argus_layout_digest: [u8; 32],
    granite_layout_digest: [u8; 32],
    hermes_wire_digest: [u8; 32],
    crest_overlay_digest: [u8; 32],
    cosmic_compatibility_digest: [u8; 32],
    cosmic_stack_digest: [u8; 32],
    linux_contract_idris_digest: [u8; 32],
    linux_contract_agda_digest: [u8; 32],
) {'''
signature_new = '''#[derive(Clone, Copy)]
struct FormalDigests {
    driver: [u8; 32],
    package: [u8; 32],
    crucible: [u8; 32],
    aegis: [u8; 32],
    argus_markup: [u8; 32],
    granite_boot: [u8; 32],
    hermes_authority: [u8; 32],
    crest_shell: [u8; 32],
    privilege: [u8; 32],
    argus_layout: [u8; 32],
    granite_layout: [u8; 32],
    hermes_wire: [u8; 32],
    crest_overlay: [u8; 32],
    cosmic_compatibility: [u8; 32],
    cosmic_stack: [u8; 32],
    linux_contract_idris: [u8; 32],
    linux_contract_agda: [u8; 32],
}

fn verify_formal_attestation(workspace: &Path, digests: FormalDigests) {'''
build = replace_once(build, signature_old, signature_new, "formal attestation signature")

replacements = {
    "driver_digest": "digests.driver",
    "package_digest": "digests.package",
    "crucible_digest": "digests.crucible",
    "aegis_digest": "digests.aegis",
    "argus_markup_digest": "digests.argus_markup",
    "granite_boot_digest": "digests.granite_boot",
    "hermes_authority_digest": "digests.hermes_authority",
    "crest_shell_digest": "digests.crest_shell",
    "privilege_digest": "digests.privilege",
    "argus_layout_digest": "digests.argus_layout",
    "granite_layout_digest": "digests.granite_layout",
    "hermes_wire_digest": "digests.hermes_wire",
    "crest_overlay_digest": "digests.crest_overlay",
    "cosmic_compatibility_digest": "digests.cosmic_compatibility",
    "cosmic_stack_digest": "digests.cosmic_stack",
    "linux_contract_idris_digest": "digests.linux_contract_idris",
    "linux_contract_agda_digest": "digests.linux_contract_agda",
}
function_start = build.index("fn verify_formal_attestation(workspace: &Path, digests: FormalDigests)")
function_end = build.index("\n\nstruct BootProcessPackage", function_start)
prefix = build[:function_start]
function = build[function_start:function_end]
suffix = build[function_end:]
for old, new in replacements.items():
    function = function.replace(old, new)
build_path.write_text(prefix + function + suffix, encoding="utf-8")

resonance_path = Path("core/aether/src/resonance_split.rs")
resonance = resonance_path.read_text(encoding="utf-8")
resonance = replace_once(
    resonance,
    '''}

#[repr(C, align(64))]
struct ObservationCore {''',
    '''}

impl Default for ResonanceIngressPage {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C, align(64))]
struct ObservationCore {''',
    "ingress default",
)
resonance = replace_once(
    resonance,
    '''}

fn encode_wire<T: Wire64>(value: &T) -> [u64; 8] {''',
    '''}

impl Default for ResonanceObservationPage {
    fn default() -> Self {
        Self::new()
    }
}

fn encode_wire<T: Wire64>(value: &T) -> [u64; 8] {''',
    "observation default",
)
resonance_path.write_text(resonance, encoding="utf-8")
