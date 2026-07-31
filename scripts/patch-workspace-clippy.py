#!/usr/bin/env python3
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


root = Path(__file__).resolve().parents[1]

build_path = root / "build.rs"
build = build_path.read_text(encoding="utf-8")
old_call = '''        verify_formal_attestation(
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
new_call = '''        verify_formal_attestation(
            &workspace,
            [
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
            ],
        );'''
build = replace_once(build, old_call, new_call, "formal attestation call")

start = build.find("fn verify_formal_attestation(")
end = build.find("struct BootProcessPackage", start)
if start < 0 or end < 0:
    raise SystemExit("formal attestation function region is missing")
region = build[start:end]
closing = region.find(") {")
if closing < 0:
    raise SystemExit("formal attestation signature terminator is missing")
region = (
    "fn verify_formal_attestation(workspace: &Path, digests: [[u8; 32]; 17]) {"
    + region[closing + 3 :]
)
names = [
    "driver_digest",
    "package_digest",
    "crucible_digest",
    "aegis_digest",
    "argus_markup_digest",
    "granite_boot_digest",
    "hermes_authority_digest",
    "crest_shell_digest",
    "privilege_digest",
    "argus_layout_digest",
    "granite_layout_digest",
    "hermes_wire_digest",
    "crest_overlay_digest",
    "cosmic_compatibility_digest",
    "cosmic_stack_digest",
    "linux_contract_idris_digest",
    "linux_contract_agda_digest",
]
for index, name in enumerate(names):
    old = f"encode_sha256({name})"
    if region.count(old) != 1:
        raise SystemExit(f"formal digest {name} does not occur exactly once")
    region = region.replace(old, f"encode_sha256(digests[{index}])")
build = build[:start] + region + build[end:]
build_path.write_text(build, encoding="utf-8")

resonance_path = root / "core/aether/src/resonance_split.rs"
resonance = resonance_path.read_text(encoding="utf-8")
resonance = replace_once(
    resonance,
    '''    pub fn overwritten_frames(&self) -> u64 {
        self.core.overwritten_frames.load(Ordering::Acquire)
    }
}

#[repr(C, align(64))]
struct ObservationCore {''',
    '''    pub fn overwritten_frames(&self) -> u64 {
        self.core.overwritten_frames.load(Ordering::Acquire)
    }
}

impl Default for ResonanceIngressPage {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C, align(64))]
struct ObservationCore {''',
    "ingress page Default",
)
resonance = replace_once(
    resonance,
    '''    pub fn reply_publications(&self) -> u64 {
        self.core.reply_publications.load(Ordering::Acquire)
    }
}

fn encode_wire<T: Wire64>(value: &T) -> [u64; 8] {''',
    '''    pub fn reply_publications(&self) -> u64 {
        self.core.reply_publications.load(Ordering::Acquire)
    }
}

impl Default for ResonanceObservationPage {
    fn default() -> Self {
        Self::new()
    }
}

fn encode_wire<T: Wire64>(value: &T) -> [u64; 8] {''',
    "observation page Default",
)
resonance_path.write_text(resonance, encoding="utf-8")
