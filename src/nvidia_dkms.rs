//! Qualification policy for NVIDIA's pinned open Linux module release.

use crate::linux_contract::{LinuxEvidence, LinuxGate, LinuxProfile};

pub const NVIDIA_RELEASE: &str = "610.43.03";
pub const NVIDIA_SOURCE_REVISION: &str = "452cec62d827034798072827d3866d1881662b77";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationError {
    UnpinnedSource,
    MissingBuildGate(LinuxGate),
    MissingRuntimeGate(LinuxGate),
}

pub fn qualify_build(
    source_revision: &str,
    evidence: LinuxEvidence,
) -> Result<(), QualificationError> {
    if source_revision != NVIDIA_SOURCE_REVISION {
        return Err(QualificationError::UnpinnedSource);
    }
    if let Some(gate) = evidence.first_missing(LinuxProfile::ExternalModuleBuild) {
        return Err(QualificationError::MissingBuildGate(gate));
    }
    Ok(())
}

pub fn qualify_runtime(
    source_revision: &str,
    evidence: LinuxEvidence,
) -> Result<(), QualificationError> {
    qualify_build(source_revision, evidence)?;
    if let Some(gate) = evidence.first_missing(LinuxProfile::NvidiaOpenRuntime) {
        return Err(QualificationError::MissingRuntimeGate(gate));
    }
    Ok(())
}

/// Evidence implemented by the current Arach tree.
///
/// The bounded native ET_REL loader and Hermes GSP path are deliberately not
/// credited: neither implements Linux Kbuild, MODPOST, `.ko` metadata, or the
/// Linux KPI consumed by NVIDIA's modules.
pub const fn current_arach_evidence() -> LinuxEvidence {
    LinuxEvidence::empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux_contract::{
        EXTERNAL_MODULE_BUILD_GATES, NVIDIA_OPEN_RUNTIME_GATES, PassedMeasurement,
    };

    const DIGEST: [u8; 32] = [0x61; 32];

    fn measurement(gate: LinuxGate) -> PassedMeasurement<'static> {
        PassedMeasurement::new(gate, "nvidia-open-contract", 1, DIGEST).unwrap()
    }

    fn evidence_for(gates: &[LinuxGate]) -> LinuxEvidence {
        gates.iter().fold(LinuxEvidence::empty(), |evidence, gate| {
            evidence.admit(&measurement(*gate))
        })
    }

    #[test]
    fn source_revision_is_part_of_build_admission() {
        assert_eq!(
            qualify_build("main", evidence_for(&EXTERNAL_MODULE_BUILD_GATES)),
            Err(QualificationError::UnpinnedSource)
        );
    }

    #[test]
    fn every_build_gate_is_required() {
        for omitted in EXTERNAL_MODULE_BUILD_GATES {
            let evidence = EXTERNAL_MODULE_BUILD_GATES
                .iter()
                .filter(|gate| **gate != omitted)
                .fold(LinuxEvidence::empty(), |evidence, gate| {
                    evidence.admit(&measurement(*gate))
                });
            assert_eq!(
                qualify_build(NVIDIA_SOURCE_REVISION, evidence),
                Err(QualificationError::MissingBuildGate(omitted))
            );
        }
    }

    #[test]
    fn build_evidence_does_not_imply_runtime_compatibility() {
        let evidence = evidence_for(&EXTERNAL_MODULE_BUILD_GATES);
        assert!(qualify_build(NVIDIA_SOURCE_REVISION, evidence).is_ok());
        assert_eq!(
            qualify_runtime(NVIDIA_SOURCE_REVISION, evidence),
            Err(QualificationError::MissingRuntimeGate(LinuxGate::KpiMemory))
        );
    }

    #[test]
    fn complete_measured_evidence_qualifies() {
        let evidence = evidence_for(&NVIDIA_OPEN_RUNTIME_GATES);
        assert!(qualify_runtime(NVIDIA_SOURCE_REVISION, evidence).is_ok());
    }

    #[test]
    fn current_tree_does_not_make_an_unmeasured_claim() {
        let evidence = current_arach_evidence();
        assert!(!evidence.qualifies(LinuxProfile::ExternalModuleBuild));
        assert!(!evidence.qualifies(LinuxProfile::NvidiaOpenRuntime));
    }
}
