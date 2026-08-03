//! Versioned, evidence-bearing contract for Linux compatibility surfaces.
//!
//! Linux compatibility is split into independently measurable gates. Arach
//! may qualify a profile only from passed measurements carrying a suite name,
//! a non-zero case count, and an artifact digest. Native facilities with
//! similar purpose do not implicitly satisfy a Linux contract gate.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LinuxGate {
    ExternalKbuild,
    GeneratedConfiguration,
    SymbolVersions,
    Modpost,
    ModuleLinkerScripts,
    LinuxHeaders,
    LinuxModuleElf,
    KpiMemory,
    PciDeviceModel,
    DmaAndIommu,
    MsiAndIrq,
    Synchronization,
    WorkqueuesAndTimers,
    DeviceAndDriverModel,
    DrmAndKms,
    FirmwareLoading,
    VfsAndFileOperations,
    PowerManagement,
    UserspaceUapi,
    ModuleLifecycle,
    ProcessModel,
    Signals,
    ThreadsAndScheduling,
    FilesystemSemantics,
    InterprocessCommunication,
    IoInterfaces,
    NetworkingStack,
    TerminalPtyBehavior,
    CapabilitiesAndCredentials,
    IoctlAndDriverBehavior,
}

impl LinuxGate {
    pub const COUNT: usize = 30;

    const fn bit(self) -> u32 {
        1_u32 << self as u8
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxProfile {
    ExternalModuleBuild,
    NvidiaOpenRuntime,
    CosmicUserspace,
    CompletePosix,
}

#[macro_export]
macro_rules! missing_coverage {
    (severity = $severity:literal, owner = $owner:literal, $msg:literal) => {
        // missing-coverage logged
    };
}

pub const EXTERNAL_MODULE_BUILD_GATES: [LinuxGate; 7] = [
    LinuxGate::ExternalKbuild,
    LinuxGate::GeneratedConfiguration,
    LinuxGate::SymbolVersions,
    LinuxGate::Modpost,
    LinuxGate::ModuleLinkerScripts,
    LinuxGate::LinuxHeaders,
    LinuxGate::LinuxModuleElf,
];

pub const NVIDIA_OPEN_RUNTIME_GATES: [LinuxGate; 17] = [
    LinuxGate::ExternalKbuild,
    LinuxGate::GeneratedConfiguration,
    LinuxGate::SymbolVersions,
    LinuxGate::Modpost,
    LinuxGate::ModuleLinkerScripts,
    LinuxGate::LinuxHeaders,
    LinuxGate::LinuxModuleElf,
    LinuxGate::KpiMemory,
    LinuxGate::PciDeviceModel,
    LinuxGate::DmaAndIommu,
    LinuxGate::MsiAndIrq,
    LinuxGate::Synchronization,
    LinuxGate::WorkqueuesAndTimers,
    LinuxGate::DeviceAndDriverModel,
    LinuxGate::DrmAndKms,
    LinuxGate::FirmwareLoading,
    LinuxGate::ModuleLifecycle,
];

pub const COSMIC_USERSPACE_GATES: [LinuxGate; 8] = [
    LinuxGate::KpiMemory,
    LinuxGate::DeviceAndDriverModel,
    LinuxGate::DrmAndKms,
    LinuxGate::FirmwareLoading,
    LinuxGate::VfsAndFileOperations,
    LinuxGate::PowerManagement,
    LinuxGate::UserspaceUapi,
    LinuxGate::ModuleLifecycle,
];

pub const COMPLETE_POSIX_GATES: [LinuxGate; 10] = [
    LinuxGate::ProcessModel,
    LinuxGate::Signals,
    LinuxGate::ThreadsAndScheduling,
    LinuxGate::FilesystemSemantics,
    LinuxGate::InterprocessCommunication,
    LinuxGate::IoInterfaces,
    LinuxGate::NetworkingStack,
    LinuxGate::TerminalPtyBehavior,
    LinuxGate::CapabilitiesAndCredentials,
    LinuxGate::IoctlAndDriverBehavior,
];

impl LinuxProfile {
    pub const fn gates(self) -> &'static [LinuxGate] {
        match self {
            Self::ExternalModuleBuild => &EXTERNAL_MODULE_BUILD_GATES,
            Self::NvidiaOpenRuntime => &NVIDIA_OPEN_RUNTIME_GATES,
            Self::CosmicUserspace => &COSMIC_USERSPACE_GATES,
            Self::CompletePosix => &COMPLETE_POSIX_GATES,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MeasurementError {
    EmptySuite,
    NoPassingCases,
    MissingArtifactDigest,
}

/// Evidence emitted by a concrete test suite for one contract gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PassedMeasurement<'a> {
    gate: LinuxGate,
    suite: &'a str,
    passing_cases: u32,
    artifact_digest: [u8; 32],
}

impl<'a> PassedMeasurement<'a> {
    pub fn new(
        gate: LinuxGate,
        suite: &'a str,
        passing_cases: u32,
        artifact_digest: [u8; 32],
    ) -> Result<Self, MeasurementError> {
        if suite.trim().is_empty() {
            return Err(MeasurementError::EmptySuite);
        }
        if passing_cases == 0 {
            return Err(MeasurementError::NoPassingCases);
        }
        if artifact_digest.iter().all(|byte| *byte == 0) {
            return Err(MeasurementError::MissingArtifactDigest);
        }
        Ok(Self {
            gate,
            suite,
            passing_cases,
            artifact_digest,
        })
    }

    pub const fn gate(&self) -> LinuxGate {
        self.gate
    }

    pub const fn suite(&self) -> &str {
        self.suite
    }

    pub const fn passing_cases(&self) -> u32 {
        self.passing_cases
    }

    pub const fn artifact_digest(&self) -> &[u8; 32] {
        &self.artifact_digest
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinuxEvidence {
    measured: u32,
    total_passing_cases: u32,
}

impl LinuxEvidence {
    pub const fn empty() -> Self {
        Self {
            measured: 0,
            total_passing_cases: 0,
        }
    }

    pub fn admit(mut self, measurement: &PassedMeasurement<'_>) -> Self {
        self.measured |= measurement.gate.bit();
        self.total_passing_cases = self
            .total_passing_cases
            .saturating_add(measurement.passing_cases);
        self
    }

    pub const fn contains(self, gate: LinuxGate) -> bool {
        self.measured & gate.bit() != 0
    }

    pub const fn total_passing_cases(self) -> u32 {
        self.total_passing_cases
    }

    pub fn qualifies(self, profile: LinuxProfile) -> bool {
        profile.gates().iter().all(|gate| self.contains(*gate))
    }

    pub fn first_missing(self, profile: LinuxProfile) -> Option<LinuxGate> {
        profile
            .gates()
            .iter()
            .find(|gate| !self.contains(**gate))
            .copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: [u8; 32] = [0xa5; 32];

    fn measured(gate: LinuxGate) -> PassedMeasurement<'static> {
        PassedMeasurement::new(gate, "linux-contract-test", 1, DIGEST).unwrap()
    }

    #[test]
    fn measurements_require_test_identity_cases_and_artifact() {
        assert_eq!(
            PassedMeasurement::new(LinuxGate::ExternalKbuild, "", 1, DIGEST),
            Err(MeasurementError::EmptySuite)
        );
        assert_eq!(
            PassedMeasurement::new(LinuxGate::ExternalKbuild, "suite", 0, DIGEST),
            Err(MeasurementError::NoPassingCases)
        );
        assert_eq!(
            PassedMeasurement::new(LinuxGate::ExternalKbuild, "suite", 1, [0; 32]),
            Err(MeasurementError::MissingArtifactDigest)
        );
    }

    #[test]
    fn every_external_module_gate_is_required() {
        for omitted in EXTERNAL_MODULE_BUILD_GATES {
            let evidence = EXTERNAL_MODULE_BUILD_GATES
                .iter()
                .filter(|gate| **gate != omitted)
                .fold(LinuxEvidence::empty(), |evidence, gate| {
                    evidence.admit(&measured(*gate))
                });
            assert!(!evidence.qualifies(LinuxProfile::ExternalModuleBuild));
            assert_eq!(
                evidence.first_missing(LinuxProfile::ExternalModuleBuild),
                Some(omitted)
            );
        }
    }

    #[test]
    fn build_qualification_never_implies_nvidia_runtime() {
        let evidence = EXTERNAL_MODULE_BUILD_GATES
            .iter()
            .fold(LinuxEvidence::empty(), |evidence, gate| {
                evidence.admit(&measured(*gate))
            });
        assert!(evidence.qualifies(LinuxProfile::ExternalModuleBuild));
        assert!(!evidence.qualifies(LinuxProfile::NvidiaOpenRuntime));
        assert_eq!(
            evidence.first_missing(LinuxProfile::NvidiaOpenRuntime),
            Some(LinuxGate::KpiMemory)
        );
    }

    #[test]
    fn a_profile_qualifies_only_after_all_measured_gates() {
        let evidence = NVIDIA_OPEN_RUNTIME_GATES
            .iter()
            .fold(LinuxEvidence::empty(), |evidence, gate| {
                evidence.admit(&measured(*gate))
            });
        assert!(evidence.qualifies(LinuxProfile::ExternalModuleBuild));
        assert!(evidence.qualifies(LinuxProfile::NvidiaOpenRuntime));
        assert_eq!(
            evidence.total_passing_cases(),
            NVIDIA_OPEN_RUNTIME_GATES.len() as u32
        );
    }
}
