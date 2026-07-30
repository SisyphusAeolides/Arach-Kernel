//! OS-wide Hermes phase manifold shared by Boulder, Crest, and formal proofs.
//!
//! The lattice mirrors `formal/idris2/HermesAuthority.idr`: Online is never a
//! free jump from Probe. Callers publish evidence; this module only advances
//! when every gate for the requested transition holds. No allocation, no host
//! GPU, no fabricated online state.

use core::fmt;

/// Matches the Idris HermesPhase constructors exactly.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum HermesPhase {
    Offline = 0,
    Probed = 1,
    Firmwared = 2,
    Queued = 3,
    Negotiated = 4,
    Online = 5,
    Recovering = 6,
    Quarantined = 7,
}

impl HermesPhase {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Offline),
            1 => Some(Self::Probed),
            2 => Some(Self::Firmwared),
            3 => Some(Self::Queued),
            4 => Some(Self::Negotiated),
            5 => Some(Self::Online),
            6 => Some(Self::Recovering),
            7 => Some(Self::Quarantined),
            _ => None,
        }
    }

    pub const fn label(self) -> &'static [u8] {
        match self {
            Self::Offline => b"OFFLINE",
            Self::Probed => b"PROBED",
            Self::Firmwared => b"FIRMWARED",
            Self::Queued => b"QUEUED",
            Self::Negotiated => b"NEGOTIATED",
            Self::Online => b"ONLINE",
            Self::Recovering => b"RECOVERING",
            Self::Quarantined => b"QUARANTINED",
        }
    }

    pub const fn is_live(self) -> bool {
        matches!(self, Self::Online)
    }

    pub const fn is_degraded(self) -> bool {
        matches!(self, Self::Recovering | Self::Quarantined)
    }
}

/// Feature lattice bits aligned with `libraries/driver-abi` Hermes features.
pub mod feature {
    pub const BOOT_RPC: u64 = 1 << 0;
    pub const COMMAND_RING: u64 = 1 << 1;
    pub const EVENT_RING: u64 = 1 << 2;
    pub const RECOVERY: u64 = 1 << 3;
    pub const DISPLAY: u64 = 1 << 4;
    pub const COMPUTE: u64 = 1 << 5;
    pub const COPY_ENGINE: u64 = 1 << 6;
    pub const TELEMETRY: u64 = 1 << 7;
    pub const POWER: u64 = 1 << 8;
    pub const MEMORY_MANAGEMENT: u64 = 1 << 9;

    /// Agda HermesWire well-formedness: display needs command ring; compute
    /// needs memory management; power needs telemetry; rings need boot RPC.
    pub const fn well_formed(bits: u64) -> bool {
        if bits == 0 {
            return true;
        }
        if bits & BOOT_RPC == 0 {
            return false;
        }
        if bits & (COMMAND_RING | EVENT_RING) != 0
            && (bits & COMMAND_RING == 0 || bits & EVENT_RING == 0)
        {
            return false;
        }
        if bits & DISPLAY != 0 && bits & COMMAND_RING == 0 {
            return false;
        }
        if bits & COMPUTE != 0 && bits & MEMORY_MANAGEMENT == 0 {
            return false;
        }
        if bits & POWER != 0 && bits & TELEMETRY == 0 {
            return false;
        }
        true
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldFault {
    InvalidPhaseJump,
    MissingPci,
    MissingFirmware,
    MissingIommu,
    MissingDomain,
    MissingWpr,
    MissingMailbox,
    MissingReadyQueue,
    EmptyFeatures,
    IllFormedFeatures,
    GenerationMismatch,
    CertificateMissing,
}

impl fmt::Display for ManifoldFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::InvalidPhaseJump => "invalid phase jump",
            Self::MissingPci => "pci identity missing",
            Self::MissingFirmware => "firmware unmeasured",
            Self::MissingIommu => "iommu isolation missing",
            Self::MissingDomain => "dma domain missing",
            Self::MissingWpr => "wpr unlocked",
            Self::MissingMailbox => "boot mailbox failed",
            Self::MissingReadyQueue => "ready queue silent",
            Self::EmptyFeatures => "feature negotiation empty",
            Self::IllFormedFeatures => "feature lattice ill-formed",
            Self::GenerationMismatch => "generation mismatch",
            Self::CertificateMissing => "online certificate missing",
        };
        f.write_str(label)
    }
}

/// Evidence required before Online may be published. Mirrors RawHermesEvidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct HermesEvidence {
    pub pci_matched: bool,
    pub firmware_measured: bool,
    pub iommu_isolated: bool,
    pub dma_domain: u32,
    pub wpr_locked: bool,
    pub boot_mailbox_ok: bool,
    pub ready_queue_observed: bool,
    pub negotiated_features: u64,
}

impl HermesEvidence {
    pub const fn empty() -> Self {
        Self {
            pci_matched: false,
            firmware_measured: false,
            iommu_isolated: false,
            dma_domain: 0,
            wpr_locked: false,
            boot_mailbox_ok: false,
            ready_queue_observed: false,
            negotiated_features: 0,
        }
    }

    pub const fn online_ready(self) -> Result<(), ManifoldFault> {
        if !self.pci_matched {
            return Err(ManifoldFault::MissingPci);
        }
        if !self.firmware_measured {
            return Err(ManifoldFault::MissingFirmware);
        }
        if !self.iommu_isolated {
            return Err(ManifoldFault::MissingIommu);
        }
        if self.dma_domain == 0 {
            return Err(ManifoldFault::MissingDomain);
        }
        if !self.wpr_locked {
            return Err(ManifoldFault::MissingWpr);
        }
        if !self.boot_mailbox_ok {
            return Err(ManifoldFault::MissingMailbox);
        }
        if !self.ready_queue_observed {
            return Err(ManifoldFault::MissingReadyQueue);
        }
        if self.negotiated_features == 0 {
            return Err(ManifoldFault::EmptyFeatures);
        }
        if !feature::well_formed(self.negotiated_features) {
            return Err(ManifoldFault::IllFormedFeatures);
        }
        Ok(())
    }
}

/// Sealed online certificate bound to one generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OnlineCertificate {
    pub generation: u32,
    pub dma_domain: u32,
    pub negotiated_features: u64,
    pub root: u64,
}

impl OnlineCertificate {
    pub fn seal(generation: u32, evidence: HermesEvidence) -> Result<Self, ManifoldFault> {
        evidence.online_ready()?;
        let mut state = 0x4845_524d_4553_4d4e_u64;
        state ^= u64::from(generation).rotate_left(7);
        state = state.wrapping_mul(0x9e37_79b1_85eb_ca87);
        state ^= u64::from(evidence.dma_domain).rotate_left(13);
        state = state.wrapping_mul(0x9e37_79b1_85eb_ca87);
        state ^= evidence.negotiated_features.rotate_left(19);
        state = state.wrapping_mul(0x9e37_79b1_85eb_ca87);
        if state == 0 {
            state = 1;
        }
        Ok(Self {
            generation,
            dma_domain: evidence.dma_domain,
            negotiated_features: evidence.negotiated_features,
            root: state,
        })
    }
}

/// OS-wide Hermes manifold: phase + evidence + optional online certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HermesManifold {
    pub generation: u32,
    pub phase: HermesPhase,
    pub evidence: HermesEvidence,
    pub certificate: Option<OnlineCertificate>,
    pub corrected_faults: u32,
    pub fatal_faults: u32,
}

impl HermesManifold {
    pub const fn dark(generation: u32) -> Self {
        Self {
            generation,
            phase: HermesPhase::Offline,
            evidence: HermesEvidence::empty(),
            certificate: None,
            corrected_faults: 0,
            fatal_faults: 0,
        }
    }

    pub const fn phase(self) -> HermesPhase {
        self.phase
    }

    pub const fn is_online(self) -> bool {
        self.phase.is_live() && self.certificate.is_some()
    }

    /// Snapshot flag contribution for Quantum Crest publication.
    pub const fn snapshot_flags(self) -> u64 {
        use crate::quantum_crest::{
            SNAPSHOT_FLAG_DMA_REVOKED, SNAPSHOT_FLAG_HERMES_ONLINE,
            SNAPSHOT_FLAG_QUARANTINE_ACTIVE, SNAPSHOT_FLAG_RECOVERY_PENDING,
        };
        let mut flags = 0;
        if self.is_online() {
            flags |= SNAPSHOT_FLAG_HERMES_ONLINE;
        }
        if matches!(self.phase, HermesPhase::Recovering) {
            flags |= SNAPSHOT_FLAG_RECOVERY_PENDING;
        }
        if matches!(self.phase, HermesPhase::Quarantined) {
            flags |= SNAPSHOT_FLAG_QUARANTINE_ACTIVE | SNAPSHOT_FLAG_DMA_REVOKED;
        }
        flags
    }

    pub fn observe_probe(&mut self, pci_matched: bool) -> Result<(), ManifoldFault> {
        if self.phase != HermesPhase::Offline {
            return Err(ManifoldFault::InvalidPhaseJump);
        }
        if !pci_matched {
            return Err(ManifoldFault::MissingPci);
        }
        self.evidence.pci_matched = true;
        self.phase = HermesPhase::Probed;
        Ok(())
    }

    pub fn observe_firmware(&mut self, measured: bool) -> Result<(), ManifoldFault> {
        if self.phase != HermesPhase::Probed {
            return Err(ManifoldFault::InvalidPhaseJump);
        }
        if !measured {
            return Err(ManifoldFault::MissingFirmware);
        }
        self.evidence.firmware_measured = true;
        self.phase = HermesPhase::Firmwared;
        Ok(())
    }

    pub fn arm_queues(&mut self, iommu: bool, domain: u32) -> Result<(), ManifoldFault> {
        if self.phase != HermesPhase::Firmwared {
            return Err(ManifoldFault::InvalidPhaseJump);
        }
        if !iommu {
            return Err(ManifoldFault::MissingIommu);
        }
        if domain == 0 {
            return Err(ManifoldFault::MissingDomain);
        }
        self.evidence.iommu_isolated = true;
        self.evidence.dma_domain = domain;
        self.phase = HermesPhase::Queued;
        Ok(())
    }

    pub fn negotiate(&mut self, features: u64) -> Result<(), ManifoldFault> {
        if self.phase != HermesPhase::Queued {
            return Err(ManifoldFault::InvalidPhaseJump);
        }
        if features == 0 {
            return Err(ManifoldFault::EmptyFeatures);
        }
        if !feature::well_formed(features) {
            return Err(ManifoldFault::IllFormedFeatures);
        }
        self.evidence.negotiated_features = features;
        self.phase = HermesPhase::Negotiated;
        Ok(())
    }

    pub fn ignite(&mut self, wpr: bool, mailbox: bool, ready: bool) -> Result<(), ManifoldFault> {
        if self.phase != HermesPhase::Negotiated {
            return Err(ManifoldFault::InvalidPhaseJump);
        }
        self.evidence.wpr_locked = wpr;
        self.evidence.boot_mailbox_ok = mailbox;
        self.evidence.ready_queue_observed = ready;
        let certificate = OnlineCertificate::seal(self.generation, self.evidence)?;
        self.certificate = Some(certificate);
        self.phase = HermesPhase::Online;
        Ok(())
    }

    pub fn detect_fault(&mut self, fatal: bool) -> Result<(), ManifoldFault> {
        if self.phase != HermesPhase::Online {
            return Err(ManifoldFault::InvalidPhaseJump);
        }
        if self.certificate.is_none() {
            return Err(ManifoldFault::CertificateMissing);
        }
        if fatal {
            self.fatal_faults = self.fatal_faults.saturating_add(1);
        } else {
            self.corrected_faults = self.corrected_faults.saturating_add(1);
        }
        self.phase = HermesPhase::Recovering;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), ManifoldFault> {
        if self.phase != HermesPhase::Recovering {
            return Err(ManifoldFault::InvalidPhaseJump);
        }
        if self.certificate.is_none() {
            return Err(ManifoldFault::CertificateMissing);
        }
        self.phase = HermesPhase::Online;
        Ok(())
    }

    pub fn contain(&mut self) -> Result<(), ManifoldFault> {
        if self.phase != HermesPhase::Recovering {
            return Err(ManifoldFault::InvalidPhaseJump);
        }
        self.phase = HermesPhase::Quarantined;
        Ok(())
    }

    pub fn release(&mut self) -> Result<(), ManifoldFault> {
        if self.phase != HermesPhase::Quarantined {
            return Err(ManifoldFault::InvalidPhaseJump);
        }
        *self = Self::dark(self.generation.wrapping_add(1));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_gate_chain_reaches_online_with_certificate() {
        let mut manifold = HermesManifold::dark(7);
        assert!(manifold.observe_probe(true).is_ok());
        assert!(manifold.observe_firmware(true).is_ok());
        assert!(manifold.arm_queues(true, 3).is_ok());
        let features = feature::BOOT_RPC
            | feature::COMMAND_RING
            | feature::EVENT_RING
            | feature::DISPLAY
            | feature::TELEMETRY
            | feature::POWER
            | feature::MEMORY_MANAGEMENT
            | feature::COMPUTE;
        assert!(manifold.negotiate(features).is_ok());
        assert!(manifold.ignite(true, true, true).is_ok());
        assert!(manifold.is_online());
        assert_eq!(manifold.phase, HermesPhase::Online);
        assert_ne!(manifold.certificate.unwrap().root, 0);
        assert_ne!(
            manifold.snapshot_flags() & crate::quantum_crest::SNAPSHOT_FLAG_HERMES_ONLINE,
            0
        );
    }

    #[test]
    fn cannot_jump_to_online_without_gates() {
        let mut manifold = HermesManifold::dark(1);
        assert_eq!(
            manifold.ignite(true, true, true),
            Err(ManifoldFault::InvalidPhaseJump)
        );
        assert!(manifold.observe_probe(true).is_ok());
        assert_eq!(
            manifold.ignite(true, true, true),
            Err(ManifoldFault::InvalidPhaseJump)
        );
    }

    #[test]
    fn ill_formed_features_reject_negotiation() {
        let mut manifold = HermesManifold::dark(2);
        assert!(manifold.observe_probe(true).is_ok());
        assert!(manifold.observe_firmware(true).is_ok());
        assert!(manifold.arm_queues(true, 1).is_ok());
        // Display without command ring is forbidden by the Agda lattice.
        assert_eq!(
            manifold.negotiate(feature::BOOT_RPC | feature::DISPLAY),
            Err(ManifoldFault::IllFormedFeatures)
        );
    }

    #[test]
    fn recovery_and_quarantine_clear_online_flags() {
        let mut manifold = HermesManifold::dark(3);
        assert!(manifold.observe_probe(true).is_ok());
        assert!(manifold.observe_firmware(true).is_ok());
        assert!(manifold.arm_queues(true, 9).is_ok());
        assert!(
            manifold
                .negotiate(feature::BOOT_RPC | feature::COMMAND_RING | feature::EVENT_RING)
                .is_ok()
        );
        assert!(manifold.ignite(true, true, true).is_ok());
        assert!(manifold.detect_fault(false).is_ok());
        assert!(manifold.phase.is_degraded());
        assert_eq!(
            manifold.snapshot_flags() & crate::quantum_crest::SNAPSHOT_FLAG_RECOVERY_PENDING,
            crate::quantum_crest::SNAPSHOT_FLAG_RECOVERY_PENDING
        );
        assert!(manifold.contain().is_ok());
        assert_ne!(
            manifold.snapshot_flags() & crate::quantum_crest::SNAPSHOT_FLAG_QUARANTINE_ACTIVE,
            0
        );
        assert!(manifold.release().is_ok());
        assert_eq!(manifold.phase, HermesPhase::Offline);
        assert_eq!(manifold.generation, 4);
    }

    #[test]
    fn feature_well_formedness_matches_agda_rules() {
        assert!(feature::well_formed(0));
        assert!(feature::well_formed(feature::BOOT_RPC));
        assert!(!feature::well_formed(feature::COMMAND_RING));
        assert!(!feature::well_formed(feature::BOOT_RPC | feature::DISPLAY));
        assert!(feature::well_formed(
            feature::BOOT_RPC | feature::COMMAND_RING | feature::EVENT_RING | feature::DISPLAY
        ));
        assert!(!feature::well_formed(feature::BOOT_RPC | feature::COMPUTE));
        assert!(feature::well_formed(
            feature::BOOT_RPC | feature::MEMORY_MANAGEMENT | feature::COMPUTE
        ));
    }
}
