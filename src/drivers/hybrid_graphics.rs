//! Fail-closed hybrid Intel/NVIDIA graphics policy.
//!
//! A muxless notebook's internal panel is normally wired to the Intel display
//! engine. Hermes may own a separately isolated Turing-or-newer NVIDIA device
//! for bounded offload work, but it must never seize that panel merely because
//! it is a more powerful GPU. This policy consumes Drivernet's measured
//! resolutions and makes the split explicit for every downstream consumer.

use super::drivernet::GpuResolution;
use super::drivernet::GpuResolutionStatus;
use super::drivernet::fingerprint::{VENDOR_INTEL, VENDOR_NVIDIA, is_nvidia_turing_or_newer};
use super::drivernet::model::DriverStrategy;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanoutOwner {
    /// The retained firmware surface is the only verified presentation path.
    Firmware,
    /// A committed Intel display backend owns the muxless panel.
    Intel,
    /// No verified presentation owner exists.
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HermesOffloadState {
    /// No Turing-or-newer NVIDIA display function was discovered.
    Absent,
    /// A supported NVIDIA GPU was measured, but a GSP backend has not met all
    /// activation requirements (firmware, isolated DMA, MMIO, IRQ, queues,
    /// negotiation, health, and recovery).
    AwaitingGsp,
    /// A committed Hermes backend owns the discrete device only for offload.
    Online,
    /// More than one suitable NVIDIA function was found; choosing one without
    /// an explicit measured display-routing policy would be ambiguous.
    Ambiguous,
    /// NVIDIA hardware is present but is older than the supported Turing
    /// baseline and cannot be routed to Hermes.
    UnsupportedArchitecture,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HybridGraphicsMode {
    FirmwareOnly,
    IntelOnly,
    /// The standard Optimus/muxless laptop configuration: Intel owns scanout
    /// and Hermes owns a distinct NVIDIA offload domain.
    IntelScanoutHermesOffload,
    /// A supported NVIDIA device exists, but no second GPU was measured. Its
    /// display ownership is intentionally not inferred by this hybrid policy.
    DiscreteOnlyFailClosed,
    AmbiguousFailClosed,
}

/// The immutable boot decision carried from hardware discovery to the desktop
/// stack. PCI roots rather than MMIO addresses cross this boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HybridGraphicsPlan {
    pub mode: HybridGraphicsMode,
    pub scanout: ScanoutOwner,
    pub hermes: HermesOffloadState,
    pub intel_evidence_root: u64,
    pub nvidia_evidence_root: u64,
}

impl HybridGraphicsPlan {
    pub const fn hermes_online(self) -> bool {
        matches!(self.hermes, HermesOffloadState::Online)
    }

    pub const fn keeps_nvidia_offload_only(self) -> bool {
        matches!(self.mode, HybridGraphicsMode::IntelScanoutHermesOffload)
    }
}

/// Selects only a topology-safe hybrid arrangement. A PCI ID makes a device a
/// candidate, never an active GSP transport: the `Online` state additionally
/// requires Drivernet's committed Hermes resolution.
pub fn plan(resolutions: &[GpuResolution]) -> HybridGraphicsPlan {
    let mut intel = None;
    let mut nvidia = None;
    let mut nvidia_count = 0_u8;
    let mut legacy_nvidia = false;
    let mut firmware_available = false;

    for resolution in resolutions.iter().copied() {
        if resolution.display_available() {
            firmware_available = true;
        }
        if resolution.fingerprint.vendor_id == VENDOR_INTEL && intel.is_none() {
            intel = Some(resolution);
        }
        if resolution.fingerprint.vendor_id != VENDOR_NVIDIA {
            continue;
        }
        if !is_nvidia_turing_or_newer(resolution.fingerprint.device_id) {
            legacy_nvidia = true;
            continue;
        }
        nvidia_count = nvidia_count.saturating_add(1);
        if nvidia.is_none() {
            nvidia = Some(resolution);
        }
    }

    let intel_online = intel.is_some_and(|resolution| {
        resolution.status == GpuResolutionStatus::Committed
            && resolution.strategy == DriverStrategy::IntelDisplay
            && resolution.driver_handle != 0
    });
    let scanout = if intel_online {
        ScanoutOwner::Intel
    } else if firmware_available {
        ScanoutOwner::Firmware
    } else {
        ScanoutOwner::Unavailable
    };
    let intel_evidence_root = intel.map_or(0, |resolution| resolution.fingerprint.evidence_root);

    let (hermes, nvidia_evidence_root) = if nvidia_count > 1 {
        (HermesOffloadState::Ambiguous, 0)
    } else if let Some(resolution) = nvidia {
        let online = resolution.status == GpuResolutionStatus::Committed
            && resolution.strategy == DriverStrategy::HermesNvidia
            && resolution.driver_handle != 0;
        (
            if online {
                HermesOffloadState::Online
            } else {
                HermesOffloadState::AwaitingGsp
            },
            resolution.fingerprint.evidence_root,
        )
    } else if legacy_nvidia {
        (HermesOffloadState::UnsupportedArchitecture, 0)
    } else {
        (HermesOffloadState::Absent, 0)
    };

    let mode = match hermes {
        HermesOffloadState::Ambiguous => HybridGraphicsMode::AmbiguousFailClosed,
        HermesOffloadState::Absent | HermesOffloadState::UnsupportedArchitecture => {
            if intel.is_some() {
                HybridGraphicsMode::IntelOnly
            } else {
                HybridGraphicsMode::FirmwareOnly
            }
        }
        HermesOffloadState::AwaitingGsp | HermesOffloadState::Online => {
            if intel.is_some() {
                HybridGraphicsMode::IntelScanoutHermesOffload
            } else {
                HybridGraphicsMode::DiscreteOnlyFailClosed
            }
        }
    };

    HybridGraphicsPlan {
        mode,
        scanout,
        hermes,
        intel_evidence_root,
        nvidia_evidence_root,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolution(vendor_id: u16, device_id: u16) -> GpuResolution {
        let mut resolution = GpuResolution::EMPTY;
        resolution.fingerprint.vendor_id = vendor_id;
        resolution.fingerprint.device_id = device_id;
        resolution.fingerprint.class_code = 0x03;
        resolution.fingerprint.evidence_root = u64::from(vendor_id) << 16 | u64::from(device_id);
        resolution
    }

    #[test]
    fn t1000_is_a_turing_hermes_candidate_but_never_steals_intel_scanout() {
        let intel = resolution(VENDOR_INTEL, 0x3e9b);
        let t1000 = resolution(VENDOR_NVIDIA, 0x1fb9);
        let plan = plan(&[intel, t1000]);
        assert_eq!(plan.mode, HybridGraphicsMode::IntelScanoutHermesOffload);
        assert_eq!(plan.hermes, HermesOffloadState::AwaitingGsp);
        assert!(!plan.hermes_online());
    }

    #[test]
    fn online_hermes_remains_an_offload_domain_for_muxless_intel() {
        let mut intel = resolution(VENDOR_INTEL, 0x3e9b);
        intel.status = GpuResolutionStatus::Committed;
        intel.strategy = DriverStrategy::IntelDisplay;
        intel.driver_handle = 1;
        let mut t1000 = resolution(VENDOR_NVIDIA, 0x1fb9);
        t1000.status = GpuResolutionStatus::Committed;
        t1000.strategy = DriverStrategy::HermesNvidia;
        t1000.driver_handle = 2;

        let plan = plan(&[intel, t1000]);
        assert_eq!(plan.scanout, ScanoutOwner::Intel);
        assert_eq!(plan.hermes, HermesOffloadState::Online);
        assert!(plan.keeps_nvidia_offload_only());
    }

    #[test]
    fn a_pre_turing_nvidia_device_is_never_admitted_to_hermes() {
        let plan = plan(&[resolution(VENDOR_NVIDIA, 0x1db6)]);
        assert_eq!(plan.hermes, HermesOffloadState::UnsupportedArchitecture);
        assert_eq!(plan.mode, HybridGraphicsMode::FirmwareOnly);
    }

    #[test]
    fn multiple_turing_plus_devices_are_ambiguous_without_a_measured_route() {
        let plan = plan(&[
            resolution(VENDOR_INTEL, 0x3e9b),
            resolution(VENDOR_NVIDIA, 0x1fb9),
            resolution(VENDOR_NVIDIA, 0x2204),
        ]);
        assert_eq!(plan.hermes, HermesOffloadState::Ambiguous);
        assert_eq!(plan.mode, HybridGraphicsMode::AmbiguousFailClosed);
    }
}
