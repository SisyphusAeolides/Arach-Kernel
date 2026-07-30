//! Measured NVIDIA GSP-RM firmware admission.
//!
//! The NVIDIA Open GPU Kernel Modules 610.43.03 source release documents that
//! its Turing-and-later module uses a matching GSP firmware ABI. Its Nouveau
//! integration further documents the two firmware lines: TU10x (also GA100)
//! and GA10x for the later supported families. This module records that
//! versioned boundary in Arach. It accepts redistributable firmware bytes
//! only after their exact length and SHA-256 match a measured manifest.
//!
//! This is deliberately an *admission* component, not a claim that the GSP is
//! online. The native boot personality, an IOMMU-backed DMA domain, MMIO
//! registers, and interrupt delivery must still complete successfully before
//! any caller can publish an online Hermes session.

use sisyphus_driver_abi::hermes::{HermesPciIdentity, HermesProbeEvidence, HermesTransportProfile};

use crate::predictive_control::hash::Sha256;

use super::drivernet::fingerprint::{
    NVIDIA_ARCHITECTURE_ADA, NVIDIA_ARCHITECTURE_AMPERE, NVIDIA_ARCHITECTURE_BLACKWELL,
    NVIDIA_ARCHITECTURE_HOPPER, NVIDIA_ARCHITECTURE_TURING, nvidia_architecture_hint,
};
use super::hermes_gsp::{
    FirmwareAuthority, FirmwareImage, FirmwareSeal, HermesFault, NVIDIA_VENDOR_ID,
};

/// Set on every image admitted as a vendor GSP-RM firmware payload.
pub const FIRMWARE_FLAG_NVIDIA_GSP_RM: u64 = 1 << 0;

/// GSP-RM firmware used by TU10x devices and GA100.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NvidiaGspFirmwareFamily {
    Tu10x,
    Ga10x,
}

/// The bounded image-size envelopes supported by Arach’s static DMA ledger.
pub const MAXIMUM_TU10X_GSP_BYTES: u32 = 32 * 1024 * 1024;
pub const MAXIMUM_GA10X_GSP_BYTES: u32 = 96 * 1024 * 1024;

/// A source-pinned redistributable firmware image. `version` is encoded as
/// `major << 32 | minor << 16 | patch`, which preserves NVIDIA’s three-part
/// release version without parsing untrusted text in the kernel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvidiaGspFirmwareManifest {
    pub family: NvidiaGspFirmwareFamily,
    pub version: u64,
    pub byte_length: u32,
    pub sha256: [u8; 32],
}

impl NvidiaGspFirmwareManifest {
    pub const fn new(
        family: NvidiaGspFirmwareFamily,
        version: u64,
        byte_length: u32,
        sha256: [u8; 32],
    ) -> Self {
        Self {
            family,
            version,
            byte_length,
            sha256,
        }
    }

    pub fn valid(self) -> bool {
        self.version != 0
            && self.byte_length != 0
            && self.sha256 != [0; 32]
            && self.byte_length <= maximum_image_bytes(self.family)
    }
}

pub const fn firmware_version(major: u16, minor: u16, patch: u16) -> u64 {
    (major as u64) << 32 | (minor as u64) << 16 | patch as u64
}

/// The locally measured 610.43.03 GSP-RM artifacts. These are manifest data,
/// not firmware copies: redistributable firmware is staged explicitly by the
/// image build and never hidden in Arach’s source tree.
pub const NVIDIA_GSP_RM_610_43_03: [NvidiaGspFirmwareManifest; 2] = [
    NvidiaGspFirmwareManifest::new(
        NvidiaGspFirmwareFamily::Tu10x,
        firmware_version(610, 43, 3),
        29_352_832,
        [
            0x73, 0x06, 0x56, 0x19, 0xdb, 0x9e, 0xc9, 0x21, 0xd1, 0x9f, 0xc4, 0xe5, 0x19, 0xdd,
            0x04, 0xd9, 0x1a, 0x91, 0x99, 0xb5, 0x25, 0xea, 0xca, 0x9b, 0x25, 0x7b, 0x89, 0xfb,
            0x8c, 0x5e, 0x52, 0xc0,
        ],
    ),
    NvidiaGspFirmwareManifest::new(
        NvidiaGspFirmwareFamily::Ga10x,
        firmware_version(610, 43, 3),
        84_277_400,
        [
            0x57, 0x23, 0x73, 0x62, 0x0a, 0x37, 0x41, 0x8f, 0x24, 0xdc, 0x16, 0xb5, 0x03, 0x1c,
            0x39, 0x33, 0x87, 0x78, 0xc3, 0x25, 0x7e, 0x48, 0xe8, 0x40, 0x8d, 0xe9, 0xa5, 0x72,
            0x91, 0xb2, 0x4f, 0x3a,
        ],
    ),
];

/// One auxiliary image used by the documented SEC2/GSP bootstrap sequence.
/// The role is typed so that an image with a valid digest cannot be supplied
/// to the wrong hardware mailbox phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TuringGspBootstrapRole {
    GenericSec2Bootloader,
    GspBootloader,
    BooterLoad,
    BooterUnload,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvidiaGspBootstrapArtifactManifest {
    pub role: TuringGspBootstrapRole,
    pub byte_length: u32,
    pub sha256: [u8; 32],
}

impl NvidiaGspBootstrapArtifactManifest {
    pub const fn new(role: TuringGspBootstrapRole, byte_length: u32, sha256: [u8; 32]) -> Self {
        Self {
            role,
            byte_length,
            sha256,
        }
    }
}

/// Exact TU117 (Quadro T1000) auxiliary images emitted by NVIDIA's official
/// 610.43.03 Nouveau extraction tool. TU117 shares its generic SEC2 and GSP
/// bootloader with TU102, but has TU116-specific Booter Load/Unload images.
/// These do not include the much larger GSP-RM application image; that image
/// is checked separately by `NvidiaGspFirmwareAuthority` above.
pub const T1000_TU117_BOOTSTRAP_610_43_03: [NvidiaGspBootstrapArtifactManifest; 4] = [
    NvidiaGspBootstrapArtifactManifest::new(
        TuringGspBootstrapRole::GenericSec2Bootloader,
        816,
        [
            0xb3, 0x77, 0x76, 0xa5, 0x11, 0xb4, 0xa0, 0x09, 0x01, 0xe4, 0xe3, 0xac, 0x56, 0x8d,
            0xb9, 0x17, 0x08, 0x6d, 0x3b, 0xf4, 0x39, 0xf8, 0x5b, 0xc9, 0xb3, 0xe4, 0xad, 0xc7,
            0x33, 0x8a, 0x0a, 0xff,
        ],
    ),
    NvidiaGspBootstrapArtifactManifest::new(
        TuringGspBootstrapRole::GspBootloader,
        4_196,
        [
            0x12, 0xe9, 0x87, 0xb6, 0x36, 0xc2, 0xf0, 0x0f, 0xa4, 0x0f, 0x42, 0xfd, 0x95, 0x09,
            0x75, 0x15, 0xc0, 0x81, 0x7b, 0x15, 0x81, 0x19, 0xc5, 0x84, 0x04, 0x9a, 0x37, 0xfa,
            0xf3, 0x8f, 0x8f, 0x96,
        ],
    ),
    NvidiaGspBootstrapArtifactManifest::new(
        TuringGspBootstrapRole::BooterLoad,
        59_016,
        [
            0x9b, 0xd0, 0x18, 0x04, 0xb4, 0xb9, 0x1d, 0x92, 0x90, 0x4e, 0x77, 0x35, 0xb0, 0x25,
            0xe0, 0x7a, 0x3c, 0x93, 0x5b, 0xc6, 0xfb, 0x92, 0xe3, 0x83, 0x3e, 0x85, 0xc2, 0x97,
            0x54, 0x60, 0x25, 0xb9,
        ],
    ),
    NvidiaGspBootstrapArtifactManifest::new(
        TuringGspBootstrapRole::BooterUnload,
        39_048,
        [
            0xbf, 0x4a, 0x2b, 0x77, 0x87, 0x22, 0xdd, 0xe5, 0x78, 0x50, 0x83, 0x9b, 0xb9, 0xf7,
            0x65, 0x1a, 0xe2, 0x95, 0x92, 0xce, 0x85, 0xd6, 0xdf, 0x41, 0x60, 0xd2, 0xd2, 0x28,
            0xff, 0x43, 0x01, 0x56,
        ],
    ),
];

/// The only complete Turing bootstrap bundle accepted by this revision of
/// Arach. It reflects the documented order in the NVIDIA source: the
/// generic SEC2 bootloader and Booter Load establish the protected region;
/// the GSP bootloader launches GSP-RM; Booter Unload is retained solely for
/// controlled recovery/teardown.
#[derive(Clone, Copy)]
pub struct TuringGspBootstrapMaterial<'a> {
    pub generic_sec2_bootloader: &'a [u8],
    pub gsp_bootloader: &'a [u8],
    pub booter_load: &'a [u8],
    pub booter_unload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedTuringGspBootstrap {
    pub manifest_root: [u8; 32],
    pub version: u64,
}

impl TuringGspBootstrapMaterial<'_> {
    /// Verifies every auxiliary image before Arach maps any firmware DMA.
    /// A missing, reordered, substituted, or version-mismatched image fails
    /// before SEC2 or GSP MMIO can be written.
    pub fn verify_t1000_610_43_03(&self) -> Result<VerifiedTuringGspBootstrap, HermesFault> {
        let bytes = [
            self.generic_sec2_bootloader,
            self.gsp_bootloader,
            self.booter_load,
            self.booter_unload,
        ];
        let mut root = Sha256::new();
        root.update(b"Sisyphus Turing GSP bootstrap v1")
            .map_err(|_| HermesFault::FirmwareRejected)?;
        for (artifact, expected) in bytes.iter().copied().zip(T1000_TU117_BOOTSTRAP_610_43_03) {
            let length = u32::try_from(artifact.len()).map_err(|_| HermesFault::FirmwareSize)?;
            let hash = Sha256::digest(artifact).map_err(|_| HermesFault::FirmwareRejected)?;
            if length != expected.byte_length || hash != expected.sha256 {
                return Err(HermesFault::FirmwareRejected);
            }
            root.update(&[expected.role as u8])
                .map_err(|_| HermesFault::FirmwareRejected)?;
            root.update(&hash)
                .map_err(|_| HermesFault::FirmwareRejected)?;
        }
        Ok(VerifiedTuringGspBootstrap {
            manifest_root: root.finalize(),
            version: firmware_version(610, 43, 3),
        })
    }
}

pub const fn maximum_image_bytes(family: NvidiaGspFirmwareFamily) -> u32 {
    match family {
        NvidiaGspFirmwareFamily::Tu10x => MAXIMUM_TU10X_GSP_BYTES,
        NvidiaGspFirmwareFamily::Ga10x => MAXIMUM_GA10X_GSP_BYTES,
    }
}

/// Classifies only NVIDIA device-ID bands that Arach already recognizes.
/// Unknown future IDs never inherit support merely because they are NVIDIA.
pub const fn firmware_family_for_device(device_id: u16) -> Option<NvidiaGspFirmwareFamily> {
    let architecture = nvidia_architecture_hint(device_id);
    if architecture & NVIDIA_ARCHITECTURE_TURING != 0
        || (device_id >= 0x2000 && device_id <= 0x20ff)
    {
        return Some(NvidiaGspFirmwareFamily::Tu10x);
    }
    if architecture
        & (NVIDIA_ARCHITECTURE_AMPERE
            | NVIDIA_ARCHITECTURE_HOPPER
            | NVIDIA_ARCHITECTURE_ADA
            | NVIDIA_ARCHITECTURE_BLACKWELL)
        != 0
    {
        return Some(NvidiaGspFirmwareFamily::Ga10x);
    }
    None
}

/// Authenticates images against an image-build supplied allow-list. The
/// authority has no default permissive path: an empty allow-list rejects all
/// GPU firmware, and a sealed evidence mismatch rejects the selected image.
pub struct NvidiaGspFirmwareAuthority<'a> {
    allow_list: &'a [NvidiaGspFirmwareManifest],
    policy_epoch: u64,
    trust_domain: u64,
}

impl<'a> NvidiaGspFirmwareAuthority<'a> {
    pub const fn new(
        allow_list: &'a [NvidiaGspFirmwareManifest],
        policy_epoch: u64,
        trust_domain: u64,
    ) -> Self {
        Self {
            allow_list,
            policy_epoch,
            trust_domain,
        }
    }

    pub const fn allow_list(&self) -> &[NvidiaGspFirmwareManifest] {
        self.allow_list
    }
}

impl FirmwareAuthority for NvidiaGspFirmwareAuthority<'_> {
    fn authenticate(
        &self,
        identity: &HermesPciIdentity,
        evidence: &HermesProbeEvidence,
        profile: &HermesTransportProfile,
        image: &FirmwareImage<'_>,
    ) -> Result<FirmwareSeal, HermesFault> {
        if identity.vendor_id != NVIDIA_VENDOR_ID
            || self.policy_epoch == 0
            || self.trust_domain == 0
            || image.flags & FIRMWARE_FLAG_NVIDIA_GSP_RM == 0
        {
            return Err(HermesFault::FirmwareRejected);
        }
        let family = firmware_family_for_device(identity.device_id)
            .ok_or(HermesFault::UnsupportedArchitecture)?;
        let measured_length =
            u32::try_from(image.bytes.len()).map_err(|_| HermesFault::FirmwareSize)?;
        if measured_length > maximum_image_bytes(family)
            || profile.firmware_maximum_bytes > maximum_image_bytes(family)
        {
            return Err(HermesFault::FirmwareSize);
        }
        let measured_hash =
            Sha256::digest(image.bytes).map_err(|_| HermesFault::FirmwareRejected)?;
        if measured_hash != image.manifest_hash
            || (evidence.firmware_manifest_hash != [0; 32]
                && evidence.firmware_manifest_hash != measured_hash)
            || (evidence.firmware_version != 0 && evidence.firmware_version != image.version)
        {
            return Err(HermesFault::FirmwareRejected);
        }
        let manifest = self
            .allow_list
            .iter()
            .copied()
            .find(|candidate| {
                candidate.valid()
                    && candidate.family == family
                    && candidate.version == image.version
                    && candidate.byte_length == measured_length
                    && candidate.sha256 == measured_hash
            })
            .ok_or(HermesFault::FirmwareRejected)?;
        if manifest.sha256 != image.manifest_hash {
            return Err(HermesFault::FirmwareRejected);
        }
        Ok(FirmwareSeal {
            manifest_hash: manifest.sha256,
            version: manifest.version,
            policy_epoch: self.policy_epoch,
            trust_domain: self.trust_domain,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(device_id: u16) -> HermesPciIdentity {
        HermesPciIdentity {
            segment: 0,
            bus: 1,
            slot: 0,
            function: 0,
            revision: 0,
            vendor_id: NVIDIA_VENDOR_ID,
            device_id,
            subsystem_vendor_id: 0,
            subsystem_device_id: 0,
            class_code: 3,
            subclass: 0,
            programming_interface: 0,
            reserved: 0,
        }
    }

    #[test]
    fn t1000_uses_the_tu10x_gsp_firmware_line() {
        assert_eq!(
            firmware_family_for_device(0x1fb9),
            Some(NvidiaGspFirmwareFamily::Tu10x)
        );
        assert_eq!(
            firmware_family_for_device(0x2204),
            Some(NvidiaGspFirmwareFamily::Ga10x)
        );
        assert_eq!(firmware_family_for_device(0x1db6), None);
    }

    #[test]
    fn authority_requires_the_exact_measured_image_and_sealed_evidence() {
        let bytes = b"measured gsp-rm image";
        let hash = Sha256::digest(bytes).unwrap();
        let version = firmware_version(610, 43, 3);
        let manifest = [NvidiaGspFirmwareManifest::new(
            NvidiaGspFirmwareFamily::Tu10x,
            version,
            bytes.len() as u32,
            hash,
        )];
        let authority = NvidiaGspFirmwareAuthority::new(&manifest, 7, 11);
        let image = FirmwareImage {
            bytes,
            manifest_hash: hash,
            version,
            flags: FIRMWARE_FLAG_NVIDIA_GSP_RM,
        };
        let mut evidence = HermesProbeEvidence::empty();
        evidence.firmware_manifest_hash = hash;
        evidence.firmware_version = version;
        let seal = authority
            .authenticate(
                &identity(0x1fb9),
                &evidence,
                &HermesTransportProfile::empty(),
                &image,
            )
            .unwrap();
        assert_eq!(seal.manifest_hash, hash);
        assert_eq!(seal.trust_domain, 11);

        let tampered = FirmwareImage {
            bytes: b"measured gsp-rm imagE",
            ..image
        };
        assert_eq!(
            authority.authenticate(
                &identity(0x1fb9),
                &evidence,
                &HermesTransportProfile::empty(),
                &tampered,
            ),
            Err(HermesFault::FirmwareRejected)
        );
    }
}
