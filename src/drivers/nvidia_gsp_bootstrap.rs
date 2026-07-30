//! Bounded parsing for NVIDIA's TU10x SEC2/GSP bootstrap images.
//!
//! NVIDIA's official Nouveau extraction tool emits each auxiliary GSP image
//! with a compact `nvfw_bin_hdr` prefix. This module validates that prefix and
//! binds the four images needed by the TU117 path into one immutable plan.
//! It intentionally performs no MMIO itself: the plan must first be admitted
//! by an IOMMU-backed native executor that implements the SEC2 Falcon flow.

use super::hermes_gsp::HermesFault;
use crate::predictive_control::hash::Sha256;

use super::nvidia_gsp_firmware::{
    NVIDIA_GSP_RM_610_43_03, NvidiaGspFirmwareFamily, T1000_TU117_BOOTSTRAP_610_43_03,
    TuringGspBootstrapMaterial, VerifiedTuringGspBootstrap,
};

const NVFW_HEADER_BYTES: usize = 24;
const NVIDIA_VENDOR_ID: u32 = 0x10de;
const NVFW_FORMAT_VERSION: u32 = 1;
const T1000_GSP_BUNDLE_ARTIFACTS: usize = 5;

/// The largest amount of firmware data a verifier invocation may hash. This
/// converts the 29 MiB GSP-RM remeasurement into resumable scheduler work;
/// an early boot path may never monopolize a core while establishing a GPU
/// capability.
pub const MAXIMUM_T1000_GSP_VERIFICATION_SLICE: usize = 64 * 1024;

/// A checked view of one `nvfw_bin_hdr` image. Both slices are bounded by the
/// original firmware slice and retain no ownership of the staged bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvfwImage<'a> {
    bytes: &'a [u8],
    descriptor_range: (usize, usize),
    payload_range: (usize, usize),
}

impl<'a> NvfwImage<'a> {
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn descriptor(&self) -> &'a [u8] {
        &self.bytes[self.descriptor_range.0..self.descriptor_range.1]
    }

    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[self.payload_range.0..self.payload_range.1]
    }
}

/// The verified source-pinned auxiliary images needed to execute NVIDIA's
/// documented TU117 route through SEC2 and into GSP-RM. The executor must use
/// them in order and retain `booter_unload` for only recovery/teardown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TuringGspBootstrapPlan<'a> {
    pub verification: VerifiedTuringGspBootstrap,
    pub generic_sec2_bootloader: NvfwImage<'a>,
    pub gsp_bootloader: NvfwImage<'a>,
    pub booter_load: NvfwImage<'a>,
    pub booter_unload: NvfwImage<'a>,
}

/// The complete, measured TU117 boot input set as received from Granite's
/// immutable boot modules.  This is deliberately not a generic GSP loader:
/// it names the exact 610.43.03 TU10x GSP-RM image and the four source-pinned
/// SEC2/GSP auxiliary artifacts required for its documented bootstrap.
#[derive(Clone, Copy)]
pub struct TuringGspStagedBundle<'a> {
    pub gsp_rm: &'a [u8],
    pub bootstrap: TuringGspBootstrapMaterial<'a>,
}

/// Evidence produced only after both the large GSP-RM artifact and every
/// SEC2/GSP bootstrap artifact have been independently authenticated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedTuringGspStagedBundle {
    pub manifest_root: [u8; 32],
    pub gsp_rm_hash: [u8; 32],
    pub bootstrap: TuringGspBootstrapPlanEvidence,
}

/// The portion of the staged evidence that identifies the auxiliary-image
/// plan without retaining a borrowed firmware slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TuringGspBootstrapPlanEvidence {
    pub manifest_root: [u8; 32],
    pub version: u64,
}

/// Resumable exact-hash verifier for the five measured T1000 boot artifacts.
/// It holds borrowed immutable module memory only; callers must retain that
/// memory and may call `advance` at bounded scheduler safe points. A complete
/// result is the sole input acceptable to WPR allocation or SEC2 MMIO.
pub struct TuringGspStagedBundleVerifier<'a> {
    bundle: TuringGspStagedBundle<'a>,
    next_artifact: usize,
    offset: usize,
    hash: Sha256,
    hashes: [[u8; 32]; T1000_GSP_BUNDLE_ARTIFACTS],
}

impl<'a> TuringGspBootstrapPlan<'a> {
    /// Builds an executable-data plan only after exact auxiliary-image
    /// verification. This still does not indicate an active GSP.
    pub fn from_verified_material(
        material: TuringGspBootstrapMaterial<'a>,
    ) -> Result<Self, HermesFault> {
        let verification = material.verify_t1000_610_43_03()?;
        Ok(Self {
            verification,
            generic_sec2_bootloader: parse_nvfw_image(material.generic_sec2_bootloader)?,
            gsp_bootloader: parse_nvfw_image(material.gsp_bootloader)?,
            booter_load: parse_nvfw_image(material.booter_load)?,
            booter_unload: parse_nvfw_image(material.booter_unload)?,
        })
    }
}

impl<'a> TuringGspStagedBundle<'a> {
    /// Starts a bounded remeasurement pass. This establishes exact artifact
    /// lengths immediately, but it intentionally does not claim the bundle is
    /// authentic until `advance` has hashed every byte.
    pub fn begin_t1000_610_43_03_verification(
        self,
    ) -> Result<TuringGspStagedBundleVerifier<'a>, HermesFault> {
        for index in 0..T1000_GSP_BUNDLE_ARTIFACTS {
            let (expected_length, _) = expected_artifact(index)?;
            if self.artifact(index)?.len() != expected_length {
                return Err(HermesFault::FirmwareRejected);
            }
        }
        Ok(TuringGspStagedBundleVerifier {
            bundle: self,
            next_artifact: 0,
            offset: 0,
            hash: Sha256::new(),
            hashes: [[0; 32]; T1000_GSP_BUNDLE_ARTIFACTS],
        })
    }

    /// Synchronous convenience wrapper for host tools and tests. Native boot
    /// code must use `begin_t1000_610_43_03_verification` and bounded calls to
    /// `TuringGspStagedBundleVerifier::advance` instead.
    pub fn verify_t1000_610_43_03(&self) -> Result<VerifiedTuringGspStagedBundle, HermesFault> {
        let mut verifier = (*self).begin_t1000_610_43_03_verification()?;
        loop {
            if let Some(evidence) = verifier.advance(MAXIMUM_T1000_GSP_VERIFICATION_SLICE)? {
                return Ok(evidence);
            }
        }
    }

    fn artifact(&self, index: usize) -> Result<&[u8], HermesFault> {
        match index {
            0 => Ok(self.gsp_rm),
            1 => Ok(self.bootstrap.generic_sec2_bootloader),
            2 => Ok(self.bootstrap.gsp_bootloader),
            3 => Ok(self.bootstrap.booter_load),
            4 => Ok(self.bootstrap.booter_unload),
            _ => Err(HermesFault::FirmwareRejected),
        }
    }
}

impl TuringGspStagedBundleVerifier<'_> {
    /// Hashes no more than `MAXIMUM_T1000_GSP_VERIFICATION_SLICE` bytes and
    /// returns `Some` only after every image, its hash, and all auxiliary
    /// `nvfw_bin_hdr` layouts have been checked.
    pub fn advance(
        &mut self,
        budget: usize,
    ) -> Result<Option<VerifiedTuringGspStagedBundle>, HermesFault> {
        if budget == 0 {
            return Err(HermesFault::BootFuelExhausted);
        }
        let mut remaining = budget.min(MAXIMUM_T1000_GSP_VERIFICATION_SLICE);
        while remaining != 0 && self.next_artifact < T1000_GSP_BUNDLE_ARTIFACTS {
            let artifact = self.bundle.artifact(self.next_artifact)?;
            let available = artifact
                .len()
                .checked_sub(self.offset)
                .ok_or(HermesFault::FirmwareRejected)?;
            let take = available.min(remaining);
            if take != 0 {
                let end = self
                    .offset
                    .checked_add(take)
                    .ok_or(HermesFault::FirmwareRejected)?;
                self.hash
                    .update(&artifact[self.offset..end])
                    .map_err(|_| HermesFault::FirmwareRejected)?;
                self.offset = end;
                remaining -= take;
            }
            if self.offset == artifact.len() {
                let (_, expected_hash) = expected_artifact(self.next_artifact)?;
                let digest = core::mem::replace(&mut self.hash, Sha256::new()).finalize();
                if digest != expected_hash {
                    return Err(HermesFault::FirmwareRejected);
                }
                self.hashes[self.next_artifact] = digest;
                self.next_artifact += 1;
                self.offset = 0;
            }
        }
        if self.next_artifact == T1000_GSP_BUNDLE_ARTIFACTS {
            return self.complete().map(Some);
        }
        Ok(None)
    }

    fn complete(&self) -> Result<VerifiedTuringGspStagedBundle, HermesFault> {
        parse_nvfw_image(self.bundle.bootstrap.generic_sec2_bootloader)?;
        parse_nvfw_image(self.bundle.bootstrap.gsp_bootloader)?;
        parse_nvfw_image(self.bundle.bootstrap.booter_load)?;
        parse_nvfw_image(self.bundle.bootstrap.booter_unload)?;

        let mut bootstrap_root = Sha256::new();
        bootstrap_root
            .update(b"Sisyphus Turing GSP bootstrap v1")
            .map_err(|_| HermesFault::FirmwareRejected)?;
        for (index, manifest) in T1000_TU117_BOOTSTRAP_610_43_03.iter().enumerate() {
            bootstrap_root
                .update(&[manifest.role as u8])
                .map_err(|_| HermesFault::FirmwareRejected)?;
            bootstrap_root
                .update(&self.hashes[index + 1])
                .map_err(|_| HermesFault::FirmwareRejected)?;
        }
        let bootstrap_root = bootstrap_root.finalize();

        let mut root = Sha256::new();
        root.update(b"Sisyphus staged T1000 GSP bundle v1")
            .map_err(|_| HermesFault::FirmwareRejected)?;
        root.update(&self.hashes[0])
            .map_err(|_| HermesFault::FirmwareRejected)?;
        root.update(&bootstrap_root)
            .map_err(|_| HermesFault::FirmwareRejected)?;

        Ok(VerifiedTuringGspStagedBundle {
            manifest_root: root.finalize(),
            gsp_rm_hash: self.hashes[0],
            bootstrap: TuringGspBootstrapPlanEvidence {
                manifest_root: bootstrap_root,
                version: firmware_version_610_43_03(),
            },
        })
    }
}

fn expected_artifact(index: usize) -> Result<(usize, [u8; 32]), HermesFault> {
    if index == 0 {
        let manifest = NVIDIA_GSP_RM_610_43_03
            .iter()
            .copied()
            .find(|candidate| candidate.family == NvidiaGspFirmwareFamily::Tu10x)
            .ok_or(HermesFault::FirmwareRejected)?;
        return Ok((manifest.byte_length as usize, manifest.sha256));
    }
    let manifest = T1000_TU117_BOOTSTRAP_610_43_03
        .get(index - 1)
        .copied()
        .ok_or(HermesFault::FirmwareRejected)?;
    Ok((manifest.byte_length as usize, manifest.sha256))
}

const fn firmware_version_610_43_03() -> u64 {
    (610_u64 << 32) | (43_u64 << 16) | 3
}

/// Parses NVIDIA's extracted boot image format without trusting any offsets
/// supplied by the artifact. NVIDIA's extraction tool records the 256-byte
/// aligned *logical* image length in the header, but writes only the header,
/// descriptor, and payload bytes. A source-provided padded form is accepted
/// only when it is exactly that logical length; no other trailing data is
/// interpreted.
pub fn parse_nvfw_image(bytes: &[u8]) -> Result<NvfwImage<'_>, HermesFault> {
    if bytes.len() < NVFW_HEADER_BYTES {
        return Err(HermesFault::FirmwareRejected);
    }
    let vendor = read_u32(bytes, 0)?;
    let format_version = read_u32(bytes, 4)?;
    let total_bytes =
        usize::try_from(read_u32(bytes, 8)?).map_err(|_| HermesFault::FirmwareSize)?;
    let descriptor_start =
        usize::try_from(read_u32(bytes, 12)?).map_err(|_| HermesFault::FirmwareRejected)?;
    let payload_start =
        usize::try_from(read_u32(bytes, 16)?).map_err(|_| HermesFault::FirmwareRejected)?;
    let payload_bytes =
        usize::try_from(read_u32(bytes, 20)?).map_err(|_| HermesFault::FirmwareRejected)?;
    let payload_end = payload_start
        .checked_add(payload_bytes)
        .ok_or(HermesFault::FirmwareRejected)?;
    let aligned_payload_end = payload_end
        .checked_add(255)
        .map(|value| value & !255)
        .ok_or(HermesFault::FirmwareRejected)?;

    if vendor != NVIDIA_VENDOR_ID
        || format_version != NVFW_FORMAT_VERSION
        || total_bytes != aligned_payload_end
        || descriptor_start != NVFW_HEADER_BYTES
        || descriptor_start >= payload_start
        || payload_start > payload_end
        || (bytes.len() != payload_end && bytes.len() != total_bytes)
    {
        return Err(HermesFault::FirmwareRejected);
    }
    Ok(NvfwImage {
        bytes,
        descriptor_range: (descriptor_start, payload_start),
        payload_range: (payload_start, payload_end),
    })
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, HermesFault> {
    let end = offset.checked_add(4).ok_or(HermesFault::FirmwareRejected)?;
    let words = bytes
        .get(offset..end)
        .ok_or(HermesFault::FirmwareRejected)?;
    Ok(u32::from_le_bytes([words[0], words[1], words[2], words[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_image() -> [u8; 256] {
        let mut bytes = [0_u8; 256];
        for (offset, value) in [
            (0, NVIDIA_VENDOR_ID),
            (4, NVFW_FORMAT_VERSION),
            (8, 256),
            (12, NVFW_HEADER_BYTES as u32),
            (16, 64),
            (20, 128),
        ] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn parses_one_exact_bounded_nvfw_image() {
        let bytes = synthetic_image();
        let image = parse_nvfw_image(&bytes).unwrap();
        assert_eq!(image.descriptor().len(), 40);
        assert_eq!(image.payload().len(), 128);
    }

    #[test]
    fn accepts_the_source_documented_unpadded_extraction_form() {
        let bytes = synthetic_image();
        let image = parse_nvfw_image(&bytes[..192]).unwrap();
        assert_eq!(image.bytes().len(), 192);
        assert_eq!(image.payload().len(), 128);
    }

    #[test]
    fn rejects_header_length_and_payload_range_drift() {
        let mut bytes = synthetic_image();
        bytes[8..12].copy_from_slice(&255_u32.to_le_bytes());
        assert_eq!(parse_nvfw_image(&bytes), Err(HermesFault::FirmwareRejected));

        let mut bytes = synthetic_image();
        bytes[16..20].copy_from_slice(&240_u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&32_u32.to_le_bytes());
        assert_eq!(parse_nvfw_image(&bytes), Err(HermesFault::FirmwareRejected));
    }

    #[test]
    fn staged_bundle_refuses_an_unmeasured_primary_image_before_auxiliary_parsing() {
        let bundle = TuringGspStagedBundle {
            gsp_rm: b"not the measured T1000 GSP-RM image",
            bootstrap: TuringGspBootstrapMaterial {
                generic_sec2_bootloader: &[],
                gsp_bootloader: &[],
                booter_load: &[],
                booter_unload: &[],
            },
        };
        assert_eq!(
            bundle.verify_t1000_610_43_03(),
            Err(HermesFault::FirmwareRejected)
        );
    }
}
