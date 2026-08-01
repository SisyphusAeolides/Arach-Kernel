use blacklab::oureboros::{
    ArtifactManifest, ArtifactMeasurement, FractalClass, OureborosError, TargetArchitecture,
    VerifiedArtifact, sha256, verify_artifact,
};

use crate::capability::{Capability, RuntimeImageControl, UserlandImageControl};
use crate::module::loader::{LoadPlan, LoaderError};

pub const MINIMUM_USER_ADDRESS: u64 = 0x1000;
pub const USER_ADDRESS_LIMIT: u64 = 0x0000_8000_0000_0000;
pub const MAXIMUM_USER_IMAGE_SPAN: u64 = 64 * 1024 * 1024;

/// A measured image and its validated static load plan.
///
/// The artifact remains immutably borrowed for this object's lifetime.
/// The address-space installer consumes this object, copies each segment into
/// inaccessible zeroed staging memory, verifies initialized data and BSS, and
/// only then seals final permissions. Static relocations remain unsupported.
pub struct PreparedUserImage<'bytes> {
    artifact: VerifiedArtifact<'bytes>,
    plan: LoadPlan,
}

impl PreparedUserImage<'_> {
    pub const fn measurement(&self) -> ArtifactMeasurement {
        self.artifact.measurement()
    }

    pub const fn plan(&self) -> &LoadPlan {
        &self.plan
    }

    pub const fn bytes(&self) -> &[u8] {
        self.artifact.bytes()
    }
}

pub fn prepare_user_image<'bytes>(
    artifact: VerifiedArtifact<'bytes>,
    _authority: &Capability<'_, UserlandImageControl>,
) -> Result<PreparedUserImage<'bytes>, UserImageError> {
    validate_artifact_identity(&artifact)?;
    let plan = LoadPlan::parse(artifact.bytes()).map_err(UserImageError::Loader)?;
    validate_user_image(artifact, plan, RuntimeLinkerPolicy::Reject)
}

/// Measures and validates an executable supplied by the runtime filesystem.
///
/// Unlike boot artifacts, runtime files have no build-time digest manifest.
/// This boundary therefore computes the digest from the immutable snapshot,
/// binds that measurement to the load plan, and retains both until the
/// transactional installer has copied and verified every segment.
pub fn prepare_runtime_user_image<'bytes>(
    inode_id: u32,
    bytes: &'bytes [u8],
    _authority: &RuntimeImageControl,
) -> Result<PreparedUserImage<'bytes>, UserImageError> {
    let plan = LoadPlan::parse(bytes).map_err(UserImageError::Loader)?;
    prepare_runtime_artifact(inode_id, bytes, plan, RuntimeLinkerPolicy::Reject)
}

/// Measures and validates the main image of a dynamic Linux execution.
/// Admission requires a canonical `PT_INTERP` path and mapped ELF program
/// headers so the kernel can construct an authoritative auxiliary vector.
pub fn prepare_runtime_dynamic_image<'bytes>(
    inode_id: u32,
    bytes: &'bytes [u8],
    _authority: &RuntimeImageControl,
) -> Result<PreparedUserImage<'bytes>, UserImageError> {
    let plan = LoadPlan::parse(bytes).map_err(UserImageError::Loader)?;
    prepare_runtime_artifact(inode_id, bytes, plan, RuntimeLinkerPolicy::Require)
}

/// Measures and validates a separately snapshotted ET_DYN runtime linker at
/// the linker-specific load base. Runtime linkers cannot recursively name a
/// second interpreter.
pub fn prepare_runtime_linker_image<'bytes>(
    inode_id: u32,
    bytes: &'bytes [u8],
    _authority: &RuntimeImageControl,
) -> Result<PreparedUserImage<'bytes>, UserImageError> {
    let plan = LoadPlan::parse_runtime_linker(bytes).map_err(UserImageError::Loader)?;
    prepare_runtime_artifact(inode_id, bytes, plan, RuntimeLinkerPolicy::Reject)
}

fn prepare_runtime_artifact<'bytes>(
    inode_id: u32,
    bytes: &'bytes [u8],
    plan: LoadPlan,
    linker_policy: RuntimeLinkerPolicy,
) -> Result<PreparedUserImage<'bytes>, UserImageError> {
    let entry_offset = plan.entry_file_offset().map_err(UserImageError::Loader)?;
    let artifact = verify_artifact(
        ArtifactManifest {
            inode_id: inode_id.max(1),
            class: FractalClass::Executable,
            architecture: TargetArchitecture::X86_64,
            entry_offset,
            expected_sha256: sha256(bytes),
        },
        bytes,
    )
    .map_err(UserImageError::Measurement)?;
    validate_user_image(artifact, plan, linker_policy)
}

fn validate_user_image<'bytes>(
    artifact: VerifiedArtifact<'bytes>,
    plan: LoadPlan,
    linker_policy: RuntimeLinkerPolicy,
) -> Result<PreparedUserImage<'bytes>, UserImageError> {
    validate_artifact_identity(&artifact)?;
    let measurement = artifact.measurement();
    match (linker_policy, plan.requires_runtime_linker) {
        (RuntimeLinkerPolicy::Reject, true) => {
            return Err(UserImageError::RuntimeLinkerUnavailable);
        }
        (RuntimeLinkerPolicy::Require, false) => {
            return Err(UserImageError::RuntimeLinkerRequired);
        }
        _ => {}
    }
    if linker_policy == RuntimeLinkerPolicy::Require && plan.program_header_address().is_none() {
        return Err(UserImageError::ProgramHeadersUnavailable);
    }
    let image_span = plan
        .image_end
        .checked_sub(plan.image_start)
        .ok_or(UserImageError::InvalidUserRange)?;
    if plan.image_start < MINIMUM_USER_ADDRESS
        || plan.image_end > USER_ADDRESS_LIMIT
        || image_span == 0
        || image_span > MAXIMUM_USER_IMAGE_SPAN
    {
        return Err(UserImageError::InvalidUserRange);
    }
    if plan
        .segments()
        .iter()
        .any(|segment| segment.executable && !segment.readable)
    {
        return Err(UserImageError::UnreadableCode);
    }
    let entry_file_offset = plan.entry_file_offset().map_err(UserImageError::Loader)?;
    if entry_file_offset != measurement.entry_offset {
        return Err(UserImageError::EntryMetadataMismatch);
    }

    Ok(PreparedUserImage { artifact, plan })
}

fn validate_artifact_identity(artifact: &VerifiedArtifact<'_>) -> Result<(), UserImageError> {
    let measurement = artifact.measurement();
    if measurement.class != FractalClass::Executable {
        return Err(UserImageError::WrongClass);
    }
    if measurement.architecture != TargetArchitecture::X86_64 {
        return Err(UserImageError::WrongArchitecture);
    }
    if measurement.bytes_written != artifact.bytes().len() {
        return Err(UserImageError::MeasurementMismatch);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeLinkerPolicy {
    Reject,
    Require,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserImageError {
    WrongClass,
    WrongArchitecture,
    MeasurementMismatch,
    RuntimeLinkerUnavailable,
    RuntimeLinkerRequired,
    ProgramHeadersUnavailable,
    InvalidUserRange,
    UnreadableCode,
    EntryMetadataMismatch,
    Measurement(OureborosError),
    Loader(LoaderError),
}

#[cfg(test)]
mod tests {
    use blacklab::oureboros::{
        FractalCatalog, FractalRecipe, FractalSeed, MINIMAL_X86_64_ELF_BYTES, measure_recipe,
    };

    use crate::capability::Authority;
    use crate::module::loader::POSITION_INDEPENDENT_LOAD_BASE;

    use super::*;

    fn recipe() -> FractalRecipe {
        FractalRecipe {
            algorithm_version: 2,
            base_entropy: 0x9999_8888_7777_6666,
            structural_mutator: 0xaaaa_bbbb_cccc_dddd,
        }
    }

    fn dynamic_executable() -> [u8; 195] {
        let mut bytes = [0_u8; 195];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&(3_u16).to_le_bytes());
        bytes[18..20].copy_from_slice(&(62_u16).to_le_bytes());
        bytes[20..24].copy_from_slice(&(1_u32).to_le_bytes());
        bytes[24..32].copy_from_slice(&(176_u64).to_le_bytes());
        bytes[32..40].copy_from_slice(&(64_u64).to_le_bytes());
        bytes[52..54].copy_from_slice(&(64_u16).to_le_bytes());
        bytes[54..56].copy_from_slice(&(56_u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&(2_u16).to_le_bytes());
        let load = &mut bytes[64..120];
        load[0..4].copy_from_slice(&(1_u32).to_le_bytes());
        load[4..8].copy_from_slice(&(5_u32).to_le_bytes());
        load[32..40].copy_from_slice(&(184_u64).to_le_bytes());
        load[40..48].copy_from_slice(&(0x1000_u64).to_le_bytes());
        load[48..56].copy_from_slice(&(0x1000_u64).to_le_bytes());
        let interpreter = &mut bytes[120..176];
        interpreter[0..4].copy_from_slice(&(3_u32).to_le_bytes());
        interpreter[8..16].copy_from_slice(&(184_u64).to_le_bytes());
        interpreter[32..40].copy_from_slice(&(11_u64).to_le_bytes());
        interpreter[40..48].copy_from_slice(&(11_u64).to_le_bytes());
        bytes[176..184].copy_from_slice(&[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xc3]);
        bytes[184..195].copy_from_slice(b"/lib/ld.so\0");
        bytes
    }

    fn runtime_linker() -> [u8; 132] {
        let mut bytes = [0_u8; 132];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&(3_u16).to_le_bytes());
        bytes[18..20].copy_from_slice(&(62_u16).to_le_bytes());
        bytes[20..24].copy_from_slice(&(1_u32).to_le_bytes());
        bytes[24..32].copy_from_slice(&(128_u64).to_le_bytes());
        bytes[32..40].copy_from_slice(&(64_u64).to_le_bytes());
        bytes[52..54].copy_from_slice(&(64_u16).to_le_bytes());
        bytes[54..56].copy_from_slice(&(56_u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&(1_u16).to_le_bytes());
        let load = &mut bytes[64..120];
        load[0..4].copy_from_slice(&(1_u32).to_le_bytes());
        load[4..8].copy_from_slice(&(5_u32).to_le_bytes());
        load[32..40].copy_from_slice(&(132_u64).to_le_bytes());
        load[40..48].copy_from_slice(&(0x1000_u64).to_le_bytes());
        load[48..56].copy_from_slice(&(0x1000_u64).to_le_bytes());
        bytes[128..132].copy_from_slice(&[0x90, 0x90, 0x90, 0xc3]);
        bytes
    }

    #[test]
    fn binds_a_measured_artifact_to_a_static_user_load_plan() {
        let recipe = recipe();
        let mut catalog = FractalCatalog::new();
        catalog
            .plant_seed(FractalSeed {
                inode_id: 1,
                class: FractalClass::Executable,
                architecture: TargetArchitecture::X86_64,
                recipe,
                unfolded_size_bytes: MINIMAL_X86_64_ELF_BYTES as u32,
                entry_offset: 128,
                expected_sha256: measure_recipe(recipe, MINIMAL_X86_64_ELF_BYTES).unwrap(),
            })
            .unwrap();
        let mut bytes = [0_u8; MINIMAL_X86_64_ELF_BYTES];
        let artifact = catalog.materialize(1, &mut bytes).unwrap();
        // SAFETY: Unit tests establish one isolated bootstrap authority.
        let authority = unsafe { Authority::assume_root() };
        let image_control = authority.grant::<UserlandImageControl>();
        let prepared = prepare_user_image(artifact, &image_control).unwrap();
        assert_eq!(prepared.plan().entry_point, POSITION_INDEPENDENT_LOAD_BASE);
        assert_eq!(prepared.plan().entry_file_offset(), Ok(128));
        assert_eq!(&prepared.bytes()[162..], b"PID1 syscall write\n");
        assert_eq!(&prepared.bytes()[128..133], &[0xb8, 1, 0, 0, 0]);
        assert_eq!(&prepared.bytes()[152..157], &[0xb8, 17, 0, 0, 0]);
    }

    #[test]
    fn refuses_non_executable_artifacts() {
        let recipe = FractalRecipe {
            algorithm_version: 1,
            base_entropy: 1,
            structural_mutator: 2,
        };
        let mut catalog = FractalCatalog::new();
        catalog
            .plant_seed(FractalSeed {
                inode_id: 2,
                class: FractalClass::Configuration,
                architecture: TargetArchitecture::Independent,
                recipe,
                unfolded_size_bytes: 8,
                entry_offset: 0,
                expected_sha256: measure_recipe(recipe, 8).unwrap(),
            })
            .unwrap();
        let mut bytes = [0_u8; 8];
        let artifact = catalog.materialize(2, &mut bytes).unwrap();
        // SAFETY: Unit tests establish one isolated bootstrap authority.
        let authority = unsafe { Authority::assume_root() };
        let image_control = authority.grant::<UserlandImageControl>();
        assert!(matches!(
            prepare_user_image(artifact, &image_control),
            Err(UserImageError::WrongClass)
        ));
    }

    #[test]
    fn runtime_image_is_measured_before_its_plan_is_returned() {
        let recipe = recipe();
        let mut bytes = [0_u8; MINIMAL_X86_64_ELF_BYTES];
        let mut catalog = FractalCatalog::new();
        catalog
            .plant_seed(FractalSeed {
                inode_id: 7,
                class: FractalClass::Executable,
                architecture: TargetArchitecture::X86_64,
                recipe,
                unfolded_size_bytes: MINIMAL_X86_64_ELF_BYTES as u32,
                entry_offset: 128,
                expected_sha256: measure_recipe(recipe, MINIMAL_X86_64_ELF_BYTES).unwrap(),
            })
            .unwrap();
        let expected = {
            let artifact = catalog.materialize(7, &mut bytes).unwrap();
            artifact.measurement().sha256
        };
        // SAFETY: Unit tests establish one isolated bootstrap authority.
        let authority = unsafe { Authority::assume_root() };
        let runtime_control = authority.delegate_runtime_image_control();
        let prepared = prepare_runtime_user_image(9, &bytes, &runtime_control).unwrap();
        assert_eq!(prepared.measurement().inode_id, 9);
        assert_eq!(prepared.measurement().sha256, expected);
        assert_eq!(prepared.plan().entry_file_offset(), Ok(128));
    }

    #[test]
    fn measures_both_sides_of_a_dynamic_execution() {
        let executable_bytes = dynamic_executable();
        let linker_bytes = runtime_linker();
        let authority = unsafe { Authority::assume_root() };
        let runtime_control = authority.delegate_runtime_image_control();

        assert_eq!(
            prepare_runtime_user_image(20, &executable_bytes, &runtime_control).map(|_| ()),
            Err(UserImageError::RuntimeLinkerUnavailable)
        );
        let executable =
            prepare_runtime_dynamic_image(20, &executable_bytes, &runtime_control).unwrap();
        let linker = prepare_runtime_linker_image(21, &linker_bytes, &runtime_control).unwrap();
        assert_eq!(
            executable.plan().interpreter_path(executable.bytes()),
            Ok(Some(&b"/lib/ld.so"[..]))
        );
        assert_eq!(
            executable.plan().program_header_address(),
            Some(POSITION_INDEPENDENT_LOAD_BASE + 64)
        );
        assert_eq!(executable.plan().program_header_count(), 2);
        assert_eq!(linker.plan().image_start, 0x0000_1800_0000);
        assert_ne!(executable.measurement().sha256, linker.measurement().sha256);
    }
}
