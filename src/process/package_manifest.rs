//! Native package identity bound to a measured service image.
//!
//! This is intentionally not a general archive format or a host package
//! recipe interpreter. It names the exact static artifact Arach has already
//! measured, the ABI it was built for, and the service class it may occupy.
//! Formal authority is folded only after the Idris/Agda attestation validates.

pub const PACKAGE_MANIFEST_SCHEMA_VERSION: u16 = 1;
pub const NATIVE_PACKAGE_ABI_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativePackageManifest {
    pub schema_version: u16,
    pub name_hash: u64,
    pub version: u16,
    pub abi_version: u16,
    pub service_class: u16,
    pub artifact_bytes: usize,
    pub entry_file_offset: usize,
    pub artifact_sha256: [u8; 32],
    /// Root over the exact source-resolution and toolchain material that
    /// produced the artifact. Formal authority is bound separately at launch.
    pub provenance_root: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageLaunchRoots {
    pub image_measurement_root: u64,
    pub capability_root: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageManifestError {
    InvalidIdentity,
    ArtifactMismatch,
    FormalAuthorityMissing,
}

impl NativePackageManifest {
    /// Validates the immutable build-time metadata before Arach uses it to
    /// describe a boot module. Artifact bytes are independently SHA-256
    /// verified by `verify_artifact` before their ELF plan is installed.
    pub const fn validate_artifact(
        self,
        expected_bytes: usize,
        expected_entry_file_offset: usize,
        expected_sha256: [u8; 32],
    ) -> Result<(), PackageManifestError> {
        if self.schema_version != PACKAGE_MANIFEST_SCHEMA_VERSION
            || self.name_hash == 0
            || self.version == 0
            || self.abi_version != NATIVE_PACKAGE_ABI_VERSION
            || self.service_class == 0
            || self.artifact_bytes == 0
            || all_zero(self.artifact_sha256)
            || self.provenance_root == 0
        {
            return Err(PackageManifestError::InvalidIdentity);
        }
        if self.artifact_bytes != expected_bytes
            || self.entry_file_offset != expected_entry_file_offset
            || !equal_digest(self.artifact_sha256, expected_sha256)
        {
            return Err(PackageManifestError::ArtifactMismatch);
        }
        Ok(())
    }

    /// Derives launch roots only after the checked formal models have supplied
    /// a nonzero authority root. These values become immutable lifecycle launch
    /// metadata rather than user-controlled syscall arguments.
    pub const fn bind_formal_authority(
        self,
        formal_authority_root: u64,
    ) -> Result<PackageLaunchRoots, PackageManifestError> {
        if formal_authority_root == 0 {
            return Err(PackageManifestError::FormalAuthorityMissing);
        }
        let image_measurement_root = nonzero(fold_manifest(self));
        let capability_root = nonzero(
            image_measurement_root
                ^ formal_authority_root.rotate_left(17)
                ^ (self.version as u64).rotate_left(41)
                ^ (self.service_class as u64).rotate_left(53),
        );
        Ok(PackageLaunchRoots {
            image_measurement_root,
            capability_root,
        })
    }
}

pub const fn package_name_hash(name: &[u8]) -> u64 {
    let mut state = 0xcbf2_9ce4_8422_2325_u64;
    let mut index = 0;
    while index < name.len() {
        state ^= name[index] as u64;
        state = state.wrapping_mul(0x0000_0100_0000_01b3);
        index += 1;
    }
    state
}

const fn fold_manifest(manifest: NativePackageManifest) -> u64 {
    let mut state = manifest.name_hash
        ^ (manifest.schema_version as u64).rotate_left(5)
        ^ (manifest.version as u64).rotate_left(19)
        ^ (manifest.abi_version as u64).rotate_left(31)
        ^ (manifest.service_class as u64).rotate_left(43)
        ^ (manifest.artifact_bytes as u64).rotate_left(11)
        ^ (manifest.entry_file_offset as u64).rotate_left(37)
        ^ manifest.provenance_root.rotate_left(47);
    let mut index = 0;
    while index < manifest.artifact_sha256.len() {
        state ^= (manifest.artifact_sha256[index] as u64).rotate_left((index as u32) & 63);
        state = state.rotate_left(9).wrapping_mul(0x9e37_79b1_85eb_ca87);
        index += 1;
    }
    state
}

const fn nonzero(value: u64) -> u64 {
    if value == 0 { 1 } else { value }
}

const fn all_zero(digest: [u8; 32]) -> bool {
    let mut index = 0;
    while index < digest.len() {
        if digest[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

const fn equal_digest(left: [u8; 32], right: [u8; 32]) -> bool {
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: [u8; 32] = [0x5a; 32];
    const MANIFEST: NativePackageManifest = NativePackageManifest {
        schema_version: PACKAGE_MANIFEST_SCHEMA_VERSION,
        name_hash: package_name_hash(b"crest"),
        version: 3,
        abi_version: NATIVE_PACKAGE_ABI_VERSION,
        service_class: 2,
        artifact_bytes: 4096,
        entry_file_offset: 128,
        artifact_sha256: DIGEST,
        provenance_root: 0x4352_4553_5450_524f,
    };

    #[test]
    fn accepts_an_exact_native_artifact_and_binds_formal_authority() {
        assert_eq!(MANIFEST.validate_artifact(4096, 128, DIGEST), Ok(()));
        let roots = MANIFEST.bind_formal_authority(0xabc).unwrap();
        assert_ne!(roots.image_measurement_root, 0);
        assert_ne!(roots.capability_root, 0);
    }

    #[test]
    fn rejects_unbound_or_mismatched_package_material() {
        assert_eq!(
            MANIFEST.validate_artifact(4097, 128, DIGEST),
            Err(PackageManifestError::ArtifactMismatch)
        );
        assert_eq!(
            MANIFEST.bind_formal_authority(0),
            Err(PackageManifestError::FormalAuthorityMissing)
        );
        assert_eq!(
            NativePackageManifest {
                name_hash: 0,
                ..MANIFEST
            }
            .validate_artifact(4096, 128, DIGEST),
            Err(PackageManifestError::InvalidIdentity)
        );
        assert_eq!(
            NativePackageManifest {
                provenance_root: 0,
                ..MANIFEST
            }
            .validate_artifact(4096, 128, DIGEST),
            Err(PackageManifestError::InvalidIdentity)
        );
    }
}
