//! Measured Linux `struct module` ABI contract.
//!
//! Linux deliberately provides no stable in-kernel module ABI and may apply
//! configured structure layout randomization. The external-Kbuild smoke object
//! therefore carries a fixed-width `.arach.module_abi` record produced by the
//! exact SDK that built it. This parser validates that record against the
//! linked `.gnu.linkonce.this_module` allocation before Arach may retain it as
//! runtime evidence.

use crate::module::elf::{ElfError, ElfModule};

const ABI_SECTION: &[u8] = b".arach.module_abi";
const THIS_MODULE_SECTION: &[u8] = b".gnu.linkonce.this_module";
const ABI_MAGIC: u32 = 0x4942_4148;
const ABI_VERSION: u32 = 1;
const ABI_RECORD_BYTES: usize = 19 * 4;
const ABSENT_OFFSET: u32 = u32::MAX;
const MAXIMUM_MODULE_STRUCTURE_BYTES: usize = 1024 * 1024;
const MAXIMUM_MODULE_MEMORY_TYPES: u32 = 32;
const MAXIMUM_MODULE_MEMORY_STRIDE: u32 = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxModuleAbiContract {
    pub module_size: u32,
    pub module_alignment: u32,
    pub module_name_length: u32,
    pub state_offset: u32,
    pub list_offset: u32,
    pub name_offset: u32,
    pub init_offset: u32,
    pub memory_offset: u32,
    pub memory_count: u32,
    pub memory_stride: u32,
    pub memory_base_offset: u32,
    pub memory_rox_offset: Option<u32>,
    pub memory_size_offset: u32,
    pub arch_offset: u32,
    pub exit_offset: Option<u32>,
    pub refcnt_offset: Option<u32>,
}

impl LinuxModuleAbiContract {
    pub fn from_module(bytes: &[u8]) -> Result<Self, LinuxModuleAbiError> {
        let module = ElfModule::parse(bytes).map_err(LinuxModuleAbiError::Elf)?;
        let mut record = None;
        let mut this_module_size = None;
        for index in 1..module.section_count() {
            let section = module
                .section(index)
                .ok_or(LinuxModuleAbiError::InvalidRecord)?;
            let name = module
                .section_name(section)
                .map_err(LinuxModuleAbiError::Elf)?;
            if name == ABI_SECTION {
                if record.is_some() {
                    return Err(LinuxModuleAbiError::DuplicateRecord);
                }
                record = Some(
                    module
                        .section_data(section)
                        .map_err(LinuxModuleAbiError::Elf)?,
                );
            } else if name == THIS_MODULE_SECTION {
                if this_module_size.is_some() {
                    return Err(LinuxModuleAbiError::DuplicateModuleStructure);
                }
                this_module_size = Some(
                    usize::try_from(section.size)
                        .map_err(|_| LinuxModuleAbiError::InvalidRecord)?,
                );
            }
        }
        let contract = Self::parse_record(record.ok_or(LinuxModuleAbiError::MissingRecord)?)?;
        if this_module_size != Some(contract.module_size as usize) {
            return Err(LinuxModuleAbiError::ModuleSizeMismatch);
        }
        Ok(contract)
    }

    pub fn parse_record(bytes: &[u8]) -> Result<Self, LinuxModuleAbiError> {
        if bytes.len() != ABI_RECORD_BYTES
            || read_u32(bytes, 0) != Some(ABI_MAGIC)
            || read_u32(bytes, 4) != Some(ABI_VERSION)
            || read_u32(bytes, 8) != Some(ABI_RECORD_BYTES as u32)
        {
            return Err(LinuxModuleAbiError::InvalidRecord);
        }
        let contract = Self {
            module_size: read_u32(bytes, 12).ok_or(LinuxModuleAbiError::InvalidRecord)?,
            module_alignment: read_u32(bytes, 16).ok_or(LinuxModuleAbiError::InvalidRecord)?,
            module_name_length: read_u32(bytes, 20).ok_or(LinuxModuleAbiError::InvalidRecord)?,
            state_offset: read_u32(bytes, 24).ok_or(LinuxModuleAbiError::InvalidRecord)?,
            list_offset: read_u32(bytes, 28).ok_or(LinuxModuleAbiError::InvalidRecord)?,
            name_offset: read_u32(bytes, 32).ok_or(LinuxModuleAbiError::InvalidRecord)?,
            init_offset: read_u32(bytes, 36).ok_or(LinuxModuleAbiError::InvalidRecord)?,
            memory_offset: read_u32(bytes, 40).ok_or(LinuxModuleAbiError::InvalidRecord)?,
            memory_count: read_u32(bytes, 44).ok_or(LinuxModuleAbiError::InvalidRecord)?,
            memory_stride: read_u32(bytes, 48).ok_or(LinuxModuleAbiError::InvalidRecord)?,
            memory_base_offset: read_u32(bytes, 52).ok_or(LinuxModuleAbiError::InvalidRecord)?,
            memory_rox_offset: optional_offset(
                read_u32(bytes, 56).ok_or(LinuxModuleAbiError::InvalidRecord)?,
            ),
            memory_size_offset: read_u32(bytes, 60).ok_or(LinuxModuleAbiError::InvalidRecord)?,
            arch_offset: read_u32(bytes, 64).ok_or(LinuxModuleAbiError::InvalidRecord)?,
            exit_offset: optional_offset(
                read_u32(bytes, 68).ok_or(LinuxModuleAbiError::InvalidRecord)?,
            ),
            refcnt_offset: optional_offset(
                read_u32(bytes, 72).ok_or(LinuxModuleAbiError::InvalidRecord)?,
            ),
        };
        contract.validate()?;
        Ok(contract)
    }

    fn validate(self) -> Result<(), LinuxModuleAbiError> {
        let module_size = self.module_size as usize;
        if module_size == 0
            || module_size > MAXIMUM_MODULE_STRUCTURE_BYTES
            || self.module_alignment == 0
            || !self.module_alignment.is_power_of_two()
            || self.module_alignment as usize > module_size
            || self.module_name_length < 2
            || self.module_name_length as usize > module_size
            || self.memory_count == 0
            || self.memory_count > MAXIMUM_MODULE_MEMORY_TYPES
            || self.memory_stride == 0
            || self.memory_stride > MAXIMUM_MODULE_MEMORY_STRIDE
        {
            return Err(LinuxModuleAbiError::InvalidRecord);
        }
        check_range(module_size, self.state_offset, 4)?;
        check_range(module_size, self.list_offset, 16)?;
        check_range(module_size, self.name_offset, self.module_name_length)?;
        check_range(module_size, self.init_offset, 8)?;
        check_range(module_size, self.arch_offset, 1)?;
        if let Some(offset) = self.exit_offset {
            check_range(module_size, offset, 8)?;
        }
        if let Some(offset) = self.refcnt_offset {
            check_range(module_size, offset, 4)?;
        }

        let memory_bytes = self
            .memory_count
            .checked_mul(self.memory_stride)
            .ok_or(LinuxModuleAbiError::InvalidRecord)?;
        check_range(module_size, self.memory_offset, memory_bytes)?;
        check_range(self.memory_stride as usize, self.memory_base_offset, 8)?;
        if let Some(offset) = self.memory_rox_offset {
            check_range(self.memory_stride as usize, offset, 1)?;
        }
        check_range(self.memory_stride as usize, self.memory_size_offset, 4)?;

        for (offset, alignment) in [
            (self.list_offset, 8),
            (self.init_offset, 8),
            (self.memory_offset, 8),
        ] {
            if offset % alignment != 0 {
                return Err(LinuxModuleAbiError::InvalidRecord);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxModuleAbiError {
    Elf(ElfError),
    MissingRecord,
    DuplicateRecord,
    DuplicateModuleStructure,
    ModuleSizeMismatch,
    InvalidRecord,
}

fn optional_offset(value: u32) -> Option<u32> {
    (value != ABSENT_OFFSET).then_some(value)
}

fn check_range(container: usize, offset: u32, size: u32) -> Result<(), LinuxModuleAbiError> {
    let offset = offset as usize;
    let size = size as usize;
    if offset.checked_add(size).is_none_or(|end| end > container) {
        Err(LinuxModuleAbiError::InvalidRecord)
    } else {
        Ok(())
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> [u8; ABI_RECORD_BYTES] {
        let values = [
            ABI_MAGIC,
            ABI_VERSION,
            ABI_RECORD_BYTES as u32,
            1408,
            64,
            56,
            0,
            8,
            24,
            320,
            384,
            7,
            72,
            0,
            8,
            12,
            888,
            1328,
            1336,
        ];
        let mut bytes = [0; ABI_RECORD_BYTES];
        for (index, value) in values.iter().enumerate() {
            bytes[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn accepts_the_measured_rhel_10_2_layout_shape() {
        let contract = LinuxModuleAbiContract::parse_record(&record()).unwrap();
        assert_eq!(contract.module_size, 1408);
        assert_eq!(contract.module_name_length, 56);
        assert_eq!(contract.init_offset, 320);
        assert_eq!(contract.exit_offset, Some(1328));
        assert_eq!(contract.memory_count, 7);
        assert_eq!(contract.memory_stride, 72);
        assert_eq!(contract.memory_rox_offset, Some(8));
    }

    #[test]
    fn rejects_truncation_bad_magic_and_ranges_outside_the_structure() {
        assert_eq!(
            LinuxModuleAbiContract::parse_record(&record()[..72]),
            Err(LinuxModuleAbiError::InvalidRecord)
        );
        let mut bad = record();
        bad[0] ^= 1;
        assert_eq!(
            LinuxModuleAbiContract::parse_record(&bad),
            Err(LinuxModuleAbiError::InvalidRecord)
        );
        let mut bad = record();
        bad[36..40].copy_from_slice(&1404_u32.to_le_bytes());
        assert_eq!(
            LinuxModuleAbiContract::parse_record(&bad),
            Err(LinuxModuleAbiError::InvalidRecord)
        );
    }

    #[test]
    fn accepts_absent_unload_offsets_but_rejects_misaligned_memory_layout() {
        let mut no_unload = record();
        no_unload[56..60].copy_from_slice(&ABSENT_OFFSET.to_le_bytes());
        no_unload[68..72].copy_from_slice(&ABSENT_OFFSET.to_le_bytes());
        no_unload[72..76].copy_from_slice(&ABSENT_OFFSET.to_le_bytes());
        let contract = LinuxModuleAbiContract::parse_record(&no_unload).unwrap();
        assert_eq!(contract.memory_rox_offset, None);
        assert_eq!(contract.exit_offset, None);
        assert_eq!(contract.refcnt_offset, None);

        let mut bad = record();
        bad[40..44].copy_from_slice(&385_u32.to_le_bytes());
        assert_eq!(
            LinuxModuleAbiContract::parse_record(&bad),
            Err(LinuxModuleAbiError::InvalidRecord)
        );
    }

    #[test]
    fn a_plain_module_without_sdk_measurement_fails_closed() {
        let bytes = crate::module::linux_ko::tests::fixture();
        assert_eq!(
            LinuxModuleAbiContract::from_module(&bytes),
            Err(LinuxModuleAbiError::MissingRecord)
        );
    }
}
