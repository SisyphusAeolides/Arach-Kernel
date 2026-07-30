//! Measured x86-64 Linux module special-section processing.
//!
//! This module begins the production pre-seal pipeline with
//! `.gnu.linkonce.this_module`. The compiler-provided object is treated as
//! untrusted input: identity and relocated lifecycle pointers are checked,
//! the complete measured structure is cleared, and only bounded fields derived
//! from the admitted load plan are reconstructed.

use alloc::vec::Vec;

use crate::module::linux_abi::{LinuxModuleAbiContract, LinuxModuleAbiError};
use crate::module::linux_loader::{
    LinuxKoLoadPlan, LinuxKoMemoryRegion, LinuxKoRegionKind, LinuxKoSpecialSection,
    LinuxKoSpecialSectionCoverage, LinuxKoSpecialSectionKind,
};
use crate::module::x86_64_memory::{
    LinuxModuleMapping, LinuxModuleTlb, X86_64LinuxModuleMemory, X86_64ModuleMapError,
};
use crate::process::x86_64::ProcessFrameMemory;

const MODULE_STATE_COMING: u32 = 1;
const LINUX_6_12_MEMORY_TYPES: u32 = 7;

#[derive(Clone, Copy)]
pub struct X86_64LinuxModuleIdentityProcessor {
    abi: LinuxModuleAbiContract,
}

impl X86_64LinuxModuleIdentityProcessor {
    pub fn new(abi: LinuxModuleAbiContract) -> Result<Self, LinuxModuleIdentityError<()>> {
        abi.validate()
            .map_err(LinuxModuleIdentityError::InvalidAbi)?;
        if abi.memory_count != LINUX_6_12_MEMORY_TYPES {
            return Err(LinuxModuleIdentityError::UnsupportedMemoryModel);
        }
        Ok(Self { abi })
    }

    pub const fn abi(&self) -> LinuxModuleAbiContract {
        self.abi
    }

    pub fn prepare<Memory, Tlb>(
        &self,
        memory: &mut X86_64LinuxModuleMemory<Memory, Tlb>,
        mapping: LinuxModuleMapping,
        plan: &LinuxKoLoadPlan<'_>,
        special_sections: &[LinuxKoSpecialSection<'_>],
    ) -> Result<LinuxKoSpecialSectionCoverage, LinuxModuleIdentityError<Memory::Error>>
    where
        Memory: ProcessFrameMemory,
        Tlb: LinuxModuleTlb,
    {
        let mut identity = None;
        for section in special_sections {
            if section.kind != LinuxKoSpecialSectionKind::ModuleIdentity {
                continue;
            }
            if identity.replace(*section).is_some() {
                return Err(LinuxModuleIdentityError::DuplicateIdentity);
            }
        }
        let identity = identity.ok_or(LinuxModuleIdentityError::MissingIdentity)?;
        self.prepare_fields(
            memory,
            mapping,
            identity,
            IdentityInputs {
                name: plan.name(),
                image_base: plan.image_virtual_address(),
                init_address: plan.init_address(),
                cleanup_address: plan.cleanup_address(),
                regions: plan.regions(),
            },
        )?;
        let mut coverage = LinuxKoSpecialSectionCoverage::empty();
        coverage.acknowledge(LinuxKoSpecialSectionKind::ModuleIdentity);
        Ok(coverage)
    }

    fn prepare_fields<Memory, Tlb>(
        &self,
        memory: &mut X86_64LinuxModuleMemory<Memory, Tlb>,
        mapping: LinuxModuleMapping,
        section: LinuxKoSpecialSection<'_>,
        inputs: IdentityInputs<'_>,
    ) -> Result<(), LinuxModuleIdentityError<Memory::Error>>
    where
        Memory: ProcessFrameMemory,
        Tlb: LinuxModuleTlb,
    {
        self.abi
            .validate()
            .map_err(LinuxModuleIdentityError::InvalidAbi)?;
        if self.abi.memory_count != LINUX_6_12_MEMORY_TYPES {
            return Err(LinuxModuleIdentityError::UnsupportedMemoryModel);
        }
        if section.name != b".gnu.linkonce.this_module"
            || section.size != self.abi.module_size as usize
        {
            return Err(LinuxModuleIdentityError::InvalidIdentitySize);
        }
        if inputs.name.is_empty()
            || inputs.name.len() >= self.abi.module_name_length as usize
            || inputs.name.iter().any(|byte| *byte == 0 || *byte == b'/')
        {
            return Err(LinuxModuleIdentityError::InvalidName);
        }
        let structure_base = section.image_offset;
        let mut original_name = Vec::new();
        original_name
            .try_reserve_exact(self.abi.module_name_length as usize)
            .map_err(|_| LinuxModuleIdentityError::AllocationFailed)?;
        original_name.resize(self.abi.module_name_length as usize, 0);
        read(
            memory,
            mapping,
            add_offset(structure_base, self.abi.name_offset)?,
            &mut original_name,
        )?;
        if original_name.get(..inputs.name.len()) != Some(inputs.name)
            || original_name.get(inputs.name.len()) != Some(&0)
        {
            return Err(LinuxModuleIdentityError::InvalidName);
        }
        let observed_init = read_u64(
            memory,
            mapping,
            add_offset(structure_base, self.abi.init_offset)?,
        )?;
        if observed_init != inputs.init_address {
            return Err(LinuxModuleIdentityError::InvalidInit);
        }
        match (self.abi.exit_offset, inputs.cleanup_address) {
            (Some(offset), expected) => {
                let observed = read_u64(memory, mapping, add_offset(structure_base, offset)?)?;
                if observed != expected.unwrap_or(0) {
                    return Err(LinuxModuleIdentityError::InvalidCleanup);
                }
            }
            (None, Some(_)) => return Err(LinuxModuleIdentityError::InvalidCleanup),
            (None, None) => {}
        }

        let mut cleared = Vec::new();
        cleared
            .try_reserve_exact(section.size)
            .map_err(|_| LinuxModuleIdentityError::AllocationFailed)?;
        cleared.resize(section.size, 0);
        write_verified(memory, mapping, structure_base, &cleared)?;

        write_verified(
            memory,
            mapping,
            add_offset(structure_base, self.abi.state_offset)?,
            &MODULE_STATE_COMING.to_le_bytes(),
        )?;
        let list_address = inputs
            .image_base
            .checked_add(structure_base as u64)
            .and_then(|address| address.checked_add(self.abi.list_offset as u64))
            .ok_or(LinuxModuleIdentityError::AddressOverflow)?;
        let list = list_address.to_le_bytes();
        let list_offset = add_offset(structure_base, self.abi.list_offset)?;
        write_verified(memory, mapping, list_offset, &list)?;
        write_verified(memory, mapping, list_offset + 8, &list)?;

        let mut canonical_name = Vec::new();
        canonical_name
            .try_reserve_exact(self.abi.module_name_length as usize)
            .map_err(|_| LinuxModuleIdentityError::AllocationFailed)?;
        canonical_name.resize(self.abi.module_name_length as usize, 0);
        canonical_name[..inputs.name.len()].copy_from_slice(inputs.name);
        write_verified(
            memory,
            mapping,
            add_offset(structure_base, self.abi.name_offset)?,
            &canonical_name,
        )?;
        write_verified(
            memory,
            mapping,
            add_offset(structure_base, self.abi.init_offset)?,
            &inputs.init_address.to_le_bytes(),
        )?;
        if let Some(exit_offset) = self.abi.exit_offset {
            write_verified(
                memory,
                mapping,
                add_offset(structure_base, exit_offset)?,
                &inputs.cleanup_address.unwrap_or(0).to_le_bytes(),
            )?;
        }
        if let Some(refcnt_offset) = self.abi.refcnt_offset {
            write_verified(
                memory,
                mapping,
                add_offset(structure_base, refcnt_offset)?,
                &0_u32.to_le_bytes(),
            )?;
        }

        let mut seen = [false; LINUX_6_12_MEMORY_TYPES as usize];
        for region in inputs.regions {
            let index = memory_type(region.kind);
            if seen[index] || region.size > u32::MAX as usize {
                return Err(LinuxModuleIdentityError::InvalidMemoryRegion);
            }
            seen[index] = true;
            let descriptor = self
                .abi
                .memory_offset
                .checked_add(
                    (index as u32)
                        .checked_mul(self.abi.memory_stride)
                        .ok_or(LinuxModuleIdentityError::AddressOverflow)?,
                )
                .ok_or(LinuxModuleIdentityError::AddressOverflow)?;
            let region_base = inputs
                .image_base
                .checked_add(region.image_offset as u64)
                .ok_or(LinuxModuleIdentityError::AddressOverflow)?;
            write_verified(
                memory,
                mapping,
                add_offset(
                    structure_base,
                    descriptor
                        .checked_add(self.abi.memory_base_offset)
                        .ok_or(LinuxModuleIdentityError::AddressOverflow)?,
                )?,
                &region_base.to_le_bytes(),
            )?;
            if let Some(rox_offset) = self.abi.memory_rox_offset {
                write_verified(
                    memory,
                    mapping,
                    add_offset(
                        structure_base,
                        descriptor
                            .checked_add(rox_offset)
                            .ok_or(LinuxModuleIdentityError::AddressOverflow)?,
                    )?,
                    &[u8::from(!region.writable)],
                )?;
            }
            write_verified(
                memory,
                mapping,
                add_offset(
                    structure_base,
                    descriptor
                        .checked_add(self.abi.memory_size_offset)
                        .ok_or(LinuxModuleIdentityError::AddressOverflow)?,
                )?,
                &(region.size as u32).to_le_bytes(),
            )?;
        }
        Ok(())
    }
}

struct IdentityInputs<'a> {
    name: &'a [u8],
    image_base: u64,
    init_address: u64,
    cleanup_address: Option<u64>,
    regions: &'a [LinuxKoMemoryRegion],
}

#[derive(Debug, Eq, PartialEq)]
pub enum LinuxModuleIdentityError<MemoryError> {
    Memory(X86_64ModuleMapError<MemoryError>),
    InvalidAbi(LinuxModuleAbiError),
    MissingIdentity,
    DuplicateIdentity,
    InvalidIdentitySize,
    InvalidName,
    InvalidInit,
    InvalidCleanup,
    UnsupportedMemoryModel,
    InvalidMemoryRegion,
    AddressOverflow,
    AllocationFailed,
    VerificationFailed,
}

fn memory_type(kind: LinuxKoRegionKind) -> usize {
    match kind {
        LinuxKoRegionKind::CoreText => 0,
        LinuxKoRegionKind::CoreWritable => 1,
        LinuxKoRegionKind::CoreReadOnly => 2,
        LinuxKoRegionKind::InitText => 4,
        LinuxKoRegionKind::InitWritable => 5,
        LinuxKoRegionKind::InitReadOnly => 6,
    }
}

fn add_offset<MemoryError>(
    base: usize,
    offset: u32,
) -> Result<usize, LinuxModuleIdentityError<MemoryError>> {
    base.checked_add(offset as usize)
        .ok_or(LinuxModuleIdentityError::AddressOverflow)
}

fn read<Memory, Tlb>(
    memory: &X86_64LinuxModuleMemory<Memory, Tlb>,
    mapping: LinuxModuleMapping,
    offset: usize,
    destination: &mut [u8],
) -> Result<(), LinuxModuleIdentityError<Memory::Error>>
where
    Memory: ProcessFrameMemory,
    Tlb: LinuxModuleTlb,
{
    memory
        .read(mapping, offset, destination)
        .map_err(LinuxModuleIdentityError::Memory)
}

fn read_u64<Memory, Tlb>(
    memory: &X86_64LinuxModuleMemory<Memory, Tlb>,
    mapping: LinuxModuleMapping,
    offset: usize,
) -> Result<u64, LinuxModuleIdentityError<Memory::Error>>
where
    Memory: ProcessFrameMemory,
    Tlb: LinuxModuleTlb,
{
    let mut bytes = [0; 8];
    read(memory, mapping, offset, &mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn write_verified<Memory, Tlb>(
    memory: &mut X86_64LinuxModuleMemory<Memory, Tlb>,
    mapping: LinuxModuleMapping,
    offset: usize,
    bytes: &[u8],
) -> Result<(), LinuxModuleIdentityError<Memory::Error>>
where
    Memory: ProcessFrameMemory,
    Tlb: LinuxModuleTlb,
{
    memory
        .write(mapping, offset, bytes)
        .map_err(LinuxModuleIdentityError::Memory)?;
    match memory
        .verify(mapping, offset, bytes)
        .map_err(LinuxModuleIdentityError::Memory)?
    {
        true => Ok(()),
        false => Err(LinuxModuleIdentityError::VerificationFailed),
    }
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use alloc::vec;

    use abyss::paging::{PAGE_SIZE, PhysicalAddress};

    use super::*;
    use crate::capability::{Authority, ModuleLoadControl};

    const ENTRY_PRESENT: u64 = 1;
    const ENTRY_WRITABLE: u64 = 1 << 1;
    const MODULE_PML4_INDEX: usize = 511;
    const STRUCTURE_OFFSET: usize = 128;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestMemoryError {
        Invalid,
    }

    struct TestFrame {
        bytes: Box<[u8; PAGE_SIZE]>,
        live: bool,
    }

    #[derive(Default)]
    struct TestMemory {
        frames: Vec<TestFrame>,
    }

    impl TestMemory {
        fn index(frame: PhysicalAddress) -> Result<usize, TestMemoryError> {
            let address = frame.as_u64() as usize;
            if address == 0 || address % PAGE_SIZE != 0 {
                return Err(TestMemoryError::Invalid);
            }
            Ok(address / PAGE_SIZE - 1)
        }

        fn frame(&self, frame: PhysicalAddress) -> Result<&TestFrame, TestMemoryError> {
            self.frames
                .get(Self::index(frame)?)
                .filter(|frame| frame.live)
                .ok_or(TestMemoryError::Invalid)
        }

        fn frame_mut(&mut self, frame: PhysicalAddress) -> Result<&mut TestFrame, TestMemoryError> {
            self.frames
                .get_mut(Self::index(frame)?)
                .filter(|frame| frame.live)
                .ok_or(TestMemoryError::Invalid)
        }
    }

    impl ProcessFrameMemory for TestMemory {
        type Error = TestMemoryError;

        fn allocate_zeroed(&mut self) -> Result<PhysicalAddress, Self::Error> {
            if let Some((index, frame)) = self
                .frames
                .iter_mut()
                .enumerate()
                .find(|(_, frame)| !frame.live)
            {
                frame.bytes.fill(0);
                frame.live = true;
                return Ok(PhysicalAddress::new((index + 1) as u64 * PAGE_SIZE as u64));
            }
            let index = self.frames.len();
            self.frames.push(TestFrame {
                bytes: Box::new([0; PAGE_SIZE]),
                live: true,
            });
            Ok(PhysicalAddress::new((index + 1) as u64 * PAGE_SIZE as u64))
        }

        fn release(&mut self, frame: PhysicalAddress) -> Result<(), Self::Error> {
            let frame = self.frame_mut(frame)?;
            frame.bytes.fill(0);
            frame.live = false;
            Ok(())
        }

        fn read_entry(&self, table: PhysicalAddress, index: usize) -> Result<u64, Self::Error> {
            let offset = index.checked_mul(8).ok_or(TestMemoryError::Invalid)?;
            Ok(u64::from_le_bytes(
                self.frame(table)?
                    .bytes
                    .get(offset..offset + 8)
                    .ok_or(TestMemoryError::Invalid)?
                    .try_into()
                    .map_err(|_| TestMemoryError::Invalid)?,
            ))
        }

        fn write_entry(
            &mut self,
            table: PhysicalAddress,
            index: usize,
            value: u64,
        ) -> Result<(), Self::Error> {
            let offset = index.checked_mul(8).ok_or(TestMemoryError::Invalid)?;
            self.frame_mut(table)?
                .bytes
                .get_mut(offset..offset + 8)
                .ok_or(TestMemoryError::Invalid)?
                .copy_from_slice(&value.to_le_bytes());
            Ok(())
        }

        fn write_bytes(
            &mut self,
            frame: PhysicalAddress,
            offset: usize,
            bytes: &[u8],
        ) -> Result<(), Self::Error> {
            self.frame_mut(frame)?
                .bytes
                .get_mut(offset..offset + bytes.len())
                .ok_or(TestMemoryError::Invalid)?
                .copy_from_slice(bytes);
            Ok(())
        }

        fn read_bytes(
            &self,
            frame: PhysicalAddress,
            offset: usize,
            destination: &mut [u8],
        ) -> Result<(), Self::Error> {
            destination.copy_from_slice(
                self.frame(frame)?
                    .bytes
                    .get(offset..offset + destination.len())
                    .ok_or(TestMemoryError::Invalid)?,
            );
            Ok(())
        }

        fn bytes_equal(
            &self,
            frame: PhysicalAddress,
            offset: usize,
            bytes: &[u8],
        ) -> Result<bool, Self::Error> {
            Ok(self.frame(frame)?.bytes.get(offset..offset + bytes.len()) == Some(bytes))
        }

        fn bytes_zero(
            &self,
            frame: PhysicalAddress,
            offset: usize,
            length: usize,
        ) -> Result<bool, Self::Error> {
            Ok(self
                .frame(frame)?
                .bytes
                .get(offset..offset + length)
                .is_some_and(|bytes| bytes.iter().all(|byte| *byte == 0)))
        }
    }

    #[derive(Default)]
    struct TestTlb;

    unsafe impl LinuxModuleTlb for TestTlb {
        fn invalidate_kernel_range(&mut self, _virtual_address: u64, _size: usize) {}
    }

    fn mapper() -> X86_64LinuxModuleMemory<TestMemory, TestTlb> {
        let mut memory = TestMemory::default();
        let root = memory.allocate_zeroed().unwrap();
        let pml3 = memory.allocate_zeroed().unwrap();
        memory
            .write_entry(
                root,
                MODULE_PML4_INDEX,
                pml3.as_u64() | ENTRY_PRESENT | ENTRY_WRITABLE,
            )
            .unwrap();
        let authority = unsafe { Authority::assume_root() };
        let right = authority.grant::<ModuleLoadControl>();
        unsafe { X86_64LinuxModuleMemory::new(memory, TestTlb, root, &right) }
    }

    fn abi() -> LinuxModuleAbiContract {
        LinuxModuleAbiContract {
            module_size: 1408,
            module_alignment: 64,
            module_name_length: 56,
            state_offset: 0,
            list_offset: 8,
            name_offset: 24,
            init_offset: 320,
            memory_offset: 384,
            memory_count: 7,
            memory_stride: 72,
            memory_base_offset: 0,
            memory_rox_offset: Some(8),
            memory_size_offset: 12,
            arch_offset: 888,
            exit_offset: Some(1328),
            refcnt_offset: Some(1336),
        }
    }

    fn regions() -> [LinuxKoMemoryRegion; 6] {
        let kinds = [
            LinuxKoRegionKind::CoreText,
            LinuxKoRegionKind::CoreReadOnly,
            LinuxKoRegionKind::CoreWritable,
            LinuxKoRegionKind::InitText,
            LinuxKoRegionKind::InitReadOnly,
            LinuxKoRegionKind::InitWritable,
        ];
        kinds.map(|kind| {
            let index = memory_type(kind);
            LinuxKoMemoryRegion {
                kind,
                image_offset: if index < 3 { index } else { index - 1 } * PAGE_SIZE,
                size: PAGE_SIZE,
                readable: true,
                writable: matches!(
                    kind,
                    LinuxKoRegionKind::CoreWritable | LinuxKoRegionKind::InitWritable
                ),
                executable: matches!(
                    kind,
                    LinuxKoRegionKind::CoreText | LinuxKoRegionKind::InitText
                ),
                discard_after_init: matches!(
                    kind,
                    LinuxKoRegionKind::InitText
                        | LinuxKoRegionKind::InitReadOnly
                        | LinuxKoRegionKind::InitWritable
                ),
            }
        })
    }

    fn read_u32_at(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    fn read_u64_at(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
    }

    #[test]
    fn reconstructs_identity_lifecycle_list_and_all_memory_descriptors() {
        let mut mapper = mapper();
        let mapping = mapper.reserve_zeroed(PAGE_SIZE * 6, PAGE_SIZE).unwrap();
        let base = mapper.mapping_base(mapping).unwrap();
        let init = base + PAGE_SIZE as u64;
        let cleanup = base + PAGE_SIZE as u64 + 32;
        let mut structure = vec![0xaa; abi().module_size as usize];
        structure[24..24 + b"measured".len()].copy_from_slice(b"measured");
        structure[24 + b"measured".len()] = 0;
        structure[320..328].copy_from_slice(&init.to_le_bytes());
        structure[1328..1336].copy_from_slice(&cleanup.to_le_bytes());
        mapper.write(mapping, STRUCTURE_OFFSET, &structure).unwrap();

        let processor = X86_64LinuxModuleIdentityProcessor::new(abi()).unwrap();
        processor
            .prepare_fields(
                &mut mapper,
                mapping,
                LinuxKoSpecialSection {
                    section_index: 17,
                    name: b".gnu.linkonce.this_module",
                    image_offset: STRUCTURE_OFFSET,
                    size: structure.len(),
                    kind: LinuxKoSpecialSectionKind::ModuleIdentity,
                },
                IdentityInputs {
                    name: b"measured",
                    image_base: base,
                    init_address: init,
                    cleanup_address: Some(cleanup),
                    regions: &regions(),
                },
            )
            .unwrap();

        let mut rebuilt = vec![0; structure.len()];
        mapper
            .read(mapping, STRUCTURE_OFFSET, &mut rebuilt)
            .unwrap();
        assert_eq!(read_u32_at(&rebuilt, 0), MODULE_STATE_COMING);
        let list = base + STRUCTURE_OFFSET as u64 + 8;
        assert_eq!(read_u64_at(&rebuilt, 8), list);
        assert_eq!(read_u64_at(&rebuilt, 16), list);
        assert_eq!(&rebuilt[24..32], b"measured");
        assert_eq!(rebuilt[32], 0);
        assert_eq!(read_u64_at(&rebuilt, 320), init);
        assert_eq!(read_u64_at(&rebuilt, 1328), cleanup);
        assert_eq!(read_u64_at(&rebuilt, 384), base);
        assert_eq!(rebuilt[392], 1);
        assert_eq!(read_u32_at(&rebuilt, 396), PAGE_SIZE as u32);
        assert_eq!(read_u64_at(&rebuilt, 384 + 3 * 72), 0);
        assert_eq!(
            read_u64_at(&rebuilt, 384 + 4 * 72),
            base + 3 * PAGE_SIZE as u64
        );
        assert_eq!(rebuilt[1000], 0);
    }

    #[test]
    fn identity_mismatch_fails_before_clearing_the_staged_structure() {
        let mut mapper = mapper();
        let mapping = mapper.reserve_zeroed(PAGE_SIZE * 2, PAGE_SIZE).unwrap();
        let base = mapper.mapping_base(mapping).unwrap();
        let mut structure = vec![0xaa; abi().module_size as usize];
        structure[24..29].copy_from_slice(b"wrong");
        structure[29] = 0;
        structure[320..328].copy_from_slice(&(base + PAGE_SIZE as u64).to_le_bytes());
        mapper.write(mapping, STRUCTURE_OFFSET, &structure).unwrap();

        let result = X86_64LinuxModuleIdentityProcessor::new(abi())
            .unwrap()
            .prepare_fields(
                &mut mapper,
                mapping,
                LinuxKoSpecialSection {
                    section_index: 1,
                    name: b".gnu.linkonce.this_module",
                    image_offset: STRUCTURE_OFFSET,
                    size: structure.len(),
                    kind: LinuxKoSpecialSectionKind::ModuleIdentity,
                },
                IdentityInputs {
                    name: b"expected",
                    image_base: base,
                    init_address: base + PAGE_SIZE as u64,
                    cleanup_address: None,
                    regions: &[],
                },
            );
        assert_eq!(result, Err(LinuxModuleIdentityError::InvalidName));
        let mut marker = [0; 1];
        mapper
            .read(mapping, STRUCTURE_OFFSET + 1000, &mut marker)
            .unwrap();
        assert_eq!(marker, [0xaa]);
    }

    #[test]
    fn rejects_unknown_linux_memory_model_before_accepting_a_processor() {
        let mut contract = abi();
        contract.memory_count = 8;
        assert_eq!(
            X86_64LinuxModuleIdentityProcessor::new(contract).err(),
            Some(LinuxModuleIdentityError::UnsupportedMemoryModel)
        );
    }
}
