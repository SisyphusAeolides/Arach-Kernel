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
use crate::module::x86_64_native::{X86_64LinuxPreSeal, X86_64LinuxPreSealReceipt};
use crate::process::x86_64::ProcessFrameMemory;

const MODULE_STATE_COMING: u32 = 1;
const LINUX_6_12_MEMORY_TYPES: u32 = 7;
const ALT_INSTR_BYTES: usize = 14;
const ALT_FLAG_NOT: u16 = 1 << 0;
const ALT_FLAG_DIRECT_CALL: u16 = 1 << 1;
const ALT_SUPPORTED_FLAGS: u16 = ALT_FLAG_NOT | ALT_FLAG_DIRECT_CALL;
const JUMP_ENTRY_BYTES: usize = 16;
const JUMP_KEY_FLAGS: u64 = 0b11;
const JUMP_KEY_TYPE_TRUE: u64 = 1;
const STATIC_CALL_SITE_BYTES: usize = 8;
const STATIC_CALL_SITE_FLAGS: u64 = 0b11;
const SMP_LOCK_ENTRY_BYTES: usize = 4;

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
    ) -> Result<X86_64LinuxPreSealReceipt, LinuxModuleIdentityError<Memory::Error>>
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
        let state_offset = add_offset(identity.image_offset, self.abi.state_offset)?;
        Ok(X86_64LinuxPreSealReceipt::new(coverage, Some(state_offset)))
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

/// CPU-feature view used while selecting x86 alternatives.
///
/// # Safety
///
/// `feature_enabled` must report a feature only when every CPU that may execute
/// the module supports it. The result must remain valid until the module is
/// unloaded or CPU admission must prevent an incompatible CPU from running it.
/// `static_key_state` and `static_call_function` must return only addresses and
/// state that are valid for the committed kernel ABI and remain stable for the
/// entire module lifetime; returning an arbitrary pointer is unsound. The SMP
/// result must describe every CPU that can execute the module and must not
/// change while this pre-seal transaction is in progress.
pub unsafe trait X86_64AlternativeFeatures {
    type Error;

    fn feature_enabled(&self, feature: u16) -> Result<bool, Self::Error>;

    /// Returns `(initial_type, enabled)` for a static key outside the module
    /// image. Module-local keys are read from the staged image directly.
    fn static_key_state(&self, _key: u64) -> Result<Option<(bool, bool)>, Self::Error> {
        Ok(None)
    }

    /// Returns the stable function address for an external static-call key.
    /// Module-local keys are read from the staged image directly.
    fn static_call_function(&self, _key: u64) -> Result<Option<u64>, Self::Error> {
        Ok(None)
    }

    /// Whether the module will execute on an SMP-capable kernel. A false
    /// result permits the `.smp_locks` table to replace lock prefixes with
    /// one-byte NOPs; the default is conservative and keeps the prefix.
    fn smp_enabled(&self) -> Result<bool, Self::Error> {
        Ok(true)
    }

    fn nop_function_address(&self) -> Option<u64> {
        None
    }
}

/// Complete pre-seal processor currently admitted by the native backend.
/// Categories without a production processor are rejected explicitly.
pub struct X86_64LinuxSpecialProcessor<Features> {
    identity: X86_64LinuxModuleIdentityProcessor,
    features: Features,
}

impl<Features> X86_64LinuxSpecialProcessor<Features> {
    pub fn new(
        abi: LinuxModuleAbiContract,
        features: Features,
    ) -> Result<Self, LinuxModuleIdentityError<()>> {
        Ok(Self {
            identity: X86_64LinuxModuleIdentityProcessor::new(abi)?,
            features,
        })
    }

    pub const fn identity(&self) -> &X86_64LinuxModuleIdentityProcessor {
        &self.identity
    }
}

unsafe impl<Memory, Tlb, Features> X86_64LinuxPreSeal<Memory, Tlb>
    for X86_64LinuxSpecialProcessor<Features>
where
    Memory: ProcessFrameMemory,
    Tlb: LinuxModuleTlb,
    Features: X86_64AlternativeFeatures,
{
    type Error = LinuxSpecialSectionError<Memory::Error, Features::Error>;

    fn prepare(
        &mut self,
        memory: &mut X86_64LinuxModuleMemory<Memory, Tlb>,
        reservation: LinuxModuleMapping,
        plan: &LinuxKoLoadPlan<'_>,
        special_sections: &[LinuxKoSpecialSection<'_>],
    ) -> Result<X86_64LinuxPreSealReceipt, Self::Error> {
        let identity = self
            .identity
            .prepare(memory, reservation, plan, special_sections)
            .map_err(LinuxSpecialSectionError::Identity)?;
        let mut coverage = identity.coverage();
        let mut has_alternatives = false;
        let mut has_jump_labels = false;
        let mut has_static_calls = false;
        let mut has_smp_locks = false;
        for section in special_sections {
            match section.kind {
                LinuxKoSpecialSectionKind::ModuleIdentity => {}
                LinuxKoSpecialSectionKind::Alternatives => has_alternatives = true,
                LinuxKoSpecialSectionKind::JumpLabels => has_jump_labels = true,
                LinuxKoSpecialSectionKind::StaticCalls => has_static_calls = true,
                LinuxKoSpecialSectionKind::CpuLockPatching => has_smp_locks = true,
                kind => return Err(LinuxSpecialSectionError::UnsupportedCategory(kind)),
            }
        }
        if has_alternatives {
            apply_alternatives(
                memory,
                reservation,
                plan.image_virtual_address(),
                plan.image_size(),
                plan.regions(),
                special_sections,
                &self.features,
            )?;
            coverage.acknowledge(LinuxKoSpecialSectionKind::Alternatives);
        }
        if has_jump_labels {
            apply_jump_labels(
                memory,
                reservation,
                plan.image_virtual_address(),
                plan.image_size(),
                plan.regions(),
                special_sections,
                &self.features,
            )?;
            coverage.acknowledge(LinuxKoSpecialSectionKind::JumpLabels);
        }
        if has_static_calls {
            apply_static_calls(
                memory,
                reservation,
                plan.image_virtual_address(),
                plan.image_size(),
                plan.regions(),
                special_sections,
                &self.features,
            )?;
            coverage.acknowledge(LinuxKoSpecialSectionKind::StaticCalls);
        }
        if has_smp_locks {
            apply_smp_locks(
                memory,
                reservation,
                plan.image_virtual_address(),
                plan.image_size(),
                plan.regions(),
                special_sections,
                &self.features,
            )?;
            coverage.acknowledge(LinuxKoSpecialSectionKind::CpuLockPatching);
        }
        Ok(X86_64LinuxPreSealReceipt::new(
            coverage,
            identity.module_state_offset(),
        ))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum LinuxSpecialSectionError<MemoryError, FeatureError> {
    Identity(LinuxModuleIdentityError<MemoryError>),
    Memory(X86_64ModuleMapError<MemoryError>),
    Feature(FeatureError),
    UnsupportedCategory(LinuxKoSpecialSectionKind),
    MissingAlternativeTable,
    DuplicateAlternativeTable,
    InvalidAlternativeTable,
    InvalidAlternativeRecord,
    UnsupportedAlternativeFlags,
    AlternativeAddressOutOfRange,
    AlternativeTargetNotExecutable,
    InvalidDirectCall,
    UnsupportedAlternativeInstruction,
    MissingJumpLabelTable,
    DuplicateJumpLabelTable,
    InvalidJumpLabelTable,
    JumpLabelKeyOutOfRange,
    JumpLabelTargetNotExecutable,
    JumpLabelKeyStateUnavailable,
    InvalidJumpLabelInstruction,
    MissingStaticCallSites,
    DuplicateStaticCallSites,
    InvalidStaticCallTable,
    StaticCallKeyOutOfRange,
    StaticCallTargetNotExecutable,
    StaticCallFunctionUnavailable,
    UnsupportedStaticCallSite,
    UnsupportedStaticCallSection,
    MissingSmpLockTable,
    DuplicateSmpLockTable,
    InvalidSmpLockTable,
    SmpLockTargetNotExecutable,
    InvalidSmpLockInstruction,
    AllocationFailed,
    VerificationFailed,
}

fn apply_alternatives<Memory, Tlb, Features>(
    memory: &mut X86_64LinuxModuleMemory<Memory, Tlb>,
    mapping: LinuxModuleMapping,
    image_base: u64,
    image_size: usize,
    regions: &[LinuxKoMemoryRegion],
    sections: &[LinuxKoSpecialSection<'_>],
    features: &Features,
) -> Result<(), LinuxSpecialSectionError<Memory::Error, Features::Error>>
where
    Memory: ProcessFrameMemory,
    Tlb: LinuxModuleTlb,
    Features: X86_64AlternativeFeatures,
{
    let mut table = None;
    for section in sections {
        if section.kind == LinuxKoSpecialSectionKind::Alternatives
            && section.name == b".altinstructions"
            && table.replace(*section).is_some()
        {
            return Err(LinuxSpecialSectionError::DuplicateAlternativeTable);
        }
    }
    let table = table.ok_or(LinuxSpecialSectionError::MissingAlternativeTable)?;
    if table.size == 0 || table.size % ALT_INSTR_BYTES != 0 {
        return Err(LinuxSpecialSectionError::InvalidAlternativeTable);
    }
    let mut record = [0; ALT_INSTR_BYTES];
    let mut instruction_shapes = Vec::new();
    instruction_shapes
        .try_reserve_exact(table.size / ALT_INSTR_BYTES)
        .map_err(|_| LinuxSpecialSectionError::AllocationFailed)?;
    for index in 0..table.size / ALT_INSTR_BYTES {
        let record_offset = table
            .image_offset
            .checked_add(index * ALT_INSTR_BYTES)
            .ok_or(LinuxSpecialSectionError::AlternativeAddressOutOfRange)?;
        read(memory, mapping, record_offset, &mut record).map_err(map_identity_memory_error)?;
        let instruction_relative = i32::from_le_bytes(record[0..4].try_into().unwrap());
        let replacement_relative = i32::from_le_bytes(record[4..8].try_into().unwrap());
        let feature = u16::from_le_bytes(record[8..10].try_into().unwrap());
        let flags = u16::from_le_bytes(record[10..12].try_into().unwrap());
        let instruction_length = usize::from(record[12]);
        let replacement_length = usize::from(record[13]);
        if flags & !ALT_SUPPORTED_FLAGS != 0
            || instruction_length == 0
            || replacement_length > instruction_length
        {
            return Err(if flags & !ALT_SUPPORTED_FLAGS != 0 {
                LinuxSpecialSectionError::UnsupportedAlternativeFlags
            } else {
                LinuxSpecialSectionError::InvalidAlternativeRecord
            });
        }
        let instruction_offset = relative_image_offset(
            image_base,
            image_size,
            record_offset,
            instruction_relative,
            instruction_length,
        )?;
        if !range_has_permissions(regions, instruction_offset, instruction_length, true) {
            return Err(LinuxSpecialSectionError::AlternativeTargetNotExecutable);
        }
        if let Some((_, length)) = instruction_shapes
            .iter()
            .find(|(offset, _)| *offset == instruction_offset)
        {
            if *length != instruction_length {
                return Err(LinuxSpecialSectionError::InvalidAlternativeRecord);
            }
        } else {
            instruction_shapes.push((instruction_offset, instruction_length));
        }
        let mut selected = features
            .feature_enabled(feature)
            .map_err(LinuxSpecialSectionError::Feature)?;
        if flags & ALT_FLAG_NOT != 0 {
            selected = !selected;
        }
        if !selected {
            continue;
        }
        let replacement_offset = relative_image_offset(
            image_base,
            image_size,
            record_offset + 4,
            replacement_relative,
            replacement_length,
        )?;
        let mut patch = Vec::new();
        patch
            .try_reserve_exact(instruction_length)
            .map_err(|_| LinuxSpecialSectionError::AllocationFailed)?;
        patch.resize(instruction_length, 0x90);
        let mut original = Vec::new();
        original
            .try_reserve_exact(instruction_length)
            .map_err(|_| LinuxSpecialSectionError::AllocationFailed)?;
        original.resize(instruction_length, 0);
        read(memory, mapping, instruction_offset, &mut original)
            .map_err(map_identity_memory_error)?;
        if replacement_length != 0 {
            read(
                memory,
                mapping,
                replacement_offset,
                &mut patch[..replacement_length],
            )
            .map_err(map_identity_memory_error)?;
        }
        if flags & ALT_FLAG_DIRECT_CALL != 0 {
            retarget_direct_call(
                memory,
                mapping,
                image_base,
                replacement_offset,
                instruction_offset,
                replacement_length,
                &original,
                &mut patch,
                features.nop_function_address(),
            )?;
        } else {
            relocate_supported_replacement(
                image_base,
                replacement_offset,
                instruction_offset,
                &mut patch[..replacement_length],
            )?;
        }
        write_verified(memory, mapping, instruction_offset, &patch)
            .map_err(map_identity_memory_error)?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct JumpLabelPatch {
    image_offset: usize,
    bytes: [u8; 5],
    width: u8,
}

fn apply_jump_labels<Memory, Tlb, Features>(
    memory: &mut X86_64LinuxModuleMemory<Memory, Tlb>,
    mapping: LinuxModuleMapping,
    image_base: u64,
    image_size: usize,
    regions: &[LinuxKoMemoryRegion],
    sections: &[LinuxKoSpecialSection<'_>],
    features: &Features,
) -> Result<(), LinuxSpecialSectionError<Memory::Error, Features::Error>>
where
    Memory: ProcessFrameMemory,
    Tlb: LinuxModuleTlb,
    Features: X86_64AlternativeFeatures,
{
    let mut table = None;
    for section in sections {
        if section.kind == LinuxKoSpecialSectionKind::JumpLabels
            && section.name == b"__jump_table"
            && table.replace(*section).is_some()
        {
            return Err(LinuxSpecialSectionError::DuplicateJumpLabelTable);
        }
    }
    let table = table.ok_or(LinuxSpecialSectionError::MissingJumpLabelTable)?;
    if table.size == 0 || table.size % JUMP_ENTRY_BYTES != 0 {
        return Err(LinuxSpecialSectionError::InvalidJumpLabelTable);
    }

    // Preflight every record before writing any text. A malformed later entry
    // must not leave an earlier branch transition visible in the reservation.
    let mut patches = Vec::new();
    patches
        .try_reserve_exact(table.size / JUMP_ENTRY_BYTES)
        .map_err(|_| LinuxSpecialSectionError::AllocationFailed)?;
    let mut record = [0; JUMP_ENTRY_BYTES];
    for index in 0..table.size / JUMP_ENTRY_BYTES {
        let record_offset = table
            .image_offset
            .checked_add(index * JUMP_ENTRY_BYTES)
            .ok_or(LinuxSpecialSectionError::AlternativeAddressOutOfRange)?;
        read(memory, mapping, record_offset, &mut record).map_err(map_identity_memory_error)?;

        let code_relative = i32::from_le_bytes(record[0..4].try_into().unwrap());
        let target_relative = i32::from_le_bytes(record[4..8].try_into().unwrap());
        let key_relative = i64::from_le_bytes(record[8..16].try_into().unwrap());
        let code_offset =
            relative_image_offset(image_base, image_size, record_offset, code_relative, 5)?;
        let target_offset = relative_image_offset(
            image_base,
            image_size,
            record_offset + 4,
            target_relative,
            1,
        )?;
        if !range_has_permissions(regions, code_offset, 2, true)
            || !range_has_permissions(regions, target_offset, 1, true)
        {
            return Err(LinuxSpecialSectionError::JumpLabelTargetNotExecutable);
        }

        let key_flags = (key_relative as u64) & JUMP_KEY_FLAGS;
        let key_address = relative_image_address(
            image_base,
            record_offset + 8,
            key_relative & !(JUMP_KEY_FLAGS as i64),
        )?;
        if key_address & 7 != 0 {
            return Err(LinuxSpecialSectionError::JumpLabelKeyOutOfRange);
        }
        let (initial_type, enabled) = if let Some(key_offset) = key_address
            .checked_sub(image_base)
            .and_then(|offset| usize::try_from(offset).ok())
            .filter(|offset| offset.checked_add(16).is_some_and(|end| end <= image_size))
        {
            let mut key_state = [0; 16];
            read(memory, mapping, key_offset, &mut key_state).map_err(map_identity_memory_error)?;
            (
                u64::from_le_bytes(key_state[8..16].try_into().unwrap()) & JUMP_KEY_TYPE_TRUE != 0,
                i32::from_le_bytes(key_state[0..4].try_into().unwrap()) > 0,
            )
        } else {
            features
                .static_key_state(key_address)
                .map_err(LinuxSpecialSectionError::Feature)?
                .ok_or(LinuxSpecialSectionError::JumpLabelKeyStateUnavailable)?
        };
        let branch = key_flags & 1 != 0;
        let initial_jump = initial_type ^ branch;
        let desired_jump = enabled ^ branch;

        let mut current = [0; 5];
        read(memory, mapping, code_offset, &mut current).map_err(map_identity_memory_error)?;
        let width = jump_instruction_width(&current)
            .ok_or(LinuxSpecialSectionError::InvalidJumpLabelInstruction)?;
        if !range_has_permissions(regions, code_offset, width, true) {
            return Err(LinuxSpecialSectionError::JumpLabelTargetNotExecutable);
        }
        let expected =
            jump_label_bytes(image_base, code_offset, target_offset, width, initial_jump)?;
        if current[..width] != expected[..width] {
            return Err(LinuxSpecialSectionError::InvalidJumpLabelInstruction);
        }
        if desired_jump != initial_jump {
            let bytes =
                jump_label_bytes(image_base, code_offset, target_offset, width, desired_jump)?;
            if let Some(previous) = patches
                .iter()
                .find(|patch: &&JumpLabelPatch| patch.image_offset == code_offset)
            {
                if usize::from(previous.width) != width || previous.bytes[..width] != bytes[..width]
                {
                    return Err(LinuxSpecialSectionError::InvalidJumpLabelInstruction);
                }
            } else {
                patches.push(JumpLabelPatch {
                    image_offset: code_offset,
                    bytes,
                    width: width as u8,
                });
            }
        }
    }

    for patch in patches {
        write_verified(
            memory,
            mapping,
            patch.image_offset,
            &patch.bytes[..usize::from(patch.width)],
        )
        .map_err(map_identity_memory_error)?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct StaticCallPatch {
    image_offset: usize,
    bytes: [u8; 5],
}

fn apply_static_calls<Memory, Tlb, Features>(
    memory: &mut X86_64LinuxModuleMemory<Memory, Tlb>,
    mapping: LinuxModuleMapping,
    image_base: u64,
    image_size: usize,
    regions: &[LinuxKoMemoryRegion],
    sections: &[LinuxKoSpecialSection<'_>],
    features: &Features,
) -> Result<(), LinuxSpecialSectionError<Memory::Error, Features::Error>>
where
    Memory: ProcessFrameMemory,
    Tlb: LinuxModuleTlb,
    Features: X86_64AlternativeFeatures,
{
    let mut sites = None;
    let mut tramp_keys = Vec::new();
    for section in sections {
        if section.kind != LinuxKoSpecialSectionKind::StaticCalls {
            continue;
        }
        match section.name {
            b".static_call_sites" => {
                if sites.replace(*section).is_some() {
                    return Err(LinuxSpecialSectionError::DuplicateStaticCallSites);
                }
            }
            b".static_call_tramp_key" => tramp_keys.push(*section),
            b".static_call.text" => {
                if !range_has_permissions(regions, section.image_offset, section.size, true) {
                    return Err(LinuxSpecialSectionError::StaticCallTargetNotExecutable);
                }
            }
            _ => return Err(LinuxSpecialSectionError::UnsupportedStaticCallSection),
        }
    }
    let sites = sites.ok_or(LinuxSpecialSectionError::MissingStaticCallSites)?;
    if sites.size == 0 || sites.size % STATIC_CALL_SITE_BYTES != 0 {
        return Err(LinuxSpecialSectionError::InvalidStaticCallTable);
    }
    for section in tramp_keys {
        if section.size == 0 || section.size % STATIC_CALL_SITE_BYTES != 0 {
            return Err(LinuxSpecialSectionError::InvalidStaticCallTable);
        }
        // The trampoline-key records are consumed by the runtime registration
        // layer. Validate both relative addresses now so malformed metadata
        // cannot be retained behind an otherwise successful load.
        let mut record = [0; STATIC_CALL_SITE_BYTES];
        for index in 0..section.size / STATIC_CALL_SITE_BYTES {
            let offset = section
                .image_offset
                .checked_add(index * STATIC_CALL_SITE_BYTES)
                .ok_or(LinuxSpecialSectionError::AlternativeAddressOutOfRange)?;
            read(memory, mapping, offset, &mut record).map_err(map_identity_memory_error)?;
            let tramp = relative_image_offset(
                image_base,
                image_size,
                offset,
                i32::from_le_bytes(record[0..4].try_into().unwrap()),
                1,
            )?;
            let key = relative_image_address(
                image_base,
                offset + 4,
                i64::from(i32::from_le_bytes(record[4..8].try_into().unwrap()))
                    & !(STATIC_CALL_SITE_FLAGS as i64),
            )?;
            if !range_has_permissions(regions, tramp, 1, true) || key & 7 != 0 {
                return Err(LinuxSpecialSectionError::StaticCallKeyOutOfRange);
            }
        }
    }

    let mut patches = Vec::new();
    patches
        .try_reserve_exact(sites.size / STATIC_CALL_SITE_BYTES)
        .map_err(|_| LinuxSpecialSectionError::AllocationFailed)?;
    let mut record = [0; STATIC_CALL_SITE_BYTES];
    for index in 0..sites.size / STATIC_CALL_SITE_BYTES {
        let record_offset = sites
            .image_offset
            .checked_add(index * STATIC_CALL_SITE_BYTES)
            .ok_or(LinuxSpecialSectionError::AlternativeAddressOutOfRange)?;
        read(memory, mapping, record_offset, &mut record).map_err(map_identity_memory_error)?;
        let code_offset = relative_image_offset(
            image_base,
            image_size,
            record_offset,
            i32::from_le_bytes(record[0..4].try_into().unwrap()),
            5,
        )?;
        if !range_has_permissions(regions, code_offset, 5, true) {
            return Err(LinuxSpecialSectionError::StaticCallTargetNotExecutable);
        }
        let key_relative = i64::from(i32::from_le_bytes(record[4..8].try_into().unwrap()));
        let key_flags = (key_relative as u64) & STATIC_CALL_SITE_FLAGS;
        if key_flags & 1 != 0 {
            return Err(LinuxSpecialSectionError::UnsupportedStaticCallSite);
        }
        let key_address = relative_image_address(
            image_base,
            record_offset + 4,
            key_relative & !(STATIC_CALL_SITE_FLAGS as i64),
        )?;
        if key_address & 7 != 0 {
            return Err(LinuxSpecialSectionError::StaticCallKeyOutOfRange);
        }
        let key_offset = key_address
            .checked_sub(image_base)
            .and_then(|offset| usize::try_from(offset).ok())
            .filter(|offset| offset.checked_add(8).is_some_and(|end| end <= image_size));
        let key_in_image = key_offset.is_some();
        let function = if let Some(key_offset) = key_offset {
            read_u64(memory, mapping, key_offset).map_err(map_identity_memory_error)?
        } else {
            features
                .static_call_function(key_address)
                .map_err(LinuxSpecialSectionError::Feature)?
                .ok_or(LinuxSpecialSectionError::StaticCallFunctionUnavailable)?
        };
        if function != 0
            && function
                .checked_sub(image_base)
                .and_then(|offset| usize::try_from(offset).ok())
                .is_some_and(|offset| range_has_permissions(regions, offset, 1, true))
        {
            // Module-local targets are checked by the region table. External
            // targets are trusted only through the unsafe provider contract.
        } else if function != 0 && key_in_image {
            return Err(LinuxSpecialSectionError::StaticCallTargetNotExecutable);
        }

        let mut current = [0; 5];
        read(memory, mapping, code_offset, &mut current).map_err(map_identity_memory_error)?;
        let current_is_nop = current == [0x0f, 0x1f, 0x44, 0x00, 0x00];
        let current_is_return_zero = current == [0x2e, 0x2e, 0x2e, 0x31, 0xc0];
        if !current_is_nop && !current_is_return_zero && current[0] != 0xe8 {
            return Err(LinuxSpecialSectionError::UnsupportedStaticCallSite);
        }
        let desired = static_call_bytes(image_base, code_offset, function)?;
        if current != desired {
            if let Some(previous) = patches
                .iter()
                .find(|patch: &&StaticCallPatch| patch.image_offset == code_offset)
            {
                if previous.bytes != desired {
                    return Err(LinuxSpecialSectionError::UnsupportedStaticCallSite);
                }
            } else {
                patches.push(StaticCallPatch {
                    image_offset: code_offset,
                    bytes: desired,
                });
            }
        }
    }
    for patch in patches {
        write_verified(memory, mapping, patch.image_offset, &patch.bytes)
            .map_err(map_identity_memory_error)?;
    }
    Ok(())
}

fn static_call_bytes<MemoryError, FeatureError>(
    image_base: u64,
    code_offset: usize,
    function: u64,
) -> Result<[u8; 5], LinuxSpecialSectionError<MemoryError, FeatureError>> {
    let mut bytes = [0x90; 5];
    if function == 0 {
        bytes.copy_from_slice(&[0x0f, 0x1f, 0x44, 0x00, 0x00]);
        return Ok(bytes);
    }
    let next = image_base
        .checked_add(code_offset as u64)
        .and_then(|address| address.checked_add(5))
        .ok_or(LinuxSpecialSectionError::AlternativeAddressOutOfRange)?;
    let displacement = i32::try_from(i128::from(function) - i128::from(next))
        .map_err(|_| LinuxSpecialSectionError::StaticCallTargetNotExecutable)?;
    bytes[0] = 0xe8;
    bytes[1..5].copy_from_slice(&displacement.to_le_bytes());
    Ok(bytes)
}

/// Validate and, on a UP kernel, remove the lock prefix entries emitted in
/// `.smp_locks`. Linux stores one signed rel32 offset per lock prefix; the
/// offset is relative to the table field itself, not to the image base. The
/// table is metadata only, so every target is preflighted before the first
/// byte is changed.
fn apply_smp_locks<Memory, Tlb, Features>(
    memory: &mut X86_64LinuxModuleMemory<Memory, Tlb>,
    mapping: LinuxModuleMapping,
    image_base: u64,
    image_size: usize,
    regions: &[LinuxKoMemoryRegion],
    sections: &[LinuxKoSpecialSection<'_>],
    features: &Features,
) -> Result<(), LinuxSpecialSectionError<Memory::Error, Features::Error>>
where
    Memory: ProcessFrameMemory,
    Tlb: LinuxModuleTlb,
    Features: X86_64AlternativeFeatures,
{
    let mut table = None;
    for section in sections {
        if section.kind != LinuxKoSpecialSectionKind::CpuLockPatching {
            continue;
        }
        if section.name != b".smp_locks" {
            return Err(LinuxSpecialSectionError::InvalidSmpLockTable);
        }
        if table.replace(*section).is_some() {
            return Err(LinuxSpecialSectionError::DuplicateSmpLockTable);
        }
    }
    let table = table.ok_or(LinuxSpecialSectionError::MissingSmpLockTable)?;
    if table.size == 0 || table.size % SMP_LOCK_ENTRY_BYTES != 0 {
        return Err(LinuxSpecialSectionError::InvalidSmpLockTable);
    }

    let remove_prefix = !features
        .smp_enabled()
        .map_err(LinuxSpecialSectionError::Feature)?;
    let mut patches = Vec::new();
    patches
        .try_reserve_exact(table.size / SMP_LOCK_ENTRY_BYTES)
        .map_err(|_| LinuxSpecialSectionError::AllocationFailed)?;
    let mut record = [0; SMP_LOCK_ENTRY_BYTES];
    for index in 0..table.size / SMP_LOCK_ENTRY_BYTES {
        let record_offset = table
            .image_offset
            .checked_add(index * SMP_LOCK_ENTRY_BYTES)
            .ok_or(LinuxSpecialSectionError::AlternativeAddressOutOfRange)?;
        read(memory, mapping, record_offset, &mut record).map_err(map_identity_memory_error)?;
        let target_offset = relative_image_offset(
            image_base,
            image_size,
            record_offset,
            i32::from_le_bytes(record),
            1,
        )?;
        if !range_has_permissions(regions, target_offset, 1, true) {
            return Err(LinuxSpecialSectionError::SmpLockTargetNotExecutable);
        }

        let mut current = [0; 1];
        read(memory, mapping, target_offset, &mut current).map_err(map_identity_memory_error)?;
        if current[0] != 0xf0 && current[0] != 0x90 {
            return Err(LinuxSpecialSectionError::InvalidSmpLockInstruction);
        }
        if remove_prefix && current[0] == 0xf0 && !patches.contains(&target_offset) {
            patches.push(target_offset);
        }
    }

    for target_offset in patches {
        write_verified(memory, mapping, target_offset, &[0x90])
            .map_err(map_identity_memory_error)?;
    }
    Ok(())
}

fn relative_image_address<MemoryError, FeatureError>(
    image_base: u64,
    field_offset: usize,
    relative: i64,
) -> Result<u64, LinuxSpecialSectionError<MemoryError, FeatureError>> {
    let field_address = image_base
        .checked_add(field_offset as u64)
        .ok_or(LinuxSpecialSectionError::AlternativeAddressOutOfRange)?;
    if relative >= 0 {
        field_address
            .checked_add(relative as u64)
            .ok_or(LinuxSpecialSectionError::AlternativeAddressOutOfRange)
    } else {
        field_address
            .checked_sub(relative.unsigned_abs())
            .ok_or(LinuxSpecialSectionError::AlternativeAddressOutOfRange)
    }
}

fn jump_instruction_width(bytes: &[u8; 5]) -> Option<usize> {
    if bytes[..2] == [0x66, 0x90] || bytes[0] == 0xeb {
        Some(2)
    } else if bytes[..5] == [0x0f, 0x1f, 0x44, 0x00, 0x00] || bytes[0] == 0xe9 {
        Some(5)
    } else {
        None
    }
}

fn jump_label_bytes<MemoryError, FeatureError>(
    image_base: u64,
    code_offset: usize,
    target_offset: usize,
    width: usize,
    jump: bool,
) -> Result<[u8; 5], LinuxSpecialSectionError<MemoryError, FeatureError>> {
    let mut bytes = [0x90; 5];
    if !jump {
        match width {
            2 => bytes[..2].copy_from_slice(&[0x66, 0x90]),
            5 => bytes[..5].copy_from_slice(&[0x0f, 0x1f, 0x44, 0x00, 0x00]),
            _ => return Err(LinuxSpecialSectionError::InvalidJumpLabelInstruction),
        }
        return Ok(bytes);
    }
    let next = image_base
        .checked_add(code_offset as u64)
        .and_then(|address| address.checked_add(width as u64))
        .ok_or(LinuxSpecialSectionError::AlternativeAddressOutOfRange)?;
    let target = image_base
        .checked_add(target_offset as u64)
        .ok_or(LinuxSpecialSectionError::AlternativeAddressOutOfRange)?;
    let displacement = i128::from(target) - i128::from(next);
    match width {
        2 => {
            let displacement = i8::try_from(displacement)
                .map_err(|_| LinuxSpecialSectionError::JumpLabelTargetNotExecutable)?;
            bytes[..2].copy_from_slice(&[0xeb, displacement as u8]);
        }
        5 => {
            let displacement = i32::try_from(displacement)
                .map_err(|_| LinuxSpecialSectionError::JumpLabelTargetNotExecutable)?;
            bytes[0] = 0xe9;
            bytes[1..5].copy_from_slice(&displacement.to_le_bytes());
        }
        _ => return Err(LinuxSpecialSectionError::InvalidJumpLabelInstruction),
    }
    Ok(bytes)
}

fn map_identity_memory_error<MemoryError, FeatureError>(
    error: LinuxModuleIdentityError<MemoryError>,
) -> LinuxSpecialSectionError<MemoryError, FeatureError> {
    match error {
        LinuxModuleIdentityError::Memory(error) => LinuxSpecialSectionError::Memory(error),
        LinuxModuleIdentityError::AllocationFailed => LinuxSpecialSectionError::AllocationFailed,
        LinuxModuleIdentityError::VerificationFailed => {
            LinuxSpecialSectionError::VerificationFailed
        }
        other => LinuxSpecialSectionError::Identity(other),
    }
}

fn relative_image_offset<MemoryError, FeatureError>(
    image_base: u64,
    image_size: usize,
    field_offset: usize,
    relative: i32,
    length: usize,
) -> Result<usize, LinuxSpecialSectionError<MemoryError, FeatureError>> {
    let field_address = image_base
        .checked_add(field_offset as u64)
        .ok_or(LinuxSpecialSectionError::AlternativeAddressOutOfRange)?;
    let target = if relative >= 0 {
        field_address.checked_add(relative as u64)
    } else {
        field_address.checked_sub(u64::from(relative.unsigned_abs()))
    }
    .ok_or(LinuxSpecialSectionError::AlternativeAddressOutOfRange)?;
    let offset = target
        .checked_sub(image_base)
        .and_then(|offset| usize::try_from(offset).ok())
        .ok_or(LinuxSpecialSectionError::AlternativeAddressOutOfRange)?;
    if offset
        .checked_add(length)
        .is_none_or(|end| end > image_size)
    {
        return Err(LinuxSpecialSectionError::AlternativeAddressOutOfRange);
    }
    Ok(offset)
}

fn range_has_permissions(
    regions: &[LinuxKoMemoryRegion],
    offset: usize,
    length: usize,
    executable: bool,
) -> bool {
    let Some(end) = offset.checked_add(length) else {
        return false;
    };
    regions.iter().any(|region| {
        region
            .image_offset
            .checked_add(region.size)
            .is_some_and(|region_end| {
                offset >= region.image_offset
                    && end <= region_end
                    && region.executable == executable
                    && !region.writable
            })
    })
}

fn retarget_direct_call<Memory, Tlb, FeatureError>(
    memory: &X86_64LinuxModuleMemory<Memory, Tlb>,
    mapping: LinuxModuleMapping,
    image_base: u64,
    replacement_offset: usize,
    instruction_offset: usize,
    replacement_length: usize,
    original: &[u8],
    patch: &mut [u8],
    nop_function_address: Option<u64>,
) -> Result<(), LinuxSpecialSectionError<Memory::Error, FeatureError>>
where
    Memory: ProcessFrameMemory,
    Tlb: LinuxModuleTlb,
{
    if replacement_length != 5
        || original.len() != 6
        || patch.len() < 6
        || patch[0] != 0xe8
        || original[0..2] != [0xff, 0x15]
    {
        return Err(LinuxSpecialSectionError::InvalidDirectCall);
    }
    let indirect_displacement = i32::from_le_bytes(original[2..6].try_into().unwrap());
    let instruction_next = image_base
        .checked_add(instruction_offset as u64)
        .and_then(|address| address.checked_add(6))
        .ok_or(LinuxSpecialSectionError::AlternativeAddressOutOfRange)?;
    let pointer_address = if indirect_displacement >= 0 {
        instruction_next.checked_add(indirect_displacement as u64)
    } else {
        instruction_next.checked_sub(u64::from(indirect_displacement.unsigned_abs()))
    }
    .ok_or(LinuxSpecialSectionError::InvalidDirectCall)?;
    let pointer_offset = pointer_address
        .checked_sub(image_base)
        .and_then(|offset| usize::try_from(offset).ok())
        .ok_or(LinuxSpecialSectionError::InvalidDirectCall)?;
    let mut target_bytes = [0; 8];
    read(memory, mapping, pointer_offset, &mut target_bytes).map_err(map_identity_memory_error)?;
    let mut target = u64::from_le_bytes(target_bytes);
    let replacement_next = image_base
        .checked_add(replacement_offset as u64)
        .and_then(|address| address.checked_add(5))
        .ok_or(LinuxSpecialSectionError::AlternativeAddressOutOfRange)?;
    if target == 0 {
        let old_displacement = i32::from_le_bytes(patch[1..5].try_into().unwrap());
        target = if old_displacement >= 0 {
            replacement_next.checked_add(old_displacement as u64)
        } else {
            replacement_next.checked_sub(u64::from(old_displacement.unsigned_abs()))
        }
        .ok_or(LinuxSpecialSectionError::InvalidDirectCall)?;
    }
    if nop_function_address == Some(target) {
        patch.fill(0x90);
        return Ok(());
    }
    let direct_call_next = image_base
        .checked_add(instruction_offset as u64)
        .and_then(|address| address.checked_add(5))
        .ok_or(LinuxSpecialSectionError::AlternativeAddressOutOfRange)?;
    let displacement = i128::from(target) - i128::from(direct_call_next);
    let displacement =
        i32::try_from(displacement).map_err(|_| LinuxSpecialSectionError::InvalidDirectCall)?;
    patch[1..5].copy_from_slice(&displacement.to_le_bytes());
    Ok(())
}

/// Conservative decoder for the replacement forms admitted by the current
/// RHEL/NVIDIA evidence. Relative calls, jumps, and long conditional branches
/// are retargeted; unknown encodings are rejected instead of copied blindly.
fn relocate_supported_replacement<MemoryError, FeatureError>(
    image_base: u64,
    replacement_offset: usize,
    instruction_offset: usize,
    bytes: &mut [u8],
) -> Result<(), LinuxSpecialSectionError<MemoryError, FeatureError>> {
    let mut offset = 0;
    while offset < bytes.len() {
        let remaining = &bytes[offset..];
        let length = match remaining {
            [0x90 | 0xc3 | 0xcc, ..] => 1,
            [0xf3, 0x90, ..] => 2,
            [0x31 | 0x33 | 0x85 | 0x89 | 0x8b, modrm, ..] if modrm >> 6 == 3 => 2,
            [0x0f, 0xae, modrm, ..] if modrm >> 6 == 3 => 3,
            [0x48, 0x31 | 0x33 | 0x85 | 0x89 | 0x8b, modrm, ..] if modrm >> 6 == 3 => 3,
            [0xf3, 0x0f, 0xb8, modrm, ..] if modrm >> 6 == 3 => 4,
            [0xf3, 0x48, 0x0f, 0xb8, modrm, ..] if modrm >> 6 == 3 => 5,
            [0x48, register, ..] if (0xb8..=0xbf).contains(register) && remaining.len() >= 10 => 10,
            [0xe8 | 0xe9, _, _, _, _, ..] => {
                relocate_rel32(
                    image_base,
                    replacement_offset + offset,
                    instruction_offset + offset,
                    &mut bytes[offset + 1..offset + 5],
                    5,
                )?;
                5
            }
            [0x0f, condition, _, _, _, _, ..] if (0x80..=0x8f).contains(condition) => {
                relocate_rel32(
                    image_base,
                    replacement_offset + offset,
                    instruction_offset + offset,
                    &mut bytes[offset + 2..offset + 6],
                    6,
                )?;
                6
            }
            _ => return Err(LinuxSpecialSectionError::UnsupportedAlternativeInstruction),
        };
        offset += length;
    }
    Ok(())
}

fn relocate_rel32<MemoryError, FeatureError>(
    image_base: u64,
    old_instruction_offset: usize,
    new_instruction_offset: usize,
    displacement: &mut [u8],
    instruction_length: usize,
) -> Result<(), LinuxSpecialSectionError<MemoryError, FeatureError>> {
    let old_displacement = i32::from_le_bytes(
        displacement
            .try_into()
            .map_err(|_| LinuxSpecialSectionError::UnsupportedAlternativeInstruction)?,
    );
    let old_next = image_base
        .checked_add(old_instruction_offset as u64)
        .and_then(|address| address.checked_add(instruction_length as u64))
        .ok_or(LinuxSpecialSectionError::AlternativeAddressOutOfRange)?;
    let target = if old_displacement >= 0 {
        old_next.checked_add(old_displacement as u64)
    } else {
        old_next.checked_sub(u64::from(old_displacement.unsigned_abs()))
    }
    .ok_or(LinuxSpecialSectionError::AlternativeAddressOutOfRange)?;
    let new_next = image_base
        .checked_add(new_instruction_offset as u64)
        .and_then(|address| address.checked_add(instruction_length as u64))
        .ok_or(LinuxSpecialSectionError::AlternativeAddressOutOfRange)?;
    let new_displacement = i32::try_from(i128::from(target) - i128::from(new_next))
        .map_err(|_| LinuxSpecialSectionError::AlternativeAddressOutOfRange)?;
    displacement.copy_from_slice(&new_displacement.to_le_bytes());
    Ok(())
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

    struct TestFeatures(bool);

    unsafe impl X86_64AlternativeFeatures for TestFeatures {
        type Error = core::convert::Infallible;

        fn feature_enabled(&self, _feature: u16) -> Result<bool, Self::Error> {
            Ok(self.0)
        }
    }

    struct TestSmpFeatures {
        smp: bool,
    }

    unsafe impl X86_64AlternativeFeatures for TestSmpFeatures {
        type Error = core::convert::Infallible;

        fn feature_enabled(&self, _feature: u16) -> Result<bool, Self::Error> {
            Ok(false)
        }

        fn smp_enabled(&self) -> Result<bool, Self::Error> {
            Ok(self.smp)
        }
    }

    fn relative(from: usize, to: usize) -> i32 {
        i32::try_from(to as i64 - from as i64).unwrap()
    }

    fn alternative_sections(
        table_offset: usize,
        table_size: usize,
        replacement_offset: usize,
        replacement_size: usize,
    ) -> [LinuxKoSpecialSection<'static>; 2] {
        [
            LinuxKoSpecialSection {
                section_index: 20,
                name: b".altinstructions",
                image_offset: table_offset,
                size: table_size,
                kind: LinuxKoSpecialSectionKind::Alternatives,
            },
            LinuxKoSpecialSection {
                section_index: 21,
                name: b".altinstr_replacement",
                image_offset: replacement_offset,
                size: replacement_size,
                kind: LinuxKoSpecialSectionKind::Alternatives,
            },
        ]
    }

    #[test]
    fn applies_selected_alternative_and_preserves_unselected_baseline() {
        for selected in [false, true] {
            let mut mapper = mapper();
            let mapping = mapper.reserve_zeroed(PAGE_SIZE * 6, PAGE_SIZE).unwrap();
            let base = mapper.mapping_base(mapping).unwrap();
            let instruction_offset = 64;
            let table_offset = PAGE_SIZE * 2 + 128;
            let replacement_offset = PAGE_SIZE * 2 + 512;
            let mut record = [0; ALT_INSTR_BYTES];
            record[0..4].copy_from_slice(&relative(table_offset, instruction_offset).to_le_bytes());
            record[4..8]
                .copy_from_slice(&relative(table_offset + 4, replacement_offset).to_le_bytes());
            record[8..10].copy_from_slice(&7_u16.to_le_bytes());
            record[12] = 8;
            record[13] = 3;
            mapper
                .write(mapping, instruction_offset, &[0xcc; 8])
                .unwrap();
            mapper.write(mapping, table_offset, &record).unwrap();
            mapper
                .write(mapping, replacement_offset, &[0x31, 0xc0, 0xc3])
                .unwrap();
            apply_alternatives(
                &mut mapper,
                mapping,
                base,
                PAGE_SIZE * 6,
                &regions(),
                &alternative_sections(table_offset, record.len(), replacement_offset, 3),
                &TestFeatures(selected),
            )
            .unwrap();
            let mut observed = [0; 8];
            mapper
                .read(mapping, instruction_offset, &mut observed)
                .unwrap();
            assert_eq!(
                observed,
                if selected {
                    [0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90]
                } else {
                    [0xcc; 8]
                }
            );
        }
    }

    #[test]
    fn retargets_selected_direct_call_from_replacement_to_instruction_site() {
        let mut mapper = mapper();
        let mapping = mapper.reserve_zeroed(PAGE_SIZE * 6, PAGE_SIZE).unwrap();
        let base = mapper.mapping_base(mapping).unwrap();
        let instruction_offset = 96;
        let call_target_offset = 256;
        let pointer_offset = PAGE_SIZE * 2 + 1000;
        let table_offset = PAGE_SIZE * 2 + 160;
        let replacement_offset = PAGE_SIZE * 2 + 600;
        let old_displacement = i32::try_from(300_i64 - (replacement_offset + 5) as i64).unwrap();
        let mut replacement = [0; 5];
        replacement[0] = 0xe8;
        replacement[1..5].copy_from_slice(&old_displacement.to_le_bytes());
        let mut record = [0; ALT_INSTR_BYTES];
        record[0..4].copy_from_slice(&relative(table_offset, instruction_offset).to_le_bytes());
        record[4..8].copy_from_slice(&relative(table_offset + 4, replacement_offset).to_le_bytes());
        record[8..10].copy_from_slice(&11_u16.to_le_bytes());
        record[10..12].copy_from_slice(&ALT_FLAG_DIRECT_CALL.to_le_bytes());
        record[12] = 6;
        record[13] = 5;
        let pointer_displacement =
            i32::try_from(pointer_offset as i64 - (instruction_offset + 6) as i64).unwrap();
        let mut indirect = [0; 6];
        indirect[0..2].copy_from_slice(&[0xff, 0x15]);
        indirect[2..6].copy_from_slice(&pointer_displacement.to_le_bytes());
        mapper
            .write(mapping, instruction_offset, &indirect)
            .unwrap();
        mapper.write(mapping, table_offset, &record).unwrap();
        mapper
            .write(mapping, replacement_offset, &replacement)
            .unwrap();
        mapper
            .write(
                mapping,
                pointer_offset,
                &(base + call_target_offset as u64).to_le_bytes(),
            )
            .unwrap();
        apply_alternatives(
            &mut mapper,
            mapping,
            base,
            PAGE_SIZE * 6,
            &regions(),
            &alternative_sections(table_offset, record.len(), replacement_offset, 5),
            &TestFeatures(true),
        )
        .unwrap();
        let mut observed = [0; 6];
        mapper
            .read(mapping, instruction_offset, &mut observed)
            .unwrap();
        let expected_displacement =
            i32::try_from(call_target_offset as i64 - (instruction_offset + 5) as i64).unwrap();
        assert_eq!(observed[0], 0xe8);
        assert_eq!(
            i32::from_le_bytes(observed[1..5].try_into().unwrap()),
            expected_displacement
        );
        assert_eq!(observed[5], 0x90);
    }

    #[test]
    fn relocates_supported_rel32_and_rejects_unknown_rip_relative_encoding() {
        for supported in [true, false] {
            let mut mapper = mapper();
            let mapping = mapper.reserve_zeroed(PAGE_SIZE * 6, PAGE_SIZE).unwrap();
            let base = mapper.mapping_base(mapping).unwrap();
            let instruction_offset = 160;
            let target_offset = 320;
            let table_offset = PAGE_SIZE * 2 + 200;
            let replacement_offset = PAGE_SIZE * 2 + 720;
            let replacement = if supported {
                let mut branch = [0; 7];
                branch[0] = 0xe9;
                let displacement =
                    i32::try_from(target_offset as i64 - (replacement_offset + 5) as i64).unwrap();
                branch[1..5].copy_from_slice(&displacement.to_le_bytes());
                branch
            } else {
                [0x48, 0x8b, 0x05, 0, 0, 0, 0]
            };
            let mut record = [0; ALT_INSTR_BYTES];
            record[0..4].copy_from_slice(&relative(table_offset, instruction_offset).to_le_bytes());
            record[4..8]
                .copy_from_slice(&relative(table_offset + 4, replacement_offset).to_le_bytes());
            record[8..10].copy_from_slice(&3_u16.to_le_bytes());
            record[12] = 7;
            record[13] = if supported { 5 } else { 7 };
            mapper
                .write(mapping, instruction_offset, &[0xcc; 7])
                .unwrap();
            mapper.write(mapping, table_offset, &record).unwrap();
            mapper
                .write(mapping, replacement_offset, &replacement)
                .unwrap();
            let result = apply_alternatives(
                &mut mapper,
                mapping,
                base,
                PAGE_SIZE * 6,
                &regions(),
                &alternative_sections(table_offset, record.len(), replacement_offset, 7),
                &TestFeatures(true),
            );
            let mut observed = [0; 7];
            mapper
                .read(mapping, instruction_offset, &mut observed)
                .unwrap();
            if supported {
                result.unwrap();
                assert_eq!(observed[0], 0xe9);
                assert_eq!(
                    i32::from_le_bytes(observed[1..5].try_into().unwrap()),
                    i32::try_from(target_offset as i64 - (instruction_offset + 5) as i64).unwrap()
                );
            } else {
                assert_eq!(
                    result,
                    Err(LinuxSpecialSectionError::UnsupportedAlternativeInstruction)
                );
                assert_eq!(observed, [0xcc; 7]);
            }
        }
    }

    #[test]
    fn admits_measured_nvidia_popcnt_and_movabs_replacements() {
        let cases: &[&[u8]] = &[
            &[0xf3, 0x0f, 0xb8, 0xc7],
            &[0xf3, 0x48, 0x0f, 0xb8, 0xc7],
            &[0x48, 0xb8, 0x00, 0xf0, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00],
            &[0x48, 0xba, 0x00, 0xf0, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00],
        ];
        for bytes in cases {
            let mut replacement = bytes.to_vec();
            let original = replacement.clone();
            relocate_supported_replacement::<(), ()>(0x20_0000, 4096, 128, &mut replacement)
                .unwrap();
            assert_eq!(replacement, original);
        }
    }

    #[test]
    fn patches_enabled_module_local_jump_label_and_validates_initial_nop() {
        let mut mapper = mapper();
        let mapping = mapper.reserve_zeroed(PAGE_SIZE * 6, PAGE_SIZE).unwrap();
        let base = mapper.mapping_base(mapping).unwrap();
        let code_offset = 64;
        let target_offset = 256;
        let table_offset = PAGE_SIZE * 2 + 128;
        let key_offset = PAGE_SIZE * 2 + 512;
        let key_relative = i64::try_from(key_offset as i128 - (table_offset + 8) as i128).unwrap();
        let mut record = [0; JUMP_ENTRY_BYTES];
        record[0..4].copy_from_slice(&relative(table_offset, code_offset).to_le_bytes());
        record[4..8].copy_from_slice(&relative(table_offset + 4, target_offset).to_le_bytes());
        record[8..16].copy_from_slice(&key_relative.to_le_bytes());

        mapper
            .write(mapping, code_offset, &[0x0f, 0x1f, 0x44, 0x00, 0x00])
            .unwrap();
        mapper.write(mapping, target_offset, &[0x90]).unwrap();
        mapper.write(mapping, table_offset, &record).unwrap();
        let mut key = [0; 16];
        key[0..4].copy_from_slice(&1_i32.to_le_bytes());
        key[8..16].copy_from_slice(&0_u64.to_le_bytes());
        mapper.write(mapping, key_offset, &key).unwrap();

        apply_jump_labels(
            &mut mapper,
            mapping,
            base,
            PAGE_SIZE * 6,
            &regions(),
            &[LinuxKoSpecialSection {
                section_index: 20,
                name: b"__jump_table",
                image_offset: table_offset,
                size: record.len(),
                kind: LinuxKoSpecialSectionKind::JumpLabels,
            }],
            &TestFeatures(true),
        )
        .unwrap();

        let mut observed = [0; 5];
        mapper.read(mapping, code_offset, &mut observed).unwrap();
        assert_eq!(observed[0], 0xe9);
        assert_eq!(
            i32::from_le_bytes(observed[1..5].try_into().unwrap()),
            i32::try_from(target_offset as i64 - (code_offset + 5) as i64).unwrap()
        );
    }

    #[test]
    fn patches_module_local_static_call_site_to_direct_call() {
        let mut mapper = mapper();
        let mapping = mapper.reserve_zeroed(PAGE_SIZE * 6, PAGE_SIZE).unwrap();
        let base = mapper.mapping_base(mapping).unwrap();
        let code_offset = 96;
        let function_offset = 256;
        let sites_offset = PAGE_SIZE * 2 + 128;
        let key_offset = PAGE_SIZE * 2 + 512;
        let key_relative = i32::try_from(key_offset as i64 - (sites_offset + 4) as i64).unwrap();
        let mut record = [0; STATIC_CALL_SITE_BYTES];
        record[0..4].copy_from_slice(&relative(sites_offset, code_offset).to_le_bytes());
        record[4..8].copy_from_slice(&key_relative.to_le_bytes());

        mapper
            .write(mapping, code_offset, &[0x0f, 0x1f, 0x44, 0x00, 0x00])
            .unwrap();
        mapper.write(mapping, function_offset, &[0x90]).unwrap();
        mapper.write(mapping, sites_offset, &record).unwrap();
        mapper
            .write(
                mapping,
                key_offset,
                &(base + function_offset as u64).to_le_bytes(),
            )
            .unwrap();

        apply_static_calls(
            &mut mapper,
            mapping,
            base,
            PAGE_SIZE * 6,
            &regions(),
            &[LinuxKoSpecialSection {
                section_index: 22,
                name: b".static_call_sites",
                image_offset: sites_offset,
                size: record.len(),
                kind: LinuxKoSpecialSectionKind::StaticCalls,
            }],
            &TestFeatures(true),
        )
        .unwrap();

        let mut observed = [0; 5];
        mapper.read(mapping, code_offset, &mut observed).unwrap();
        assert_eq!(observed[0], 0xe8);
        assert_eq!(
            i32::from_le_bytes(observed[1..5].try_into().unwrap()),
            i32::try_from(function_offset as i64 - (code_offset + 5) as i64).unwrap()
        );
    }

    #[test]
    fn removes_smp_lock_prefixes_only_for_a_up_kernel() {
        for smp in [false, true] {
            let mut mapper = mapper();
            let mapping = mapper.reserve_zeroed(PAGE_SIZE * 6, PAGE_SIZE).unwrap();
            let base = mapper.mapping_base(mapping).unwrap();
            let target_offset = 128;
            let table_offset = PAGE_SIZE * 4 + 128;
            let record = relative(table_offset, target_offset).to_le_bytes();
            mapper.write(mapping, target_offset, &[0xf0]).unwrap();
            mapper.write(mapping, table_offset, &record).unwrap();

            apply_smp_locks(
                &mut mapper,
                mapping,
                base,
                PAGE_SIZE * 6,
                &regions(),
                &[LinuxKoSpecialSection {
                    section_index: 23,
                    name: b".smp_locks",
                    image_offset: table_offset,
                    size: record.len(),
                    kind: LinuxKoSpecialSectionKind::CpuLockPatching,
                }],
                &TestSmpFeatures { smp },
            )
            .unwrap();

            let mut observed = [0; 1];
            mapper.read(mapping, target_offset, &mut observed).unwrap();
            assert_eq!(observed[0], if smp { 0xf0 } else { 0x90 });
        }
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
