//! Native x86-64 backend for transactional Linux module installation.
//!
//! This adapter joins the architecture-owned W^X mapper to the generic Linux
//! `.ko` transaction. It deliberately delegates pre-seal Linux special-section
//! processing and lifecycle invocation to explicit unsafe contracts; there is
//! no permissive no-op processor or host-call fallback.

use crate::module::linux_loader::{
    LinuxKoBackend, LinuxKoLoadPlan, LinuxKoMemoryRegion, LinuxKoSpecialSection,
    LinuxKoSpecialSectionCoverage,
};
use crate::module::x86_64_memory::{
    LinuxModuleMapping, LinuxModuleTlb, MAXIMUM_LIVE_LINUX_MODULES, X86_64LinuxModuleMemory,
    X86_64ModuleMapError,
};
use crate::process::x86_64::ProcessFrameMemory;

pub const LINUX_MODULE_NAME_BYTES: usize = 56;

/// Auditable metadata produced while the module image is still inaccessible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X86_64LinuxPreSealReceipt {
    coverage: LinuxKoSpecialSectionCoverage,
    module_state_offset: Option<usize>,
}

impl X86_64LinuxPreSealReceipt {
    pub const fn new(
        coverage: LinuxKoSpecialSectionCoverage,
        module_state_offset: Option<usize>,
    ) -> Self {
        Self {
            coverage,
            module_state_offset,
        }
    }

    pub const fn coverage(self) -> LinuxKoSpecialSectionCoverage {
        self.coverage
    }

    pub const fn module_state_offset(self) -> Option<usize> {
        self.module_state_offset
    }
}

/// Pre-publication processing for one fully relocated Linux module image.
///
/// # Safety
///
/// Implementors must process every required architecture and Linux special
/// section represented by `plan`, or return an error. They may mutate only the
/// supplied staging reservation and must not seal, commit, execute, or retain
/// its mapping handle. The returned coverage receipt must acknowledge exactly
/// the categories actually present in `special_sections`; the backend rejects
/// missing or extraneous acknowledgements before sealing.
pub unsafe trait X86_64LinuxPreSeal<Memory, Tlb>
where
    Memory: ProcessFrameMemory,
    Tlb: LinuxModuleTlb,
{
    type Error;

    fn prepare(
        &mut self,
        memory: &mut X86_64LinuxModuleMemory<Memory, Tlb>,
        reservation: LinuxModuleMapping,
        plan: &LinuxKoLoadPlan<'_>,
        special_sections: &[LinuxKoSpecialSection<'_>],
    ) -> Result<X86_64LinuxPreSealReceipt, Self::Error>;
}

/// Serialized control transfer into a committed Linux module.
///
/// # Safety
///
/// Implementors must use the Linux x86-64 lifecycle ABI and preserve Arach's
/// kernel execution context. Returning `Err` guarantees module control was not
/// entered. Calls must return only after the lifecycle callback has returned.
pub unsafe trait X86_64LinuxExecutor {
    type Error;

    unsafe fn invoke_init(&mut self, address: u64) -> Result<i32, Self::Error>;
    unsafe fn invoke_cleanup(&mut self, address: u64) -> Result<(), Self::Error>;
}

#[derive(Debug, Eq, PartialEq)]
pub enum X86_64LinuxBackendError<MemoryError, PreSealError, ExecutorError> {
    Memory(X86_64ModuleMapError<MemoryError>),
    PreSeal(PreSealError),
    Execution(ExecutorError),
    InvalidModuleName,
    DuplicateModuleName,
    InvalidSpecialSectionInventory,
    IncompleteSpecialSectionCoverage,
    InvalidModuleState,
    InvalidLifecycle,
    InvalidLifecycleAddress,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum X86_64LinuxModuleLifecycle {
    Committed,
    Initialized,
    InitializationFailed,
    Cleaned,
}

/// Unique ownership handle for one committed native module mapping.
#[must_use = "a live module must be retained until it is explicitly unloaded"]
pub struct X86_64LinuxModule {
    mapping: LinuxModuleMapping,
    name: [u8; LINUX_MODULE_NAME_BYTES],
    name_length: u8,
    base: u64,
    size: usize,
    module_state_offset: usize,
    lifecycle: X86_64LinuxModuleLifecycle,
    init_discard_complete: bool,
}

impl X86_64LinuxModule {
    pub fn name(&self) -> &[u8] {
        &self.name[..usize::from(self.name_length)]
    }

    pub const fn base(&self) -> u64 {
        self.base
    }

    pub const fn size(&self) -> usize {
        self.size
    }

    pub const fn module_state_offset(&self) -> usize {
        self.module_state_offset
    }

    pub const fn lifecycle(&self) -> X86_64LinuxModuleLifecycle {
        self.lifecycle
    }

    pub const fn init_discard_complete(&self) -> bool {
        self.init_discard_complete
    }
}

/// Native transactional `.ko` backend with a fixed-capacity live-name table.
pub struct X86_64LinuxNativeBackend<Memory, Tlb, PreSeal, Executor>
where
    Memory: ProcessFrameMemory,
    Tlb: LinuxModuleTlb,
    PreSeal: X86_64LinuxPreSeal<Memory, Tlb>,
    Executor: X86_64LinuxExecutor,
{
    memory: X86_64LinuxModuleMemory<Memory, Tlb>,
    pre_seal: PreSeal,
    executor: Executor,
    prepared_generations: [u32; MAXIMUM_LIVE_LINUX_MODULES],
    prepared_state_offsets: [usize; MAXIMUM_LIVE_LINUX_MODULES],
    live_generations: [u32; MAXIMUM_LIVE_LINUX_MODULES],
    live_name_lengths: [u8; MAXIMUM_LIVE_LINUX_MODULES],
    live_names: [[u8; LINUX_MODULE_NAME_BYTES]; MAXIMUM_LIVE_LINUX_MODULES],
    deferred_reclamation_events: usize,
}

impl<Memory, Tlb, PreSeal, Executor> X86_64LinuxNativeBackend<Memory, Tlb, PreSeal, Executor>
where
    Memory: ProcessFrameMemory,
    Tlb: LinuxModuleTlb,
    PreSeal: X86_64LinuxPreSeal<Memory, Tlb>,
    Executor: X86_64LinuxExecutor,
{
    pub const fn new(
        memory: X86_64LinuxModuleMemory<Memory, Tlb>,
        pre_seal: PreSeal,
        executor: Executor,
    ) -> Self {
        Self {
            memory,
            pre_seal,
            executor,
            prepared_generations: [0; MAXIMUM_LIVE_LINUX_MODULES],
            prepared_state_offsets: [usize::MAX; MAXIMUM_LIVE_LINUX_MODULES],
            live_generations: [0; MAXIMUM_LIVE_LINUX_MODULES],
            live_name_lengths: [0; MAXIMUM_LIVE_LINUX_MODULES],
            live_names: [[0; LINUX_MODULE_NAME_BYTES]; MAXIMUM_LIVE_LINUX_MODULES],
            deferred_reclamation_events: 0,
        }
    }

    pub const fn memory_owner(&self) -> &X86_64LinuxModuleMemory<Memory, Tlb> {
        &self.memory
    }

    pub const fn deferred_reclamation_events(&self) -> usize {
        self.deferred_reclamation_events
    }

    pub fn live_module_count(&self) -> usize {
        self.live_generations
            .iter()
            .filter(|generation| **generation != 0)
            .count()
    }

    pub fn reclaim_quarantine(
        &mut self,
    ) -> Result<usize, X86_64LinuxBackendError<Memory::Error, PreSeal::Error, Executor::Error>>
    {
        self.memory
            .reclaim_quarantine()
            .map_err(X86_64LinuxBackendError::Memory)
    }

    fn mapping_slot(mapping: LinuxModuleMapping) -> usize {
        usize::from(mapping.slot())
    }

    fn prepared(&self, mapping: LinuxModuleMapping) -> bool {
        self.prepared_generations[Self::mapping_slot(mapping)] == mapping.generation()
    }

    fn clear_prepared(&mut self, mapping: LinuxModuleMapping) {
        let slot = Self::mapping_slot(mapping);
        self.prepared_generations[slot] = 0;
        self.prepared_state_offsets[slot] = usize::MAX;
    }

    fn valid_module_state(plan: &LinuxKoLoadPlan<'_>, offset: usize) -> bool {
        let Some(end) = offset.checked_add(core::mem::size_of::<u32>()) else {
            return false;
        };
        plan.regions().iter().any(|region| {
            let Some(region_end) = region.image_offset.checked_add(region.size) else {
                return false;
            };
            region.writable
                && !region.executable
                && offset >= region.image_offset
                && end <= region_end
        })
    }

    fn registry_matches(&self, module: &X86_64LinuxModule) -> bool {
        self.live_generations[Self::mapping_slot(module.mapping)] == module.mapping.generation()
    }

    fn name_is_live(&self, name: &[u8]) -> bool {
        self.live_generations
            .iter()
            .enumerate()
            .any(|(index, generation)| {
                *generation != 0
                    && usize::from(self.live_name_lengths[index]) == name.len()
                    && &self.live_names[index][..name.len()] == name
            })
    }

    fn clear_registry(&mut self, mapping: LinuxModuleMapping) {
        let slot = Self::mapping_slot(mapping);
        if self.live_generations[slot] == mapping.generation() {
            self.live_generations[slot] = 0;
            self.live_name_lengths[slot] = 0;
            self.live_names[slot].fill(0);
        }
    }

    fn valid_name(name: &[u8]) -> bool {
        !name.is_empty()
            && name.len() < LINUX_MODULE_NAME_BYTES
            && name
                .iter()
                .all(|byte| byte.is_ascii_graphic() && *byte != b'/')
    }

    fn note_reclamation_result(&mut self, result: Result<(), X86_64ModuleMapError<Memory::Error>>) {
        if result.is_err() {
            self.deferred_reclamation_events = self.deferred_reclamation_events.saturating_add(1);
        }
    }
}

impl<Memory, Tlb, PreSeal, Executor> LinuxKoBackend
    for X86_64LinuxNativeBackend<Memory, Tlb, PreSeal, Executor>
where
    Memory: ProcessFrameMemory,
    Tlb: LinuxModuleTlb,
    PreSeal: X86_64LinuxPreSeal<Memory, Tlb>,
    Executor: X86_64LinuxExecutor,
{
    type Error = X86_64LinuxBackendError<Memory::Error, PreSeal::Error, Executor::Error>;
    type Reservation = LinuxModuleMapping;
    type Module = X86_64LinuxModule;

    fn reserve_zeroed(
        &mut self,
        size: usize,
        alignment: usize,
    ) -> Result<(Self::Reservation, u64), Self::Error> {
        let mapping = self
            .memory
            .reserve_zeroed(size, alignment)
            .map_err(X86_64LinuxBackendError::Memory)?;
        match self.memory.mapping_base(mapping) {
            Ok(base) => Ok((mapping, base)),
            Err(error) => {
                let abort = self.memory.abort(mapping);
                self.note_reclamation_result(abort);
                Err(X86_64LinuxBackendError::Memory(error))
            }
        }
    }

    fn write(
        &mut self,
        reservation: Self::Reservation,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        self.memory
            .write(reservation, offset, bytes)
            .map_err(X86_64LinuxBackendError::Memory)
    }

    fn verify(
        &mut self,
        reservation: Self::Reservation,
        offset: usize,
        expected: &[u8],
    ) -> Result<bool, Self::Error> {
        self.memory
            .verify(reservation, offset, expected)
            .map_err(X86_64LinuxBackendError::Memory)
    }

    fn prepare_for_seal(
        &mut self,
        reservation: Self::Reservation,
        plan: &LinuxKoLoadPlan<'_>,
    ) -> Result<(), Self::Error> {
        let slot = Self::mapping_slot(reservation);
        let base = self
            .memory
            .mapping_base(reservation)
            .map_err(X86_64LinuxBackendError::Memory)?;
        let size = self
            .memory
            .mapping_size(reservation)
            .map_err(X86_64LinuxBackendError::Memory)?;
        if self.prepared_generations[slot] != 0
            || base != plan.image_virtual_address()
            || size != plan.image_size()
            || !self
                .memory
                .verify(reservation, 0, &[])
                .map_err(X86_64LinuxBackendError::Memory)?
        {
            return Err(X86_64LinuxBackendError::InvalidLifecycle);
        }
        let special_sections = plan
            .special_sections()
            .map_err(|_| X86_64LinuxBackendError::InvalidSpecialSectionInventory)?;
        let receipt = self
            .pre_seal
            .prepare(&mut self.memory, reservation, plan, &special_sections)
            .map_err(X86_64LinuxBackendError::PreSeal)?;
        if receipt.coverage() != LinuxKoSpecialSectionCoverage::from_sections(&special_sections) {
            return Err(X86_64LinuxBackendError::IncompleteSpecialSectionCoverage);
        }
        let state_offset = receipt
            .module_state_offset()
            .filter(|offset| Self::valid_module_state(plan, *offset))
            .ok_or(X86_64LinuxBackendError::InvalidModuleState)?;
        self.prepared_generations[slot] = reservation.generation();
        self.prepared_state_offsets[slot] = state_offset;
        Ok(())
    }

    fn seal(
        &mut self,
        reservation: Self::Reservation,
        regions: &[LinuxKoMemoryRegion],
    ) -> Result<(), Self::Error> {
        if !self.prepared(reservation) {
            return Err(X86_64LinuxBackendError::InvalidLifecycle);
        }
        self.memory
            .seal(reservation, regions)
            .map_err(X86_64LinuxBackendError::Memory)?;
        Ok(())
    }

    fn commit(
        &mut self,
        reservation: Self::Reservation,
        name: &[u8],
    ) -> Result<Self::Module, Self::Error> {
        if !Self::valid_name(name) {
            return Err(X86_64LinuxBackendError::InvalidModuleName);
        }
        if self.name_is_live(name) {
            return Err(X86_64LinuxBackendError::DuplicateModuleName);
        }
        if !self.prepared(reservation) {
            return Err(X86_64LinuxBackendError::InvalidLifecycle);
        }
        let base = self
            .memory
            .mapping_base(reservation)
            .map_err(X86_64LinuxBackendError::Memory)?;
        let size = self
            .memory
            .mapping_size(reservation)
            .map_err(X86_64LinuxBackendError::Memory)?;
        let slot = Self::mapping_slot(reservation);
        let module_state_offset = self.prepared_state_offsets[slot];
        if module_state_offset == usize::MAX {
            return Err(X86_64LinuxBackendError::InvalidModuleState);
        }
        self.memory
            .commit(reservation)
            .map_err(X86_64LinuxBackendError::Memory)?;

        let mut stored_name = [0; LINUX_MODULE_NAME_BYTES];
        stored_name[..name.len()].copy_from_slice(name);
        self.live_generations[slot] = reservation.generation();
        self.live_name_lengths[slot] = name.len() as u8;
        self.live_names[slot] = stored_name;
        self.clear_prepared(reservation);
        Ok(X86_64LinuxModule {
            mapping: reservation,
            name: stored_name,
            name_length: name.len() as u8,
            base,
            size,
            module_state_offset,
            lifecycle: X86_64LinuxModuleLifecycle::Committed,
            init_discard_complete: true,
        })
    }

    unsafe fn invoke_init(
        &mut self,
        module: &mut Self::Module,
        address: u64,
    ) -> Result<i32, Self::Error> {
        if !self.registry_matches(module)
            || module.lifecycle != X86_64LinuxModuleLifecycle::Committed
        {
            return Err(X86_64LinuxBackendError::InvalidLifecycle);
        }
        if !self
            .memory
            .executable_address(module.mapping, address)
            .map_err(X86_64LinuxBackendError::Memory)?
        {
            return Err(X86_64LinuxBackendError::InvalidLifecycleAddress);
        }
        let status = unsafe { self.executor.invoke_init(address) }
            .map_err(X86_64LinuxBackendError::Execution)?;
        module.lifecycle = if status == 0 {
            X86_64LinuxModuleLifecycle::Initialized
        } else {
            X86_64LinuxModuleLifecycle::InitializationFailed
        };
        Ok(status)
    }

    fn discard_init(&mut self, module: &mut Self::Module, offset: usize, size: usize) {
        if !self.registry_matches(module)
            || module.lifecycle != X86_64LinuxModuleLifecycle::Initialized
        {
            module.init_discard_complete = false;
            self.deferred_reclamation_events = self.deferred_reclamation_events.saturating_add(1);
            return;
        }
        let result = self.memory.discard(module.mapping, offset, size);
        module.init_discard_complete = result.is_ok();
        self.note_reclamation_result(result);
    }

    unsafe fn invoke_cleanup(
        &mut self,
        module: &mut Self::Module,
        address: u64,
    ) -> Result<(), Self::Error> {
        if !self.registry_matches(module)
            || module.lifecycle != X86_64LinuxModuleLifecycle::Initialized
        {
            return Err(X86_64LinuxBackendError::InvalidLifecycle);
        }
        if !self
            .memory
            .executable_address(module.mapping, address)
            .map_err(X86_64LinuxBackendError::Memory)?
        {
            return Err(X86_64LinuxBackendError::InvalidLifecycleAddress);
        }
        unsafe { self.executor.invoke_cleanup(address) }
            .map_err(X86_64LinuxBackendError::Execution)?;
        module.lifecycle = X86_64LinuxModuleLifecycle::Cleaned;
        Ok(())
    }

    fn abort(&mut self, reservation: Self::Reservation) {
        self.clear_prepared(reservation);
        let result = self.memory.abort(reservation);
        self.note_reclamation_result(result);
    }

    fn release(&mut self, module: Self::Module) {
        if !self.registry_matches(&module) {
            self.deferred_reclamation_events = self.deferred_reclamation_events.saturating_add(1);
            return;
        }
        self.clear_registry(module.mapping);
        let result = self.memory.release(module.mapping);
        self.note_reclamation_result(result);
    }
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use alloc::vec::Vec;

    use abyss::paging::{PAGE_SIZE, PhysicalAddress};

    use super::*;
    use crate::capability::{Authority, ModuleLoadControl};
    use crate::module::linux_ko::{LinuxExportClass, LinuxKernelSymbol, LinuxKernelSymbolResolver};
    use crate::module::linux_loader::{
        LinuxKoInstallError, LinuxKoSpecialSectionKind, install_linux_module,
    };

    const ENTRY_PRESENT: u64 = 1;
    const ENTRY_WRITABLE: u64 = 1 << 1;
    const MODULE_PML4_INDEX: usize = 511;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestMemoryError {
        InvalidFrame,
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
            let raw = frame.as_u64();
            if raw == 0 || raw % PAGE_SIZE as u64 != 0 {
                return Err(TestMemoryError::InvalidFrame);
            }
            usize::try_from(raw / PAGE_SIZE as u64 - 1).map_err(|_| TestMemoryError::InvalidFrame)
        }

        fn frame(&self, frame: PhysicalAddress) -> Result<&TestFrame, TestMemoryError> {
            self.frames
                .get(Self::index(frame)?)
                .filter(|frame| frame.live)
                .ok_or(TestMemoryError::InvalidFrame)
        }

        fn frame_mut(&mut self, frame: PhysicalAddress) -> Result<&mut TestFrame, TestMemoryError> {
            self.frames
                .get_mut(Self::index(frame)?)
                .filter(|frame| frame.live)
                .ok_or(TestMemoryError::InvalidFrame)
        }

        fn live_frames(&self) -> usize {
            self.frames.iter().filter(|frame| frame.live).count()
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
            let offset = index
                .checked_mul(8)
                .filter(|offset| *offset + 8 <= PAGE_SIZE)
                .ok_or(TestMemoryError::InvalidFrame)?;
            Ok(u64::from_le_bytes(
                self.frame(table)?.bytes[offset..offset + 8]
                    .try_into()
                    .map_err(|_| TestMemoryError::InvalidFrame)?,
            ))
        }

        fn write_entry(
            &mut self,
            table: PhysicalAddress,
            index: usize,
            value: u64,
        ) -> Result<(), Self::Error> {
            let offset = index
                .checked_mul(8)
                .filter(|offset| *offset + 8 <= PAGE_SIZE)
                .ok_or(TestMemoryError::InvalidFrame)?;
            self.frame_mut(table)?.bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            Ok(())
        }

        fn write_bytes(
            &mut self,
            frame: PhysicalAddress,
            offset: usize,
            bytes: &[u8],
        ) -> Result<(), Self::Error> {
            let end = offset
                .checked_add(bytes.len())
                .filter(|end| *end <= PAGE_SIZE)
                .ok_or(TestMemoryError::InvalidFrame)?;
            self.frame_mut(frame)?.bytes[offset..end].copy_from_slice(bytes);
            Ok(())
        }

        fn read_bytes(
            &self,
            frame: PhysicalAddress,
            offset: usize,
            destination: &mut [u8],
        ) -> Result<(), Self::Error> {
            let end = offset
                .checked_add(destination.len())
                .filter(|end| *end <= PAGE_SIZE)
                .ok_or(TestMemoryError::InvalidFrame)?;
            destination.copy_from_slice(&self.frame(frame)?.bytes[offset..end]);
            Ok(())
        }

        fn bytes_equal(
            &self,
            frame: PhysicalAddress,
            offset: usize,
            bytes: &[u8],
        ) -> Result<bool, Self::Error> {
            let end = offset
                .checked_add(bytes.len())
                .filter(|end| *end <= PAGE_SIZE)
                .ok_or(TestMemoryError::InvalidFrame)?;
            Ok(&self.frame(frame)?.bytes[offset..end] == bytes)
        }

        fn bytes_zero(
            &self,
            frame: PhysicalAddress,
            offset: usize,
            length: usize,
        ) -> Result<bool, Self::Error> {
            let end = offset
                .checked_add(length)
                .filter(|end| *end <= PAGE_SIZE)
                .ok_or(TestMemoryError::InvalidFrame)?;
            Ok(self.frame(frame)?.bytes[offset..end]
                .iter()
                .all(|byte| *byte == 0))
        }
    }

    #[derive(Default)]
    struct TestTlb {
        flushes: usize,
    }

    unsafe impl LinuxModuleTlb for TestTlb {
        fn invalidate_kernel_range(&mut self, _virtual_address: u64, _size: usize) {
            self.flushes += 1;
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestPreSealError {
        Rejected,
    }

    #[derive(Default)]
    struct TestPreSeal {
        calls: usize,
        reject: bool,
        incomplete: bool,
        missing_state: bool,
        state_in_text: bool,
    }

    unsafe impl X86_64LinuxPreSeal<TestMemory, TestTlb> for TestPreSeal {
        type Error = TestPreSealError;

        fn prepare(
            &mut self,
            _memory: &mut X86_64LinuxModuleMemory<TestMemory, TestTlb>,
            _reservation: LinuxModuleMapping,
            plan: &LinuxKoLoadPlan<'_>,
            special_sections: &[LinuxKoSpecialSection<'_>],
        ) -> Result<X86_64LinuxPreSealReceipt, Self::Error> {
            self.calls += 1;
            assert!(!plan.name().is_empty());
            assert!(plan.source_bytes().starts_with(b"\x7fELF"));
            assert!(
                special_sections
                    .iter()
                    .any(|section| section.name == b".gnu.linkonce.this_module")
            );
            if self.reject {
                Err(TestPreSealError::Rejected)
            } else {
                let coverage = if self.incomplete {
                    LinuxKoSpecialSectionCoverage::empty()
                } else {
                    LinuxKoSpecialSectionCoverage::from_sections(special_sections)
                };
                let state = special_sections
                    .iter()
                    .find(|section| section.kind == LinuxKoSpecialSectionKind::ModuleIdentity)
                    .map(|section| {
                        if self.state_in_text {
                            plan.regions()
                                .iter()
                                .find(|region| region.executable)
                                .unwrap()
                                .image_offset
                        } else {
                            section.image_offset
                        }
                    })
                    .filter(|_| !self.missing_state);
                Ok(X86_64LinuxPreSealReceipt::new(coverage, state))
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestExecutionError {
        Unavailable,
    }

    #[derive(Default)]
    struct TestExecutor {
        init_calls: Vec<u64>,
        cleanup_calls: Vec<u64>,
        init_status: i32,
        cleanup_failures: usize,
    }

    unsafe impl X86_64LinuxExecutor for TestExecutor {
        type Error = TestExecutionError;

        unsafe fn invoke_init(&mut self, address: u64) -> Result<i32, Self::Error> {
            self.init_calls.push(address);
            Ok(self.init_status)
        }

        unsafe fn invoke_cleanup(&mut self, address: u64) -> Result<(), Self::Error> {
            if self.cleanup_failures != 0 {
                self.cleanup_failures -= 1;
                return Err(TestExecutionError::Unavailable);
            }
            self.cleanup_calls.push(address);
            Ok(())
        }
    }

    struct Resolver;

    impl LinuxKernelSymbolResolver for Resolver {
        fn resolve<'a>(&'a self, name: &[u8]) -> Option<LinuxKernelSymbol<'a>> {
            let (address, crc) = match name {
                b"module_layout" => (0xffff_ffff_8010_0000, 0x1122_3344),
                b"external" => (0xffff_ffff_8020_0000, 0xaabb_ccdd),
                _ => return None,
            };
            Some(LinuxKernelSymbol {
                address,
                crc,
                class: LinuxExportClass::Regular,
                namespace: None,
            })
        }
    }

    type Backend = X86_64LinuxNativeBackend<TestMemory, TestTlb, TestPreSeal, TestExecutor>;

    fn backend() -> Backend {
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
        let memory =
            unsafe { X86_64LinuxModuleMemory::new(memory, TestTlb::default(), root, &right) };
        X86_64LinuxNativeBackend::new(memory, TestPreSeal::default(), TestExecutor::default())
    }

    #[test]
    fn full_native_transaction_preserves_name_lifecycle_and_reclamation() {
        let bytes = crate::module::linux_ko::tests::fixture();
        let mut backend = backend();
        let live =
            unsafe { install_linux_module(&bytes, b"6.12", &Resolver, &mut backend) }.unwrap();
        assert_eq!(live.handle().name(), b"smoke");
        assert!(live.handle().module_state_offset() < live.handle().size());
        assert_eq!(
            live.handle().lifecycle(),
            X86_64LinuxModuleLifecycle::Initialized
        );
        assert!(live.handle().init_discard_complete());
        assert_eq!(backend.pre_seal.calls, 1);
        assert_eq!(backend.executor.init_calls.len(), 1);
        assert_eq!(backend.live_module_count(), 1);

        assert!(unsafe { live.unload(&mut backend) }.is_ok());
        assert_eq!(backend.executor.cleanup_calls.len(), 1);
        assert_eq!(backend.live_module_count(), 0);
        assert_eq!(backend.memory_owner().memory().live_frames(), 3);
        assert_eq!(backend.deferred_reclamation_events(), 0);
    }

    #[test]
    fn duplicate_live_name_aborts_only_the_second_reservation() {
        let bytes = crate::module::linux_ko::tests::fixture();
        let mut backend = backend();
        let first =
            unsafe { install_linux_module(&bytes, b"6.12", &Resolver, &mut backend) }.unwrap();
        let second = unsafe { install_linux_module(&bytes, b"6.12", &Resolver, &mut backend) };
        assert!(matches!(
            second,
            Err(LinuxKoInstallError::Backend(
                X86_64LinuxBackendError::DuplicateModuleName
            ))
        ));
        assert_eq!(backend.live_module_count(), 1);
        assert_eq!(backend.executor.init_calls.len(), 1);
        assert_eq!(backend.deferred_reclamation_events(), 0);
        assert!(unsafe { first.unload(&mut backend) }.is_ok());
    }

    #[test]
    fn cleanup_dispatch_failure_retains_registry_and_mapping_for_retry() {
        let bytes = crate::module::linux_ko::tests::fixture();
        let mut backend = backend();
        backend.executor.cleanup_failures = 1;
        let live =
            unsafe { install_linux_module(&bytes, b"6.12", &Resolver, &mut backend) }.unwrap();
        let live = match unsafe { live.unload(&mut backend) } {
            Err((live, X86_64LinuxBackendError::Execution(TestExecutionError::Unavailable))) => {
                live
            }
            _ => panic!("cleanup failure did not preserve native ownership"),
        };
        assert_eq!(backend.live_module_count(), 1);
        assert!(unsafe { live.unload(&mut backend) }.is_ok());
        assert_eq!(backend.live_module_count(), 0);
    }

    #[test]
    fn failed_init_releases_registry_and_committed_mapping() {
        let bytes = crate::module::linux_ko::tests::fixture();
        let mut backend = backend();
        backend.executor.init_status = -19;
        let result = unsafe { install_linux_module(&bytes, b"6.12", &Resolver, &mut backend) };
        assert!(matches!(result, Err(LinuxKoInstallError::InitFailed(-19))));
        assert_eq!(backend.live_module_count(), 0);
        assert_eq!(backend.memory_owner().memory().live_frames(), 3);
    }

    #[test]
    fn rejected_pre_seal_processing_never_publishes_or_registers_module() {
        let bytes = crate::module::linux_ko::tests::fixture();
        let mut backend = backend();
        backend.pre_seal.reject = true;
        let result = unsafe { install_linux_module(&bytes, b"6.12", &Resolver, &mut backend) };
        assert!(matches!(
            result,
            Err(LinuxKoInstallError::Backend(
                X86_64LinuxBackendError::PreSeal(TestPreSealError::Rejected)
            ))
        ));
        assert_eq!(backend.live_module_count(), 0);
        assert!(backend.executor.init_calls.is_empty());
        assert_eq!(backend.memory_owner().memory().live_frames(), 3);
    }

    #[test]
    fn incomplete_special_section_coverage_never_reaches_seal_or_execution() {
        let bytes = crate::module::linux_ko::tests::fixture();
        let mut backend = backend();
        backend.pre_seal.incomplete = true;
        let result = unsafe { install_linux_module(&bytes, b"6.12", &Resolver, &mut backend) };
        assert!(matches!(
            result,
            Err(LinuxKoInstallError::Backend(
                X86_64LinuxBackendError::IncompleteSpecialSectionCoverage
            ))
        ));
        assert_eq!(backend.pre_seal.calls, 1);
        assert_eq!(backend.live_module_count(), 0);
        assert!(backend.executor.init_calls.is_empty());
        assert_eq!(backend.memory_owner().memory().live_frames(), 3);
    }

    #[test]
    fn missing_or_nonwritable_module_state_receipts_never_publish() {
        let bytes = crate::module::linux_ko::tests::fixture();
        for state_in_text in [false, true] {
            let mut backend = backend();
            backend.pre_seal.missing_state = !state_in_text;
            backend.pre_seal.state_in_text = state_in_text;
            let result = unsafe { install_linux_module(&bytes, b"6.12", &Resolver, &mut backend) };
            assert!(matches!(
                result,
                Err(LinuxKoInstallError::Backend(
                    X86_64LinuxBackendError::InvalidModuleState
                ))
            ));
            assert_eq!(backend.live_module_count(), 0);
            assert!(backend.executor.init_calls.is_empty());
            assert_eq!(backend.memory_owner().memory().live_frames(), 3);
        }
    }

    #[test]
    fn control_characters_in_module_identity_fail_before_registry_commit() {
        let mut bytes = crate::module::linux_ko::tests::fixture();
        let name = bytes
            .windows(b"name=smoke".len())
            .position(|window| window == b"name=smoke")
            .unwrap();
        bytes[name + b"name=".len()] = b'\n';
        let mut backend = backend();
        let result = unsafe { install_linux_module(&bytes, b"6.12", &Resolver, &mut backend) };
        assert!(matches!(
            result,
            Err(LinuxKoInstallError::Backend(
                X86_64LinuxBackendError::InvalidModuleName
            ))
        ));
        assert_eq!(backend.live_module_count(), 0);
        assert!(backend.executor.init_calls.is_empty());
        assert_eq!(backend.memory_owner().memory().live_frames(), 3);
    }
}
