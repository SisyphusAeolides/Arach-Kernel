//! Native x86-64 page ownership for Linux module images.
//!
//! Arach's linked kernel occupies the lower 1 GiB of the final PML4 entry.
//! This mapper owns the adjacent final 1 GiB PML3 slot, keeping every module
//! within signed 32-bit PC-relative reach of linked kernel text. Reservations
//! allocate zeroed physical frames and page-table leaves but remain non-present
//! until one atomic W^X seal operation publishes them.

use alloc::vec::Vec;
use core::marker::PhantomData;
use core::sync::atomic::{Ordering, compiler_fence};

use abyss::paging::{PAGE_SIZE, PhysicalAddress};

use crate::capability::{Capability, ModuleLoadControl};
use crate::module::linux_loader::LinuxKoMemoryRegion;
use crate::process::x86_64::ProcessFrameMemory;

pub const LINUX_MODULE_WINDOW_BASE: u64 = 0xffff_ffff_c000_0000;
pub const LINUX_MODULE_WINDOW_SIZE: usize = 1024 * 1024 * 1024;
pub const LINUX_MODULE_EXTENT_SIZE: usize = 2 * 1024 * 1024;
pub const MAXIMUM_LIVE_LINUX_MODULES: usize = 32;

const PAGE_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const ENTRY_PRESENT: u64 = 1 << 0;
const ENTRY_WRITABLE: u64 = 1 << 1;
const ENTRY_USER: u64 = 1 << 2;
const ENTRY_HUGE: u64 = 1 << 7;
const ENTRY_NO_EXECUTE: u64 = 1 << 63;
const MODULE_PML4_INDEX: usize = 511;
const MODULE_PML3_INDEX: usize = 511;
const PAGES_PER_EXTENT: usize = LINUX_MODULE_EXTENT_SIZE / PAGE_SIZE;
const WINDOW_EXTENTS: usize = LINUX_MODULE_WINDOW_SIZE / LINUX_MODULE_EXTENT_SIZE;

/// Architecture-owned TLB synchronization.
///
/// Implementations must invalidate the supplied kernel range on every CPU
/// that can execute with the shared Arach kernel hierarchy. The call returns
/// only after stale translations cannot be observed.
///
/// # Safety
///
/// A no-op or local-CPU-only implementation is unsound once a virtual extent
/// can be reused. Implementors must provide synchronous, system-wide
/// invalidation for the shared kernel hierarchy.
pub unsafe trait LinuxModuleTlb {
    fn invalidate_kernel_range(&mut self, virtual_address: u64, size: usize);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxModuleMapping {
    slot: u8,
    generation: u32,
}

impl LinuxModuleMapping {
    pub const fn slot(self) -> u8 {
        self.slot
    }

    pub const fn generation(self) -> u32 {
        self.generation
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum X86_64ModuleMapError<MemoryError> {
    Memory(MemoryError),
    InvalidKernelRoot,
    ModuleWindowConflict,
    InvalidRange,
    InvalidAlignment,
    InvalidHandle,
    InvalidState,
    MappingConflict,
    UnsupportedPermissions,
    OutOfFrames,
    OutOfVirtualSpace,
    MetadataAllocationFailed,
    FrameReleaseDebt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SlotPhase {
    Free,
    Staging,
    Sealed,
    Committed,
    Quarantined,
}

struct ModuleSlot {
    phase: SlotPhase,
    generation: u32,
    start_extent: usize,
    extent_count: usize,
    image_size: usize,
    data_frames: Vec<Option<PhysicalAddress>>,
    leaf_tables: Vec<Option<PhysicalAddress>>,
    detached: bool,
}

impl ModuleSlot {
    const EMPTY: Self = Self {
        phase: SlotPhase::Free,
        generation: 0,
        start_extent: 0,
        extent_count: 0,
        image_size: 0,
        data_frames: Vec::new(),
        leaf_tables: Vec::new(),
        detached: true,
    };

    fn base(&self) -> u64 {
        LINUX_MODULE_WINDOW_BASE + (self.start_extent * LINUX_MODULE_EXTENT_SIZE) as u64
    }

    fn overlaps(&self, start: usize, count: usize) -> bool {
        self.phase != SlotPhase::Free
            && start < self.start_extent + self.extent_count
            && self.start_extent < start + count
    }
}

/// Owns the page-table and physical-frame state for native Linux modules.
///
/// The active kernel root must retain PML4[511] as a normal page-table link,
/// with PML3[511] unused. The mapper installs one owned PML2 page there and
/// divides its 1 GiB range into first-fit 2 MiB extents. Each reservation owns
/// complete PML1 tables, so abort and unload never share leaf-table ownership.
pub struct X86_64LinuxModuleMemory<Memory, Tlb>
where
    Memory: ProcessFrameMemory,
    Tlb: LinuxModuleTlb,
{
    memory: Memory,
    tlb: Tlb,
    kernel_root: PhysicalAddress,
    module_pml3: Option<PhysicalAddress>,
    module_pml2: Option<PhysicalAddress>,
    slots: [ModuleSlot; MAXIMUM_LIVE_LINUX_MODULES],
    orphaned_frames: Vec<PhysicalAddress>,
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl<Memory, Tlb> X86_64LinuxModuleMemory<Memory, Tlb>
where
    Memory: ProcessFrameMemory,
    Tlb: LinuxModuleTlb,
{
    /// Creates a serialized module-memory owner for the active kernel root.
    ///
    /// # Safety
    ///
    /// `kernel_root` must be the active Arach hierarchy and no other object may
    /// modify PML3[511] for its lifetime. Callers must serialize all methods
    /// against page-table replacement and cross-CPU module execution.
    pub const unsafe fn new(
        memory: Memory,
        tlb: Tlb,
        kernel_root: PhysicalAddress,
        _authority: &Capability<'_, ModuleLoadControl>,
    ) -> Self {
        Self {
            memory,
            tlb,
            kernel_root,
            module_pml3: None,
            module_pml2: None,
            slots: [const { ModuleSlot::EMPTY }; MAXIMUM_LIVE_LINUX_MODULES],
            orphaned_frames: Vec::new(),
            _not_send_or_sync: PhantomData,
        }
    }

    pub const fn memory(&self) -> &Memory {
        &self.memory
    }

    pub const fn orphaned_frame_count(&self) -> usize {
        self.orphaned_frames.len()
    }

    pub fn mapping_base(
        &self,
        mapping: LinuxModuleMapping,
    ) -> Result<u64, X86_64ModuleMapError<Memory::Error>> {
        Ok(self.slot(mapping)?.base())
    }

    pub fn mapping_size(
        &self,
        mapping: LinuxModuleMapping,
    ) -> Result<usize, X86_64ModuleMapError<Memory::Error>> {
        Ok(self.slot(mapping)?.image_size)
    }

    /// Transfers a sealed reservation into the live module lifecycle.
    pub fn commit(
        &mut self,
        mapping: LinuxModuleMapping,
    ) -> Result<(), X86_64ModuleMapError<Memory::Error>> {
        let slot_index = self.sealed_slot(mapping)?;
        self.slots[slot_index].phase = SlotPhase::Committed;
        Ok(())
    }

    /// Proves that `address` resolves to this module's present RX mapping.
    pub fn executable_address(
        &self,
        mapping: LinuxModuleMapping,
        address: u64,
    ) -> Result<bool, X86_64ModuleMapError<Memory::Error>> {
        let slot_index = self.committed_slot(mapping)?;
        let slot = &self.slots[slot_index];
        let Some(offset) = address.checked_sub(slot.base()) else {
            return Ok(false);
        };
        let Ok(offset) = usize::try_from(offset) else {
            return Ok(false);
        };
        if offset >= slot.image_size {
            return Ok(false);
        }
        let page = offset / PAGE_SIZE;
        let Some(expected_frame) = slot.data_frames.get(page).copied().flatten() else {
            return Ok(false);
        };
        let table =
            slot.leaf_tables[page / PAGES_PER_EXTENT].ok_or(X86_64ModuleMapError::InvalidState)?;
        let entry = self
            .memory
            .read_entry(table, page % PAGES_PER_EXTENT)
            .map_err(X86_64ModuleMapError::Memory)?;
        Ok(entry & ENTRY_PRESENT != 0
            && entry & (ENTRY_WRITABLE | ENTRY_USER | ENTRY_NO_EXECUTE) == 0
            && entry & PAGE_ADDRESS_MASK == expected_frame.as_u64())
    }

    /// Allocates zeroed data and leaf-table frames without publishing a single
    /// present image PTE.
    pub fn reserve_zeroed(
        &mut self,
        size: usize,
        alignment: usize,
    ) -> Result<LinuxModuleMapping, X86_64ModuleMapError<Memory::Error>> {
        if size == 0 || size > LINUX_MODULE_WINDOW_SIZE || size % PAGE_SIZE != 0 {
            return Err(X86_64ModuleMapError::InvalidRange);
        }
        if alignment < PAGE_SIZE
            || !alignment.is_power_of_two()
            || alignment > LINUX_MODULE_WINDOW_SIZE
        {
            return Err(X86_64ModuleMapError::InvalidAlignment);
        }
        let extent_count = size.div_ceil(LINUX_MODULE_EXTENT_SIZE);
        let page_count = size / PAGE_SIZE;
        self.orphaned_frames
            .try_reserve(
                page_count
                    .checked_add(extent_count)
                    .and_then(|count| count.checked_add(1))
                    .ok_or(X86_64ModuleMapError::MetadataAllocationFailed)?,
            )
            .map_err(|_| X86_64ModuleMapError::MetadataAllocationFailed)?;
        self.ensure_module_hierarchy()?;
        let slot_index = self
            .slots
            .iter()
            .position(|slot| slot.phase == SlotPhase::Free)
            .ok_or(X86_64ModuleMapError::OutOfVirtualSpace)?;
        let start_extent = self
            .find_extent(extent_count, alignment)
            .ok_or(X86_64ModuleMapError::OutOfVirtualSpace)?;
        let module_pml2 = self.module_pml2.ok_or(X86_64ModuleMapError::InvalidState)?;
        for index in start_extent..start_extent + extent_count {
            let entry = self
                .memory
                .read_entry(module_pml2, index)
                .map_err(X86_64ModuleMapError::Memory)?;
            if entry != 0 {
                return Err(X86_64ModuleMapError::MappingConflict);
            }
        }

        let mut data_frames = Vec::new();
        let mut leaf_tables = Vec::new();
        data_frames
            .try_reserve_exact(page_count)
            .map_err(|_| X86_64ModuleMapError::MetadataAllocationFailed)?;
        leaf_tables
            .try_reserve_exact(extent_count)
            .map_err(|_| X86_64ModuleMapError::MetadataAllocationFailed)?;
        for _ in 0..page_count {
            match self.memory.allocate_zeroed() {
                Ok(frame) if valid_frame(frame) => data_frames.push(Some(frame)),
                Ok(frame) => {
                    self.retain_orphan(frame);
                    self.release_temporary(&mut data_frames);
                    return Err(X86_64ModuleMapError::OutOfFrames);
                }
                Err(error) => {
                    self.release_temporary(&mut data_frames);
                    return Err(X86_64ModuleMapError::Memory(error));
                }
            }
        }
        for _ in 0..extent_count {
            match self.memory.allocate_zeroed() {
                Ok(frame) if valid_frame(frame) => leaf_tables.push(Some(frame)),
                Ok(frame) => {
                    self.retain_orphan(frame);
                    self.release_temporary(&mut data_frames);
                    self.release_temporary(&mut leaf_tables);
                    return Err(X86_64ModuleMapError::OutOfFrames);
                }
                Err(error) => {
                    self.release_temporary(&mut data_frames);
                    self.release_temporary(&mut leaf_tables);
                    return Err(X86_64ModuleMapError::Memory(error));
                }
            }
        }

        let mut attached = 0;
        for (offset, table) in leaf_tables.iter().enumerate() {
            let table = table.ok_or(X86_64ModuleMapError::InvalidState)?;
            if let Err(error) = self.memory.write_entry(
                module_pml2,
                start_extent + offset,
                table.as_u64() | ENTRY_PRESENT | ENTRY_WRITABLE,
            ) {
                let detached = self.detach_temporary_tables(module_pml2, start_extent, attached);
                compiler_fence(Ordering::SeqCst);
                self.tlb.invalidate_kernel_range(
                    LINUX_MODULE_WINDOW_BASE + (start_extent * LINUX_MODULE_EXTENT_SIZE) as u64,
                    extent_count * LINUX_MODULE_EXTENT_SIZE,
                );
                if !detached {
                    self.slots[slot_index] = ModuleSlot {
                        phase: SlotPhase::Quarantined,
                        generation: next_generation(self.slots[slot_index].generation),
                        start_extent,
                        extent_count,
                        image_size: size,
                        data_frames,
                        leaf_tables,
                        detached: false,
                    };
                } else {
                    self.release_temporary(&mut data_frames);
                    self.release_temporary(&mut leaf_tables);
                }
                return Err(X86_64ModuleMapError::Memory(error));
            }
            attached += 1;
        }

        let generation = next_generation(self.slots[slot_index].generation);
        self.slots[slot_index] = ModuleSlot {
            phase: SlotPhase::Staging,
            generation,
            start_extent,
            extent_count,
            image_size: size,
            data_frames,
            leaf_tables,
            detached: false,
        };
        Ok(LinuxModuleMapping {
            slot: slot_index as u8,
            generation,
        })
    }

    pub fn write(
        &mut self,
        mapping: LinuxModuleMapping,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), X86_64ModuleMapError<Memory::Error>> {
        let slot_index = self.staging_slot(mapping)?;
        if offset
            .checked_add(bytes.len())
            .is_none_or(|end| end > self.slots[slot_index].image_size)
        {
            return Err(X86_64ModuleMapError::InvalidRange);
        }
        let mut copied = 0;
        while copied < bytes.len() {
            let absolute = offset + copied;
            let page = absolute / PAGE_SIZE;
            let within = absolute % PAGE_SIZE;
            let length = (PAGE_SIZE - within).min(bytes.len() - copied);
            let frame = self.slots[slot_index]
                .data_frames
                .get(page)
                .copied()
                .flatten()
                .ok_or(X86_64ModuleMapError::InvalidState)?;
            self.memory
                .write_bytes(frame, within, &bytes[copied..copied + length])
                .map_err(X86_64ModuleMapError::Memory)?;
            copied += length;
        }
        Ok(())
    }

    pub fn verify(
        &self,
        mapping: LinuxModuleMapping,
        offset: usize,
        expected: &[u8],
    ) -> Result<bool, X86_64ModuleMapError<Memory::Error>> {
        let slot_index = self.staging_slot(mapping)?;
        if offset
            .checked_add(expected.len())
            .is_none_or(|end| end > self.slots[slot_index].image_size)
        {
            return Err(X86_64ModuleMapError::InvalidRange);
        }
        let mut compared = 0;
        while compared < expected.len() {
            let absolute = offset + compared;
            let page = absolute / PAGE_SIZE;
            let within = absolute % PAGE_SIZE;
            let length = (PAGE_SIZE - within).min(expected.len() - compared);
            let frame = self.slots[slot_index]
                .data_frames
                .get(page)
                .copied()
                .flatten()
                .ok_or(X86_64ModuleMapError::InvalidState)?;
            if !self
                .memory
                .bytes_equal(frame, within, &expected[compared..compared + length])
                .map_err(X86_64ModuleMapError::Memory)?
            {
                return Ok(false);
            }
            compared += length;
        }
        Ok(true)
    }

    /// Publishes every leaf with its final permissions after validating that
    /// the regions exactly and contiguously cover the image.
    pub fn seal(
        &mut self,
        mapping: LinuxModuleMapping,
        regions: &[LinuxKoMemoryRegion],
    ) -> Result<(), X86_64ModuleMapError<Memory::Error>> {
        let slot_index = self.staging_slot(mapping)?;
        validate_regions(regions, self.slots[slot_index].image_size)?;
        let page_count = self.slots[slot_index].data_frames.len();
        let base = self.slots[slot_index].base();
        let mut published = 0;
        let mut region_index = 0;
        for page in 0..page_count {
            let offset = page * PAGE_SIZE;
            while offset >= regions[region_index].image_offset + regions[region_index].size {
                region_index += 1;
            }
            let region = regions[region_index];
            let frame = self.slots[slot_index].data_frames[page]
                .ok_or(X86_64ModuleMapError::InvalidState)?;
            let table = self.slots[slot_index].leaf_tables[page / PAGES_PER_EXTENT]
                .ok_or(X86_64ModuleMapError::InvalidState)?;
            let mut entry = frame.as_u64() | ENTRY_PRESENT;
            if region.writable {
                entry |= ENTRY_WRITABLE;
            }
            if !region.executable {
                entry |= ENTRY_NO_EXECUTE;
            }
            if let Err(error) = self
                .memory
                .write_entry(table, page % PAGES_PER_EXTENT, entry)
            {
                let cleared = self.clear_leaf_prefix(slot_index, published);
                compiler_fence(Ordering::SeqCst);
                self.tlb
                    .invalidate_kernel_range(base, self.slots[slot_index].image_size);
                if !cleared {
                    self.slots[slot_index].phase = SlotPhase::Quarantined;
                }
                return Err(X86_64ModuleMapError::Memory(error));
            }
            published += 1;
        }
        compiler_fence(Ordering::SeqCst);
        self.tlb
            .invalidate_kernel_range(base, self.slots[slot_index].image_size);
        self.slots[slot_index].phase = SlotPhase::Sealed;
        Ok(())
    }

    /// Revokes and reclaims a page-aligned subrange such as `.init.*`.
    pub fn discard(
        &mut self,
        mapping: LinuxModuleMapping,
        offset: usize,
        size: usize,
    ) -> Result<(), X86_64ModuleMapError<Memory::Error>> {
        let slot_index = self.committed_slot(mapping)?;
        if size == 0
            || offset % PAGE_SIZE != 0
            || size % PAGE_SIZE != 0
            || offset
                .checked_add(size)
                .is_none_or(|end| end > self.slots[slot_index].image_size)
        {
            return Err(X86_64ModuleMapError::InvalidRange);
        }
        let first = offset / PAGE_SIZE;
        let count = size / PAGE_SIZE;
        for page in first..first + count {
            let table = self.slots[slot_index].leaf_tables[page / PAGES_PER_EXTENT]
                .ok_or(X86_64ModuleMapError::InvalidState)?;
            if let Err(error) = self.memory.write_entry(table, page % PAGES_PER_EXTENT, 0) {
                compiler_fence(Ordering::SeqCst);
                self.tlb
                    .invalidate_kernel_range(self.slots[slot_index].base() + offset as u64, size);
                return Err(X86_64ModuleMapError::Memory(error));
            }
        }
        compiler_fence(Ordering::SeqCst);
        self.tlb
            .invalidate_kernel_range(self.slots[slot_index].base() + offset as u64, size);
        let mut debt = false;
        for page in first..first + count {
            if let Some(frame) = self.slots[slot_index].data_frames[page] {
                if self.memory.release(frame).is_ok() {
                    self.slots[slot_index].data_frames[page] = None;
                } else {
                    debt = true;
                }
            }
        }
        if debt {
            Err(X86_64ModuleMapError::FrameReleaseDebt)
        } else {
            Ok(())
        }
    }

    /// Revokes an uncommitted staging or sealed reservation.
    pub fn abort(
        &mut self,
        mapping: LinuxModuleMapping,
    ) -> Result<(), X86_64ModuleMapError<Memory::Error>> {
        let slot_index = self.slot_index(mapping)?;
        if !matches!(
            self.slots[slot_index].phase,
            SlotPhase::Staging | SlotPhase::Sealed
        ) {
            return Err(X86_64ModuleMapError::InvalidState);
        }
        self.revoke_mapping(slot_index)
    }

    /// Revokes a committed module and reclaims every exclusively owned frame.
    pub fn release(
        &mut self,
        mapping: LinuxModuleMapping,
    ) -> Result<(), X86_64ModuleMapError<Memory::Error>> {
        let slot_index = self.committed_slot(mapping)?;
        self.revoke_mapping(slot_index)
    }

    /// Detaches a complete image before reclaiming physical ownership. Any
    /// incomplete revocation quarantines the slot and its virtual extent.
    fn revoke_mapping(
        &mut self,
        slot_index: usize,
    ) -> Result<(), X86_64ModuleMapError<Memory::Error>> {
        let base = self.slots[slot_index].base();
        let leaves_cleared = self.clear_all_leaves(slot_index);
        let tables_detached = self.detach_slot_tables(slot_index);
        compiler_fence(Ordering::SeqCst);
        self.tlb
            .invalidate_kernel_range(base, self.slots[slot_index].image_size);
        if !leaves_cleared || !tables_detached {
            self.slots[slot_index].phase = SlotPhase::Quarantined;
            return Err(X86_64ModuleMapError::InvalidState);
        }
        if !self.release_slot_frames(slot_index) {
            self.slots[slot_index].phase = SlotPhase::Quarantined;
            return Err(X86_64ModuleMapError::FrameReleaseDebt);
        }
        self.free_slot(slot_index);
        Ok(())
    }

    /// Retries address revocation and physical reclamation for quarantined
    /// slots and temporary frames. Extents remain unavailable until this
    /// method proves all corresponding ownership debt is gone.
    pub fn reclaim_quarantine(&mut self) -> Result<usize, X86_64ModuleMapError<Memory::Error>> {
        let mut reclaimed = 0;
        let mut index = 0;
        while index < self.orphaned_frames.len() {
            if self.memory.release(self.orphaned_frames[index]).is_ok() {
                self.orphaned_frames.swap_remove(index);
                reclaimed += 1;
            } else {
                index += 1;
            }
        }
        for slot_index in 0..self.slots.len() {
            if self.slots[slot_index].phase != SlotPhase::Quarantined {
                continue;
            }
            let base = self.slots[slot_index].base();
            if !self.slots[slot_index].detached {
                let leaves_cleared = self.clear_all_leaves(slot_index);
                let tables_detached = self.detach_slot_tables(slot_index);
                compiler_fence(Ordering::SeqCst);
                self.tlb
                    .invalidate_kernel_range(base, self.slots[slot_index].image_size);
                if !leaves_cleared || !tables_detached {
                    continue;
                }
            }
            if self.release_slot_frames(slot_index) {
                self.free_slot(slot_index);
                reclaimed += 1;
            }
        }
        if self.orphaned_frames.is_empty()
            && self
                .slots
                .iter()
                .all(|slot| slot.phase != SlotPhase::Quarantined)
        {
            Ok(reclaimed)
        } else {
            Err(X86_64ModuleMapError::FrameReleaseDebt)
        }
    }

    fn ensure_module_hierarchy(&mut self) -> Result<(), X86_64ModuleMapError<Memory::Error>> {
        if !valid_frame(self.kernel_root) {
            return Err(X86_64ModuleMapError::InvalidKernelRoot);
        }
        let pml4_entry = self
            .memory
            .read_entry(self.kernel_root, MODULE_PML4_INDEX)
            .map_err(X86_64ModuleMapError::Memory)?;
        if pml4_entry & ENTRY_PRESENT == 0
            || pml4_entry & ENTRY_WRITABLE == 0
            || pml4_entry & (ENTRY_USER | ENTRY_HUGE | ENTRY_NO_EXECUTE) != 0
            || pml4_entry & PAGE_ADDRESS_MASK == 0
        {
            return Err(X86_64ModuleMapError::InvalidKernelRoot);
        }
        let pml3 = PhysicalAddress::new(pml4_entry & PAGE_ADDRESS_MASK);
        if let Some(expected) = self.module_pml3 {
            if expected != pml3 {
                return Err(X86_64ModuleMapError::ModuleWindowConflict);
            }
        }
        let current = self
            .memory
            .read_entry(pml3, MODULE_PML3_INDEX)
            .map_err(X86_64ModuleMapError::Memory)?;
        if let Some(pml2) = self.module_pml2 {
            if current & PAGE_ADDRESS_MASK != pml2.as_u64()
                || current & ENTRY_PRESENT == 0
                || current & ENTRY_WRITABLE == 0
                || current & (ENTRY_USER | ENTRY_HUGE | ENTRY_NO_EXECUTE) != 0
            {
                return Err(X86_64ModuleMapError::ModuleWindowConflict);
            }
            return Ok(());
        }
        if current != 0 {
            return Err(X86_64ModuleMapError::ModuleWindowConflict);
        }
        let pml2 = self
            .memory
            .allocate_zeroed()
            .map_err(X86_64ModuleMapError::Memory)?;
        if !valid_frame(pml2) {
            self.retain_orphan(pml2);
            return Err(X86_64ModuleMapError::OutOfFrames);
        }
        if let Err(error) = self.memory.write_entry(
            pml3,
            MODULE_PML3_INDEX,
            pml2.as_u64() | ENTRY_PRESENT | ENTRY_WRITABLE,
        ) {
            self.retain_or_release(pml2);
            return Err(X86_64ModuleMapError::Memory(error));
        }
        compiler_fence(Ordering::SeqCst);
        self.tlb
            .invalidate_kernel_range(LINUX_MODULE_WINDOW_BASE, LINUX_MODULE_WINDOW_SIZE);
        self.module_pml3 = Some(pml3);
        self.module_pml2 = Some(pml2);
        Ok(())
    }

    fn find_extent(&self, count: usize, alignment: usize) -> Option<usize> {
        if count == 0 || count > WINDOW_EXTENTS {
            return None;
        }
        (0..=WINDOW_EXTENTS - count).find(|start| {
            let base = LINUX_MODULE_WINDOW_BASE + (*start * LINUX_MODULE_EXTENT_SIZE) as u64;
            base % alignment as u64 == 0
                && self.slots.iter().all(|slot| !slot.overlaps(*start, count))
        })
    }

    fn slot_index(
        &self,
        mapping: LinuxModuleMapping,
    ) -> Result<usize, X86_64ModuleMapError<Memory::Error>> {
        let index = usize::from(mapping.slot);
        self.slots
            .get(index)
            .filter(|slot| slot.phase != SlotPhase::Free && slot.generation == mapping.generation)
            .map(|_| index)
            .ok_or(X86_64ModuleMapError::InvalidHandle)
    }

    fn slot(
        &self,
        mapping: LinuxModuleMapping,
    ) -> Result<&ModuleSlot, X86_64ModuleMapError<Memory::Error>> {
        let index = self.slot_index(mapping)?;
        Ok(&self.slots[index])
    }

    fn staging_slot(
        &self,
        mapping: LinuxModuleMapping,
    ) -> Result<usize, X86_64ModuleMapError<Memory::Error>> {
        let index = self.slot_index(mapping)?;
        if self.slots[index].phase != SlotPhase::Staging {
            return Err(X86_64ModuleMapError::InvalidState);
        }
        Ok(index)
    }

    fn sealed_slot(
        &self,
        mapping: LinuxModuleMapping,
    ) -> Result<usize, X86_64ModuleMapError<Memory::Error>> {
        let index = self.slot_index(mapping)?;
        if self.slots[index].phase != SlotPhase::Sealed {
            return Err(X86_64ModuleMapError::InvalidState);
        }
        Ok(index)
    }

    fn committed_slot(
        &self,
        mapping: LinuxModuleMapping,
    ) -> Result<usize, X86_64ModuleMapError<Memory::Error>> {
        let index = self.slot_index(mapping)?;
        if self.slots[index].phase != SlotPhase::Committed {
            return Err(X86_64ModuleMapError::InvalidState);
        }
        Ok(index)
    }

    fn clear_leaf_prefix(&mut self, slot_index: usize, count: usize) -> bool {
        let mut cleared = true;
        for page in 0..count {
            let Some(table) = self.slots[slot_index].leaf_tables[page / PAGES_PER_EXTENT] else {
                cleared = false;
                continue;
            };
            if self
                .memory
                .write_entry(table, page % PAGES_PER_EXTENT, 0)
                .is_err()
            {
                cleared = false;
            }
        }
        cleared
    }

    fn clear_all_leaves(&mut self, slot_index: usize) -> bool {
        self.clear_leaf_prefix(slot_index, self.slots[slot_index].data_frames.len())
    }

    fn detach_slot_tables(&mut self, slot_index: usize) -> bool {
        if self.slots[slot_index].detached {
            return true;
        }
        let Some(pml2) = self.module_pml2 else {
            return false;
        };
        let start = self.slots[slot_index].start_extent;
        let count = self.slots[slot_index].extent_count;
        let mut detached = true;
        for index in start..start + count {
            if self.memory.write_entry(pml2, index, 0).is_err() {
                detached = false;
            }
        }
        self.slots[slot_index].detached = detached;
        detached
    }

    fn detach_temporary_tables(
        &mut self,
        pml2: PhysicalAddress,
        start: usize,
        count: usize,
    ) -> bool {
        let mut detached = true;
        for index in start..start + count {
            if self.memory.write_entry(pml2, index, 0).is_err() {
                detached = false;
            }
        }
        detached
    }

    fn release_slot_frames(&mut self, slot_index: usize) -> bool {
        let mut clear = true;
        for frame in &mut self.slots[slot_index].data_frames {
            if let Some(owned) = *frame {
                if self.memory.release(owned).is_ok() {
                    *frame = None;
                } else {
                    clear = false;
                }
            }
        }
        for frame in &mut self.slots[slot_index].leaf_tables {
            if let Some(owned) = *frame {
                if self.memory.release(owned).is_ok() {
                    *frame = None;
                } else {
                    clear = false;
                }
            }
        }
        clear
    }

    fn release_temporary(&mut self, frames: &mut Vec<Option<PhysicalAddress>>) {
        for frame in frames.drain(..).flatten() {
            self.retain_or_release(frame);
        }
    }

    fn retain_or_release(&mut self, frame: PhysicalAddress) {
        if self.memory.release(frame).is_err() {
            self.retain_orphan(frame);
        }
    }

    fn retain_orphan(&mut self, frame: PhysicalAddress) {
        self.orphaned_frames.push(frame);
    }

    fn free_slot(&mut self, slot_index: usize) {
        let generation = self.slots[slot_index].generation;
        self.slots[slot_index] = ModuleSlot {
            generation,
            ..ModuleSlot::EMPTY
        };
    }
}

fn validate_regions<MemoryError>(
    regions: &[LinuxKoMemoryRegion],
    image_size: usize,
) -> Result<(), X86_64ModuleMapError<MemoryError>> {
    if regions.is_empty() {
        return Err(X86_64ModuleMapError::InvalidRange);
    }
    let mut end = 0;
    for region in regions {
        if region.image_offset != end
            || region.size == 0
            || region.image_offset % PAGE_SIZE != 0
            || region.size % PAGE_SIZE != 0
            || !region.readable
            || region.writable && region.executable
        {
            return Err(X86_64ModuleMapError::UnsupportedPermissions);
        }
        end = region
            .image_offset
            .checked_add(region.size)
            .ok_or(X86_64ModuleMapError::InvalidRange)?;
    }
    if end != image_size {
        return Err(X86_64ModuleMapError::InvalidRange);
    }
    Ok(())
}

fn valid_frame(frame: PhysicalAddress) -> bool {
    frame.as_u64() != 0
        && frame.as_u64() & (PAGE_SIZE as u64 - 1) == 0
        && frame.as_u64() & !PAGE_ADDRESS_MASK == 0
}

fn next_generation(generation: u32) -> u32 {
    let next = generation.wrapping_add(1);
    if next == 0 { 1 } else { next }
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use alloc::vec;

    use super::*;
    use crate::capability::Authority;
    use crate::module::linux_loader::LinuxKoRegionKind;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FakeError {
        InvalidFrame,
        OutOfMemory,
        ReleaseFault,
        WriteFault,
    }

    struct FakeFrame {
        bytes: Box<[u8; PAGE_SIZE]>,
        live: bool,
    }

    #[derive(Default)]
    struct FakeMemory {
        frames: Vec<FakeFrame>,
        allocation_limit: Option<usize>,
        allocations: usize,
        fail_release: Option<PhysicalAddress>,
        fail_writes: Vec<(PhysicalAddress, usize)>,
    }

    impl FakeMemory {
        fn frame_index(frame: PhysicalAddress) -> Result<usize, FakeError> {
            let raw = frame.as_u64();
            if raw == 0 || raw % PAGE_SIZE as u64 != 0 {
                return Err(FakeError::InvalidFrame);
            }
            usize::try_from(raw / PAGE_SIZE as u64 - 1).map_err(|_| FakeError::InvalidFrame)
        }

        fn frame(&self, frame: PhysicalAddress) -> Result<&FakeFrame, FakeError> {
            self.frames
                .get(Self::frame_index(frame)?)
                .filter(|frame| frame.live)
                .ok_or(FakeError::InvalidFrame)
        }

        fn frame_mut(&mut self, frame: PhysicalAddress) -> Result<&mut FakeFrame, FakeError> {
            let index = Self::frame_index(frame)?;
            self.frames
                .get_mut(index)
                .filter(|frame| frame.live)
                .ok_or(FakeError::InvalidFrame)
        }

        fn live_frames(&self) -> usize {
            self.frames.iter().filter(|frame| frame.live).count()
        }
    }

    impl ProcessFrameMemory for FakeMemory {
        type Error = FakeError;

        fn allocate_zeroed(&mut self) -> Result<PhysicalAddress, Self::Error> {
            if self
                .allocation_limit
                .is_some_and(|limit| self.allocations >= limit)
            {
                return Err(FakeError::OutOfMemory);
            }
            self.allocations += 1;
            if let Some((index, frame)) = self
                .frames
                .iter_mut()
                .enumerate()
                .find(|(_, frame)| !frame.live)
            {
                frame.bytes.fill(0);
                frame.live = true;
                return Ok(PhysicalAddress::new((index as u64 + 1) * PAGE_SIZE as u64));
            }
            let index = self.frames.len();
            self.frames.push(FakeFrame {
                bytes: Box::new([0; PAGE_SIZE]),
                live: true,
            });
            Ok(PhysicalAddress::new((index as u64 + 1) * PAGE_SIZE as u64))
        }

        fn release(&mut self, frame: PhysicalAddress) -> Result<(), Self::Error> {
            if self.fail_release == Some(frame) {
                self.fail_release = None;
                return Err(FakeError::ReleaseFault);
            }
            let target = self.frame_mut(frame)?;
            target.bytes.fill(0);
            target.live = false;
            Ok(())
        }

        fn read_entry(&self, table: PhysicalAddress, index: usize) -> Result<u64, Self::Error> {
            if index >= 512 {
                return Err(FakeError::InvalidFrame);
            }
            let offset = index * 8;
            Ok(u64::from_le_bytes(
                self.frame(table)?.bytes[offset..offset + 8]
                    .try_into()
                    .unwrap(),
            ))
        }

        fn write_entry(
            &mut self,
            table: PhysicalAddress,
            index: usize,
            value: u64,
        ) -> Result<(), Self::Error> {
            if index >= 512 {
                return Err(FakeError::InvalidFrame);
            }
            if self.fail_writes.first() == Some(&(table, index)) {
                self.fail_writes.remove(0);
                return Err(FakeError::WriteFault);
            }
            let offset = index * 8;
            self.frame_mut(table)?.bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            Ok(())
        }

        fn write_bytes(
            &mut self,
            frame: PhysicalAddress,
            offset: usize,
            bytes: &[u8],
        ) -> Result<(), Self::Error> {
            let target = self.frame_mut(frame)?;
            let end = offset
                .checked_add(bytes.len())
                .filter(|end| *end <= PAGE_SIZE)
                .ok_or(FakeError::InvalidFrame)?;
            target.bytes[offset..end].copy_from_slice(bytes);
            Ok(())
        }

        fn bytes_equal(
            &self,
            frame: PhysicalAddress,
            offset: usize,
            bytes: &[u8],
        ) -> Result<bool, Self::Error> {
            let source = self.frame(frame)?;
            Ok(source.bytes.get(offset..offset + bytes.len()) == Some(bytes))
        }

        fn bytes_zero(
            &self,
            frame: PhysicalAddress,
            offset: usize,
            length: usize,
        ) -> Result<bool, Self::Error> {
            let source = self.frame(frame)?;
            Ok(source
                .bytes
                .get(offset..offset + length)
                .is_some_and(|bytes| bytes.iter().all(|byte| *byte == 0)))
        }
    }

    #[derive(Default)]
    struct RecordingTlb {
        ranges: Vec<(u64, usize)>,
    }

    unsafe impl LinuxModuleTlb for RecordingTlb {
        fn invalidate_kernel_range(&mut self, virtual_address: u64, size: usize) {
            self.ranges.push((virtual_address, size));
        }
    }

    fn mapper() -> X86_64LinuxModuleMemory<FakeMemory, RecordingTlb> {
        let mut memory = FakeMemory::default();
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
        let module_load = authority.grant::<ModuleLoadControl>();
        unsafe { X86_64LinuxModuleMemory::new(memory, RecordingTlb::default(), root, &module_load) }
    }

    fn regions() -> [LinuxKoMemoryRegion; 2] {
        [
            LinuxKoMemoryRegion {
                kind: LinuxKoRegionKind::CoreText,
                image_offset: 0,
                size: PAGE_SIZE,
                readable: true,
                writable: false,
                executable: true,
                discard_after_init: false,
            },
            LinuxKoMemoryRegion {
                kind: LinuxKoRegionKind::InitWritable,
                image_offset: PAGE_SIZE,
                size: PAGE_SIZE * 2,
                readable: true,
                writable: true,
                executable: false,
                discard_after_init: true,
            },
        ]
    }

    #[test]
    fn staging_is_inaccessible_then_seals_exact_wx_permissions() {
        let mut mapper = mapper();
        let mapping = mapper.reserve_zeroed(PAGE_SIZE * 3, PAGE_SIZE).unwrap();
        assert_eq!(
            mapper.mapping_base(mapping).unwrap(),
            LINUX_MODULE_WINDOW_BASE
        );

        let pml2 = mapper.module_pml2.unwrap();
        let leaf =
            PhysicalAddress::new(mapper.memory.read_entry(pml2, 0).unwrap() & PAGE_ADDRESS_MASK);
        for page in 0..3 {
            assert_eq!(mapper.memory.read_entry(leaf, page).unwrap(), 0);
        }

        let payload = vec![0x5a; PAGE_SIZE + 17];
        mapper.write(mapping, PAGE_SIZE - 9, &payload).unwrap();
        assert!(mapper.verify(mapping, PAGE_SIZE - 9, &payload).unwrap());
        mapper.seal(mapping, &regions()).unwrap();

        let text = mapper.memory.read_entry(leaf, 0).unwrap();
        let writable = mapper.memory.read_entry(leaf, 1).unwrap();
        assert_eq!(
            text & (ENTRY_PRESENT | ENTRY_WRITABLE | ENTRY_USER | ENTRY_NO_EXECUTE),
            ENTRY_PRESENT
        );
        assert_eq!(
            writable & (ENTRY_PRESENT | ENTRY_WRITABLE | ENTRY_USER | ENTRY_NO_EXECUTE),
            ENTRY_PRESENT | ENTRY_WRITABLE | ENTRY_NO_EXECUTE
        );
        assert_eq!(
            mapper.tlb.ranges.last(),
            Some(&(LINUX_MODULE_WINDOW_BASE, PAGE_SIZE * 3))
        );

        assert_eq!(
            mapper.executable_address(mapping, LINUX_MODULE_WINDOW_BASE),
            Err(X86_64ModuleMapError::InvalidState)
        );
        mapper.commit(mapping).unwrap();
        assert!(
            mapper
                .executable_address(mapping, LINUX_MODULE_WINDOW_BASE)
                .unwrap()
        );
        assert!(
            !mapper
                .executable_address(mapping, LINUX_MODULE_WINDOW_BASE + PAGE_SIZE as u64)
                .unwrap()
        );
        assert_eq!(
            mapper.commit(mapping),
            Err(X86_64ModuleMapError::InvalidState)
        );
        mapper.discard(mapping, PAGE_SIZE, PAGE_SIZE * 2).unwrap();
        assert_eq!(mapper.memory.read_entry(leaf, 1).unwrap(), 0);
        assert_eq!(mapper.memory.read_entry(leaf, 2).unwrap(), 0);
        mapper.release(mapping).unwrap();
        assert_eq!(mapper.memory.read_entry(pml2, 0).unwrap(), 0);
        assert_eq!(mapper.memory.live_frames(), 3); // root, PML3, owned module PML2
    }

    #[test]
    fn extents_do_not_overlap_and_stale_generations_are_rejected() {
        let mut mapper = mapper();
        let first = mapper.reserve_zeroed(PAGE_SIZE, PAGE_SIZE).unwrap();
        let second = mapper.reserve_zeroed(PAGE_SIZE, PAGE_SIZE).unwrap();
        assert_eq!(
            mapper.mapping_base(first).unwrap(),
            LINUX_MODULE_WINDOW_BASE
        );
        assert_eq!(
            mapper.mapping_base(second).unwrap(),
            LINUX_MODULE_WINDOW_BASE + LINUX_MODULE_EXTENT_SIZE as u64
        );
        mapper.abort(first).unwrap();
        let replacement = mapper.reserve_zeroed(PAGE_SIZE, PAGE_SIZE).unwrap();
        assert_eq!(
            mapper.mapping_base(replacement).unwrap(),
            LINUX_MODULE_WINDOW_BASE
        );
        assert_ne!(first.generation(), replacement.generation());
        assert_eq!(
            mapper.mapping_base(first),
            Err(X86_64ModuleMapError::InvalidHandle)
        );
    }

    #[test]
    fn occupied_final_pml3_slot_fails_before_allocating_module_frames() {
        let mut mapper = mapper();
        let pml3 = PhysicalAddress::new(
            mapper
                .memory
                .read_entry(mapper.kernel_root, MODULE_PML4_INDEX)
                .unwrap()
                & PAGE_ADDRESS_MASK,
        );
        mapper
            .memory
            .write_entry(pml3, MODULE_PML3_INDEX, 0x9000 | ENTRY_PRESENT)
            .unwrap();
        let live_before = mapper.memory.live_frames();
        assert_eq!(
            mapper.reserve_zeroed(PAGE_SIZE, PAGE_SIZE),
            Err(X86_64ModuleMapError::ModuleWindowConflict)
        );
        assert_eq!(mapper.memory.live_frames(), live_before);
    }

    #[test]
    fn unowned_pml2_entry_fails_before_allocating_image_frames() {
        let mut mapper = mapper();
        mapper.ensure_module_hierarchy().unwrap();
        let pml2 = mapper.module_pml2.unwrap();
        mapper
            .memory
            .write_entry(pml2, 0, 0x9000 | ENTRY_PRESENT | ENTRY_WRITABLE)
            .unwrap();
        let live_before = mapper.memory.live_frames();
        let allocations_before = mapper.memory.allocations;
        assert_eq!(
            mapper.reserve_zeroed(PAGE_SIZE, PAGE_SIZE),
            Err(X86_64ModuleMapError::MappingConflict)
        );
        assert_eq!(mapper.memory.live_frames(), live_before);
        assert_eq!(mapper.memory.allocations, allocations_before);
    }

    #[test]
    fn upper_hierarchy_must_allow_writable_data_and_executable_text() {
        for forbidden in [ENTRY_NO_EXECUTE, 0] {
            let mut mapper = mapper();
            let original = mapper
                .memory
                .read_entry(mapper.kernel_root, MODULE_PML4_INDEX)
                .unwrap();
            let entry = if forbidden == 0 {
                original & !ENTRY_WRITABLE
            } else {
                original | forbidden
            };
            mapper
                .memory
                .write_entry(mapper.kernel_root, MODULE_PML4_INDEX, entry)
                .unwrap();
            let live_before = mapper.memory.live_frames();
            assert_eq!(
                mapper.reserve_zeroed(PAGE_SIZE, PAGE_SIZE),
                Err(X86_64ModuleMapError::InvalidKernelRoot)
            );
            assert_eq!(mapper.memory.live_frames(), live_before);
        }
    }

    #[test]
    fn owned_module_hierarchy_rejects_later_permission_tampering() {
        let mut mapper = mapper();
        let mapping = mapper.reserve_zeroed(PAGE_SIZE, PAGE_SIZE).unwrap();
        let pml3 = mapper.module_pml3.unwrap();
        let current = mapper.memory.read_entry(pml3, MODULE_PML3_INDEX).unwrap();
        mapper
            .memory
            .write_entry(pml3, MODULE_PML3_INDEX, current | ENTRY_NO_EXECUTE)
            .unwrap();
        assert_eq!(
            mapper.reserve_zeroed(PAGE_SIZE, PAGE_SIZE),
            Err(X86_64ModuleMapError::ModuleWindowConflict)
        );
        assert_eq!(mapper.mapping_base(mapping), Ok(LINUX_MODULE_WINDOW_BASE));
    }

    #[test]
    fn allocation_failure_reclaims_every_temporary_frame() {
        let mut mapper = mapper();
        // Root + PML3 already consumed two allocations. Permit the module PML2
        // and two data pages, then fail while building a four-page image.
        mapper.memory.allocation_limit = Some(5);
        assert_eq!(
            mapper.reserve_zeroed(PAGE_SIZE * 4, PAGE_SIZE),
            Err(X86_64ModuleMapError::Memory(FakeError::OutOfMemory))
        );
        assert_eq!(mapper.orphaned_frame_count(), 0);
        assert_eq!(mapper.memory.live_frames(), 3); // root, PML3, module PML2
    }

    #[test]
    fn partial_leaf_table_publication_is_detached_and_reclaimed() {
        let mut mapper = mapper();
        mapper.ensure_module_hierarchy().unwrap();
        let pml2 = mapper.module_pml2.unwrap();
        mapper.memory.fail_writes = vec![(pml2, 1)];
        assert_eq!(
            mapper.reserve_zeroed(LINUX_MODULE_EXTENT_SIZE + PAGE_SIZE, PAGE_SIZE),
            Err(X86_64ModuleMapError::Memory(FakeError::WriteFault))
        );
        assert_eq!(mapper.memory.read_entry(pml2, 0).unwrap(), 0);
        assert_eq!(mapper.memory.read_entry(pml2, 1).unwrap(), 0);
        assert_eq!(mapper.orphaned_frame_count(), 0);
        assert_eq!(mapper.memory.live_frames(), 3); // root, PML3, module PML2
        assert_eq!(
            mapper.tlb.ranges.last(),
            Some(&(LINUX_MODULE_WINDOW_BASE, LINUX_MODULE_EXTENT_SIZE * 2))
        );
    }

    #[test]
    fn failed_partial_detach_quarantines_the_complete_extent() {
        let mut mapper = mapper();
        mapper.ensure_module_hierarchy().unwrap();
        let pml2 = mapper.module_pml2.unwrap();
        mapper.memory.fail_writes = vec![(pml2, 1), (pml2, 0)];
        assert_eq!(
            mapper.reserve_zeroed(LINUX_MODULE_EXTENT_SIZE + PAGE_SIZE, PAGE_SIZE),
            Err(X86_64ModuleMapError::Memory(FakeError::WriteFault))
        );
        assert_ne!(mapper.memory.read_entry(pml2, 0).unwrap(), 0);
        assert_eq!(mapper.memory.read_entry(pml2, 1).unwrap(), 0);

        let next = mapper.reserve_zeroed(PAGE_SIZE, PAGE_SIZE).unwrap();
        assert_eq!(
            mapper.mapping_base(next).unwrap(),
            LINUX_MODULE_WINDOW_BASE + LINUX_MODULE_EXTENT_SIZE as u64 * 2
        );
        assert_eq!(mapper.reclaim_quarantine(), Ok(1));
        assert_eq!(mapper.memory.read_entry(pml2, 0).unwrap(), 0);
        let reused = mapper.reserve_zeroed(PAGE_SIZE, PAGE_SIZE).unwrap();
        assert_eq!(
            mapper.mapping_base(reused).unwrap(),
            LINUX_MODULE_WINDOW_BASE
        );
    }

    #[test]
    fn failed_seal_rollback_is_quarantined_until_every_pte_is_revoked() {
        let mut mapper = mapper();
        let mapping = mapper.reserve_zeroed(PAGE_SIZE * 3, PAGE_SIZE).unwrap();
        let pml2 = mapper.module_pml2.unwrap();
        let leaf =
            PhysicalAddress::new(mapper.memory.read_entry(pml2, 0).unwrap() & PAGE_ADDRESS_MASK);
        mapper.memory.fail_writes = vec![(leaf, 1), (leaf, 0)];
        assert_eq!(
            mapper.seal(mapping, &regions()),
            Err(X86_64ModuleMapError::Memory(FakeError::WriteFault))
        );
        assert_ne!(mapper.memory.read_entry(leaf, 0).unwrap(), 0);
        assert_eq!(mapper.mapping_base(mapping), Ok(LINUX_MODULE_WINDOW_BASE));
        assert_eq!(mapper.reclaim_quarantine(), Ok(1));
        assert_eq!(mapper.memory.live_frames(), 3); // root, PML3, module PML2
    }

    #[test]
    fn partial_discard_failure_flushes_before_a_safe_retry() {
        let mut mapper = mapper();
        let mapping = mapper.reserve_zeroed(PAGE_SIZE * 3, PAGE_SIZE).unwrap();
        mapper.seal(mapping, &regions()).unwrap();
        mapper.commit(mapping).unwrap();
        let pml2 = mapper.module_pml2.unwrap();
        let leaf =
            PhysicalAddress::new(mapper.memory.read_entry(pml2, 0).unwrap() & PAGE_ADDRESS_MASK);
        let flush_count = mapper.tlb.ranges.len();
        mapper.memory.fail_writes = vec![(leaf, 2)];
        assert_eq!(
            mapper.discard(mapping, PAGE_SIZE, PAGE_SIZE * 2),
            Err(X86_64ModuleMapError::Memory(FakeError::WriteFault))
        );
        assert_eq!(mapper.memory.read_entry(leaf, 1).unwrap(), 0);
        assert_ne!(mapper.memory.read_entry(leaf, 2).unwrap(), 0);
        assert_eq!(mapper.tlb.ranges.len(), flush_count + 1);
        assert_eq!(
            mapper.tlb.ranges.last(),
            Some(&(LINUX_MODULE_WINDOW_BASE + PAGE_SIZE as u64, PAGE_SIZE * 2))
        );
        mapper.discard(mapping, PAGE_SIZE, PAGE_SIZE * 2).unwrap();
        mapper.release(mapping).unwrap();
    }

    #[test]
    fn malformed_regions_never_publish_image_pages() {
        let mut mapper = mapper();
        let mapping = mapper.reserve_zeroed(PAGE_SIZE * 2, PAGE_SIZE).unwrap();
        let pml2 = mapper.module_pml2.unwrap();
        let leaf =
            PhysicalAddress::new(mapper.memory.read_entry(pml2, 0).unwrap() & PAGE_ADDRESS_MASK);
        let malformed = [LinuxKoMemoryRegion {
            kind: LinuxKoRegionKind::CoreText,
            image_offset: PAGE_SIZE,
            size: PAGE_SIZE,
            readable: true,
            writable: false,
            executable: true,
            discard_after_init: false,
        }];
        assert_eq!(
            mapper.seal(mapping, &malformed),
            Err(X86_64ModuleMapError::UnsupportedPermissions)
        );
        assert_eq!(mapper.memory.read_entry(leaf, 0).unwrap(), 0);
        assert_eq!(mapper.memory.read_entry(leaf, 1).unwrap(), 0);
        mapper.abort(mapping).unwrap();
    }

    #[test]
    fn failed_frame_release_quarantines_extent_until_retry() {
        let mut mapper = mapper();
        let mapping = mapper.reserve_zeroed(PAGE_SIZE * 3, PAGE_SIZE).unwrap();
        mapper.seal(mapping, &regions()).unwrap();
        mapper.commit(mapping).unwrap();
        let slot = usize::from(mapping.slot());
        let failed_frame = mapper.slots[slot].data_frames[0].unwrap();
        mapper.memory.fail_release = Some(failed_frame);
        assert_eq!(
            mapper.release(mapping),
            Err(X86_64ModuleMapError::FrameReleaseDebt)
        );
        let next = mapper.reserve_zeroed(PAGE_SIZE, PAGE_SIZE).unwrap();
        assert_eq!(
            mapper.mapping_base(next).unwrap(),
            LINUX_MODULE_WINDOW_BASE + LINUX_MODULE_EXTENT_SIZE as u64
        );
        assert_eq!(mapper.reclaim_quarantine(), Ok(1));
        let reused = mapper.reserve_zeroed(PAGE_SIZE, PAGE_SIZE).unwrap();
        assert_eq!(
            mapper.mapping_base(reused).unwrap(),
            LINUX_MODULE_WINDOW_BASE
        );
    }
}
