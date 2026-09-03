use alloc::alloc::{alloc, handle_alloc_error};
use alloc::boxed::Box;
use core::{alloc::Layout, mem::size_of, ptr};

use abyss::frame::FrameAllocatorError;
use abyss::paging::{PAGE_SIZE, PhysicalAddress};

#[cfg(target_os = "none")]
use crate::arch::x86_64::{X86_64, active_page_table_root, load_page_table_root};
#[cfg(target_os = "none")]
use crate::capability::InterruptGuard;
use crate::capability::{
    Capability, PhysicalMemoryControl, ProcessInstallControl, RuntimeImageControl,
};
use crate::memory::frame_pool::PhysicalFramePool;
use crate::process::install::{
    MappingPermissions, ProcessImageHandle, ProcessImageInfo, UserAddressSpaceBackend,
};

const PAGE_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const ENTRY_PRESENT: u64 = 1 << 0;
const ENTRY_WRITABLE: u64 = 1 << 1;
const ENTRY_USER: u64 = 1 << 2;
const ENTRY_ACCESSED: u64 = 1 << 5;
const ENTRY_DIRTY: u64 = 1 << 6;
const ENTRY_HUGE: u64 = 1 << 7;
const ENTRY_NO_EXECUTE: u64 = 1 << 63;
const USER_PML4_ENTRIES: usize = 256;
const TABLE_ENTRIES: usize = 512;

// The process backend retains a fixed, allocation-free metadata pool. The
// page budget covers the validated 64 MiB image span, both 16 MiB Linux heap
// and mmap arenas, measured stacks, and the bounded shared mappings. The
// separate frame budget leaves room for page-table hierarchy frames for every
// admitted mapping without turning an ordinary process into an allocator
// policy decision.
pub const MAXIMUM_PROCESS_PAGES: usize = if cfg!(test) { 1024 } else { 32 * 1024 };
pub const MAXIMUM_OWNED_FRAMES: usize = if cfg!(test) {
    1088
} else {
    MAXIMUM_PROCESS_PAGES + 512
};
/// One retained address-space slot per measured service class. Class zero is
/// unusable, so the spare slot remains available while every admitted class
/// is live and provides the inactive hierarchy required by transactional
/// image replacement. Unit tests use two slots to keep the inline hardware
/// page-record pool below the host test harness's per-thread stack ceiling.
pub const MAXIMUM_RETAINED_PROCESSES: usize = if cfg!(test) {
    2
} else {
    crate::process::service_registry::MAXIMUM_SERVICE_CLASSES
};
pub const INITIAL_USER_STACK_BASE: u64 = 0x0040_0000;
pub const INITIAL_USER_STACK_PAGES: usize = if cfg!(test) { 112 } else { 192 };
/// Exclusive top of the highest mapped initial-stack page.
pub const INITIAL_USER_STACK_POINTER: u64 = INITIAL_USER_STACK_BASE + PAGE_SIZE as u64;

/// First address used for Linux anonymous mappings when the caller supplies
/// no hint.  It is deliberately above the bootstrap image/stack and below the
/// canonical user limit; the allocator still checks every existing mapping.
pub const LINUX_MMAP_BASE: u64 = 0x0000_4000_0000;
pub const LINUX_MMAP_MAXIMUM_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_SHARED_BACKINGS: usize = 32;
const MAXIMUM_SHARED_PAGES: usize = crate::linux_memfd::MAXIMUM_MEMFD_BYTES / PAGE_SIZE;
/// Initial program break for the Linux personality.  Keeping the heap below
/// the mmap arena gives libc a stable, non-overlapping brk region while still
/// leaving the fixed image/stack addresses untouched.
pub const LINUX_BRK_BASE: u64 = 0x0000_2000_0000;
pub const LINUX_BRK_MAXIMUM_BYTES: usize = 16 * 1024 * 1024;

/// Kernel-owned values required by an x86-64 ELF image at process entry.
/// `runtime_linker_base` is zero for a statically linked image and non-zero
/// when the image was paired with a separately measured runtime linker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxAuxiliaryVector<'path> {
    pub program_header_address: u64,
    pub program_header_count: u16,
    pub runtime_linker_base: u64,
    pub executable_entry_point: u64,
    pub executable_path: &'path [u8],
    pub random: [u8; 16],
}

/// Physical-memory operations required by the process page-table builder.
///
/// Implementations must provide exclusive ownership of allocated frames and
/// must make page-table writes visible before a root can be activated.
pub trait ProcessFrameMemory {
    type Error;

    fn allocate_zeroed(&mut self) -> Result<PhysicalAddress, Self::Error>;
    fn release(&mut self, frame: PhysicalAddress) -> Result<(), Self::Error>;
    fn read_entry(&self, table: PhysicalAddress, index: usize) -> Result<u64, Self::Error>;
    fn write_entry(
        &mut self,
        table: PhysicalAddress,
        index: usize,
        value: u64,
    ) -> Result<(), Self::Error>;
    fn write_bytes(
        &mut self,
        frame: PhysicalAddress,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), Self::Error>;
    fn read_bytes(
        &self,
        frame: PhysicalAddress,
        offset: usize,
        destination: &mut [u8],
    ) -> Result<(), Self::Error>;
    fn bytes_equal(
        &self,
        frame: PhysicalAddress,
        offset: usize,
        bytes: &[u8],
    ) -> Result<bool, Self::Error>;
    fn bytes_zero(
        &self,
        frame: PhysicalAddress,
        offset: usize,
        length: usize,
    ) -> Result<bool, Self::Error>;
}

/// Accesses allocator-owned RAM through Arach's established direct map.
pub struct DirectMapFrameMemory<'allocator, 'storage> {
    frames: &'allocator PhysicalFramePool<'storage>,
    direct_map_base: usize,
    mapped_physical_limit: u64,
}

impl<'allocator, 'storage> DirectMapFrameMemory<'allocator, 'storage> {
    /// Creates a physical-memory adapter over a live direct map.
    ///
    /// # Safety
    ///
    /// Every frame returned by `frames` below `mapped_physical_limit` must
    /// be mapped writable at `direct_map_base + physical_address`. The mapping
    /// must remain stable and exclusively represent ordinary RAM for this
    /// adapter's lifetime.
    pub const unsafe fn new(
        frames: &'allocator PhysicalFramePool<'storage>,
        direct_map_base: usize,
        mapped_physical_limit: u64,
        _authority: &Capability<'_, PhysicalMemoryControl>,
    ) -> Self {
        Self {
            frames,
            direct_map_base,
            mapped_physical_limit,
        }
    }

    fn pointer(
        &self,
        frame: PhysicalAddress,
        offset: usize,
        length: usize,
    ) -> Result<*mut u8, DirectMapMemoryError> {
        if !frame.is_page_aligned()
            || offset.checked_add(length).is_none_or(|end| end > PAGE_SIZE)
            || frame
                .as_u64()
                .checked_add(PAGE_SIZE as u64)
                .is_none_or(|end| end > self.mapped_physical_limit)
        {
            return Err(DirectMapMemoryError::InvalidAccess);
        }
        let physical =
            usize::try_from(frame.as_u64()).map_err(|_| DirectMapMemoryError::AddressOverflow)?;
        let address = self
            .direct_map_base
            .checked_add(physical)
            .and_then(|base| base.checked_add(offset))
            .ok_or(DirectMapMemoryError::AddressOverflow)?;
        Ok(address as *mut u8)
    }
}

impl ProcessFrameMemory for DirectMapFrameMemory<'_, '_> {
    type Error = DirectMapMemoryError;

    fn allocate_zeroed(&mut self) -> Result<PhysicalAddress, Self::Error> {
        let frame = self
            .frames
            .allocate()
            .ok_or(DirectMapMemoryError::OutOfFrames)?;
        let pointer = match self.pointer(frame, 0, PAGE_SIZE) {
            Ok(pointer) => pointer,
            Err(error) => {
                self.frames
                    .release(frame)
                    .map_err(DirectMapMemoryError::Allocator)?;
                return Err(error);
            }
        };
        // SAFETY: The adapter owns the allocated frame and `pointer` covers
        // exactly its stable writable direct-map alias.
        unsafe { ptr::write_bytes(pointer, 0, PAGE_SIZE) };
        Ok(frame)
    }

    fn release(&mut self, frame: PhysicalAddress) -> Result<(), Self::Error> {
        self.frames
            .release(frame)
            .map_err(DirectMapMemoryError::Allocator)
    }

    fn read_entry(&self, table: PhysicalAddress, index: usize) -> Result<u64, Self::Error> {
        if index >= TABLE_ENTRIES {
            return Err(DirectMapMemoryError::InvalidAccess);
        }
        let pointer = self.pointer(table, index * size_of::<u64>(), size_of::<u64>())?;
        // SAFETY: `pointer` identifies one aligned entry in a mapped frame.
        Ok(unsafe { pointer.cast::<u64>().read_volatile() })
    }

    fn write_entry(
        &mut self,
        table: PhysicalAddress,
        index: usize,
        value: u64,
    ) -> Result<(), Self::Error> {
        if index >= TABLE_ENTRIES {
            return Err(DirectMapMemoryError::InvalidAccess);
        }
        let pointer = self.pointer(table, index * size_of::<u64>(), size_of::<u64>())?;
        // SAFETY: The builder exclusively owns destination tables and writes
        // one naturally aligned hardware entry.
        unsafe { pointer.cast::<u64>().write_volatile(value) };
        Ok(())
    }

    fn write_bytes(
        &mut self,
        frame: PhysicalAddress,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        let pointer = self.pointer(frame, offset, bytes.len())?;
        // SAFETY: Bounds were checked against the exclusively owned frame and
        // source and destination cannot overlap.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), pointer, bytes.len()) };
        Ok(())
    }

    fn read_bytes(
        &self,
        frame: PhysicalAddress,
        offset: usize,
        destination: &mut [u8],
    ) -> Result<(), Self::Error> {
        let pointer = self.pointer(frame, offset, destination.len())?;
        // SAFETY: The checked direct-map range remains readable and cannot
        // overlap the caller-owned destination.
        unsafe {
            ptr::copy_nonoverlapping(
                pointer.cast_const(),
                destination.as_mut_ptr(),
                destination.len(),
            )
        };
        Ok(())
    }

    fn bytes_equal(
        &self,
        frame: PhysicalAddress,
        offset: usize,
        bytes: &[u8],
    ) -> Result<bool, Self::Error> {
        let pointer = self.pointer(frame, offset, bytes.len())?;
        // SAFETY: The checked direct-map range remains readable for the
        // adapter lifetime.
        let actual = unsafe { core::slice::from_raw_parts(pointer.cast_const(), bytes.len()) };
        Ok(actual == bytes)
    }

    fn bytes_zero(
        &self,
        frame: PhysicalAddress,
        offset: usize,
        length: usize,
    ) -> Result<bool, Self::Error> {
        let pointer = self.pointer(frame, offset, length)?;
        // SAFETY: The checked direct-map range remains readable for the
        // adapter lifetime.
        let actual = unsafe { core::slice::from_raw_parts(pointer.cast_const(), length) };
        Ok(actual.iter().all(|byte| *byte == 0))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectMapMemoryError {
    OutOfFrames,
    InvalidAccess,
    AddressOverflow,
    Allocator(FrameAllocatorError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameBackedSpace {
    slot: u16,
    generation: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameBackedMapping {
    space_slot: u16,
    slot: u8,
    generation: u32,
}

#[derive(Clone, Copy)]
struct MappingRecord {
    occupied: bool,
    sealed: bool,
    /// Runtime private mappings may be removed by Linux `munmap`. Static ELF
    /// and bootstrap mappings remain owned for the process lifetime.
    releasable: bool,
    /// The process heap is a runtime VMA with `brk` growth semantics rather
    /// than an ordinary `mmap` range.  It is never accepted by `munmap`.
    heap: bool,
    generation: u32,
    virtual_address: u64,
    memory_size: usize,
    first_page: u16,
    page_count: u16,
    permissions: MappingPermissions,
    shared_identity: u32,
    shared_page_offset: u16,
}

impl MappingRecord {
    const EMPTY: Self = Self {
        occupied: false,
        sealed: false,
        releasable: false,
        heap: false,
        generation: 0,
        virtual_address: 0,
        memory_size: 0,
        first_page: 0,
        page_count: 0,
        permissions: MappingPermissions {
            readable: false,
            writable: false,
            executable: false,
        },
        shared_identity: 0,
        shared_page_offset: 0,
    };
}

struct SharedBacking {
    occupied: bool,
    descriptor_open: bool,
    identity: u32,
    size_bytes: usize,
    allocated_pages: u16,
    mapping_references: u16,
    frames: [PhysicalAddress; MAXIMUM_SHARED_PAGES],
}

impl SharedBacking {
    const EMPTY: Self = Self {
        occupied: false,
        descriptor_open: false,
        identity: 0,
        size_bytes: 0,
        allocated_pages: 0,
        mapping_references: 0,
        frames: [PhysicalAddress::new(0); MAXIMUM_SHARED_PAGES],
    };

    fn initialize(&mut self, identity: u32) {
        debug_assert!(!self.occupied);
        self.occupied = true;
        self.descriptor_open = true;
        self.identity = identity;
        self.size_bytes = 0;
        self.allocated_pages = 0;
        self.mapping_references = 0;
        self.frames.fill(PhysicalAddress::new(0));
    }

    fn reset(&mut self) {
        debug_assert_eq!(self.allocated_pages, 0);
        debug_assert_eq!(self.mapping_references, 0);
        self.occupied = false;
        self.descriptor_open = false;
        self.identity = 0;
        self.size_bytes = 0;
        self.allocated_pages = 0;
        self.mapping_references = 0;
        self.frames.fill(PhysicalAddress::new(0));
    }
}

#[derive(Clone, Copy)]
struct PageRecord {
    frame: PhysicalAddress,
    virtual_address: u64,
}

impl PageRecord {
    const EMPTY: Self = Self {
        frame: PhysicalAddress::new(0),
        virtual_address: 0,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SpacePhase {
    Free,
    Staging,
    Committed,
}

struct FrameBackedSlot {
    phase: SpacePhase,
    root: Option<PhysicalAddress>,
    generation: u32,
    image_start: u64,
    image_end: u64,
    mappings: [MappingRecord; super::install::MAXIMUM_PROCESS_SEGMENTS],
    mapping_count: usize,
    pages: [PageRecord; MAXIMUM_PROCESS_PAGES],
    page_count: usize,
    owned_frames: [PhysicalAddress; MAXIMUM_OWNED_FRAMES],
    owned_frame_count: usize,
    initial_stack_pages: usize,
    heap_break: u64,
    process_info: ProcessImageInfo,
}

impl FrameBackedSlot {
    const EMPTY: Self = Self {
        phase: SpacePhase::Free,
        root: None,
        generation: 0,
        image_start: 0,
        image_end: 0,
        mappings: [MappingRecord::EMPTY; super::install::MAXIMUM_PROCESS_SEGMENTS],
        mapping_count: 0,
        pages: [PageRecord::EMPTY; MAXIMUM_PROCESS_PAGES],
        page_count: 0,
        owned_frames: [PhysicalAddress::new(0); MAXIMUM_OWNED_FRAMES],
        owned_frame_count: 0,
        initial_stack_pages: 0,
        heap_break: LINUX_BRK_BASE,
        process_info: ProcessImageInfo {
            entry_point: 0,
            segment_count: 0,
            address_space_root: None,
            owned_frames: 0,
            initial_stack_pointer: None,
        },
    };
}

/// Builds a fixed-capacity pool of x86_64 hardware-format user address spaces.
///
/// The root inherits only PML4 entries 256..511 from the active kernel root.
/// A committed root can be switched into CR3 for a bounded validation while
/// the kernel remains entirely in its inherited higher-half mappings. Retained
/// ownership and privilege entry remain responsibilities of the scheduler.
pub struct FrameBackedAddressSpace<Memory: ProcessFrameMemory> {
    memory: Memory,
    kernel_root: PhysicalAddress,
    active_slot: Option<u16>,
    slots: [FrameBackedSlot; MAXIMUM_RETAINED_PROCESSES],
    shared: [SharedBacking; MAXIMUM_SHARED_BACKINGS],
}

impl<Memory: ProcessFrameMemory> FrameBackedAddressSpace<Memory> {
    pub const fn new(
        memory: Memory,
        kernel_root: PhysicalAddress,
        _authority: &Capability<'_, ProcessInstallControl>,
    ) -> Self {
        Self {
            memory,
            kernel_root,
            active_slot: None,
            slots: [const { FrameBackedSlot::EMPTY }; MAXIMUM_RETAINED_PROCESSES],
            shared: [const { SharedBacking::EMPTY }; MAXIMUM_SHARED_BACKINGS],
        }
    }

    /// Allocates and initializes the production metadata pool directly in
    /// its final heap allocation.  Constructing the fixed-capacity value as
    /// a temporary before putting it in a `Box` would copy every retained
    /// page record through the bootstrap stack and exceed the 8 MiB early
    /// stack even though the ownership ultimately belongs to the heap.
    #[inline(never)]
    pub fn boxed_new(
        memory: Memory,
        kernel_root: PhysicalAddress,
        _authority: &Capability<'_, ProcessInstallControl>,
    ) -> Box<Self> {
        let layout = Layout::new::<Self>();
        // SAFETY: `layout` is the exact layout of `Self`; ownership of the
        // allocation is transferred to the returned `Box` after every field
        // has been initialized below.
        let raw = unsafe { alloc(layout).cast::<Self>() };
        if raw.is_null() {
            handle_alloc_error(layout);
        }

        // SAFETY: `raw` points to an allocation with the layout of `Self` and
        // each field is written exactly once before `Box::from_raw` exposes
        // the value to safe code. The array elements are initialized in place
        // so no full metadata pool is ever materialized on the stack.
        unsafe {
            ptr::addr_of_mut!((*raw).memory).write(memory);
            ptr::addr_of_mut!((*raw).kernel_root).write(kernel_root);
            ptr::addr_of_mut!((*raw).active_slot).write(None);
            for index in 0..MAXIMUM_RETAINED_PROCESSES {
                ptr::addr_of_mut!((*raw).slots[index]).write(FrameBackedSlot::EMPTY);
            }
            for index in 0..MAXIMUM_SHARED_BACKINGS {
                ptr::addr_of_mut!((*raw).shared[index]).write(SharedBacking::EMPTY);
            }
            Box::from_raw(raw)
        }
    }

    pub const fn memory(&self) -> &Memory {
        &self.memory
    }

    /// Returns the immutable kernel hierarchy inherited by every user root.
    pub const fn kernel_root(&self) -> u64 {
        self.kernel_root.as_u64()
    }

    pub fn memory_mut(&mut self) -> &mut Memory {
        &mut self.memory
    }

    pub fn linux_shared_memory_create(
        &mut self,
        identity: u32,
    ) -> Result<(), FrameBackedError<Memory::Error>> {
        if identity == 0
            || self
                .shared
                .iter()
                .any(|backing| backing.identity == identity)
        {
            return Err(FrameBackedError::InvalidHandle);
        }
        let index = self
            .shared
            .iter()
            .position(|backing| !backing.occupied)
            .ok_or(FrameBackedError::CapacityExceeded)?;
        self.shared[index].initialize(identity);
        Ok(())
    }

    pub fn linux_shared_memory_resize(
        &mut self,
        identity: u32,
        expected_size: usize,
        size_bytes: usize,
    ) -> Result<(), FrameBackedError<Memory::Error>> {
        if size_bytes > crate::linux_memfd::MAXIMUM_MEMFD_BYTES {
            return Err(FrameBackedError::InvalidRange);
        }
        let index = self
            .shared
            .iter()
            .position(|backing| {
                backing.occupied && backing.descriptor_open && backing.identity == identity
            })
            .ok_or(FrameBackedError::InvalidHandle)?;
        if self.shared[index].size_bytes != expected_size {
            return Err(FrameBackedError::InvalidState);
        }
        if size_bytes < expected_size && self.shared[index].mapping_references != 0 {
            return Err(FrameBackedError::InvalidState);
        }
        let retained_pages = size_bytes.div_ceil(PAGE_SIZE);
        while usize::from(self.shared[index].allocated_pages) > retained_pages {
            let frame_index = usize::from(self.shared[index].allocated_pages) - 1;
            let frame = self.shared[index].frames[frame_index];
            self.memory
                .release(frame)
                .map_err(FrameBackedError::Memory)?;
            self.shared[index].frames[frame_index] = PhysicalAddress::new(0);
            self.shared[index].allocated_pages -= 1;
        }
        self.shared[index].size_bytes = size_bytes;
        Ok(())
    }

    pub fn linux_shared_memory_close(
        &mut self,
        identity: u32,
    ) -> Result<(), FrameBackedError<Memory::Error>> {
        let index = self
            .shared
            .iter()
            .position(|backing| {
                backing.occupied && backing.descriptor_open && backing.identity == identity
            })
            .ok_or(FrameBackedError::InvalidHandle)?;
        if self.shared[index].mapping_references == 0 {
            self.release_shared_backing(index)
        } else {
            self.shared[index].descriptor_open = false;
            Ok(())
        }
    }

    fn release_shared_backing(
        &mut self,
        index: usize,
    ) -> Result<(), FrameBackedError<Memory::Error>> {
        while self.shared[index].allocated_pages != 0 {
            let frame_index = usize::from(self.shared[index].allocated_pages) - 1;
            let frame = self.shared[index].frames[frame_index];
            self.memory
                .release(frame)
                .map_err(FrameBackedError::Memory)?;
            self.shared[index].frames[frame_index] = PhysicalAddress::new(0);
            self.shared[index].allocated_pages -= 1;
        }
        self.shared[index].reset();
        Ok(())
    }

    fn drop_shared_mapping_reference(
        &mut self,
        identity: u32,
    ) -> Result<(), FrameBackedError<Memory::Error>> {
        let index = self
            .shared
            .iter()
            .position(|backing| backing.occupied && backing.identity == identity)
            .ok_or(FrameBackedError::CorruptHierarchy)?;
        let references = self.shared[index].mapping_references;
        let remaining = references
            .checked_sub(1)
            .ok_or(FrameBackedError::CorruptHierarchy)?;
        if remaining == 0 && !self.shared[index].descriptor_open {
            self.shared[index].mapping_references = remaining;
            if let Err(error) = self.release_shared_backing(index) {
                self.shared[index].mapping_references = references;
                return Err(error);
            }
        } else {
            self.shared[index].mapping_references = remaining;
        }
        Ok(())
    }

    pub const fn owned_frame_count(&self) -> usize {
        let mut total = 0;
        let mut index = 0;
        while index < self.slots.len() {
            total += self.slots[index].owned_frame_count;
            index += 1;
        }
        total
    }

    /// Adds a fixed 128 KiB zeroed, writable, non-executable stack to a
    /// committed process while retaining ownership in this backend.
    pub fn install_initial_stack(
        &mut self,
        process: &ProcessImageHandle,
        _authority: &Capability<'_, ProcessInstallControl>,
    ) -> Result<u64, FrameBackedError<Memory::Error>> {
        self.install_stack_pages(process, INITIAL_USER_STACK_PAGES)
    }

    pub fn install_runtime_stack(
        &mut self,
        process: &ProcessImageHandle,
        _authority: &RuntimeImageControl,
    ) -> Result<u64, FrameBackedError<Memory::Error>> {
        self.install_stack_pages(process, INITIAL_USER_STACK_PAGES)
    }

    /// Adds a zeroed, writable, non-executable stack with an image-specific
    /// page budget. The budget is fixed at boot and retained with the process;
    /// it is never influenced by a Ring 3 caller.
    pub fn install_initial_stack_pages(
        &mut self,
        process: &ProcessImageHandle,
        pages: usize,
        _authority: &Capability<'_, ProcessInstallControl>,
    ) -> Result<u64, FrameBackedError<Memory::Error>> {
        self.install_stack_pages(process, pages)
    }

    fn install_stack_pages(
        &mut self,
        process: &ProcessImageHandle,
        pages: usize,
    ) -> Result<u64, FrameBackedError<Memory::Error>> {
        let slot_index = self.process_slot(process)?;
        let stack_span = pages
            .checked_sub(1)
            .and_then(|count| (count as u64).checked_mul(PAGE_SIZE as u64))
            .ok_or(FrameBackedError::InvalidRange)?;
        let mapping_base = INITIAL_USER_STACK_BASE
            .checked_sub(stack_span)
            .ok_or(FrameBackedError::InvalidRange)?;
        let initial_pointer = INITIAL_USER_STACK_BASE
            .checked_add(PAGE_SIZE as u64)
            .ok_or(FrameBackedError::InvalidRange)?;
        if self.active_slot.is_some()
            || self.slots[slot_index]
                .process_info
                .initial_stack_pointer
                .is_some()
            || mapping_base < 0x1000
            || self.slots[slot_index]
                .page_count
                .checked_add(pages)
                .is_none_or(|total| total > self.slots[slot_index].pages.len())
        {
            return Err(FrameBackedError::InvalidState);
        }

        let owned_before = self.slots[slot_index].owned_frame_count;
        let pages_before = self.slots[slot_index].page_count;
        for page in 0..pages {
            let virtual_address = mapping_base + (page as u64 * PAGE_SIZE as u64);
            let (table, index) = match self.ensure_leaf_slot(slot_index, virtual_address) {
                Ok(slot) => slot,
                Err(error) => {
                    self.rollback_stack_install(slot_index, owned_before, pages_before)?;
                    return Err(error);
                }
            };
            let frame = match self.allocate_owned(slot_index) {
                Ok(frame) => frame,
                Err(error) => {
                    self.rollback_stack_install(slot_index, owned_before, pages_before)?;
                    return Err(error);
                }
            };
            let entry =
                frame.as_u64() | ENTRY_PRESENT | ENTRY_WRITABLE | ENTRY_USER | ENTRY_NO_EXECUTE;
            if let Err(error) = self.memory.write_entry(table, index, entry) {
                self.rollback_stack_install(slot_index, owned_before, pages_before)?;
                return Err(FrameBackedError::Memory(error));
            }
            let page_index = self.slots[slot_index].page_count;
            self.slots[slot_index].pages[page_index] = PageRecord {
                frame,
                virtual_address,
            };
            self.slots[slot_index].page_count += 1;
        }
        self.slots[slot_index].process_info.initial_stack_pointer = Some(initial_pointer);
        self.slots[slot_index].process_info.owned_frames = self.slots[slot_index].owned_frame_count;
        self.slots[slot_index].initial_stack_pages = pages;
        Ok(initial_pointer)
    }

    /// Maps a kernel-owned thermal page into the user's address space.
    pub fn install_thermal_page(
        &mut self,
        process: &ProcessImageHandle,
        _authority: &Capability<'_, ProcessInstallControl>,
    ) -> Result<u64, FrameBackedError<Memory::Error>> {
        let slot_index = self.process_slot(process)?;
        if self.active_slot.is_some() {
            return Err(FrameBackedError::InvalidState);
        }
        let virtual_address = 0x0080_0000;
        let (table, index) = self.ensure_leaf_slot(slot_index, virtual_address)?;
        let frame = self.allocate_owned(slot_index)?;
        // Zero the frame
        if let Some(ptr) = crate::mmio::direct_map_address(frame.as_u64()) {
            unsafe { core::ptr::write_bytes(ptr as *mut u8, 0, 4096) };
        }
        let entry = frame.as_u64() | ENTRY_PRESENT | ENTRY_USER | ENTRY_NO_EXECUTE; // Read-only for user
        self.memory
            .write_entry(table, index, entry)
            .map_err(FrameBackedError::Memory)?;
        let page_index = self.slots[slot_index].page_count;
        self.slots[slot_index].pages[page_index] = PageRecord {
            frame,
            virtual_address,
        };
        self.slots[slot_index].page_count += 1;
        self.slots[slot_index].process_info.owned_frames = self.slots[slot_index].owned_frame_count;
        Ok(virtual_address)
    }

    pub const CEREBRAL_INGRESS_ADDRESS: u64 = 0x600_0000_0000;
    pub const CEREBRAL_OBSERVATION_ADDRESS: u64 = 0x600_0000_1000;
    pub const CEREBRAL_CERTIFICATE_ADDRESS: u64 = 0x600_0000_2000;

    /// Maps the retained split Resonance pages into the user's address space.
    pub fn install_nexus_plane(
        &mut self,
        process: &ProcessImageHandle,
        _authority: &Capability<'_, ProcessInstallControl>,
    ) -> Result<(), FrameBackedError<Memory::Error>> {
        let slot_index = self.process_slot(process)?;
        if self.active_slot.is_some()
            || self.slots[slot_index]
                .page_count
                .checked_add(3)
                .is_none_or(|count| count > self.slots[slot_index].pages.len())
        {
            return Err(FrameBackedError::InvalidState);
        }

        let mappings = [
            (
                Self::CEREBRAL_INGRESS_ADDRESS,
                crate::nexus_plane::ingress() as *const _ as usize,
                true,
            ),
            (
                Self::CEREBRAL_OBSERVATION_ADDRESS,
                crate::nexus_plane::observation() as *const _ as usize,
                false,
            ),
            (
                Self::CEREBRAL_CERTIFICATE_ADDRESS,
                crate::nexus_plane::certificate() as *const _ as usize,
                false,
            ),
        ];

        for (virtual_address, kernel_pointer, writable) in mappings {
            if kernel_pointer & (PAGE_SIZE - 1) != 0 {
                return Err(FrameBackedError::InvalidPhysicalFrame);
            }

            let physical = crate::mmio::kernel_virtual_to_physical(kernel_pointer, PAGE_SIZE)
                .ok_or(FrameBackedError::InvalidPhysicalFrame)?;
            if physical & (PAGE_SIZE as u64 - 1) != 0 || physical & !PAGE_ADDRESS_MASK != 0 {
                return Err(FrameBackedError::InvalidPhysicalFrame);
            }

            let (table, index) = self.ensure_leaf_slot(slot_index, virtual_address)?;
            let mut entry = physical | ENTRY_PRESENT | ENTRY_USER | ENTRY_NO_EXECUTE;
            if writable {
                entry |= ENTRY_WRITABLE;
            }
            self.memory
                .write_entry(table, index, entry)
                .map_err(FrameBackedError::Memory)?;

            let page_index = self.slots[slot_index].page_count;
            self.slots[slot_index].pages[page_index] = PageRecord {
                frame: PhysicalAddress::new(physical),
                virtual_address,
            };
            self.slots[slot_index].page_count += 1;
        }

        self.slots[slot_index].process_info.owned_frames = self.slots[slot_index].owned_frame_count;
        Ok(())
    }

    /// Maps a bounded anonymous private Linux range into a committed process.
    /// Every returned address has real zeroed frames and user PTEs behind it.
    pub fn linux_mmap_anonymous(
        &mut self,
        process: &ProcessImageHandle,
        hint: u64,
        length: usize,
        permissions: MappingPermissions,
    ) -> Result<u64, FrameBackedError<Memory::Error>> {
        self.linux_mmap_private(process, hint, length, permissions, &[])
    }

    /// Eagerly snapshots initialized bytes into a bounded private mapping.
    /// The remaining bytes in the page-rounded range stay allocator-zeroed,
    /// and no reference to the source descriptor survives this transaction.
    pub fn linux_mmap_file_private(
        &mut self,
        process: &ProcessImageHandle,
        hint: u64,
        length: usize,
        permissions: MappingPermissions,
        initialized: &[u8],
    ) -> Result<u64, FrameBackedError<Memory::Error>> {
        self.linux_mmap_private(process, hint, length, permissions, initialized)
    }

    fn linux_mmap_private(
        &mut self,
        process: &ProcessImageHandle,
        hint: u64,
        length: usize,
        permissions: MappingPermissions,
        initialized: &[u8],
    ) -> Result<u64, FrameBackedError<Memory::Error>> {
        let slot_index = self.process_slot(process)?;
        if self.active_slot.is_some()
            || length == 0
            || length > LINUX_MMAP_MAXIMUM_BYTES
            || !permissions.readable
            || (permissions.writable && permissions.executable)
        {
            return Err(FrameBackedError::InvalidRange);
        }
        let length = length
            .checked_add(PAGE_SIZE - 1)
            .map(|value| value & !(PAGE_SIZE - 1))
            .ok_or(FrameBackedError::InvalidRange)?;
        if initialized.len() > length {
            return Err(FrameBackedError::InvalidRange);
        }
        let pages_needed = length / PAGE_SIZE;
        let mapping_index = (0..self.slots[slot_index].mapping_count)
            .find(|index| !self.slots[slot_index].mappings[*index].occupied)
            .unwrap_or(self.slots[slot_index].mapping_count);
        if mapping_index >= self.slots[slot_index].mappings.len()
            || pages_needed == 0
            || self.slots[slot_index]
                .owned_frame_count
                .checked_add(pages_needed)
                .is_none_or(|count| count > self.slots[slot_index].owned_frames.len())
        {
            return Err(FrameBackedError::CapacityExceeded);
        }
        let page_start = self
            .free_page_run(slot_index, pages_needed)
            .ok_or(FrameBackedError::CapacityExceeded)?;
        let first_page =
            u16::try_from(page_start).map_err(|_| FrameBackedError::CapacityExceeded)?;
        let page_count =
            u16::try_from(pages_needed).map_err(|_| FrameBackedError::CapacityExceeded)?;
        let base = self.find_linux_mmap_base(slot_index, hint, length)?;

        // Keep the mapping record empty until all leaf entries have been
        // published.  A failure can therefore leave only empty page-table
        // branches, never a user-visible partial mapping.
        let mut allocated = 0usize;
        for page in 0..pages_needed {
            let virtual_address = match base.checked_add((page * PAGE_SIZE) as u64) {
                Some(address) => address,
                None => {
                    self.rollback_linux_mapping_pages(slot_index, page_start, allocated)?;
                    return Err(FrameBackedError::InvalidRange);
                }
            };
            let (table, index) = match self.ensure_leaf_slot(slot_index, virtual_address) {
                Ok(value) => value,
                Err(error) => {
                    self.rollback_linux_mapping_pages(slot_index, page_start, allocated)?;
                    return Err(error);
                }
            };
            let frame = match self.allocate_owned(slot_index) {
                Ok(frame) => frame,
                Err(error) => {
                    self.rollback_linux_mapping_pages(slot_index, page_start, allocated)?;
                    return Err(error);
                }
            };
            let source_start = page * PAGE_SIZE;
            if source_start < initialized.len() {
                let source_end = (source_start + PAGE_SIZE).min(initialized.len());
                if let Err(error) =
                    self.memory
                        .write_bytes(frame, 0, &initialized[source_start..source_end])
                {
                    let original = FrameBackedError::Memory(error);
                    self.release_owned_frame(slot_index, frame)?;
                    self.rollback_linux_mapping_pages(slot_index, page_start, allocated)?;
                    return Err(original);
                }
            }
            let entry = user_mapping_entry(frame, permissions);
            if let Err(error) = self.memory.write_entry(table, index, entry) {
                self.release_owned_frame(slot_index, frame)?;
                self.rollback_linux_mapping_pages(slot_index, page_start, allocated)?;
                return Err(FrameBackedError::Memory(error));
            }
            self.slots[slot_index].pages[page_start + page] = PageRecord {
                frame,
                virtual_address,
            };
            allocated += 1;
        }

        self.slots[slot_index].mappings[mapping_index] = MappingRecord {
            occupied: true,
            sealed: true,
            releasable: true,
            heap: false,
            generation: self.slots[slot_index].generation,
            virtual_address: base,
            memory_size: length,
            first_page,
            page_count,
            permissions,
            shared_identity: 0,
            shared_page_offset: 0,
        };
        self.slots[slot_index].mapping_count =
            self.slots[slot_index].mapping_count.max(mapping_index + 1);
        self.slots[slot_index].page_count = self.slots[slot_index]
            .page_count
            .max(page_start + pages_needed);
        self.slots[slot_index].process_info.owned_frames = self.slots[slot_index].owned_frame_count;
        Ok(base)
    }

    pub fn linux_mmap_shared(
        &mut self,
        process: &ProcessImageHandle,
        identity: u32,
        hint: u64,
        length: usize,
        offset: usize,
        permissions: MappingPermissions,
    ) -> Result<u64, FrameBackedError<Memory::Error>> {
        let slot_index = self.process_slot(process)?;
        if self.active_slot.is_some()
            || identity == 0
            || length == 0
            || length > crate::linux_memfd::MAXIMUM_MEMFD_BYTES
            || offset & (PAGE_SIZE - 1) != 0
            || !permissions.readable
            || permissions.writable && permissions.executable
        {
            return Err(FrameBackedError::InvalidRange);
        }
        let backing_index = self
            .shared
            .iter()
            .position(|backing| {
                backing.occupied && backing.descriptor_open && backing.identity == identity
            })
            .ok_or(FrameBackedError::InvalidHandle)?;
        if offset
            .checked_add(length)
            .is_none_or(|end| end > self.shared[backing_index].size_bytes)
        {
            return Err(FrameBackedError::InvalidRange);
        }
        let mapping_references = self.shared[backing_index]
            .mapping_references
            .checked_add(1)
            .ok_or(FrameBackedError::CapacityExceeded)?;
        let length = length
            .checked_add(PAGE_SIZE - 1)
            .map(|value| value & !(PAGE_SIZE - 1))
            .ok_or(FrameBackedError::InvalidRange)?;
        let pages_needed = length / PAGE_SIZE;
        let shared_page_offset = offset / PAGE_SIZE;
        let required_shared_pages = shared_page_offset
            .checked_add(pages_needed)
            .ok_or(FrameBackedError::InvalidRange)?;
        if required_shared_pages > MAXIMUM_SHARED_PAGES {
            return Err(FrameBackedError::CapacityExceeded);
        }
        self.ensure_shared_frames(backing_index, required_shared_pages)?;

        let mapping_index = (0..self.slots[slot_index].mapping_count)
            .find(|index| !self.slots[slot_index].mappings[*index].occupied)
            .unwrap_or(self.slots[slot_index].mapping_count);
        if mapping_index >= self.slots[slot_index].mappings.len() || pages_needed == 0 {
            return Err(FrameBackedError::CapacityExceeded);
        }
        let page_start = self
            .free_page_run(slot_index, pages_needed)
            .ok_or(FrameBackedError::CapacityExceeded)?;
        let first_page =
            u16::try_from(page_start).map_err(|_| FrameBackedError::CapacityExceeded)?;
        let page_count =
            u16::try_from(pages_needed).map_err(|_| FrameBackedError::CapacityExceeded)?;
        let shared_page_offset =
            u16::try_from(shared_page_offset).map_err(|_| FrameBackedError::CapacityExceeded)?;
        let base = self.find_linux_mmap_base(slot_index, hint, length)?;

        let mut mapped = 0;
        for page in 0..pages_needed {
            let virtual_address = match base.checked_add((page * PAGE_SIZE) as u64) {
                Some(address) => address,
                None => {
                    self.rollback_shared_mapping_pages(slot_index, page_start, mapped)?;
                    return Err(FrameBackedError::InvalidRange);
                }
            };
            let (table, index) = match self.ensure_leaf_slot(slot_index, virtual_address) {
                Ok(value) => value,
                Err(error) => {
                    self.rollback_shared_mapping_pages(slot_index, page_start, mapped)?;
                    return Err(error);
                }
            };
            let frame = self.shared[backing_index].frames[usize::from(shared_page_offset) + page];
            if let Err(error) =
                self.memory
                    .write_entry(table, index, user_mapping_entry(frame, permissions))
            {
                self.rollback_shared_mapping_pages(slot_index, page_start, mapped)?;
                return Err(FrameBackedError::Memory(error));
            }
            self.slots[slot_index].pages[page_start + page] = PageRecord {
                frame,
                virtual_address,
            };
            mapped += 1;
        }

        self.shared[backing_index].mapping_references = mapping_references;
        self.slots[slot_index].mappings[mapping_index] = MappingRecord {
            occupied: true,
            sealed: true,
            releasable: true,
            heap: false,
            generation: self.slots[slot_index].generation,
            virtual_address: base,
            memory_size: length,
            first_page,
            page_count,
            permissions,
            shared_identity: identity,
            shared_page_offset,
        };
        self.slots[slot_index].mapping_count =
            self.slots[slot_index].mapping_count.max(mapping_index + 1);
        self.slots[slot_index].page_count = self.slots[slot_index]
            .page_count
            .max(page_start + pages_needed);
        Ok(base)
    }

    fn ensure_shared_frames(
        &mut self,
        backing_index: usize,
        required_pages: usize,
    ) -> Result<(), FrameBackedError<Memory::Error>> {
        let allocated_before = usize::from(self.shared[backing_index].allocated_pages);
        while usize::from(self.shared[backing_index].allocated_pages) < required_pages {
            let frame = match self.memory.allocate_zeroed() {
                Ok(frame) => frame,
                Err(error) => {
                    self.rollback_shared_frames(backing_index, allocated_before)?;
                    return Err(FrameBackedError::Memory(error));
                }
            };
            if !frame.is_page_aligned() || frame.as_u64() & !PAGE_ADDRESS_MASK != 0 {
                self.memory
                    .release(frame)
                    .map_err(FrameBackedError::Memory)?;
                self.rollback_shared_frames(backing_index, allocated_before)?;
                return Err(FrameBackedError::InvalidPhysicalFrame);
            }
            let index = usize::from(self.shared[backing_index].allocated_pages);
            self.shared[backing_index].frames[index] = frame;
            self.shared[backing_index].allocated_pages += 1;
        }
        Ok(())
    }

    fn rollback_shared_frames(
        &mut self,
        backing_index: usize,
        retained_pages: usize,
    ) -> Result<(), FrameBackedError<Memory::Error>> {
        while usize::from(self.shared[backing_index].allocated_pages) > retained_pages {
            let index = usize::from(self.shared[backing_index].allocated_pages) - 1;
            let frame = self.shared[backing_index].frames[index];
            self.memory
                .release(frame)
                .map_err(FrameBackedError::Memory)?;
            self.shared[backing_index].frames[index] = PhysicalAddress::new(0);
            self.shared[backing_index].allocated_pages -= 1;
        }
        Ok(())
    }

    fn rollback_shared_mapping_pages(
        &mut self,
        slot_index: usize,
        page_start: usize,
        mapped: usize,
    ) -> Result<(), FrameBackedError<Memory::Error>> {
        for page in (0..mapped).rev() {
            let page_index = page_start + page;
            let record = self.slots[slot_index].pages[page_index];
            let (table, index) = self.leaf_slot(slot_index, record.virtual_address)?;
            self.memory
                .write_entry(table, index, 0)
                .map_err(FrameBackedError::Memory)?;
            self.slots[slot_index].pages[page_index] = PageRecord::EMPTY;
        }
        Ok(())
    }

    /// Resolve a lifecycle-published address-space root to the backend's
    /// generation-bound image handle before changing its page tables.
    pub fn linux_mmap_for_root(
        &mut self,
        address_space_root: u64,
        hint: u64,
        length: usize,
        permissions: MappingPermissions,
    ) -> Result<u64, FrameBackedError<Memory::Error>> {
        let process = self
            .slots
            .iter()
            .enumerate()
            .find(|(_, slot)| {
                slot.phase == SpacePhase::Committed
                    && slot.generation != 0
                    && slot.process_info.address_space_root == Some(address_space_root)
            })
            .map(|(index, slot)| ProcessImageHandle::new(index as u16, slot.generation))
            .ok_or(FrameBackedError::InvalidHandle)?;
        self.linux_mmap_anonymous(&process, hint, length, permissions)
    }

    pub fn linux_mmap_file_for_root(
        &mut self,
        address_space_root: u64,
        hint: u64,
        length: usize,
        permissions: MappingPermissions,
        initialized: &[u8],
    ) -> Result<u64, FrameBackedError<Memory::Error>> {
        let process = self
            .slots
            .iter()
            .enumerate()
            .find(|(_, slot)| {
                slot.phase == SpacePhase::Committed
                    && slot.generation != 0
                    && slot.process_info.address_space_root == Some(address_space_root)
            })
            .map(|(index, slot)| ProcessImageHandle::new(index as u16, slot.generation))
            .ok_or(FrameBackedError::InvalidHandle)?;
        self.linux_mmap_file_private(&process, hint, length, permissions, initialized)
    }

    pub fn linux_mmap_shared_for_root(
        &mut self,
        address_space_root: u64,
        identity: u32,
        hint: u64,
        length: usize,
        offset: usize,
        permissions: MappingPermissions,
    ) -> Result<u64, FrameBackedError<Memory::Error>> {
        let process = self
            .slots
            .iter()
            .enumerate()
            .find(|(_, slot)| {
                slot.phase == SpacePhase::Committed
                    && slot.generation != 0
                    && slot.process_info.address_space_root == Some(address_space_root)
            })
            .map(|(index, slot)| ProcessImageHandle::new(index as u16, slot.generation))
            .ok_or(FrameBackedError::InvalidHandle)?;
        self.linux_mmap_shared(&process, identity, hint, length, offset, permissions)
    }

    /// Changes one complete runtime mapping while preserving W^X. Partial
    /// ranges are rejected until VMA split/merge bookkeeping is admitted.
    /// Every leaf is preflighted before mutation, and a failed write restores
    /// all leaves already changed before the mapping record can be updated.
    pub fn linux_mprotect(
        &mut self,
        process: &ProcessImageHandle,
        virtual_address: u64,
        length: usize,
        permissions: MappingPermissions,
    ) -> Result<(), FrameBackedError<Memory::Error>> {
        let slot_index = self.process_slot(process)?;
        if self.active_slot.is_some()
            || virtual_address & (PAGE_SIZE as u64 - 1) != 0
            || length == 0
            || !permissions.readable
            || permissions.writable && permissions.executable
        {
            return Err(FrameBackedError::InvalidRange);
        }
        let length = length
            .checked_add(PAGE_SIZE - 1)
            .map(|value| value & !(PAGE_SIZE - 1))
            .ok_or(FrameBackedError::InvalidRange)?;
        let mapping_index = self.slots[slot_index]
            .mappings
            .iter()
            .position(|mapping| {
                mapping.occupied
                    && mapping.sealed
                    && mapping.releasable
                    && !mapping.heap
                    && mapping.generation == self.slots[slot_index].generation
                    && mapping.virtual_address == virtual_address
                    && mapping.memory_size == length
            })
            .ok_or(FrameBackedError::InvalidRange)?;
        let mapping = self.slots[slot_index].mappings[mapping_index];
        if usize::from(mapping.page_count)
            .checked_mul(PAGE_SIZE)
            .is_none_or(|mapped_bytes| mapped_bytes != mapping.memory_size)
            || usize::from(mapping.first_page)
                .checked_add(usize::from(mapping.page_count))
                .is_none_or(|end| end > self.slots[slot_index].pages.len())
        {
            return Err(FrameBackedError::CorruptHierarchy);
        }
        for page in 0..usize::from(mapping.page_count) {
            let (_, _, entry) = self.checked_mapping_leaf(slot_index, mapping, page)?;
            if normalized_user_mapping_entry(entry)
                != user_mapping_entry(
                    self.frame_for_mapping_page(slot_index, mapping, page)?,
                    mapping.permissions,
                )
            {
                return Err(FrameBackedError::CorruptHierarchy);
            }
        }
        if mapping.permissions == permissions {
            return Ok(());
        }

        for page in 0..usize::from(mapping.page_count) {
            let (table, index, entry) = self.checked_mapping_leaf(slot_index, mapping, page)?;
            let updated = replace_user_mapping_permissions(entry, permissions);
            if let Err(error) = self.memory.write_entry(table, index, updated) {
                let original = FrameBackedError::Memory(error);
                self.rollback_mapping_permissions(slot_index, mapping, page)?;
                return Err(original);
            }
            match self.memory.read_entry(table, index) {
                Ok(observed)
                    if normalized_user_mapping_entry(observed)
                        == normalized_user_mapping_entry(updated) => {}
                Ok(_) => {
                    self.rollback_mapping_permissions(slot_index, mapping, page + 1)?;
                    return Err(FrameBackedError::CorruptHierarchy);
                }
                Err(error) => {
                    let original = FrameBackedError::Memory(error);
                    self.rollback_mapping_permissions(slot_index, mapping, page + 1)?;
                    return Err(original);
                }
            }
        }
        self.slots[slot_index].mappings[mapping_index].permissions = permissions;
        Ok(())
    }

    pub fn linux_mprotect_for_root(
        &mut self,
        address_space_root: u64,
        virtual_address: u64,
        length: usize,
        permissions: MappingPermissions,
    ) -> Result<(), FrameBackedError<Memory::Error>> {
        let process = self
            .slots
            .iter()
            .enumerate()
            .find(|(_, slot)| {
                slot.phase == SpacePhase::Committed
                    && slot.generation != 0
                    && slot.process_info.address_space_root == Some(address_space_root)
            })
            .map(|(index, slot)| ProcessImageHandle::new(index as u16, slot.generation))
            .ok_or(FrameBackedError::InvalidHandle)?;
        self.linux_mprotect(&process, virtual_address, length, permissions)
    }

    /// Remove one complete runtime mapping. Partial unmaps are intentionally
    /// rejected until the VMA split/merge bookkeeping is implemented.
    pub fn linux_munmap(
        &mut self,
        process: &ProcessImageHandle,
        virtual_address: u64,
        length: usize,
    ) -> Result<(), FrameBackedError<Memory::Error>> {
        let slot_index = self.process_slot(process)?;
        if self.active_slot.is_some()
            || virtual_address & (PAGE_SIZE as u64 - 1) != 0
            || length == 0
        {
            return Err(FrameBackedError::InvalidRange);
        }
        let length = length
            .checked_add(PAGE_SIZE - 1)
            .map(|value| value & !(PAGE_SIZE - 1))
            .ok_or(FrameBackedError::InvalidRange)?;
        let mapping_index = self.slots[slot_index]
            .mappings
            .iter()
            .position(|mapping| {
                mapping.occupied
                    && mapping.releasable
                    && mapping.generation == self.slots[slot_index].generation
                    && mapping.virtual_address == virtual_address
                    && mapping.memory_size == length
            })
            .ok_or(FrameBackedError::InvalidRange)?;
        let mapping = self.slots[slot_index].mappings[mapping_index];
        for page in 0..usize::from(mapping.page_count) {
            let page_index = usize::from(mapping.first_page) + page;
            let page_record = self.slots[slot_index].pages[page_index];
            if page_record.virtual_address == 0 {
                continue;
            }
            let (table, index) = self.leaf_slot(slot_index, page_record.virtual_address)?;
            self.memory
                .write_entry(table, index, 0)
                .map_err(FrameBackedError::Memory)?;
            if mapping.shared_identity == 0 {
                self.release_owned_frame(slot_index, page_record.frame)?;
            }
            self.slots[slot_index].pages[page_index] = PageRecord::EMPTY;
        }
        if mapping.shared_identity != 0 {
            self.drop_shared_mapping_reference(mapping.shared_identity)?;
        }
        self.slots[slot_index].mappings[mapping_index] = MappingRecord::EMPTY;
        self.slots[slot_index].process_info.owned_frames = self.slots[slot_index].owned_frame_count;
        Ok(())
    }

    pub fn linux_munmap_for_root(
        &mut self,
        address_space_root: u64,
        virtual_address: u64,
        length: usize,
    ) -> Result<(), FrameBackedError<Memory::Error>> {
        let process = self
            .slots
            .iter()
            .enumerate()
            .find(|(_, slot)| {
                slot.phase == SpacePhase::Committed
                    && slot.generation != 0
                    && slot.process_info.address_space_root == Some(address_space_root)
            })
            .map(|(index, slot)| ProcessImageHandle::new(index as u16, slot.generation))
            .ok_or(FrameBackedError::InvalidHandle)?;
        self.linux_munmap(&process, virtual_address, length)
    }

    /// Implements the bounded Linux `brk` contract for a committed process.
    ///
    /// The returned value is the exact (possibly non-page-aligned) break. The
    /// backing VMA is page-granular and is extended or trimmed only at page
    /// boundaries.  Newly exposed pages come from the same zeroing allocator
    /// as `mmap`, are user writable and NX, and are retained in the
    /// generation-bound slot so a stale process handle cannot change another
    /// process's heap.
    pub fn linux_brk(
        &mut self,
        process: &ProcessImageHandle,
        requested: u64,
    ) -> Result<u64, FrameBackedError<Memory::Error>> {
        let slot_index = self.process_slot(process)?;
        if self.active_slot.is_some() {
            return Err(FrameBackedError::InvalidState);
        }

        let current = self.slots[slot_index].heap_break;
        if requested == 0 {
            return Ok(current);
        }
        if requested < LINUX_BRK_BASE || requested >= 0x0000_8000_0000_0000 {
            return Err(FrameBackedError::InvalidRange);
        }
        let requested_bytes = requested
            .checked_sub(LINUX_BRK_BASE)
            .ok_or(FrameBackedError::InvalidRange)?;
        if requested_bytes > LINUX_BRK_MAXIMUM_BYTES as u64 {
            return Err(FrameBackedError::CapacityExceeded);
        }
        let desired_pages = if requested_bytes == 0 {
            0
        } else {
            usize::try_from(
                requested_bytes
                    .checked_add(PAGE_SIZE as u64 - 1)
                    .ok_or(FrameBackedError::InvalidRange)?
                    / PAGE_SIZE as u64,
            )
            .map_err(|_| FrameBackedError::CapacityExceeded)?
        };

        let mapping_index = self.slots[slot_index].mappings.iter().position(|mapping| {
            mapping.occupied
                && mapping.heap
                && mapping.generation == self.slots[slot_index].generation
        });
        let current_pages = mapping_index
            .map(|index| usize::from(self.slots[slot_index].mappings[index].page_count))
            .unwrap_or(0);

        if desired_pages == current_pages {
            self.slots[slot_index].heap_break = requested;
            return Ok(requested);
        }

        if desired_pages < current_pages {
            let index = mapping_index.ok_or(FrameBackedError::CorruptHierarchy)?;
            let mapping = self.slots[slot_index].mappings[index];
            let first_page = usize::from(mapping.first_page);
            for page in desired_pages..current_pages {
                let page_index = first_page + page;
                let page_record = self.slots[slot_index].pages[page_index];
                if page_record.virtual_address == 0 {
                    return Err(FrameBackedError::CorruptHierarchy);
                }
                let (table, leaf) = self.leaf_slot(slot_index, page_record.virtual_address)?;
                self.memory
                    .write_entry(table, leaf, 0)
                    .map_err(FrameBackedError::Memory)?;
                self.release_owned_frame(slot_index, page_record.frame)?;
                self.slots[slot_index].pages[page_index] = PageRecord::EMPTY;
            }
            self.slots[slot_index].mappings[index].page_count =
                u16::try_from(desired_pages).map_err(|_| FrameBackedError::CapacityExceeded)?;
            self.slots[slot_index].mappings[index].memory_size = desired_pages
                .checked_mul(PAGE_SIZE)
                .ok_or(FrameBackedError::InvalidRange)?;
            self.slots[slot_index].process_info.owned_frames =
                self.slots[slot_index].owned_frame_count;
            self.slots[slot_index].heap_break = requested;
            return Ok(requested);
        }

        let additional_pages = desired_pages - current_pages;
        if self.slots[slot_index]
            .owned_frame_count
            .checked_add(additional_pages)
            .is_none_or(|count| count > self.slots[slot_index].owned_frames.len())
        {
            return Err(FrameBackedError::CapacityExceeded);
        }

        let (index, first_page) = if let Some(index) = mapping_index {
            let mapping = self.slots[slot_index].mappings[index];
            let first_page = usize::from(mapping.first_page);
            let end = first_page
                .checked_add(current_pages)
                .and_then(|end| end.checked_add(additional_pages))
                .ok_or(FrameBackedError::CapacityExceeded)?;
            if end > self.slots[slot_index].pages.len()
                || !self.slots[slot_index].pages[first_page + current_pages..end]
                    .iter()
                    .all(|page| page.virtual_address == 0)
            {
                return Err(FrameBackedError::CapacityExceeded);
            }
            (index, first_page)
        } else {
            let index = (0..self.slots[slot_index].mapping_count)
                .find(|index| !self.slots[slot_index].mappings[*index].occupied)
                .unwrap_or(self.slots[slot_index].mapping_count);
            if index >= self.slots[slot_index].mappings.len() {
                return Err(FrameBackedError::CapacityExceeded);
            }
            let first_page = self
                .free_page_run(slot_index, desired_pages)
                .ok_or(FrameBackedError::CapacityExceeded)?;
            (index, first_page)
        };

        let page_start = first_page + current_pages;
        let mut allocated = 0usize;
        for page in current_pages..desired_pages {
            let virtual_address = LINUX_BRK_BASE
                .checked_add((page * PAGE_SIZE) as u64)
                .ok_or(FrameBackedError::InvalidRange)?;
            let (table, leaf) = match self.ensure_leaf_slot(slot_index, virtual_address) {
                Ok(value) => value,
                Err(error) => {
                    self.rollback_linux_mapping_pages(slot_index, page_start, allocated)?;
                    return Err(error);
                }
            };
            let frame = match self.allocate_owned(slot_index) {
                Ok(frame) => frame,
                Err(error) => {
                    self.rollback_linux_mapping_pages(slot_index, page_start, allocated)?;
                    return Err(error);
                }
            };
            let entry =
                frame.as_u64() | ENTRY_PRESENT | ENTRY_USER | ENTRY_WRITABLE | ENTRY_NO_EXECUTE;
            if let Err(error) = self.memory.write_entry(table, leaf, entry) {
                self.release_owned_frame(slot_index, frame)?;
                self.rollback_linux_mapping_pages(slot_index, page_start, allocated)?;
                return Err(FrameBackedError::Memory(error));
            }
            self.slots[slot_index].pages[first_page + page] = PageRecord {
                frame,
                virtual_address,
            };
            allocated += 1;
        }

        if mapping_index.is_none() {
            self.slots[slot_index].mappings[index] = MappingRecord {
                occupied: true,
                sealed: true,
                releasable: false,
                heap: true,
                generation: self.slots[slot_index].generation,
                virtual_address: LINUX_BRK_BASE,
                memory_size: desired_pages
                    .checked_mul(PAGE_SIZE)
                    .ok_or(FrameBackedError::InvalidRange)?,
                first_page: u16::try_from(first_page)
                    .map_err(|_| FrameBackedError::CapacityExceeded)?,
                page_count: u16::try_from(desired_pages)
                    .map_err(|_| FrameBackedError::CapacityExceeded)?,
                permissions: MappingPermissions {
                    readable: true,
                    writable: true,
                    executable: false,
                },
                shared_identity: 0,
                shared_page_offset: 0,
            };
            self.slots[slot_index].mapping_count =
                self.slots[slot_index].mapping_count.max(index + 1);
        } else {
            self.slots[slot_index].mappings[index].page_count =
                u16::try_from(desired_pages).map_err(|_| FrameBackedError::CapacityExceeded)?;
            self.slots[slot_index].mappings[index].memory_size = desired_pages
                .checked_mul(PAGE_SIZE)
                .ok_or(FrameBackedError::InvalidRange)?;
        }
        self.slots[slot_index].page_count = self.slots[slot_index]
            .page_count
            .max(first_page + desired_pages);
        self.slots[slot_index].process_info.owned_frames = self.slots[slot_index].owned_frame_count;
        self.slots[slot_index].heap_break = requested;
        Ok(requested)
    }

    pub fn linux_brk_for_root(
        &mut self,
        address_space_root: u64,
        requested: u64,
    ) -> Result<u64, FrameBackedError<Memory::Error>> {
        let process = self
            .slots
            .iter()
            .enumerate()
            .find(|(_, slot)| {
                slot.phase == SpacePhase::Committed
                    && slot.generation != 0
                    && slot.process_info.address_space_root == Some(address_space_root)
            })
            .map(|(index, slot)| ProcessImageHandle::new(index as u16, slot.generation))
            .ok_or(FrameBackedError::InvalidHandle)?;
        self.linux_brk(&process, requested)
    }

    /// Materializes the documented `[argc][argv][envp]` entry block in the
    /// retained user stack and returns the stack pointer to pass to Ring 3.
    pub fn prepare_initial_stack(
        &mut self,
        process: &ProcessImageHandle,
        argv: &[&[u8]],
        envp: &[&[u8]],
    ) -> Result<u64, FrameBackedError<Memory::Error>> {
        let slot_index = self.process_slot(process)?;
        if self.active_slot.is_some()
            || self.slots[slot_index]
                .process_info
                .initial_stack_pointer
                .is_none()
        {
            return Err(FrameBackedError::InvalidState);
        }
        let word_count = 1usize
            .checked_add(argv.len())
            .and_then(|count| count.checked_add(1))
            .and_then(|count| count.checked_add(envp.len()))
            .and_then(|count| count.checked_add(1))
            .ok_or(FrameBackedError::InvalidRange)?;
        let pointer_bytes = word_count
            .checked_mul(core::mem::size_of::<u64>())
            .ok_or(FrameBackedError::InvalidRange)?;
        let string_bytes = argv
            .iter()
            .chain(envp.iter())
            .try_fold(0usize, |total, value| {
                total.checked_add(value.len().checked_add(1)?)
            })
            .ok_or(FrameBackedError::InvalidRange)?;
        let stack_bytes = self.slots[slot_index]
            .initial_stack_pages
            .checked_mul(PAGE_SIZE)
            .ok_or(FrameBackedError::InvalidState)?;
        if pointer_bytes
            .checked_add(string_bytes)
            .is_none_or(|size| size > stack_bytes)
        {
            return Err(FrameBackedError::InvalidRange);
        }

        let stack_top = self.slots[slot_index]
            .process_info
            .initial_stack_pointer
            .ok_or(FrameBackedError::InvalidState)?;
        let mapped_bytes = self.slots[slot_index]
            .initial_stack_pages
            .checked_mul(PAGE_SIZE)
            .ok_or(FrameBackedError::InvalidState)?;
        let mapped_base = stack_top
            .checked_sub(mapped_bytes as u64)
            .ok_or(FrameBackedError::InvalidState)?;
        let block_bytes = pointer_bytes
            .checked_add(string_bytes)
            .ok_or(FrameBackedError::InvalidRange)?;
        let stack_pointer = stack_top
            .checked_sub(block_bytes as u64)
            .map(|address| address & !0xf)
            .filter(|address| *address >= mapped_base)
            .ok_or(FrameBackedError::InvalidRange)?;

        let mut word_address = stack_pointer;
        self.write_stack_word(slot_index, word_address, argv.len() as u64)?;
        word_address += 8;
        let string_start = stack_pointer + pointer_bytes as u64;
        let mut string_address = string_start;
        for value in argv {
            self.write_stack_word(slot_index, word_address, string_address)?;
            word_address += 8;
            string_address += value.len() as u64 + 1;
        }
        self.write_stack_word(slot_index, word_address, 0)?;
        word_address += 8;
        for value in envp {
            self.write_stack_word(slot_index, word_address, string_address)?;
            word_address += 8;
            string_address += value.len() as u64 + 1;
        }
        self.write_stack_word(slot_index, word_address, 0)?;

        string_address = string_start;
        for value in argv.iter().chain(envp.iter()) {
            self.write_stack_bytes(slot_index, string_address, value)?;
            string_address += value.len() as u64;
            self.write_stack_bytes(slot_index, string_address, &[0])?;
            string_address += 1;
        }
        self.slots[slot_index].process_info.initial_stack_pointer = Some(stack_pointer);
        Ok(stack_pointer)
    }

    /// Materializes the System V x86-64 process-entry stack consumed by an
    /// ELF startup object: argv, envp, a bounded auxiliary vector, executable
    /// path, and 16 bytes backing `AT_RANDOM`. Static images use an `AT_BASE`
    /// value of zero; dynamic images provide the measured linker base.
    pub fn prepare_linux_dynamic_stack(
        &mut self,
        process: &ProcessImageHandle,
        argv: &[&[u8]],
        envp: &[&[u8]],
        auxiliary: LinuxAuxiliaryVector<'_>,
    ) -> Result<u64, FrameBackedError<Memory::Error>> {
        const AUXILIARY_ENTRY_COUNT: usize = 14;
        const AT_NULL: u64 = 0;
        const AT_PHDR: u64 = 3;
        const AT_PHENT: u64 = 4;
        const AT_PHNUM: u64 = 5;
        const AT_PAGESZ: u64 = 6;
        const AT_BASE: u64 = 7;
        const AT_FLAGS: u64 = 8;
        const AT_ENTRY: u64 = 9;
        const AT_UID: u64 = 11;
        const AT_EUID: u64 = 12;
        const AT_GID: u64 = 13;
        const AT_EGID: u64 = 14;
        const AT_SECURE: u64 = 23;
        const AT_RANDOM: u64 = 25;
        const AT_EXECFN: u64 = 31;

        let slot_index = self.process_slot(process)?;
        if self.active_slot.is_some()
            || self.slots[slot_index]
                .process_info
                .initial_stack_pointer
                .is_none()
            || auxiliary.program_header_address == 0
            || auxiliary.program_header_count == 0
            || auxiliary.executable_entry_point == 0
            || auxiliary.executable_path.is_empty()
            || auxiliary.executable_path.contains(&0)
        {
            return Err(FrameBackedError::InvalidState);
        }
        let word_count = 1usize
            .checked_add(argv.len())
            .and_then(|count| count.checked_add(1))
            .and_then(|count| count.checked_add(envp.len()))
            .and_then(|count| count.checked_add(1))
            .and_then(|count| count.checked_add((AUXILIARY_ENTRY_COUNT + 1) * 2))
            .ok_or(FrameBackedError::InvalidRange)?;
        let pointer_bytes = word_count
            .checked_mul(size_of::<u64>())
            .ok_or(FrameBackedError::InvalidRange)?;
        let vector_string_bytes = argv
            .iter()
            .chain(envp.iter())
            .try_fold(0usize, |total, value| {
                total.checked_add(value.len().checked_add(1)?)
            })
            .ok_or(FrameBackedError::InvalidRange)?;
        let data_bytes = vector_string_bytes
            .checked_add(auxiliary.executable_path.len())
            .and_then(|count| count.checked_add(1 + auxiliary.random.len()))
            .ok_or(FrameBackedError::InvalidRange)?;
        let stack_bytes = self.slots[slot_index]
            .initial_stack_pages
            .checked_mul(PAGE_SIZE)
            .ok_or(FrameBackedError::InvalidState)?;
        if pointer_bytes
            .checked_add(data_bytes)
            .is_none_or(|size| size > stack_bytes)
        {
            return Err(FrameBackedError::InvalidRange);
        }

        let stack_top = self.slots[slot_index]
            .process_info
            .initial_stack_pointer
            .ok_or(FrameBackedError::InvalidState)?;
        let mapped_base = stack_top
            .checked_sub(stack_bytes as u64)
            .ok_or(FrameBackedError::InvalidState)?;
        let block_bytes = pointer_bytes
            .checked_add(data_bytes)
            .ok_or(FrameBackedError::InvalidRange)?;
        let stack_pointer = stack_top
            .checked_sub(block_bytes as u64)
            .map(|address| address & !0xf)
            .filter(|address| *address >= mapped_base)
            .ok_or(FrameBackedError::InvalidRange)?;

        let mut word_address = stack_pointer;
        self.write_stack_word(slot_index, word_address, argv.len() as u64)?;
        word_address += 8;
        let string_start = stack_pointer + pointer_bytes as u64;
        let mut string_address = string_start;
        for value in argv {
            self.write_stack_word(slot_index, word_address, string_address)?;
            word_address += 8;
            string_address += value.len() as u64 + 1;
        }
        self.write_stack_word(slot_index, word_address, 0)?;
        word_address += 8;
        for value in envp {
            self.write_stack_word(slot_index, word_address, string_address)?;
            word_address += 8;
            string_address += value.len() as u64 + 1;
        }
        self.write_stack_word(slot_index, word_address, 0)?;
        word_address += 8;

        let executable_path_address = string_start
            .checked_add(vector_string_bytes as u64)
            .ok_or(FrameBackedError::InvalidRange)?;
        let random_address = executable_path_address
            .checked_add(auxiliary.executable_path.len() as u64 + 1)
            .ok_or(FrameBackedError::InvalidRange)?;
        let entries = [
            (AT_PHDR, auxiliary.program_header_address),
            (AT_PHENT, 56),
            (AT_PHNUM, u64::from(auxiliary.program_header_count)),
            (AT_PAGESZ, PAGE_SIZE as u64),
            (AT_BASE, auxiliary.runtime_linker_base),
            (AT_FLAGS, 0),
            (AT_ENTRY, auxiliary.executable_entry_point),
            (AT_UID, 0),
            (AT_EUID, 0),
            (AT_GID, 0),
            (AT_EGID, 0),
            (AT_SECURE, 0),
            (AT_RANDOM, random_address),
            (AT_EXECFN, executable_path_address),
        ];
        for (kind, value) in entries {
            self.write_stack_word(slot_index, word_address, kind)?;
            self.write_stack_word(slot_index, word_address + 8, value)?;
            word_address += 16;
        }
        self.write_stack_word(slot_index, word_address, AT_NULL)?;
        self.write_stack_word(slot_index, word_address + 8, 0)?;

        string_address = string_start;
        for value in argv.iter().chain(envp.iter()) {
            self.write_stack_bytes(slot_index, string_address, value)?;
            string_address += value.len() as u64;
            self.write_stack_bytes(slot_index, string_address, &[0])?;
            string_address += 1;
        }
        self.write_stack_bytes(
            slot_index,
            executable_path_address,
            auxiliary.executable_path,
        )?;
        self.write_stack_bytes(
            slot_index,
            executable_path_address + auxiliary.executable_path.len() as u64,
            &[0],
        )?;
        self.write_stack_bytes(slot_index, random_address, &auxiliary.random)?;
        self.slots[slot_index].process_info.initial_stack_pointer = Some(stack_pointer);
        Ok(stack_pointer)
    }

    /// Retries reclamation after a frame-memory backend reported a release
    /// failure. Failed frames remain recorded until this succeeds.
    pub fn retry_cleanup(
        &mut self,
        _authority: &Capability<'_, PhysicalMemoryControl>,
    ) -> Result<(), FrameBackedError<Memory::Error>> {
        if self.active_slot.is_some() {
            return Err(FrameBackedError::InvalidState);
        }
        for slot_index in 0..self.slots.len() {
            if self.slots[slot_index].phase == SpacePhase::Free
                && self.slots[slot_index].owned_frame_count != 0
            {
                self.release_owned(slot_index)?;
            }
        }
        Ok(())
    }

    fn allocate_owned(
        &mut self,
        slot_index: usize,
    ) -> Result<PhysicalAddress, FrameBackedError<Memory::Error>> {
        if self.slots[slot_index].owned_frame_count == self.slots[slot_index].owned_frames.len() {
            return Err(FrameBackedError::CapacityExceeded);
        }
        let frame = self
            .memory
            .allocate_zeroed()
            .map_err(FrameBackedError::Memory)?;
        if !frame.is_page_aligned() || frame.as_u64() & !PAGE_ADDRESS_MASK != 0 {
            self.memory
                .release(frame)
                .map_err(FrameBackedError::Memory)?;
            return Err(FrameBackedError::InvalidPhysicalFrame);
        }
        let frame_index = self.slots[slot_index].owned_frame_count;
        self.slots[slot_index].owned_frames[frame_index] = frame;
        self.slots[slot_index].owned_frame_count += 1;
        Ok(frame)
    }

    fn release_owned(&mut self, slot_index: usize) -> Result<(), FrameBackedError<Memory::Error>> {
        let mut first_error = None;
        let mut retained = [PhysicalAddress::new(0); MAXIMUM_OWNED_FRAMES];
        let mut retained_count = 0;
        for index in (0..self.slots[slot_index].owned_frame_count).rev() {
            let frame = self.slots[slot_index].owned_frames[index];
            if let Err(error) = self.memory.release(frame) {
                retained[retained_count] = frame;
                retained_count += 1;
                if first_error.is_none() {
                    first_error = Some(FrameBackedError::Memory(error));
                }
            }
        }
        self.slots[slot_index].owned_frames = retained;
        self.slots[slot_index].owned_frame_count = retained_count;
        self.slots[slot_index].root = None;
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn release_last_owned(
        &mut self,
        slot_index: usize,
        frame: PhysicalAddress,
    ) -> Result<(), FrameBackedError<Memory::Error>> {
        let Some(index) = self.slots[slot_index].owned_frame_count.checked_sub(1) else {
            return Err(FrameBackedError::CorruptHierarchy);
        };
        if self.slots[slot_index].owned_frames[index] != frame {
            return Err(FrameBackedError::CorruptHierarchy);
        }
        self.memory
            .release(frame)
            .map_err(FrameBackedError::Memory)?;
        self.slots[slot_index].owned_frames[index] = PhysicalAddress::new(0);
        self.slots[slot_index].owned_frame_count = index;
        Ok(())
    }

    fn rollback_stack_install(
        &mut self,
        slot_index: usize,
        owned_before: usize,
        pages_before: usize,
    ) -> Result<(), FrameBackedError<Memory::Error>> {
        while self.slots[slot_index].owned_frame_count > owned_before {
            let frame =
                self.slots[slot_index].owned_frames[self.slots[slot_index].owned_frame_count - 1];
            self.release_last_owned(slot_index, frame)?;
        }
        let page_count = self.slots[slot_index].page_count;
        self.slots[slot_index].pages[pages_before..page_count].fill(PageRecord::EMPTY);
        self.slots[slot_index].page_count = pages_before;
        Ok(())
    }

    fn free_page_run(&self, slot_index: usize, pages_needed: usize) -> Option<usize> {
        if pages_needed == 0 || pages_needed > self.slots[slot_index].pages.len() {
            return None;
        }
        (0..=self.slots[slot_index].pages.len() - pages_needed).find(|start| {
            self.slots[slot_index].pages[*start..*start + pages_needed]
                .iter()
                .all(|page| page.virtual_address == 0)
        })
    }

    fn find_linux_mmap_base(
        &self,
        slot_index: usize,
        hint: u64,
        length: usize,
    ) -> Result<u64, FrameBackedError<Memory::Error>> {
        let mut candidate = if hint == 0 {
            LINUX_MMAP_BASE
        } else {
            hint & !(PAGE_SIZE as u64 - 1)
        };
        if candidate < PAGE_SIZE as u64 {
            candidate = LINUX_MMAP_BASE;
        }
        let length = length as u64;
        loop {
            let end = candidate
                .checked_add(length)
                .ok_or(FrameBackedError::InvalidRange)?;
            if end > 0x0000_8000_0000_0000 {
                return Err(FrameBackedError::CapacityExceeded);
            }

            // Keep the complete bounded brk arena reserved even when the
            // current break has been trimmed back to its base.  Without this
            // guard an explicit mmap hint could occupy the dormant heap and
            // make a later libc brk growth fail nondeterministically.
            let mut next = ranges_overlap(candidate, end, LINUX_BRK_BASE, LINUX_BRK_MAXIMUM_BYTES)
                .then_some(LINUX_BRK_BASE + LINUX_BRK_MAXIMUM_BYTES as u64);
            for mapping in &self.slots[slot_index].mappings {
                if mapping.occupied
                    && ranges_overlap(candidate, end, mapping.virtual_address, mapping.memory_size)
                {
                    let mapping_end = mapping
                        .virtual_address
                        .checked_add(mapping.memory_size as u64)
                        .ok_or(FrameBackedError::InvalidRange)?;
                    next = Some(next.map_or(mapping_end, |value: u64| value.max(mapping_end)));
                }
            }
            for page in &self.slots[slot_index].pages {
                if page.virtual_address != 0
                    && ranges_overlap(candidate, end, page.virtual_address, PAGE_SIZE)
                {
                    let page_end = page
                        .virtual_address
                        .checked_add(PAGE_SIZE as u64)
                        .ok_or(FrameBackedError::InvalidRange)?;
                    next = Some(next.map_or(page_end, |value: u64| value.max(page_end)));
                }
            }
            let Some(next) = next else {
                return Ok(candidate);
            };
            candidate = next
                .checked_add(PAGE_SIZE as u64 - 1)
                .map(|value| value & !(PAGE_SIZE as u64 - 1))
                .ok_or(FrameBackedError::InvalidRange)?;
        }
    }

    fn rollback_linux_mapping_pages(
        &mut self,
        slot_index: usize,
        page_start: usize,
        page_count: usize,
    ) -> Result<(), FrameBackedError<Memory::Error>> {
        for page in 0..page_count {
            let page_index = page_start + page;
            let record = self.slots[slot_index].pages[page_index];
            if record.virtual_address == 0 {
                continue;
            }
            let (table, index) = self.leaf_slot(slot_index, record.virtual_address)?;
            self.memory
                .write_entry(table, index, 0)
                .map_err(FrameBackedError::Memory)?;
            self.release_owned_frame(slot_index, record.frame)?;
            self.slots[slot_index].pages[page_index] = PageRecord::EMPTY;
        }
        Ok(())
    }

    fn checked_mapping_leaf(
        &self,
        slot_index: usize,
        mapping: MappingRecord,
        page: usize,
    ) -> Result<(PhysicalAddress, usize, u64), FrameBackedError<Memory::Error>> {
        let page_index = usize::from(mapping.first_page)
            .checked_add(page)
            .ok_or(FrameBackedError::CorruptHierarchy)?;
        let record = *self.slots[slot_index]
            .pages
            .get(page_index)
            .ok_or(FrameBackedError::CorruptHierarchy)?;
        let expected_address = mapping
            .virtual_address
            .checked_add((page * PAGE_SIZE) as u64)
            .ok_or(FrameBackedError::CorruptHierarchy)?;
        if record.virtual_address != expected_address || record.frame.as_u64() == 0 {
            return Err(FrameBackedError::CorruptHierarchy);
        }
        let (table, index) = self.leaf_slot(slot_index, record.virtual_address)?;
        let entry = self
            .memory
            .read_entry(table, index)
            .map_err(FrameBackedError::Memory)?;
        if entry & (PAGE_ADDRESS_MASK | ENTRY_PRESENT | ENTRY_USER | ENTRY_HUGE)
            != record.frame.as_u64() | ENTRY_PRESENT | ENTRY_USER
        {
            return Err(FrameBackedError::CorruptHierarchy);
        }
        Ok((table, index, entry))
    }

    fn rollback_mapping_permissions(
        &mut self,
        slot_index: usize,
        mapping: MappingRecord,
        changed_pages: usize,
    ) -> Result<(), FrameBackedError<Memory::Error>> {
        for page in 0..changed_pages {
            let (table, index, entry) = self.checked_mapping_leaf(slot_index, mapping, page)?;
            let restored = replace_user_mapping_permissions(entry, mapping.permissions);
            self.memory
                .write_entry(table, index, restored)
                .map_err(FrameBackedError::Memory)?;
            let observed = self
                .memory
                .read_entry(table, index)
                .map_err(FrameBackedError::Memory)?;
            if normalized_user_mapping_entry(observed) != normalized_user_mapping_entry(restored) {
                return Err(FrameBackedError::CorruptHierarchy);
            }
        }
        Ok(())
    }

    fn release_owned_frame(
        &mut self,
        slot_index: usize,
        frame: PhysicalAddress,
    ) -> Result<(), FrameBackedError<Memory::Error>> {
        let Some(index) = self.slots[slot_index].owned_frames
            [..self.slots[slot_index].owned_frame_count]
            .iter()
            .position(|owned| *owned == frame)
        else {
            return Err(FrameBackedError::CorruptHierarchy);
        };
        self.memory
            .release(frame)
            .map_err(FrameBackedError::Memory)?;
        let last = self.slots[slot_index].owned_frame_count - 1;
        self.slots[slot_index].owned_frames[index] = self.slots[slot_index].owned_frames[last];
        self.slots[slot_index].owned_frames[last] = PhysicalAddress::new(0);
        self.slots[slot_index].owned_frame_count = last;
        Ok(())
    }

    fn write_stack_word(
        &mut self,
        slot_index: usize,
        address: u64,
        value: u64,
    ) -> Result<(), FrameBackedError<Memory::Error>> {
        self.write_stack_bytes(slot_index, address, &value.to_le_bytes())
    }

    fn write_stack_bytes(
        &mut self,
        slot_index: usize,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), FrameBackedError<Memory::Error>> {
        let mut copied = 0usize;
        while copied < bytes.len() {
            let current = address
                .checked_add(copied as u64)
                .ok_or(FrameBackedError::InvalidRange)?;
            let page_index = self.slots[slot_index]
                .pages
                .iter()
                .take(self.slots[slot_index].page_count)
                .position(|page| {
                    current >= page.virtual_address
                        && current < page.virtual_address + PAGE_SIZE as u64
                })
                .ok_or(FrameBackedError::InvalidRange)?;
            let page = self.slots[slot_index].pages[page_index];
            let offset = (current - page.virtual_address) as usize;
            let length = (PAGE_SIZE - offset).min(bytes.len() - copied);
            self.memory
                .write_bytes(page.frame, offset, &bytes[copied..copied + length])
                .map_err(FrameBackedError::Memory)?;
            copied += length;
        }
        Ok(())
    }

    fn reset_records(&mut self, slot_index: usize) {
        self.slots[slot_index].mappings.fill(MappingRecord::EMPTY);
        self.slots[slot_index].mapping_count = 0;
        self.slots[slot_index].pages.fill(PageRecord::EMPTY);
        self.slots[slot_index].page_count = 0;
        self.slots[slot_index].initial_stack_pages = 0;
        self.slots[slot_index].heap_break = LINUX_BRK_BASE;
        self.slots[slot_index].process_info = ProcessImageInfo {
            entry_point: 0,
            segment_count: 0,
            address_space_root: None,
            owned_frames: 0,
            initial_stack_pointer: None,
        };
    }

    fn drop_slot_shared_mappings(
        &mut self,
        slot_index: usize,
    ) -> Result<(), FrameBackedError<Memory::Error>> {
        let mapping_count = self.slots[slot_index].mapping_count;
        for index in 0..mapping_count {
            let identity = self.slots[slot_index].mappings[index].shared_identity;
            if self.slots[slot_index].mappings[index].occupied && identity != 0 {
                self.drop_shared_mapping_reference(identity)?;
                self.slots[slot_index].mappings[index].shared_identity = 0;
            }
        }
        Ok(())
    }

    fn initialize_root(
        &mut self,
        slot_index: usize,
    ) -> Result<(), FrameBackedError<Memory::Error>> {
        let root = self.allocate_owned(slot_index)?;
        self.slots[slot_index].root = Some(root);
        for index in USER_PML4_ENTRIES..TABLE_ENTRIES {
            let entry = self
                .memory
                .read_entry(self.kernel_root, index)
                .map_err(FrameBackedError::Memory)?;
            self.memory
                .write_entry(root, index, entry)
                .map_err(FrameBackedError::Memory)?;
        }
        Ok(())
    }

    fn mapping(
        &self,
        mapping: FrameBackedMapping,
    ) -> Result<MappingRecord, FrameBackedError<Memory::Error>> {
        if self.active_slot != Some(mapping.space_slot) {
            return Err(FrameBackedError::InvalidHandle);
        }
        self.slots[usize::from(mapping.space_slot)]
            .mappings
            .get(usize::from(mapping.slot))
            .copied()
            .filter(|record| record.occupied && record.generation == mapping.generation)
            .ok_or(FrameBackedError::InvalidHandle)
    }

    fn ensure_leaf_slot(
        &mut self,
        slot_index: usize,
        virtual_address: u64,
    ) -> Result<(PhysicalAddress, usize), FrameBackedError<Memory::Error>> {
        let indices = page_indices(virtual_address)?;
        if indices[0] >= USER_PML4_ENTRIES {
            return Err(FrameBackedError::InvalidUserRange);
        }
        let mut table = self.slots[slot_index]
            .root
            .ok_or(FrameBackedError::InvalidState)?;
        for index in &indices[..3] {
            let entry = self
                .memory
                .read_entry(table, *index)
                .map_err(FrameBackedError::Memory)?;
            if entry & ENTRY_PRESENT != 0 {
                if entry & ENTRY_HUGE != 0 {
                    return Err(FrameBackedError::MappingConflict);
                }
                table = PhysicalAddress::new(entry & PAGE_ADDRESS_MASK);
            } else {
                let next = self.allocate_owned(slot_index)?;
                self.memory
                    .write_entry(
                        table,
                        *index,
                        next.as_u64() | ENTRY_PRESENT | ENTRY_WRITABLE | ENTRY_USER,
                    )
                    .map_err(FrameBackedError::Memory)?;
                table = next;
            }
        }
        let leaf_index = indices[3];
        let leaf = self
            .memory
            .read_entry(table, leaf_index)
            .map_err(FrameBackedError::Memory)?;
        if leaf != 0 {
            return Err(FrameBackedError::MappingConflict);
        }
        Ok((table, leaf_index))
    }

    fn leaf_slot(
        &self,
        slot_index: usize,
        virtual_address: u64,
    ) -> Result<(PhysicalAddress, usize), FrameBackedError<Memory::Error>> {
        let indices = page_indices(virtual_address)?;
        let mut table = self.slots[slot_index]
            .root
            .ok_or(FrameBackedError::InvalidState)?;
        for index in &indices[..3] {
            let entry = self
                .memory
                .read_entry(table, *index)
                .map_err(FrameBackedError::Memory)?;
            if entry & ENTRY_PRESENT == 0 || entry & ENTRY_HUGE != 0 {
                return Err(FrameBackedError::CorruptHierarchy);
            }
            table = PhysicalAddress::new(entry & PAGE_ADDRESS_MASK);
        }
        Ok((table, indices[3]))
    }

    fn frame_for_mapping_page(
        &self,
        slot_index: usize,
        mapping: MappingRecord,
        page: usize,
    ) -> Result<PhysicalAddress, FrameBackedError<Memory::Error>> {
        if page >= usize::from(mapping.page_count) {
            return Err(FrameBackedError::InvalidRange);
        }
        let frame = self.slots[slot_index]
            .pages
            .get(usize::from(mapping.first_page) + page)
            .map(|record| record.frame)
            .ok_or(FrameBackedError::CorruptHierarchy)?;
        if mapping.shared_identity != 0 {
            let backing = self
                .shared
                .iter()
                .find(|backing| backing.occupied && backing.identity == mapping.shared_identity)
                .ok_or(FrameBackedError::CorruptHierarchy)?;
            let shared_page = usize::from(mapping.shared_page_offset)
                .checked_add(page)
                .ok_or(FrameBackedError::CorruptHierarchy)?;
            if shared_page >= usize::from(backing.allocated_pages)
                || backing.frames[shared_page] != frame
            {
                return Err(FrameBackedError::CorruptHierarchy);
            }
        }
        Ok(frame)
    }

    fn cleanup_transaction(
        &mut self,
        slot_index: usize,
    ) -> Result<(), FrameBackedError<Memory::Error>> {
        self.active_slot = None;
        self.slots[slot_index].phase = SpacePhase::Free;
        self.reset_records(slot_index);
        self.release_owned(slot_index)
    }

    fn process_slot(
        &self,
        process: &ProcessImageHandle,
    ) -> Result<usize, FrameBackedError<Memory::Error>> {
        let slot_index = usize::from(process.slot());
        self.slots
            .get(slot_index)
            .filter(|slot| {
                slot.phase == SpacePhase::Committed && slot.generation == process.generation()
            })
            .map(|_| slot_index)
            .ok_or(FrameBackedError::InvalidHandle)
    }

    pub unsafe fn validate_runtime_activation(
        &mut self,
        process: &ProcessImageHandle,
        _authority: &RuntimeImageControl,
    ) -> Result<(), FrameBackedError<Memory::Error>> {
        // SAFETY: The caller provides the same serialized activation boundary
        // required by the private implementation.
        unsafe { self.validate_process_activation(process) }
    }

    unsafe fn validate_process_activation(
        &mut self,
        process: &ProcessImageHandle,
    ) -> Result<(), FrameBackedError<Memory::Error>> {
        let root = self
            .process_info(process)
            .and_then(|info| info.address_space_root)
            .ok_or(FrameBackedError::InvalidHandle)?;

        #[cfg(target_os = "none")]
        {
            let _interrupt_guard = InterruptGuard::<X86_64>::enter();
            let original_root = unsafe { active_page_table_root() };
            unsafe { load_page_table_root(root) };
            if unsafe { active_page_table_root() } != root {
                unsafe { load_page_table_root(original_root) };
                return Err(FrameBackedError::ActivationFailed);
            }
            unsafe { load_page_table_root(original_root) };
            if unsafe { active_page_table_root() } != original_root {
                return Err(FrameBackedError::RestoreFailed);
            }
        }

        #[cfg(not(target_os = "none"))]
        let _ = root;

        Ok(())
    }
}

impl<Memory: ProcessFrameMemory> UserAddressSpaceBackend for FrameBackedAddressSpace<Memory> {
    type Error = FrameBackedError<Memory::Error>;
    type Space = FrameBackedSpace;
    type Mapping = FrameBackedMapping;
    type Process = ProcessImageHandle;

    fn begin(&mut self, image_start: u64, image_end: u64) -> Result<Self::Space, Self::Error> {
        if self.active_slot.is_some()
            || image_start >= image_end
            || image_end > 0x0000_8000_0000_0000
            || !self.kernel_root.is_page_aligned()
        {
            return Err(FrameBackedError::InvalidState);
        }
        let slot_index = self
            .slots
            .iter()
            .position(|slot| slot.phase == SpacePhase::Free && slot.owned_frame_count == 0)
            .ok_or(FrameBackedError::CapacityExceeded)?;
        self.slots[slot_index].generation = next_generation(self.slots[slot_index].generation);
        self.slots[slot_index].phase = SpacePhase::Staging;
        self.slots[slot_index].image_start = image_start;
        self.slots[slot_index].image_end = image_end;
        self.active_slot = Some(slot_index as u16);
        self.reset_records(slot_index);
        if let Err(error) = self.initialize_root(slot_index) {
            return match self.cleanup_transaction(slot_index) {
                Ok(()) => Err(error),
                Err(cleanup) => Err(cleanup),
            };
        }
        Ok(FrameBackedSpace {
            slot: slot_index as u16,
            generation: self.slots[slot_index].generation,
        })
    }

    fn map_zeroed(
        &mut self,
        space: Self::Space,
        virtual_address: u64,
        memory_size: usize,
    ) -> Result<Self::Mapping, Self::Error> {
        let end = virtual_address
            .checked_add(memory_size as u64)
            .ok_or(FrameBackedError::InvalidRange)?;
        let slot_index = usize::from(space.slot);
        let Some(slot) = self.slots.get(slot_index) else {
            return Err(FrameBackedError::InvalidHandle);
        };
        if self.active_slot != Some(space.slot)
            || slot.phase != SpacePhase::Staging
            || space.generation != slot.generation
            || memory_size == 0
            || virtual_address & (PAGE_SIZE as u64 - 1) != 0
            || virtual_address < slot.image_start
            || end > slot.image_end
        {
            return Err(FrameBackedError::InvalidRange);
        }
        let pages_needed = memory_size.div_ceil(PAGE_SIZE);
        if pages_needed == 0
            || pages_needed > u16::MAX as usize
            || self.slots[slot_index].page_count + pages_needed > self.slots[slot_index].pages.len()
        {
            return Err(FrameBackedError::CapacityExceeded);
        }
        let mapping_index = self.slots[slot_index].mapping_count;
        if mapping_index >= self.slots[slot_index].mappings.len() {
            return Err(FrameBackedError::CapacityExceeded);
        }
        let first_page = self.slots[slot_index].page_count;
        for page in 0..pages_needed {
            let page_virtual = virtual_address
                .checked_add((page * PAGE_SIZE) as u64)
                .ok_or(FrameBackedError::InvalidRange)?;
            let frame = self.allocate_owned(slot_index)?;
            let _ = self.ensure_leaf_slot(slot_index, page_virtual)?;
            let page_index = self.slots[slot_index].page_count;
            self.slots[slot_index].pages[page_index] = PageRecord {
                frame,
                virtual_address: page_virtual,
            };
            self.slots[slot_index].page_count += 1;
        }
        self.slots[slot_index].mappings[mapping_index] = MappingRecord {
            occupied: true,
            sealed: false,
            releasable: false,
            heap: false,
            generation: self.slots[slot_index].generation,
            virtual_address,
            memory_size,
            first_page: u16::try_from(first_page)
                .map_err(|_| FrameBackedError::CapacityExceeded)?,
            page_count: u16::try_from(pages_needed)
                .map_err(|_| FrameBackedError::CapacityExceeded)?,
            permissions: MappingPermissions {
                readable: false,
                writable: false,
                executable: false,
            },
            shared_identity: 0,
            shared_page_offset: 0,
        };
        self.slots[slot_index].mapping_count += 1;
        Ok(FrameBackedMapping {
            space_slot: space.slot,
            slot: mapping_index as u8,
            generation: self.slots[slot_index].generation,
        })
    }

    fn copy_into(
        &mut self,
        mapping: Self::Mapping,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        let record = self.mapping(mapping)?;
        if record.sealed
            || offset
                .checked_add(bytes.len())
                .is_none_or(|end| end > record.memory_size)
        {
            return Err(FrameBackedError::InvalidRange);
        }
        let mut copied = 0;
        while copied < bytes.len() {
            let absolute = offset + copied;
            let page = absolute / PAGE_SIZE;
            let within_page = absolute % PAGE_SIZE;
            let length = (PAGE_SIZE - within_page).min(bytes.len() - copied);
            let frame =
                self.frame_for_mapping_page(usize::from(mapping.space_slot), record, page)?;
            self.memory
                .write_bytes(frame, within_page, &bytes[copied..copied + length])
                .map_err(FrameBackedError::Memory)?;
            copied += length;
        }
        Ok(())
    }

    fn verify_contents(
        &mut self,
        mapping: Self::Mapping,
        segment_offset: usize,
        initialized: &[u8],
        memory_size: usize,
    ) -> Result<bool, Self::Error> {
        let record = self.mapping(mapping)?;
        let segment_end = segment_offset
            .checked_add(memory_size)
            .ok_or(FrameBackedError::InvalidRange)?;
        if record.sealed || segment_end > record.memory_size || initialized.len() > memory_size {
            return Err(FrameBackedError::InvalidRange);
        }

        let mut offset = 0;
        while offset < segment_offset {
            let page = offset / PAGE_SIZE;
            let within_page = offset % PAGE_SIZE;
            let length = (PAGE_SIZE - within_page).min(segment_offset - offset);
            let frame =
                self.frame_for_mapping_page(usize::from(mapping.space_slot), record, page)?;
            if !self
                .memory
                .bytes_zero(frame, within_page, length)
                .map_err(FrameBackedError::Memory)?
            {
                return Ok(false);
            }
            offset += length;
        }

        let initialized_end = segment_offset + initialized.len();
        offset = segment_offset;
        while offset < initialized_end {
            let page = offset / PAGE_SIZE;
            let within_page = offset % PAGE_SIZE;
            let length = (PAGE_SIZE - within_page).min(initialized_end - offset);
            let frame =
                self.frame_for_mapping_page(usize::from(mapping.space_slot), record, page)?;
            if !self
                .memory
                .bytes_equal(
                    frame,
                    within_page,
                    &initialized[offset - segment_offset..offset - segment_offset + length],
                )
                .map_err(FrameBackedError::Memory)?
            {
                return Ok(false);
            }
            offset += length;
        }

        offset = initialized_end;
        while offset < segment_end {
            let page = offset / PAGE_SIZE;
            let within_page = offset % PAGE_SIZE;
            let length = (PAGE_SIZE - within_page).min(segment_end - offset);
            let frame =
                self.frame_for_mapping_page(usize::from(mapping.space_slot), record, page)?;
            if !self
                .memory
                .bytes_zero(frame, within_page, length)
                .map_err(FrameBackedError::Memory)?
            {
                return Ok(false);
            }
            offset += length;
        }

        offset = record.memory_size.min(segment_end);
        while offset < record.memory_size {
            let page = offset / PAGE_SIZE;
            let within_page = offset % PAGE_SIZE;
            let length = (PAGE_SIZE - within_page).min(record.memory_size - offset);
            let frame =
                self.frame_for_mapping_page(usize::from(mapping.space_slot), record, page)?;
            if !self
                .memory
                .bytes_zero(frame, within_page, length)
                .map_err(FrameBackedError::Memory)?
            {
                return Ok(false);
            }
            offset += length;
        }
        Ok(true)
    }

    fn seal(
        &mut self,
        mapping: Self::Mapping,
        permissions: MappingPermissions,
    ) -> Result<(), Self::Error> {
        let record = self.mapping(mapping)?;
        let slot_index = usize::from(mapping.space_slot);
        if record.sealed
            || !permissions.readable
            || (permissions.writable && permissions.executable)
        {
            return Err(FrameBackedError::UnsupportedPermissions);
        }
        for page in 0..usize::from(record.page_count) {
            let page_record = self.slots[slot_index].pages[usize::from(record.first_page) + page];
            let (table, index) = self.leaf_slot(slot_index, page_record.virtual_address)?;
            let mut entry = page_record.frame.as_u64() | ENTRY_PRESENT | ENTRY_USER;
            if permissions.writable {
                entry |= ENTRY_WRITABLE;
            }
            if !permissions.executable {
                entry |= ENTRY_NO_EXECUTE;
            }
            self.memory
                .write_entry(table, index, entry)
                .map_err(FrameBackedError::Memory)?;
        }
        self.slots[slot_index].mappings[usize::from(mapping.slot)].permissions = permissions;
        self.slots[slot_index].mappings[usize::from(mapping.slot)].sealed = true;
        Ok(())
    }

    fn commit(
        &mut self,
        space: Self::Space,
        entry_point: u64,
        segment_count: usize,
    ) -> Result<Self::Process, Self::Error> {
        let slot_index = usize::from(space.slot);
        let Some(slot) = self.slots.get(slot_index) else {
            return Err(FrameBackedError::InvalidHandle);
        };
        if self.active_slot != Some(space.slot)
            || slot.phase != SpacePhase::Staging
            || space.generation != slot.generation
            || slot.mapping_count == 0
            || segment_count == 0
            || segment_count > super::install::MAXIMUM_PROCESS_SEGMENTS
            || slot.mappings[..slot.mapping_count]
                .iter()
                .any(|mapping| !mapping.sealed)
            || !slot.mappings[..slot.mapping_count].iter().any(|mapping| {
                mapping.permissions.executable
                    && entry_point >= mapping.virtual_address
                    && entry_point < mapping.virtual_address + mapping.memory_size as u64
            })
        {
            return Err(FrameBackedError::InvalidState);
        }
        let root = slot.root.ok_or(FrameBackedError::InvalidState)?;
        self.active_slot = None;
        self.slots[slot_index].phase = SpacePhase::Committed;
        self.slots[slot_index].process_info = ProcessImageInfo {
            entry_point,
            segment_count,
            address_space_root: Some(root.as_u64()),
            owned_frames: self.slots[slot_index].owned_frame_count,
            initial_stack_pointer: None,
        };
        Ok(ProcessImageHandle::new(
            space.slot,
            self.slots[slot_index].generation,
        ))
    }

    fn abort(&mut self, space: Self::Space) -> Result<(), Self::Error> {
        let slot_index = usize::from(space.slot);
        if self.active_slot != Some(space.slot)
            || self.slots.get(slot_index).is_none_or(|slot| {
                slot.phase != SpacePhase::Staging || slot.generation != space.generation
            })
        {
            return Err(FrameBackedError::InvalidHandle);
        }
        self.cleanup_transaction(slot_index)
    }

    fn process_info(&self, process: &Self::Process) -> Option<ProcessImageInfo> {
        self.process_slot(process)
            .ok()
            .map(|slot_index| self.slots[slot_index].process_info)
    }

    fn process_generation(&self, process: &Self::Process) -> Option<u32> {
        self.process_info(process).map(|_| process.generation())
    }

    unsafe fn validate_activation(
        &mut self,
        process: &Self::Process,
        _authority: &Capability<'_, ProcessInstallControl>,
    ) -> Result<(), Self::Error> {
        // SAFETY: ProcessInstallControl proves the caller owns the serialized
        // bootstrap activation boundary.
        unsafe { self.validate_process_activation(process) }
    }

    fn release_process(&mut self, process: &Self::Process) -> Result<(), Self::Error> {
        let slot_index = self.process_slot(process)?;
        let root = self.slots[slot_index]
            .process_info
            .address_space_root
            .ok_or(FrameBackedError::InvalidHandle)?;
        #[cfg(target_os = "none")]
        if unsafe { active_page_table_root() } == root {
            return Err(FrameBackedError::ActiveProcess);
        }
        #[cfg(not(target_os = "none"))]
        let _ = root;
        self.drop_slot_shared_mappings(slot_index)?;
        self.slots[slot_index].phase = SpacePhase::Free;
        self.reset_records(slot_index);
        self.release_owned(slot_index)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameBackedError<MemoryError> {
    Memory(MemoryError),
    InvalidState,
    InvalidHandle,
    InvalidRange,
    InvalidUserRange,
    InvalidPhysicalFrame,
    CapacityExceeded,
    MappingConflict,
    CorruptHierarchy,
    UnsupportedPermissions,
    ActivationFailed,
    RestoreFailed,
    ActiveProcess,
}

const fn user_mapping_entry(frame: PhysicalAddress, permissions: MappingPermissions) -> u64 {
    frame.as_u64()
        | ENTRY_PRESENT
        | ENTRY_USER
        | if permissions.writable {
            ENTRY_WRITABLE
        } else {
            0
        }
        | if permissions.executable {
            0
        } else {
            ENTRY_NO_EXECUTE
        }
}

const fn replace_user_mapping_permissions(entry: u64, permissions: MappingPermissions) -> u64 {
    (entry & !(ENTRY_WRITABLE | ENTRY_NO_EXECUTE))
        | if permissions.writable {
            ENTRY_WRITABLE
        } else {
            0
        }
        | if permissions.executable {
            0
        } else {
            ENTRY_NO_EXECUTE
        }
}

const fn normalized_user_mapping_entry(entry: u64) -> u64 {
    entry & !(ENTRY_ACCESSED | ENTRY_DIRTY)
}

fn page_indices<MemoryError>(address: u64) -> Result<[usize; 4], FrameBackedError<MemoryError>> {
    if address >= 0x0000_8000_0000_0000 {
        return Err(FrameBackedError::InvalidUserRange);
    }
    Ok([
        ((address >> 39) & 0x1ff) as usize,
        ((address >> 30) & 0x1ff) as usize,
        ((address >> 21) & 0x1ff) as usize,
        ((address >> 12) & 0x1ff) as usize,
    ])
}

fn ranges_overlap(left_start: u64, left_end: u64, right_start: u64, right_size: usize) -> bool {
    let Some(right_end) = right_start.checked_add(right_size as u64) else {
        return true;
    };
    left_start < right_end && right_start < left_end
}

const fn next_generation(generation: u32) -> u32 {
    let next = generation.wrapping_add(1);
    if next == 0 { 1 } else { next }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::boxed::Box;
    use blacklab::oureboros::{
        FractalCatalog, FractalClass, FractalRecipe, FractalSeed, MINIMAL_X86_64_ELF_BYTES,
        TargetArchitecture, measure_recipe,
    };
    use std::thread;

    use crate::capability::{Authority, ProcessInstallControl, UserlandImageControl};
    use crate::module::loader::{POSITION_INDEPENDENT_LOAD_BASE, RUNTIME_LINKER_LOAD_BASE};
    use crate::process::image::prepare_user_image;
    use crate::process::install::{InstallError, install_user_image};

    use super::*;

    struct TestMemory<const FRAMES: usize> {
        frames: [[u8; PAGE_SIZE]; FRAMES],
        allocated: [bool; FRAMES],
        fail_release_once: bool,
        fail_write_entry_after: Option<usize>,
    }

    impl<const FRAMES: usize> TestMemory<FRAMES> {
        const fn new() -> Self {
            Self {
                frames: [[0; PAGE_SIZE]; FRAMES],
                allocated: [false; FRAMES],
                fail_release_once: false,
                fail_write_entry_after: None,
            }
        }

        fn in_use(&self) -> usize {
            self.allocated
                .iter()
                .filter(|allocated| **allocated)
                .count()
        }

        fn range(
            &self,
            frame: PhysicalAddress,
            offset: usize,
            length: usize,
        ) -> Result<(usize, core::ops::Range<usize>), TestMemoryError> {
            let index = usize::try_from(frame.as_u64() / PAGE_SIZE as u64)
                .map_err(|_| TestMemoryError::Invalid)?;
            let end = offset.checked_add(length).ok_or(TestMemoryError::Invalid)?;
            if index >= FRAMES || end > PAGE_SIZE {
                return Err(TestMemoryError::Invalid);
            }
            Ok((index, offset..end))
        }
    }

    impl<const FRAMES: usize> ProcessFrameMemory for TestMemory<FRAMES> {
        type Error = TestMemoryError;

        fn allocate_zeroed(&mut self) -> Result<PhysicalAddress, Self::Error> {
            let index = self
                .allocated
                .iter()
                .enumerate()
                .skip(1)
                .find_map(|(index, allocated)| (!*allocated).then_some(index))
                .ok_or(TestMemoryError::Exhausted)?;
            self.allocated[index] = true;
            self.frames[index].fill(0);
            Ok(PhysicalAddress::new((index * PAGE_SIZE) as u64))
        }

        fn release(&mut self, frame: PhysicalAddress) -> Result<(), Self::Error> {
            let (index, _) = self.range(frame, 0, PAGE_SIZE)?;
            if !self.allocated[index] {
                return Err(TestMemoryError::Invalid);
            }
            if self.fail_release_once {
                self.fail_release_once = false;
                return Err(TestMemoryError::ReleaseFailed);
            }
            self.allocated[index] = false;
            self.frames[index].fill(0);
            Ok(())
        }

        fn read_entry(&self, table: PhysicalAddress, index: usize) -> Result<u64, Self::Error> {
            let (frame, range) = self.range(table, index * 8, 8)?;
            Ok(u64::from_le_bytes(
                self.frames[frame][range]
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
            if let Some(remaining) = self.fail_write_entry_after {
                if remaining == 0 {
                    self.fail_write_entry_after = None;
                    return Err(TestMemoryError::WriteFailed);
                }
                self.fail_write_entry_after = Some(remaining - 1);
            }
            let (frame, range) = self.range(table, index * 8, 8)?;
            self.frames[frame][range].copy_from_slice(&value.to_le_bytes());
            Ok(())
        }

        fn write_bytes(
            &mut self,
            frame: PhysicalAddress,
            offset: usize,
            bytes: &[u8],
        ) -> Result<(), Self::Error> {
            let (frame, range) = self.range(frame, offset, bytes.len())?;
            self.frames[frame][range].copy_from_slice(bytes);
            Ok(())
        }

        fn read_bytes(
            &self,
            frame: PhysicalAddress,
            offset: usize,
            destination: &mut [u8],
        ) -> Result<(), Self::Error> {
            let (frame, range) = self.range(frame, offset, destination.len())?;
            destination.copy_from_slice(&self.frames[frame][range]);
            Ok(())
        }

        fn bytes_equal(
            &self,
            frame: PhysicalAddress,
            offset: usize,
            bytes: &[u8],
        ) -> Result<bool, Self::Error> {
            let (frame, range) = self.range(frame, offset, bytes.len())?;
            Ok(self.frames[frame][range] == *bytes)
        }

        fn bytes_zero(
            &self,
            frame: PhysicalAddress,
            offset: usize,
            length: usize,
        ) -> Result<bool, Self::Error> {
            let (frame, range) = self.range(frame, offset, length)?;
            Ok(self.frames[frame][range].iter().all(|byte| *byte == 0))
        }
    }

    impl<const FRAMES: usize> ProcessFrameMemory for Box<TestMemory<FRAMES>> {
        type Error = TestMemoryError;

        fn allocate_zeroed(&mut self) -> Result<PhysicalAddress, Self::Error> {
            (**self).allocate_zeroed()
        }
        fn release(&mut self, frame: PhysicalAddress) -> Result<(), Self::Error> {
            (**self).release(frame)
        }
        fn read_entry(&self, table: PhysicalAddress, index: usize) -> Result<u64, Self::Error> {
            (**self).read_entry(table, index)
        }
        fn write_entry(
            &mut self,
            table: PhysicalAddress,
            index: usize,
            value: u64,
        ) -> Result<(), Self::Error> {
            (**self).write_entry(table, index, value)
        }
        fn write_bytes(
            &mut self,
            frame: PhysicalAddress,
            offset: usize,
            bytes: &[u8],
        ) -> Result<(), Self::Error> {
            (**self).write_bytes(frame, offset, bytes)
        }
        fn read_bytes(
            &self,
            frame: PhysicalAddress,
            offset: usize,
            destination: &mut [u8],
        ) -> Result<(), Self::Error> {
            (**self).read_bytes(frame, offset, destination)
        }
        fn bytes_equal(
            &self,
            frame: PhysicalAddress,
            offset: usize,
            bytes: &[u8],
        ) -> Result<bool, Self::Error> {
            (**self).bytes_equal(frame, offset, bytes)
        }
        fn bytes_zero(
            &self,
            frame: PhysicalAddress,
            offset: usize,
            length: usize,
        ) -> Result<bool, Self::Error> {
            (**self).bytes_zero(frame, offset, length)
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestMemoryError {
        Exhausted,
        Invalid,
        ReleaseFailed,
        WriteFailed,
    }

    fn catalog() -> FractalCatalog {
        let recipe = FractalRecipe {
            algorithm_version: 2,
            base_entropy: 1,
            structural_mutator: 2,
        };
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
        catalog
    }

    fn read_user_bytes<const FRAMES: usize>(
        backend: &FrameBackedAddressSpace<Box<TestMemory<FRAMES>>>,
        process: &ProcessImageHandle,
        address: u64,
        output: &mut [u8],
    ) {
        let slot_index = backend.process_slot(process).unwrap();
        let page = backend.slots[slot_index]
            .pages
            .iter()
            .take(backend.slots[slot_index].page_count)
            .find(|page| {
                address >= page.virtual_address
                    && address + output.len() as u64 <= page.virtual_address + PAGE_SIZE as u64
            })
            .unwrap();
        backend
            .memory()
            .read_bytes(
                page.frame,
                (address - page.virtual_address) as usize,
                output,
            )
            .unwrap();
    }

    fn read_user_u64<const FRAMES: usize>(
        backend: &FrameBackedAddressSpace<Box<TestMemory<FRAMES>>>,
        process: &ProcessImageHandle,
        address: u64,
    ) -> u64 {
        let mut bytes = [0_u8; 8];
        read_user_bytes(backend, process, address, &mut bytes);
        u64::from_le_bytes(bytes)
    }

    #[test]
    fn builds_hardware_entries_and_reclaims_every_owned_frame() {
        let mut memory = Box::new(TestMemory::<176>::new());
        let inherited = 0x1234_5000 | ENTRY_PRESENT | ENTRY_WRITABLE;
        memory
            .write_entry(PhysicalAddress::new(0), 256, inherited)
            .unwrap();
        let authority = unsafe { Authority::assume_root() };
        let install_control = authority.grant::<ProcessInstallControl>();
        let mut backend =
            FrameBackedAddressSpace::new(memory, PhysicalAddress::new(0), &install_control);
        let catalog = catalog();
        let mut bytes = [0_u8; MINIMAL_X86_64_ELF_BYTES];
        let image_control = authority.grant::<UserlandImageControl>();
        let artifact = catalog.materialize(1, &mut bytes).unwrap();
        let image = prepare_user_image(artifact, &image_control).unwrap();
        let installed = install_user_image(image, &mut backend, &install_control).unwrap();
        let info = backend.process_info(&installed.process).unwrap();
        // SAFETY: Host tests exercise structural activation validation only;
        // privileged CR3 switching is compiled solely for the bare-metal target.
        unsafe {
            backend
                .validate_activation(&installed.process, &install_control)
                .unwrap();
        }
        let root = PhysicalAddress::new(info.address_space_root.unwrap());
        assert_eq!(info.owned_frames, 5);
        assert_eq!(backend.memory().read_entry(root, 256), Ok(inherited));
        assert_eq!(
            backend.install_initial_stack(&installed.process, &install_control),
            Ok(INITIAL_USER_STACK_POINTER)
        );
        let stacked = backend.process_info(&installed.process).unwrap();
        // The 4 MiB stack base crosses two fresh page-table levels in this
        // synthetic hierarchy in addition to the stack data frames.
        assert_eq!(stacked.owned_frames, 5 + INITIAL_USER_STACK_PAGES + 2);
        assert_eq!(
            stacked.initial_stack_pointer,
            Some(INITIAL_USER_STACK_POINTER)
        );
        let stack_pointer = backend
            .prepare_initial_stack(&installed.process, &[b"rustd"], &[b"ARACH_PROCESS=rustd"])
            .unwrap();
        assert_eq!(stack_pointer & 0xf, 0);
        assert!(stack_pointer < INITIAL_USER_STACK_POINTER);

        let large_argument = [b'x'; PAGE_SIZE + 128];
        let large_stack_pointer = backend
            .prepare_initial_stack(&installed.process, &[&large_argument], &[])
            .unwrap();
        assert_eq!(large_stack_pointer & 0xf, 0);
        assert!(large_stack_pointer + (PAGE_SIZE as u64) < INITIAL_USER_STACK_POINTER);

        let p3 = backend.memory().read_entry(root, 0).unwrap() & PAGE_ADDRESS_MASK;
        let p2 = backend
            .memory()
            .read_entry(PhysicalAddress::new(p3), 0)
            .unwrap()
            & PAGE_ADDRESS_MASK;
        let p1 = backend
            .memory()
            .read_entry(
                PhysicalAddress::new(p2),
                ((POSITION_INDEPENDENT_LOAD_BASE >> 21) & 0x1ff) as usize,
            )
            .unwrap()
            & PAGE_ADDRESS_MASK;
        let leaf = backend
            .memory()
            .read_entry(
                PhysicalAddress::new(p1),
                ((POSITION_INDEPENDENT_LOAD_BASE >> 12) & 0x1ff) as usize,
            )
            .unwrap();
        assert_eq!(
            leaf & (ENTRY_PRESENT | ENTRY_USER),
            ENTRY_PRESENT | ENTRY_USER
        );
        assert_eq!(leaf & (ENTRY_WRITABLE | ENTRY_NO_EXECUTE), 0);
        let data = PhysicalAddress::new(leaf & PAGE_ADDRESS_MASK);
        assert_eq!(
            backend
                .memory()
                .bytes_equal(data, 34, b"PID1 syscall write\n"),
            Ok(true)
        );
        assert_eq!(
            backend.memory().bytes_zero(data, 53, PAGE_SIZE - 53),
            Ok(true)
        );
        assert_eq!(
            backend.install_initial_stack(&installed.process, &install_control),
            Err(FrameBackedError::InvalidState)
        );

        backend.release_process(&installed.process).unwrap();
        assert_eq!(backend.process_info(&installed.process), None);
        // SAFETY: This verifies that released handles cannot authorize a later
        // activation; no privileged operation is compiled into this host test.
        assert_eq!(
            unsafe { backend.validate_activation(&installed.process, &install_control) },
            Err(FrameBackedError::InvalidHandle)
        );
        assert_eq!(backend.memory().in_use(), 0);
    }

    #[test]
    fn builds_a_complete_dynamic_linux_auxiliary_vector() {
        let memory = Box::new(TestMemory::<176>::new());
        let authority = unsafe { Authority::assume_root() };
        let install_control = authority.grant::<ProcessInstallControl>();
        let image_control = authority.grant::<UserlandImageControl>();
        let mut backend =
            FrameBackedAddressSpace::new(memory, PhysicalAddress::new(0), &install_control);
        let catalog = catalog();
        let mut bytes = [0_u8; MINIMAL_X86_64_ELF_BYTES];
        let image = prepare_user_image(catalog.materialize(1, &mut bytes).unwrap(), &image_control)
            .unwrap();
        let installed = install_user_image(image, &mut backend, &install_control).unwrap();
        backend
            .install_initial_stack(&installed.process, &install_control)
            .unwrap();
        let random = [0xa5; 16];
        let stack_pointer = backend
            .prepare_linux_dynamic_stack(
                &installed.process,
                &[b"dynamic-main"],
                &[b"ARACH_DYNAMIC=1"],
                LinuxAuxiliaryVector {
                    program_header_address: 0x1000_0040,
                    program_header_count: 2,
                    runtime_linker_base: RUNTIME_LINKER_LOAD_BASE,
                    executable_entry_point: 0x1000_00b0,
                    executable_path: b"/dynamic-main",
                    random,
                },
            )
            .unwrap();
        assert_eq!(stack_pointer & 0xf, 0);
        assert_eq!(
            read_user_u64(&backend, &installed.process, stack_pointer),
            1
        );
        assert_ne!(
            read_user_u64(&backend, &installed.process, stack_pointer + 8),
            0
        );
        assert_eq!(
            read_user_u64(&backend, &installed.process, stack_pointer + 16),
            0
        );
        assert_ne!(
            read_user_u64(&backend, &installed.process, stack_pointer + 24),
            0
        );
        assert_eq!(
            read_user_u64(&backend, &installed.process, stack_pointer + 32),
            0
        );

        let mut auxiliary_address = stack_pointer + 40;
        let mut random_address = 0;
        let mut executable_path_address = 0;
        loop {
            let kind = read_user_u64(&backend, &installed.process, auxiliary_address);
            let value = read_user_u64(&backend, &installed.process, auxiliary_address + 8);
            if kind == 0 {
                assert_eq!(value, 0);
                break;
            }
            match kind {
                3 => assert_eq!(value, 0x1000_0040),
                4 => assert_eq!(value, 56),
                5 => assert_eq!(value, 2),
                6 => assert_eq!(value, PAGE_SIZE as u64),
                7 => assert_eq!(value, RUNTIME_LINKER_LOAD_BASE),
                9 => assert_eq!(value, 0x1000_00b0),
                25 => random_address = value,
                31 => executable_path_address = value,
                _ => {}
            }
            auxiliary_address += 16;
        }
        let mut actual_path = [0_u8; 14];
        read_user_bytes(
            &backend,
            &installed.process,
            executable_path_address,
            &mut actual_path,
        );
        assert_eq!(&actual_path, b"/dynamic-main\0");
        let mut actual_random = [0_u8; 16];
        read_user_bytes(
            &backend,
            &installed.process,
            random_address,
            &mut actual_random,
        );
        assert_eq!(actual_random, random);

        backend.release_process(&installed.process).unwrap();
        assert_eq!(backend.memory().in_use(), 0);
    }

    #[test]
    fn linux_anonymous_mapping_has_real_pages_and_can_be_unmapped() {
        let mut memory = Box::new(TestMemory::<176>::new());
        memory
            .write_entry(
                PhysicalAddress::new(0),
                256,
                0x1234_5000 | ENTRY_PRESENT | ENTRY_WRITABLE,
            )
            .unwrap();
        let authority = unsafe { Authority::assume_root() };
        let install_control = authority.grant::<ProcessInstallControl>();
        let mut backend =
            FrameBackedAddressSpace::new(memory, PhysicalAddress::new(0), &install_control);
        let catalog = catalog();
        let mut bytes = [0_u8; MINIMAL_X86_64_ELF_BYTES];
        let image_control = authority.grant::<UserlandImageControl>();
        let image = prepare_user_image(catalog.materialize(1, &mut bytes).unwrap(), &image_control)
            .unwrap();
        let installed = install_user_image(image, &mut backend, &install_control).unwrap();
        let before = backend
            .process_info(&installed.process)
            .unwrap()
            .owned_frames;
        let address = backend
            .linux_mmap_anonymous(
                &installed.process,
                0,
                PAGE_SIZE * 2,
                MappingPermissions {
                    readable: true,
                    writable: true,
                    executable: false,
                },
            )
            .unwrap();
        assert_eq!(address, LINUX_MMAP_BASE);
        let root = PhysicalAddress::new(
            backend
                .process_info(&installed.process)
                .unwrap()
                .address_space_root
                .unwrap(),
        );
        let p3 = backend.memory().read_entry(root, 0).unwrap() & PAGE_ADDRESS_MASK;
        let p2 = backend
            .memory()
            .read_entry(PhysicalAddress::new(p3), 1)
            .unwrap()
            & PAGE_ADDRESS_MASK;
        let p1 = backend
            .memory()
            .read_entry(PhysicalAddress::new(p2), 0)
            .unwrap()
            & PAGE_ADDRESS_MASK;
        let leaf = backend
            .memory()
            .read_entry(PhysicalAddress::new(p1), 0)
            .unwrap();
        assert_eq!(
            leaf & (ENTRY_PRESENT | ENTRY_USER | ENTRY_WRITABLE),
            ENTRY_PRESENT | ENTRY_USER | ENTRY_WRITABLE
        );
        assert_ne!(leaf & ENTRY_NO_EXECUTE, 0);
        let mapped_frame = PhysicalAddress::new(leaf & PAGE_ADDRESS_MASK);
        assert_eq!(
            backend.memory().bytes_zero(mapped_frame, 0, PAGE_SIZE),
            Ok(true)
        );
        let after_map = backend
            .process_info(&installed.process)
            .unwrap()
            .owned_frames;
        assert!(after_map >= before + 2);

        backend
            .linux_munmap(&installed.process, address, PAGE_SIZE * 2)
            .unwrap();
        let after_unmap = backend
            .process_info(&installed.process)
            .unwrap()
            .owned_frames;
        assert_eq!(after_unmap, after_map - 2);
        assert_eq!(
            backend
                .linux_mmap_anonymous(
                    &installed.process,
                    address,
                    PAGE_SIZE,
                    MappingPermissions {
                        readable: true,
                        writable: false,
                        executable: false,
                    },
                )
                .unwrap(),
            address
        );
        assert_eq!(
            backend.linux_mmap_anonymous(
                &installed.process,
                0,
                PAGE_SIZE,
                MappingPermissions {
                    readable: true,
                    writable: true,
                    executable: true,
                },
            ),
            Err(FrameBackedError::InvalidRange)
        );
    }

    #[test]
    fn shared_memfd_frames_alias_across_processes_and_outlive_the_descriptor() {
        let mut memory = Box::new(TestMemory::<176>::new());
        memory
            .write_entry(
                PhysicalAddress::new(0),
                256,
                0x1234_5000 | ENTRY_PRESENT | ENTRY_WRITABLE,
            )
            .unwrap();
        let authority = unsafe { Authority::assume_root() };
        let install_control = authority.grant::<ProcessInstallControl>();
        let image_control = authority.grant::<UserlandImageControl>();
        let mut backend =
            FrameBackedAddressSpace::new(memory, PhysicalAddress::new(0), &install_control);
        let catalog = catalog();

        let mut first_bytes = [0_u8; MINIMAL_X86_64_ELF_BYTES];
        let first_image = prepare_user_image(
            catalog.materialize(1, &mut first_bytes).unwrap(),
            &image_control,
        )
        .unwrap();
        let first = install_user_image(first_image, &mut backend, &install_control).unwrap();
        let mut second_bytes = [0_u8; MINIMAL_X86_64_ELF_BYTES];
        let second_image = prepare_user_image(
            catalog.materialize(1, &mut second_bytes).unwrap(),
            &image_control,
        )
        .unwrap();
        let second = install_user_image(second_image, &mut backend, &install_control).unwrap();

        const IDENTITY: u32 = 0x5348_4d31;
        let writable = MappingPermissions {
            readable: true,
            writable: true,
            executable: false,
        };
        backend.linux_shared_memory_create(IDENTITY).unwrap();
        backend
            .linux_shared_memory_resize(IDENTITY, 0, PAGE_SIZE * 2)
            .unwrap();
        let first_address = backend
            .linux_mmap_shared(&first.process, IDENTITY, 0, PAGE_SIZE * 2, 0, writable)
            .unwrap();
        let second_address = backend
            .linux_mmap_shared(&second.process, IDENTITY, 0, PAGE_SIZE, PAGE_SIZE, writable)
            .unwrap();

        let first_slot = backend.process_slot(&first.process).unwrap();
        let second_slot = backend.process_slot(&second.process).unwrap();
        let first_frame = backend.slots[first_slot]
            .pages
            .iter()
            .find(|page| page.virtual_address == first_address + PAGE_SIZE as u64)
            .unwrap()
            .frame;
        let second_frame = backend.slots[second_slot]
            .pages
            .iter()
            .find(|page| page.virtual_address == second_address)
            .unwrap()
            .frame;
        assert_eq!(first_frame, second_frame);
        backend
            .memory_mut()
            .write_bytes(first_frame, 37, b"cross-process-shared-frame")
            .unwrap();
        let mut observed = [0_u8; 26];
        read_user_bytes(
            &backend,
            &second.process,
            second_address + 37,
            &mut observed,
        );
        assert_eq!(&observed, b"cross-process-shared-frame");

        assert_eq!(
            backend.linux_shared_memory_resize(IDENTITY, PAGE_SIZE * 2, PAGE_SIZE),
            Err(FrameBackedError::InvalidState)
        );
        backend.linux_shared_memory_close(IDENTITY).unwrap();
        let retained = backend
            .shared
            .iter()
            .find(|backing| backing.occupied && backing.identity == IDENTITY)
            .unwrap();
        assert!(!retained.descriptor_open);
        assert_eq!(retained.mapping_references, 2);

        backend
            .linux_munmap(&first.process, first_address, PAGE_SIZE * 2)
            .unwrap();
        let mut after_sender_unmap = [0_u8; 26];
        read_user_bytes(
            &backend,
            &second.process,
            second_address + 37,
            &mut after_sender_unmap,
        );
        assert_eq!(after_sender_unmap, observed);
        backend.memory_mut().fail_release_once = true;
        assert_eq!(
            backend.linux_munmap(&second.process, second_address, PAGE_SIZE),
            Err(FrameBackedError::Memory(TestMemoryError::ReleaseFailed))
        );
        let retained_after_failure = backend
            .shared
            .iter()
            .find(|backing| backing.occupied && backing.identity == IDENTITY)
            .unwrap();
        assert_eq!(retained_after_failure.mapping_references, 1);
        backend
            .linux_munmap(&second.process, second_address, PAGE_SIZE)
            .unwrap();
        assert!(
            backend
                .shared
                .iter()
                .all(|backing| !backing.occupied || backing.identity != IDENTITY)
        );
        let shared_frame_index = usize::try_from(second_frame.as_u64()).unwrap() / PAGE_SIZE;
        assert!(!backend.memory().allocated[shared_frame_index]);

        backend.release_process(&first.process).unwrap();
        backend.release_process(&second.process).unwrap();
        assert_eq!(backend.memory().in_use(), 0);
    }

    #[test]
    fn linux_file_mapping_copies_bytes_and_mprotect_rolls_back_exactly() {
        let mut memory = Box::new(TestMemory::<176>::new());
        memory
            .write_entry(
                PhysicalAddress::new(0),
                256,
                0x1234_5000 | ENTRY_PRESENT | ENTRY_WRITABLE,
            )
            .unwrap();
        let authority = unsafe { Authority::assume_root() };
        let install_control = authority.grant::<ProcessInstallControl>();
        let mut backend =
            FrameBackedAddressSpace::new(memory, PhysicalAddress::new(0), &install_control);
        let catalog = catalog();
        let mut image_bytes = [0_u8; MINIMAL_X86_64_ELF_BYTES];
        let image = prepare_user_image(
            catalog.materialize(1, &mut image_bytes).unwrap(),
            &authority.grant::<UserlandImageControl>(),
        )
        .unwrap();
        let installed = install_user_image(image, &mut backend, &install_control).unwrap();

        let mut initialized = [0_u8; PAGE_SIZE + 7];
        for (index, byte) in initialized.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(17).wrapping_add(3);
        }
        let writable = MappingPermissions {
            readable: true,
            writable: true,
            executable: false,
        };
        let executable = MappingPermissions {
            readable: true,
            writable: false,
            executable: true,
        };
        let mapped = backend
            .linux_mmap_file_private(&installed.process, 0, PAGE_SIZE * 2, writable, &initialized)
            .unwrap();
        let mut first = [0_u8; 32];
        read_user_bytes(&backend, &installed.process, mapped, &mut first);
        assert_eq!(first, initialized[..first.len()]);
        let mut second = [0_u8; 7];
        read_user_bytes(
            &backend,
            &installed.process,
            mapped + PAGE_SIZE as u64,
            &mut second,
        );
        assert_eq!(second, initialized[PAGE_SIZE..]);

        let slot_index = backend.process_slot(&installed.process).unwrap();
        let mut leaves = [(PhysicalAddress::new(0), 0_usize); 2];
        for (page, leaf) in leaves.iter_mut().enumerate() {
            *leaf = backend
                .leaf_slot(slot_index, mapped + (page * PAGE_SIZE) as u64)
                .unwrap();
            let entry = backend.memory().read_entry(leaf.0, leaf.1).unwrap();
            backend
                .memory_mut()
                .write_entry(leaf.0, leaf.1, entry | ENTRY_ACCESSED | ENTRY_DIRTY)
                .unwrap();
        }

        backend
            .linux_mprotect(&installed.process, mapped, PAGE_SIZE * 2, executable)
            .unwrap();
        for (table, index) in leaves {
            let entry = backend.memory().read_entry(table, index).unwrap();
            assert_eq!(entry & ENTRY_WRITABLE, 0);
            assert_eq!(entry & ENTRY_NO_EXECUTE, 0);
            assert_eq!(
                entry & (ENTRY_ACCESSED | ENTRY_DIRTY),
                ENTRY_ACCESSED | ENTRY_DIRTY
            );
        }
        assert_eq!(
            backend.linux_mprotect(&installed.process, mapped, PAGE_SIZE, writable),
            Err(FrameBackedError::InvalidRange)
        );
        assert_eq!(
            backend.linux_mprotect(
                &installed.process,
                mapped,
                PAGE_SIZE * 2,
                MappingPermissions {
                    readable: true,
                    writable: true,
                    executable: true,
                },
            ),
            Err(FrameBackedError::InvalidRange)
        );

        backend.memory_mut().fail_write_entry_after = Some(1);
        assert_eq!(
            backend.linux_mprotect(&installed.process, mapped, PAGE_SIZE * 2, writable),
            Err(FrameBackedError::Memory(TestMemoryError::WriteFailed))
        );
        for (table, index) in leaves {
            let entry = backend.memory().read_entry(table, index).unwrap();
            assert_eq!(entry & ENTRY_WRITABLE, 0);
            assert_eq!(entry & ENTRY_NO_EXECUTE, 0);
        }
        backend
            .linux_mprotect(&installed.process, mapped, PAGE_SIZE * 2, writable)
            .unwrap();
        for (table, index) in leaves {
            let entry = backend.memory().read_entry(table, index).unwrap();
            assert_ne!(entry & ENTRY_WRITABLE, 0);
            assert_ne!(entry & ENTRY_NO_EXECUTE, 0);
        }
    }

    #[test]
    fn linux_brk_grows_with_zeroed_writable_pages_and_shrinks() {
        let mut memory = Box::new(TestMemory::<176>::new());
        memory
            .write_entry(
                PhysicalAddress::new(0),
                256,
                0x1234_5000 | ENTRY_PRESENT | ENTRY_WRITABLE,
            )
            .unwrap();
        let authority = unsafe { Authority::assume_root() };
        let install_control = authority.grant::<ProcessInstallControl>();
        let mut backend =
            FrameBackedAddressSpace::new(memory, PhysicalAddress::new(0), &install_control);
        let catalog = catalog();
        let mut bytes = [0_u8; MINIMAL_X86_64_ELF_BYTES];
        let image = prepare_user_image(
            catalog.materialize(1, &mut bytes).unwrap(),
            &authority.grant::<UserlandImageControl>(),
        )
        .unwrap();
        let installed = install_user_image(image, &mut backend, &install_control).unwrap();

        assert_eq!(backend.linux_brk(&installed.process, 0), Ok(LINUX_BRK_BASE));
        let before = backend
            .process_info(&installed.process)
            .unwrap()
            .owned_frames;
        let requested = LINUX_BRK_BASE + PAGE_SIZE as u64 + 7;
        assert_eq!(
            backend.linux_brk(&installed.process, requested),
            Ok(requested)
        );
        let after_growth = backend
            .process_info(&installed.process)
            .unwrap()
            .owned_frames;
        assert!(after_growth >= before + 2);

        let root = PhysicalAddress::new(
            backend
                .process_info(&installed.process)
                .unwrap()
                .address_space_root
                .unwrap(),
        );
        let indices = page_indices::<TestMemoryError>(LINUX_BRK_BASE).unwrap();
        let p3 = backend.memory().read_entry(root, indices[0]).unwrap() & PAGE_ADDRESS_MASK;
        let p2 = backend
            .memory()
            .read_entry(PhysicalAddress::new(p3), indices[1])
            .unwrap()
            & PAGE_ADDRESS_MASK;
        let p1 = backend
            .memory()
            .read_entry(PhysicalAddress::new(p2), indices[2])
            .unwrap()
            & PAGE_ADDRESS_MASK;
        let leaf = backend
            .memory()
            .read_entry(PhysicalAddress::new(p1), indices[3])
            .unwrap();
        assert_eq!(
            leaf & (ENTRY_PRESENT | ENTRY_USER | ENTRY_WRITABLE),
            ENTRY_PRESENT | ENTRY_USER | ENTRY_WRITABLE
        );
        assert_ne!(leaf & ENTRY_NO_EXECUTE, 0);
        assert_eq!(
            backend.memory().bytes_zero(
                PhysicalAddress::new(leaf & PAGE_ADDRESS_MASK),
                0,
                PAGE_SIZE
            ),
            Ok(true)
        );

        let one_page = LINUX_BRK_BASE + 1;
        assert_eq!(
            backend.linux_brk(&installed.process, one_page),
            Ok(one_page)
        );
        let after_shrink = backend
            .process_info(&installed.process)
            .unwrap()
            .owned_frames;
        assert_eq!(after_shrink, after_growth - 1);
        assert_eq!(
            backend.linux_brk(&installed.process, LINUX_BRK_BASE),
            Ok(LINUX_BRK_BASE)
        );
        assert_eq!(
            backend
                .process_info(&installed.process)
                .unwrap()
                .owned_frames,
            after_shrink - 1
        );
        let mmap = backend
            .linux_mmap_anonymous(
                &installed.process,
                LINUX_BRK_BASE,
                PAGE_SIZE,
                MappingPermissions {
                    readable: true,
                    writable: true,
                    executable: false,
                },
            )
            .unwrap();
        assert!(mmap >= LINUX_BRK_BASE + LINUX_BRK_MAXIMUM_BYTES as u64);
        backend
            .linux_munmap(&installed.process, mmap, PAGE_SIZE)
            .unwrap();
        assert_eq!(backend.linux_brk(&installed.process, 0), Ok(LINUX_BRK_BASE));
    }

    #[test]
    fn retains_a_measured_image_with_an_explicit_larger_stack_budget() {
        let memory = Box::new(TestMemory::<176>::new());
        let authority = unsafe { Authority::assume_root() };
        let image_control = authority.grant::<UserlandImageControl>();
        let install_control = authority.grant::<ProcessInstallControl>();
        let mut backend =
            FrameBackedAddressSpace::new(memory, PhysicalAddress::new(0), &install_control);
        let catalog = catalog();
        let mut bytes = [0_u8; MINIMAL_X86_64_ELF_BYTES];
        let artifact = catalog.materialize(1, &mut bytes).unwrap();
        let image = prepare_user_image(artifact, &image_control).unwrap();
        let installed = install_user_image(image, &mut backend, &install_control).unwrap();

        const BOOTSTRAP_STACK_PAGES: usize = 160;
        let expected_initial_pointer = INITIAL_USER_STACK_POINTER;
        assert_eq!(
            backend.install_initial_stack_pages(
                &installed.process,
                BOOTSTRAP_STACK_PAGES,
                &install_control,
            ),
            Ok(expected_initial_pointer),
        );
        let installed_info = backend.process_info(&installed.process).unwrap();
        assert_eq!(
            installed_info.initial_stack_pointer,
            Some(expected_initial_pointer)
        );
        assert_eq!(installed_info.owned_frames, 5 + BOOTSTRAP_STACK_PAGES + 2);
        let stack_pointer = backend
            .prepare_initial_stack(&installed.process, &[b"bootstrap"], &[])
            .unwrap();
        assert_eq!(stack_pointer & 0xf, 0);
        assert!(stack_pointer < INITIAL_USER_STACK_POINTER);
        assert_eq!(
            backend.install_initial_stack_pages(&installed.process, 1, &install_control),
            Err(FrameBackedError::InvalidState),
        );
    }

    #[test]
    fn fills_the_bounded_process_pool_and_recycles_only_the_released_slot() {
        let memory = Box::new(TestMemory::<176>::new());
        let authority = unsafe { Authority::assume_root() };
        let image_control = authority.grant::<UserlandImageControl>();
        let install_control = authority.grant::<ProcessInstallControl>();
        let mut backend =
            FrameBackedAddressSpace::new(memory, PhysicalAddress::new(0), &install_control);
        let catalog = catalog();
        let mut first_bytes = [0_u8; MINIMAL_X86_64_ELF_BYTES];
        let first_artifact = catalog.materialize(1, &mut first_bytes).unwrap();
        let first_image = prepare_user_image(first_artifact, &image_control).unwrap();
        let first = install_user_image(first_image, &mut backend, &install_control).unwrap();
        let first_info = backend.process_info(&first.process).unwrap();

        let mut second_bytes = [0_u8; MINIMAL_X86_64_ELF_BYTES];
        let second_artifact = catalog.materialize(1, &mut second_bytes).unwrap();
        let second_image = prepare_user_image(second_artifact, &image_control).unwrap();
        let second = install_user_image(second_image, &mut backend, &install_control).unwrap();
        let second_info = backend.process_info(&second.process).unwrap();

        assert_ne!(first.process.slot(), second.process.slot());
        assert_ne!(
            first_info.address_space_root,
            second_info.address_space_root
        );
        assert_eq!(
            backend.owned_frame_count(),
            first_info.owned_frames + second_info.owned_frames
        );
        assert_eq!(backend.memory().in_use(), backend.owned_frame_count());

        let mut rejected_bytes = [0_u8; MINIMAL_X86_64_ELF_BYTES];
        let rejected_artifact = catalog.materialize(1, &mut rejected_bytes).unwrap();
        let rejected_image = prepare_user_image(rejected_artifact, &image_control).unwrap();
        assert_eq!(
            install_user_image(rejected_image, &mut backend, &install_control),
            Err(InstallError::Backend(FrameBackedError::CapacityExceeded))
        );

        backend.release_process(&first.process).unwrap();
        assert_eq!(backend.process_info(&first.process), None);
        assert_eq!(backend.process_info(&second.process), Some(second_info));
        assert_eq!(backend.memory().in_use(), backend.owned_frame_count());

        let mut replacement_bytes = [0_u8; MINIMAL_X86_64_ELF_BYTES];
        let replacement_artifact = catalog.materialize(1, &mut replacement_bytes).unwrap();
        let replacement_image = prepare_user_image(replacement_artifact, &image_control).unwrap();
        let replacement =
            install_user_image(replacement_image, &mut backend, &install_control).unwrap();
        assert_eq!(replacement.process.slot(), first.process.slot());
        assert_ne!(replacement.process.generation(), first.process.generation());
        assert_eq!(backend.process_info(&first.process), None);

        backend.release_process(&replacement.process).unwrap();
        backend.release_process(&second.process).unwrap();
        assert_eq!(backend.owned_frame_count(), 0);
        assert_eq!(backend.memory().in_use(), 0);
    }

    #[test]
    fn failed_committed_release_quarantines_only_failed_frames() {
        let memory = TestMemory::<16>::new();
        let authority = unsafe { Authority::assume_root() };
        let image_control = authority.grant::<UserlandImageControl>();
        let install_control = authority.grant::<ProcessInstallControl>();
        let physical_memory = authority.grant::<PhysicalMemoryControl>();
        let mut backend =
            FrameBackedAddressSpace::new(memory, PhysicalAddress::new(0), &install_control);
        let catalog = catalog();
        let mut bytes = [0_u8; MINIMAL_X86_64_ELF_BYTES];
        let artifact = catalog.materialize(1, &mut bytes).unwrap();
        let image = prepare_user_image(artifact, &image_control).unwrap();
        let installed = install_user_image(image, &mut backend, &install_control).unwrap();
        assert_eq!(backend.owned_frame_count(), 5);

        backend.memory_mut().fail_release_once = true;
        assert_eq!(
            backend.release_process(&installed.process),
            Err(FrameBackedError::Memory(TestMemoryError::ReleaseFailed))
        );
        assert_eq!(backend.process_info(&installed.process), None);
        assert_eq!(backend.owned_frame_count(), 1);
        assert_eq!(backend.memory().in_use(), 1);

        backend.retry_cleanup(&physical_memory).unwrap();
        assert_eq!(backend.owned_frame_count(), 0);
        assert_eq!(backend.memory().in_use(), 0);
    }

    #[test]
    fn allocation_failure_aborts_and_reclaims_partial_hierarchy() {
        let memory = TestMemory::<5>::new();
        let catalog = catalog();
        let mut bytes = [0_u8; MINIMAL_X86_64_ELF_BYTES];
        let authority = unsafe { Authority::assume_root() };
        let image_control = authority.grant::<UserlandImageControl>();
        let install_control = authority.grant::<ProcessInstallControl>();
        let mut backend =
            FrameBackedAddressSpace::new(memory, PhysicalAddress::new(0), &install_control);
        let artifact = catalog.materialize(1, &mut bytes).unwrap();
        let image = prepare_user_image(artifact, &image_control).unwrap();
        assert_eq!(
            install_user_image(image, &mut backend, &install_control),
            Err(InstallError::Backend(FrameBackedError::Memory(
                TestMemoryError::Exhausted
            )))
        );
        assert_eq!(backend.memory().in_use(), 0);
    }

    #[test]
    fn staging_is_nonpresent_before_rw_nx_sealing() {
        let memory = TestMemory::<16>::new();
        let authority = unsafe { Authority::assume_root() };
        let install_control = authority.grant::<ProcessInstallControl>();
        let mut backend =
            FrameBackedAddressSpace::new(memory, PhysicalAddress::new(0), &install_control);
        let space = backend.begin(0x1000, 0x2000).unwrap();
        let mapping = backend.map_zeroed(space, 0x1000, PAGE_SIZE).unwrap();
        let root = backend.slots[usize::from(space.slot)].root.unwrap();
        let p3 = backend.memory().read_entry(root, 0).unwrap() & PAGE_ADDRESS_MASK;
        let p2 = backend
            .memory()
            .read_entry(PhysicalAddress::new(p3), 0)
            .unwrap()
            & PAGE_ADDRESS_MASK;
        let p1 = backend
            .memory()
            .read_entry(PhysicalAddress::new(p2), 0)
            .unwrap()
            & PAGE_ADDRESS_MASK;
        assert_eq!(
            backend.memory().read_entry(PhysicalAddress::new(p1), 1),
            Ok(0)
        );

        backend
            .seal(
                mapping,
                MappingPermissions {
                    readable: true,
                    writable: true,
                    executable: false,
                },
            )
            .unwrap();
        let leaf = backend
            .memory()
            .read_entry(PhysicalAddress::new(p1), 1)
            .unwrap();
        assert_eq!(
            leaf & (ENTRY_PRESENT | ENTRY_WRITABLE | ENTRY_USER | ENTRY_NO_EXECUTE),
            ENTRY_PRESENT | ENTRY_WRITABLE | ENTRY_USER | ENTRY_NO_EXECUTE
        );
        backend.abort(space).unwrap();
        assert_eq!(backend.memory().in_use(), 0);
    }

    #[test]
    fn maps_a_large_bounded_frame_without_a_u8_page_count_wrap() {
        thread::Builder::new()
            .name("large-frame-regression".into())
            .stack_size(16 * 1024 * 1024)
            .spawn(maps_a_large_bounded_frame_without_a_u8_page_count_wrap_inner)
            .unwrap()
            .join()
            .unwrap();
    }

    fn maps_a_large_bounded_frame_without_a_u8_page_count_wrap_inner() {
        let memory = Box::new(TestMemory::<400>::new());
        let authority = unsafe { Authority::assume_root() };
        let install_control = authority.grant::<ProcessInstallControl>();
        let mut backend = Box::new(FrameBackedAddressSpace::new(
            memory,
            PhysicalAddress::new(0),
            &install_control,
        ));
        let space = backend.begin(0x1000, 0x1f0_000).unwrap();
        let mapping = backend
            .map_zeroed(space, 0x1000, 300 * PAGE_SIZE)
            .expect("bounded multi-page image mapping");
        assert_eq!(
            backend.mapping(mapping).unwrap().page_count,
            300,
            "mapping metadata must represent more than 255 pages"
        );
        backend
            .seal(
                mapping,
                MappingPermissions {
                    readable: true,
                    writable: true,
                    executable: false,
                },
            )
            .unwrap();
        backend.abort(space).unwrap();
        assert_eq!(backend.memory().in_use(), 0);
    }

    #[test]
    fn failed_frame_release_remains_owned_for_retry() {
        let memory = TestMemory::<16>::new();
        let authority = unsafe { Authority::assume_root() };
        let install_control = authority.grant::<ProcessInstallControl>();
        let physical_memory = authority.grant::<PhysicalMemoryControl>();
        let mut backend =
            FrameBackedAddressSpace::new(memory, PhysicalAddress::new(0), &install_control);
        let space = backend.begin(0x1000, 0x2000).unwrap();
        backend.map_zeroed(space, 0x1000, PAGE_SIZE).unwrap();
        backend.memory_mut().fail_release_once = true;
        assert_eq!(
            backend.abort(space),
            Err(FrameBackedError::Memory(TestMemoryError::ReleaseFailed))
        );
        assert_eq!(backend.owned_frame_count(), 1);
        backend.retry_cleanup(&physical_memory).unwrap();
        assert_eq!(backend.owned_frame_count(), 0);
        assert_eq!(backend.memory().in_use(), 0);
    }
}
