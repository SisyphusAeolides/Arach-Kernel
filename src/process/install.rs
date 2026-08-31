use blacklab::oureboros::ArtifactMeasurement;

use crate::capability::{Capability, ProcessInstallControl, RuntimeImageControl};
use crate::module::loader::LoaderError;
use crate::process::image::PreparedUserImage;

/// ELF load segments plus a bounded set of runtime mappings. The latter are
/// needed by the Linux personality for anonymous `mmap`; keeping the array
/// fixed preserves the kernel's allocation-free process control path.
pub const MAXIMUM_PROCESS_SEGMENTS: usize = 64;
const PAGE_SIZE: u64 = 4096;
const PAGE_MASK: u64 = PAGE_SIZE - 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappingPermissions {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

impl MappingPermissions {
    const NONE: Self = Self {
        readable: false,
        writable: false,
        executable: false,
    };

    const fn union(self, other: Self) -> Self {
        Self {
            readable: self.readable || other.readable,
            writable: self.writable || other.writable,
            executable: self.executable || other.executable,
        }
    }
}

#[derive(Clone, Copy)]
struct StagedSegmentGroup {
    virtual_address: u64,
    memory_size: usize,
    permissions: MappingPermissions,
}

impl StagedSegmentGroup {
    const EMPTY: Self = Self {
        virtual_address: 0,
        memory_size: 0,
        permissions: MappingPermissions::NONE,
    };

    fn end(self) -> Option<u64> {
        self.virtual_address.checked_add(self.memory_size as u64)
    }
}

/// Backend contract for a transactional user-image installation.
///
/// `map_zeroed` must create inaccessible staging memory. `seal` publishes the
/// final user permissions, and `commit` may make the address space schedulable
/// only after every mapping has been verified and sealed. On any intermediate
/// error the installer invokes `abort`.
pub trait UserAddressSpaceBackend {
    type Error;
    type Space: Copy;
    type Mapping: Copy;
    type Process;

    fn begin(&mut self, image_start: u64, image_end: u64) -> Result<Self::Space, Self::Error>;

    fn map_zeroed(
        &mut self,
        space: Self::Space,
        virtual_address: u64,
        memory_size: usize,
    ) -> Result<Self::Mapping, Self::Error>;

    fn copy_into(
        &mut self,
        mapping: Self::Mapping,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), Self::Error>;

    fn verify_contents(
        &mut self,
        mapping: Self::Mapping,
        offset: usize,
        initialized: &[u8],
        memory_size: usize,
    ) -> Result<bool, Self::Error>;

    fn seal(
        &mut self,
        mapping: Self::Mapping,
        permissions: MappingPermissions,
    ) -> Result<(), Self::Error>;

    fn commit(
        &mut self,
        space: Self::Space,
        entry_point: u64,
        segment_count: usize,
    ) -> Result<Self::Process, Self::Error>;

    fn abort(&mut self, space: Self::Space) -> Result<(), Self::Error>;

    fn process_info(&self, process: &Self::Process) -> Option<ProcessImageInfo>;

    fn process_generation(&self, process: &Self::Process) -> Option<u32>;

    /// Proves that the committed address space can become the active hardware
    /// translation root while preserving kernel execution.
    ///
    /// # Safety
    ///
    /// The implementation may install process-owned translation state. The
    /// caller must invoke this only during a serialized kernel phase in which
    /// no scheduler or interrupt path can retain the temporary process state.
    unsafe fn validate_activation(
        &mut self,
        process: &Self::Process,
        authority: &Capability<'_, ProcessInstallControl>,
    ) -> Result<(), Self::Error>;

    fn release_process(&mut self, process: &Self::Process) -> Result<(), Self::Error>;
}

#[derive(Debug, Eq, PartialEq)]
pub struct InstalledUserImage<Process> {
    pub process: Process,
    pub entry_point: u64,
    pub segment_count: usize,
    pub measurement: ArtifactMeasurement,
}

#[derive(Debug, Eq, PartialEq)]
pub struct InstalledRuntimeLinkedImage<Process> {
    pub process: Process,
    /// Runtime-linker entry point used for the first Ring 3 instruction.
    pub entry_point: u64,
    /// Main executable entry exported through `AT_ENTRY`.
    pub executable_entry_point: u64,
    pub executable_program_header: u64,
    pub executable_program_header_count: u16,
    pub runtime_linker_base: u64,
    pub segment_count: usize,
    pub executable_measurement: ArtifactMeasurement,
    pub runtime_linker_measurement: ArtifactMeasurement,
}

pub fn install_user_image<Backend: UserAddressSpaceBackend>(
    image: PreparedUserImage<'_>,
    backend: &mut Backend,
    _authority: &Capability<'_, ProcessInstallControl>,
) -> Result<InstalledUserImage<Backend::Process>, InstallError<Backend::Error>> {
    install_user_image_inner(image, backend)
}

pub fn install_runtime_user_image<Backend: UserAddressSpaceBackend>(
    image: PreparedUserImage<'_>,
    backend: &mut Backend,
    _authority: &RuntimeImageControl,
) -> Result<InstalledUserImage<Backend::Process>, InstallError<Backend::Error>> {
    install_user_image_inner(image, backend)
}

/// Installs a measured executable and its measured runtime linker in one
/// inactive hierarchy. No mapping is published unless both plans are copied,
/// verified, sealed, and committed together.
pub fn install_runtime_linked_user_image<Backend: UserAddressSpaceBackend>(
    executable: PreparedUserImage<'_>,
    runtime_linker: PreparedUserImage<'_>,
    backend: &mut Backend,
    _authority: &RuntimeImageControl,
) -> Result<InstalledRuntimeLinkedImage<Backend::Process>, InstallError<Backend::Error>> {
    let executable_plan = *executable.plan();
    let linker_plan = *runtime_linker.plan();
    let executable_measurement = executable.measurement();
    let runtime_linker_measurement = runtime_linker.measurement();
    if executable_plan.image_start < linker_plan.image_end
        && linker_plan.image_start < executable_plan.image_end
    {
        return Err(InstallError::LinkedImageOverlap);
    }
    let executable_program_header = executable_plan
        .program_header_address()
        .ok_or(InstallError::ProgramHeadersUnavailable)?;
    let image_start = executable_plan.image_start.min(linker_plan.image_start);
    let image_end = executable_plan.image_end.max(linker_plan.image_end);
    let image_start = page_align_down(image_start);
    let image_end = page_align_up(image_end).ok_or(InstallError::InvalidSegmentSize)?;
    let space = backend
        .begin(image_start, image_end)
        .map_err(InstallError::Backend)?;

    let executable_segments = match map_image_segments(executable, backend, space) {
        Ok(count) => count,
        Err(error) => return fail_after_abort(backend, space, error),
    };
    let linker_segments = match map_image_segments(runtime_linker, backend, space) {
        Ok(count) => count,
        Err(error) => return fail_after_abort(backend, space, error),
    };
    let process = match backend.commit(
        space,
        linker_plan.entry_point,
        executable_segments + linker_segments,
    ) {
        Ok(process) => process,
        Err(error) => {
            return fail_after_abort(backend, space, InstallError::Backend(error));
        }
    };
    Ok(InstalledRuntimeLinkedImage {
        process,
        entry_point: linker_plan.entry_point,
        executable_entry_point: executable_plan.entry_point,
        executable_program_header,
        executable_program_header_count: executable_plan.program_header_count(),
        runtime_linker_base: linker_plan.load_bias,
        segment_count: executable_segments + linker_segments,
        executable_measurement,
        runtime_linker_measurement,
    })
}

fn install_user_image_inner<Backend: UserAddressSpaceBackend>(
    image: PreparedUserImage<'_>,
    backend: &mut Backend,
) -> Result<InstalledUserImage<Backend::Process>, InstallError<Backend::Error>> {
    let plan = *image.plan();
    let measurement = image.measurement();
    let image_start = page_align_down(plan.image_start);
    let image_end = page_align_up(plan.image_end).ok_or(InstallError::InvalidSegmentSize)?;
    let space = backend
        .begin(image_start, image_end)
        .map_err(InstallError::Backend)?;

    let segment_count = match map_image_segments(image, backend, space) {
        Ok(count) => count,
        Err(error) => return fail_after_abort(backend, space, error),
    };

    let process = match backend.commit(space, plan.entry_point, segment_count) {
        Ok(process) => process,
        Err(error) => {
            return fail_after_abort(backend, space, InstallError::Backend(error));
        }
    };
    Ok(InstalledUserImage {
        process,
        entry_point: plan.entry_point,
        segment_count,
        measurement,
    })
}

fn map_image_segments<Backend: UserAddressSpaceBackend>(
    image: PreparedUserImage<'_>,
    backend: &mut Backend,
    space: Backend::Space,
) -> Result<usize, InstallError<Backend::Error>> {
    let plan = *image.plan();
    let segments = plan.segments();
    let mut groups = [StagedSegmentGroup::EMPTY; MAXIMUM_PROCESS_SEGMENTS];
    let mut group_count = 0usize;

    // ELF p_vaddr is allowed to be unaligned. Stage whole pages and merge
    // ranges that touch the same hardware page before any bytes are copied;
    // this also handles PT_LOAD layouts with a shared boundary page.
    for segment in segments {
        let _memory_size =
            usize::try_from(segment.memory_size).map_err(|_| InstallError::InvalidSegmentSize)?;
        let segment_end = segment
            .virtual_address
            .checked_add(segment.memory_size)
            .ok_or(InstallError::InvalidSegmentSize)?;
        let range_start = page_align_down(segment.virtual_address);
        let range_end = page_align_up(segment_end).ok_or(InstallError::InvalidSegmentSize)?;
        if range_start >= range_end {
            return Err(InstallError::InvalidSegmentSize);
        }
        let permissions = MappingPermissions {
            readable: segment.readable,
            writable: segment.writable,
            executable: segment.executable,
        };

        let mut start = range_start;
        let mut end = range_end;
        let mut merged_permissions = permissions;
        let mut group_index = 0usize;
        while group_index < group_count {
            let group = groups[group_index];
            let group_end = group.end().ok_or(InstallError::InvalidSegmentSize)?;
            if ranges_overlap(start, end, group.virtual_address, group_end) {
                start = start.min(group.virtual_address);
                end = end.max(group_end);
                merged_permissions = merged_permissions.union(group.permissions);
                groups[group_index] = StagedSegmentGroup {
                    virtual_address: start,
                    memory_size: usize::try_from(end - start)
                        .map_err(|_| InstallError::InvalidSegmentSize)?,
                    permissions: merged_permissions,
                };

                // A merge can make the enlarged interval touch another group.
                // Fold all such groups into this one so every page is staged
                // exactly once.
                let mut other = group_index + 1;
                while other < group_count {
                    let candidate = groups[other];
                    let candidate_end = candidate.end().ok_or(InstallError::InvalidSegmentSize)?;
                    if ranges_overlap(start, end, candidate.virtual_address, candidate_end) {
                        start = start.min(candidate.virtual_address);
                        end = end.max(candidate_end);
                        merged_permissions = merged_permissions.union(candidate.permissions);
                        groups[group_index] = StagedSegmentGroup {
                            virtual_address: start,
                            memory_size: usize::try_from(end - start)
                                .map_err(|_| InstallError::InvalidSegmentSize)?,
                            permissions: merged_permissions,
                        };
                        groups[other] = groups[group_count - 1];
                        group_count -= 1;
                    } else {
                        other += 1;
                    }
                }
                break;
            }
            group_index += 1;
        }
        if group_index == group_count {
            if group_count >= groups.len() {
                return Err(InstallError::InvalidSegmentSize);
            }
            groups[group_count] = StagedSegmentGroup {
                virtual_address: start,
                memory_size: usize::try_from(end - start)
                    .map_err(|_| InstallError::InvalidSegmentSize)?,
                permissions: merged_permissions,
            };
            group_count += 1;
        }
    }

    let mut mappings: [Option<Backend::Mapping>; MAXIMUM_PROCESS_SEGMENTS] =
        [None; MAXIMUM_PROCESS_SEGMENTS];
    for group_index in 0..group_count {
        let group = groups[group_index];
        mappings[group_index] = Some(
            backend
                .map_zeroed(space, group.virtual_address, group.memory_size)
                .map_err(InstallError::Backend)?,
        );
    }

    for segment in segments {
        let memory_size =
            usize::try_from(segment.memory_size).map_err(|_| InstallError::InvalidSegmentSize)?;
        let segment_end = segment
            .virtual_address
            .checked_add(segment.memory_size)
            .ok_or(InstallError::InvalidSegmentSize)?;
        let range_start = page_align_down(segment.virtual_address);
        let range_end = page_align_up(segment_end).ok_or(InstallError::InvalidSegmentSize)?;
        let group_index = (0..group_count)
            .find(|index| {
                let group = groups[*index];
                group.virtual_address <= range_start
                    && group.end().is_some_and(|end| end >= range_end)
            })
            .ok_or(InstallError::InvalidSegmentSize)?;
        let mapping = mappings[group_index].ok_or(InstallError::InvalidSegmentSize)?;
        let group = groups[group_index];
        let offset = usize::try_from(segment.virtual_address - group.virtual_address)
            .map_err(|_| InstallError::InvalidSegmentSize)?;
        let data = plan
            .segment_data(image.bytes(), *segment)
            .map_err(InstallError::Loader)?;
        backend
            .copy_into(mapping, offset, data)
            .map_err(InstallError::Backend)?;
        match backend.verify_contents(mapping, offset, data, memory_size) {
            Ok(true) => {}
            Ok(false) => return Err(InstallError::VerificationFailed),
            Err(error) => return Err(InstallError::Backend(error)),
        }
    }

    for group_index in 0..group_count {
        let mapping = mappings[group_index].ok_or(InstallError::InvalidSegmentSize)?;
        let permissions = groups[group_index].permissions;
        if permissions.writable && permissions.executable {
            return Err(InstallError::WriteExecuteMapping);
        }
        backend
            .seal(mapping, permissions)
            .map_err(InstallError::Backend)?;
    }
    Ok(segments.len())
}

fn page_align_down(address: u64) -> u64 {
    address & !PAGE_MASK
}

fn page_align_up(address: u64) -> Option<u64> {
    address
        .checked_add(PAGE_MASK)
        .map(|value| value & !PAGE_MASK)
}

fn ranges_overlap(left_start: u64, left_end: u64, right_start: u64, right_end: u64) -> bool {
    left_start < right_end && right_start < left_end
}

fn fail_after_abort<Backend: UserAddressSpaceBackend, T>(
    backend: &mut Backend,
    space: Backend::Space,
    error: InstallError<Backend::Error>,
) -> Result<T, InstallError<Backend::Error>> {
    match backend.abort(space) {
        Ok(()) => Err(error),
        Err(cleanup_error) => Err(InstallError::Cleanup(cleanup_error)),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallError<BackendError> {
    Backend(BackendError),
    Cleanup(BackendError),
    Loader(LoaderError),
    InvalidSegmentSize,
    VerificationFailed,
    WriteExecuteMapping,
    LinkedImageOverlap,
    ProgramHeadersUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DryRunSpace {
    generation: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DryRunMapping {
    slot: u8,
    generation: u32,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ProcessImageHandle {
    slot: u16,
    generation: u32,
}

impl ProcessImageHandle {
    pub(crate) const fn new(slot: u16, generation: u32) -> Self {
        Self { slot, generation }
    }

    pub const fn slot(&self) -> u16 {
        self.slot
    }

    pub const fn generation(&self) -> u32 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessImageInfo {
    pub entry_point: u64,
    pub segment_count: usize,
    pub address_space_root: Option<u64>,
    pub owned_frames: usize,
    pub initial_stack_pointer: Option<u64>,
}

#[derive(Clone, Copy)]
struct DryRunSlot<const BYTES: usize> {
    occupied: bool,
    sealed: bool,
    generation: u32,
    virtual_address: u64,
    memory_size: usize,
    permissions: MappingPermissions,
    bytes: [u8; BYTES],
}

impl<const BYTES: usize> DryRunSlot<BYTES> {
    const EMPTY: Self = Self {
        occupied: false,
        sealed: false,
        generation: 0,
        virtual_address: 0,
        memory_size: 0,
        permissions: MappingPermissions {
            readable: false,
            writable: false,
            executable: false,
        },
        bytes: [0; BYTES],
    };
}

/// Bounded software model for validating installer ordering during bootstrap.
///
/// It deliberately does not create hardware page tables or claim isolation.
pub struct DryRunAddressSpace<const BYTES_PER_SEGMENT: usize> {
    generation: u32,
    active: bool,
    image_start: u64,
    image_end: u64,
    slots: [DryRunSlot<BYTES_PER_SEGMENT>; MAXIMUM_PROCESS_SEGMENTS],
    slot_count: usize,
    process_live: bool,
    process_generation: u32,
    process_info: ProcessImageInfo,
}

impl<const BYTES_PER_SEGMENT: usize> DryRunAddressSpace<BYTES_PER_SEGMENT> {
    pub const fn new() -> Self {
        Self {
            generation: 0,
            active: false,
            image_start: 0,
            image_end: 0,
            slots: [const { DryRunSlot::EMPTY }; MAXIMUM_PROCESS_SEGMENTS],
            slot_count: 0,
            process_live: false,
            process_generation: 0,
            process_info: ProcessImageInfo {
                entry_point: 0,
                segment_count: 0,
                address_space_root: None,
                owned_frames: 0,
                initial_stack_pointer: None,
            },
        }
    }

    pub fn resolve_process(&self, handle: &ProcessImageHandle) -> Option<ProcessImageInfo> {
        (self.process_live && handle.slot == 0 && handle.generation == self.process_generation)
            .then_some(self.process_info)
    }

    pub fn release(&mut self, handle: &ProcessImageHandle) -> Result<(), DryRunError> {
        if self.resolve_process(handle).is_none() {
            return Err(DryRunError::InvalidHandle);
        }
        self.process_live = false;
        Ok(())
    }

    fn mapping_mut(
        &mut self,
        mapping: DryRunMapping,
    ) -> Result<&mut DryRunSlot<BYTES_PER_SEGMENT>, DryRunError> {
        self.slots
            .get_mut(usize::from(mapping.slot))
            .filter(|slot| slot.occupied && slot.generation == mapping.generation)
            .ok_or(DryRunError::InvalidHandle)
    }
}

impl<const BYTES_PER_SEGMENT: usize> Default for DryRunAddressSpace<BYTES_PER_SEGMENT> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const BYTES_PER_SEGMENT: usize> UserAddressSpaceBackend
    for DryRunAddressSpace<BYTES_PER_SEGMENT>
{
    type Error = DryRunError;
    type Space = DryRunSpace;
    type Mapping = DryRunMapping;
    type Process = ProcessImageHandle;

    fn begin(&mut self, image_start: u64, image_end: u64) -> Result<Self::Space, Self::Error> {
        if self.active || self.process_live || image_start >= image_end {
            return Err(DryRunError::BusyOrInvalid);
        }
        self.generation = next_generation(self.generation);
        self.active = true;
        self.image_start = image_start;
        self.image_end = image_end;
        self.slot_count = 0;
        self.slots.fill(DryRunSlot::EMPTY);
        Ok(DryRunSpace {
            generation: self.generation,
        })
    }

    fn map_zeroed(
        &mut self,
        space: Self::Space,
        virtual_address: u64,
        memory_size: usize,
    ) -> Result<Self::Mapping, Self::Error> {
        if !self.active
            || space.generation != self.generation
            || memory_size == 0
            || memory_size > BYTES_PER_SEGMENT
            || virtual_address < self.image_start
            || virtual_address
                .checked_add(memory_size as u64)
                .is_none_or(|end| end > self.image_end)
        {
            return Err(DryRunError::BusyOrInvalid);
        }
        let index = self.slot_count;
        let slot = self
            .slots
            .get_mut(index)
            .ok_or(DryRunError::CapacityExceeded)?;
        slot.occupied = true;
        slot.sealed = false;
        slot.generation = self.generation;
        slot.virtual_address = virtual_address;
        slot.memory_size = memory_size;
        slot.bytes.fill(0);
        self.slot_count += 1;
        Ok(DryRunMapping {
            slot: index as u8,
            generation: self.generation,
        })
    }

    fn copy_into(
        &mut self,
        mapping: Self::Mapping,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        let slot = self.mapping_mut(mapping)?;
        if slot.sealed
            || offset
                .checked_add(bytes.len())
                .is_none_or(|end| end > slot.memory_size)
        {
            return Err(DryRunError::BusyOrInvalid);
        }
        slot.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    fn verify_contents(
        &mut self,
        mapping: Self::Mapping,
        offset: usize,
        initialized: &[u8],
        memory_size: usize,
    ) -> Result<bool, Self::Error> {
        let slot = self.mapping_mut(mapping)?;
        let end = offset
            .checked_add(memory_size)
            .ok_or(DryRunError::BusyOrInvalid)?;
        if end > slot.memory_size || initialized.len() > memory_size {
            return Err(DryRunError::BusyOrInvalid);
        }
        Ok(slot.bytes[..offset].iter().all(|byte| *byte == 0)
            && slot.bytes[offset..offset + initialized.len()] == *initialized
            && slot.bytes[offset + initialized.len()..end]
                .iter()
                .all(|byte| *byte == 0)
            && slot.bytes[end..slot.memory_size]
                .iter()
                .all(|byte| *byte == 0))
    }

    fn seal(
        &mut self,
        mapping: Self::Mapping,
        permissions: MappingPermissions,
    ) -> Result<(), Self::Error> {
        if permissions.writable && permissions.executable {
            return Err(DryRunError::WriteExecute);
        }
        let slot = self.mapping_mut(mapping)?;
        if slot.sealed {
            return Err(DryRunError::BusyOrInvalid);
        }
        slot.permissions = permissions;
        slot.sealed = true;
        Ok(())
    }

    fn commit(
        &mut self,
        space: Self::Space,
        entry_point: u64,
        segment_count: usize,
    ) -> Result<Self::Process, Self::Error> {
        if !self.active
            || space.generation != self.generation
            || self.slot_count == 0
            || segment_count == 0
            || segment_count > MAXIMUM_PROCESS_SEGMENTS
            || self.slots[..self.slot_count]
                .iter()
                .any(|slot| !slot.sealed)
            || !self.slots[..self.slot_count].iter().any(|slot| {
                slot.permissions.executable
                    && entry_point >= slot.virtual_address
                    && entry_point < slot.virtual_address + slot.memory_size as u64
            })
        {
            return Err(DryRunError::BusyOrInvalid);
        }
        self.active = false;
        self.process_generation = next_generation(self.process_generation);
        self.process_live = true;
        self.process_info = ProcessImageInfo {
            entry_point,
            segment_count,
            address_space_root: None,
            owned_frames: 0,
            initial_stack_pointer: None,
        };
        Ok(ProcessImageHandle::new(0, self.process_generation))
    }

    fn abort(&mut self, space: Self::Space) -> Result<(), Self::Error> {
        if self.active && space.generation == self.generation {
            self.active = false;
            self.slot_count = 0;
            self.slots.fill(DryRunSlot::EMPTY);
            Ok(())
        } else {
            Err(DryRunError::InvalidHandle)
        }
    }

    fn process_info(&self, process: &Self::Process) -> Option<ProcessImageInfo> {
        self.resolve_process(process)
    }

    fn process_generation(&self, process: &Self::Process) -> Option<u32> {
        self.resolve_process(process).map(|_| process.generation())
    }

    unsafe fn validate_activation(
        &mut self,
        process: &Self::Process,
        _authority: &Capability<'_, ProcessInstallControl>,
    ) -> Result<(), Self::Error> {
        self.resolve_process(process)
            .map(|_| ())
            .ok_or(DryRunError::InvalidHandle)
    }

    fn release_process(&mut self, process: &Self::Process) -> Result<(), Self::Error> {
        self.release(process)
    }
}

const fn next_generation(generation: u32) -> u32 {
    let next = generation.wrapping_add(1);
    if next == 0 { 1 } else { next }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DryRunError {
    BusyOrInvalid,
    CapacityExceeded,
    InvalidHandle,
    WriteExecute,
}

#[cfg(test)]
mod tests {
    use blacklab::oureboros::{
        FractalCatalog, FractalClass, FractalRecipe, FractalSeed, MINIMAL_X86_64_ELF_BYTES,
        TargetArchitecture, measure_recipe,
    };

    use crate::capability::{Authority, UserlandImageControl};
    use crate::module::loader::{POSITION_INDEPENDENT_LOAD_BASE, RUNTIME_LINKER_LOAD_BASE};
    use crate::process::image::{
        prepare_runtime_dynamic_image, prepare_runtime_linker_image, prepare_user_image,
    };

    use super::*;

    fn prepared<'bytes>(
        catalog: &FractalCatalog,
        bytes: &'bytes mut [u8; MINIMAL_X86_64_ELF_BYTES],
        image_control: &Capability<'_, UserlandImageControl>,
    ) -> PreparedUserImage<'bytes> {
        let artifact = catalog.materialize(1, bytes).unwrap();
        prepare_user_image(artifact, image_control).unwrap()
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

    fn dynamic_pair() -> ([u8; 195], [u8; 132]) {
        let mut executable = [0_u8; 195];
        executable[..4].copy_from_slice(b"\x7fELF");
        executable[4] = 2;
        executable[5] = 1;
        executable[6] = 1;
        executable[16..18].copy_from_slice(&(3_u16).to_le_bytes());
        executable[18..20].copy_from_slice(&(62_u16).to_le_bytes());
        executable[20..24].copy_from_slice(&(1_u32).to_le_bytes());
        executable[24..32].copy_from_slice(&(176_u64).to_le_bytes());
        executable[32..40].copy_from_slice(&(64_u64).to_le_bytes());
        executable[52..54].copy_from_slice(&(64_u16).to_le_bytes());
        executable[54..56].copy_from_slice(&(56_u16).to_le_bytes());
        executable[56..58].copy_from_slice(&(2_u16).to_le_bytes());
        let load = &mut executable[64..120];
        load[0..4].copy_from_slice(&(1_u32).to_le_bytes());
        load[4..8].copy_from_slice(&(5_u32).to_le_bytes());
        load[32..40].copy_from_slice(&(184_u64).to_le_bytes());
        load[40..48].copy_from_slice(&(0x1000_u64).to_le_bytes());
        load[48..56].copy_from_slice(&(0x1000_u64).to_le_bytes());
        let interpreter = &mut executable[120..176];
        interpreter[0..4].copy_from_slice(&(3_u32).to_le_bytes());
        interpreter[8..16].copy_from_slice(&(184_u64).to_le_bytes());
        interpreter[32..40].copy_from_slice(&(11_u64).to_le_bytes());
        interpreter[40..48].copy_from_slice(&(11_u64).to_le_bytes());
        executable[176..184].copy_from_slice(&[0x90; 8]);
        executable[184..195].copy_from_slice(b"/lib/ld.so\0");

        let mut linker = [0_u8; 132];
        linker[..4].copy_from_slice(b"\x7fELF");
        linker[4] = 2;
        linker[5] = 1;
        linker[6] = 1;
        linker[16..18].copy_from_slice(&(3_u16).to_le_bytes());
        linker[18..20].copy_from_slice(&(62_u16).to_le_bytes());
        linker[20..24].copy_from_slice(&(1_u32).to_le_bytes());
        linker[24..32].copy_from_slice(&(128_u64).to_le_bytes());
        linker[32..40].copy_from_slice(&(64_u64).to_le_bytes());
        linker[52..54].copy_from_slice(&(64_u16).to_le_bytes());
        linker[54..56].copy_from_slice(&(56_u16).to_le_bytes());
        linker[56..58].copy_from_slice(&(1_u16).to_le_bytes());
        let load = &mut linker[64..120];
        load[0..4].copy_from_slice(&(1_u32).to_le_bytes());
        load[4..8].copy_from_slice(&(5_u32).to_le_bytes());
        load[32..40].copy_from_slice(&(132_u64).to_le_bytes());
        load[40..48].copy_from_slice(&(0x1000_u64).to_le_bytes());
        load[48..56].copy_from_slice(&(0x1000_u64).to_le_bytes());
        linker[128..132].copy_from_slice(&[0x90; 4]);
        (executable, linker)
    }

    #[test]
    fn installs_verifies_seals_and_releases_a_process_model() {
        let catalog = catalog();
        let mut bytes = [0_u8; MINIMAL_X86_64_ELF_BYTES];
        // SAFETY: Unit tests establish one isolated bootstrap authority.
        let authority = unsafe { Authority::assume_root() };
        let image_control = authority.grant::<UserlandImageControl>();
        let install_control = authority.grant::<ProcessInstallControl>();
        let image = prepared(&catalog, &mut bytes, &image_control);
        let mut backend = DryRunAddressSpace::<4096>::new();
        let installed = install_user_image(image, &mut backend, &install_control).unwrap();
        assert_eq!(installed.entry_point, POSITION_INDEPENDENT_LOAD_BASE);
        assert_eq!(installed.segment_count, 1);
        assert_eq!(
            backend.resolve_process(&installed.process),
            Some(ProcessImageInfo {
                entry_point: POSITION_INDEPENDENT_LOAD_BASE,
                segment_count: 1,
                address_space_root: None,
                owned_frames: 0,
                initial_stack_pointer: None,
            })
        );
        // SAFETY: The dry-run backend has no privileged state and validates
        // only the committed handle lifecycle.
        unsafe {
            backend
                .validate_activation(&installed.process, &install_control)
                .unwrap();
        }
        backend.release(&installed.process).unwrap();
        assert_eq!(backend.resolve_process(&installed.process), None);
        // SAFETY: This is the same non-privileged dry-run lifecycle check.
        assert_eq!(
            unsafe { backend.validate_activation(&installed.process, &install_control) },
            Err(DryRunError::InvalidHandle)
        );
    }

    #[test]
    fn aborts_when_the_backend_cannot_hold_a_segment() {
        let catalog = catalog();
        let mut bytes = [0_u8; MINIMAL_X86_64_ELF_BYTES];
        // SAFETY: Unit tests establish one isolated bootstrap authority.
        let authority = unsafe { Authority::assume_root() };
        let image_control = authority.grant::<UserlandImageControl>();
        let install_control = authority.grant::<ProcessInstallControl>();
        let image = prepared(&catalog, &mut bytes, &image_control);
        let mut backend = DryRunAddressSpace::<2>::new();
        assert_eq!(
            install_user_image(image, &mut backend, &install_control),
            Err(InstallError::Backend(DryRunError::BusyOrInvalid))
        );
        assert!(!backend.active);
        assert_eq!(backend.slot_count, 0);
    }

    #[test]
    fn commits_a_measured_executable_and_linker_as_one_image() {
        let (executable_bytes, linker_bytes) = dynamic_pair();
        let authority = unsafe { Authority::assume_root() };
        let runtime_control = authority.delegate_runtime_image_control();
        let executable =
            prepare_runtime_dynamic_image(30, &executable_bytes, &runtime_control).unwrap();
        let linker = prepare_runtime_linker_image(31, &linker_bytes, &runtime_control).unwrap();
        let mut backend = DryRunAddressSpace::<4096>::new();
        let installed =
            install_runtime_linked_user_image(executable, linker, &mut backend, &runtime_control)
                .unwrap();
        assert_eq!(installed.entry_point, RUNTIME_LINKER_LOAD_BASE + 128);
        assert_eq!(
            installed.executable_entry_point,
            POSITION_INDEPENDENT_LOAD_BASE + 176
        );
        assert_eq!(
            installed.executable_program_header,
            POSITION_INDEPENDENT_LOAD_BASE + 64
        );
        assert_eq!(installed.runtime_linker_base, RUNTIME_LINKER_LOAD_BASE);
        assert_eq!(installed.segment_count, 2);
        assert_eq!(
            backend.resolve_process(&installed.process),
            Some(ProcessImageInfo {
                entry_point: RUNTIME_LINKER_LOAD_BASE + 128,
                segment_count: 2,
                address_space_root: None,
                owned_frames: 0,
                initial_stack_pointer: None,
            })
        );
        assert_ne!(
            installed.executable_measurement.sha256,
            installed.runtime_linker_measurement.sha256
        );
        backend.release(&installed.process).unwrap();
    }
}
