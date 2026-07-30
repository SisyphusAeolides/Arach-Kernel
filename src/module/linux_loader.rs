//! Transactional Linux x86-64 `.ko` loading and lifecycle orchestration.
//!
//! The build/admission parser in [`super::linux_ko`] establishes module
//! identity, vermagic, symbol-version and export-policy compatibility. This
//! module turns that admitted object into a page-separated W^X image. External
//! addresses and every relocation value are frozen before staging begins.

use alloc::vec::Vec;

use crate::module::elf::{ElfError, ElfModule, SectionHeader};
use crate::module::elf_headers::{RelocationEntry, SymbolEntry};
use crate::module::linux_ko::{
    self, LinuxKernelSymbolResolver, LinuxKoAdmission, LinuxKoAdmissionError, LinuxKoError,
    LinuxKoRequirements, LinuxKoResolution,
};

const PAGE_BYTES: usize = 4096;
const MAXIMUM_IMAGE_BYTES: usize = 512 * 1024 * 1024;
const MAXIMUM_RELOCATIONS: usize = 2_000_000;

const SECTION_TYPE_PROGRAM_BITS: u32 = 1;
const SECTION_TYPE_SYMBOL_TABLE: u32 = 2;
const SECTION_TYPE_STRING_TABLE: u32 = 3;
const SECTION_TYPE_RELA: u32 = 4;
const SECTION_TYPE_NOTE: u32 = 7;
const SECTION_TYPE_NOBITS: u32 = 8;

const SECTION_WRITE: u64 = 1 << 0;
const SECTION_ALLOCATE: u64 = 1 << 1;
const SECTION_EXECUTE: u64 = 1 << 2;
const SECTION_MERGE: u64 = 1 << 4;
const SECTION_STRINGS: u64 = 1 << 5;
const SECTION_LINK_ORDER: u64 = 1 << 7;
const SUPPORTED_ALLOCATED_FLAGS: u64 = SECTION_WRITE
    | SECTION_ALLOCATE
    | SECTION_EXECUTE
    | SECTION_MERGE
    | SECTION_STRINGS
    | SECTION_LINK_ORDER;

const SECTION_UNDEFINED: u16 = 0;
const SECTION_ABSOLUTE: u16 = 0xfff1;
const RESERVED_SECTION_START: u16 = 0xff00;
const SYMBOL_BINDING_GLOBAL: u8 = 1;
const SYMBOL_TYPE_FUNCTION: u8 = 2;

const R_X86_64_64: u32 = 1;
const R_X86_64_PC32: u32 = 2;
const R_X86_64_PLT32: u32 = 4;
const R_X86_64_32: u32 = 10;
const R_X86_64_32S: u32 = 11;
const R_X86_64_PC64: u32 = 24;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxKoRegionKind {
    CoreText,
    CoreReadOnly,
    CoreWritable,
    InitText,
    InitReadOnly,
    InitWritable,
}

impl LinuxKoRegionKind {
    const ORDER: [Self; 6] = [
        Self::CoreText,
        Self::CoreReadOnly,
        Self::CoreWritable,
        Self::InitText,
        Self::InitReadOnly,
        Self::InitWritable,
    ];

    const fn executable(self) -> bool {
        matches!(self, Self::CoreText | Self::InitText)
    }

    const fn writable(self) -> bool {
        matches!(self, Self::CoreWritable | Self::InitWritable)
    }

    const fn is_init(self) -> bool {
        matches!(
            self,
            Self::InitText | Self::InitReadOnly | Self::InitWritable
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxKoMemoryRegion {
    pub kind: LinuxKoRegionKind,
    pub image_offset: usize,
    pub size: usize,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub discard_after_init: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxKoSectionPlacement {
    pub section_index: usize,
    pub image_offset: usize,
    pub memory_size: usize,
    pub region: LinuxKoRegionKind,
    file_offset: usize,
    file_size: usize,
}

/// Runtime work implied by an allocated Linux module section.
///
/// These categories are deliberately semantic rather than a collection of
/// booleans. A native backend must either process/register every reported
/// category or reject the transaction before executable mappings are
/// published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxKoSpecialSectionKind {
    ModuleIdentity,
    Alternatives,
    JumpLabels,
    StaticCalls,
    DynamicTracing,
    CpuLockPatching,
    CallSitePatching,
    OrcUnwind,
    BugTable,
    Parameters,
    Tracepoints,
    SymbolExports,
    PerCpu,
    AllocationTags,
    PrintkIndex,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxKoSpecialSection<'a> {
    pub section_index: usize,
    pub name: &'a [u8],
    pub image_offset: usize,
    pub size: usize,
    pub kind: LinuxKoSpecialSectionKind,
}

/// Explicit processor receipt for the special-section categories handled in
/// one transaction. Native publication requires an exact match with the
/// inventory derived from that module.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinuxKoSpecialSectionCoverage(u16);

impl LinuxKoSpecialSectionCoverage {
    pub const fn empty() -> Self {
        Self(0)
    }

    pub fn acknowledge(&mut self, kind: LinuxKoSpecialSectionKind) {
        self.0 |= 1_u16 << kind as u8;
    }

    pub fn merge(&mut self, other: Self) {
        self.0 |= other.0;
    }

    pub fn from_sections(sections: &[LinuxKoSpecialSection<'_>]) -> Self {
        let mut coverage = Self::empty();
        for section in sections {
            coverage.acknowledge(section.kind);
        }
        coverage
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PreparedPatch {
    image_offset: usize,
    bytes: [u8; 8],
    width: u8,
}

impl PreparedPatch {
    fn value(&self) -> &[u8] {
        &self.bytes[..usize::from(self.width)]
    }
}

/// Base-independent section layout and admitted module requirements.
///
/// Construct this before reserving kernel virtual memory. Binding it to the
/// address returned by the backend freezes live KPI addresses and relocation
/// values without mutating the target mapping.
pub struct LinuxKoLoadBlueprint<'a> {
    bytes: &'a [u8],
    requirements: LinuxKoRequirements<'a>,
    placements: Vec<LinuxKoSectionPlacement>,
    regions: Vec<LinuxKoMemoryRegion>,
    image_size: usize,
    image_alignment: usize,
    core_size: usize,
    init_size: usize,
}

impl<'a> LinuxKoLoadBlueprint<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, LinuxKoLoadError> {
        let requirements = linux_ko::requirements(bytes).map_err(LinuxKoLoadError::Requirements)?;
        let module = ElfModule::parse(bytes).map_err(LinuxKoLoadError::Elf)?;
        let (placements, regions, image_size, image_alignment, core_size) =
            plan_allocated_sections(&module)?;
        let init_size = image_size
            .checked_sub(core_size)
            .ok_or(LinuxKoLoadError::InvalidSectionLayout)?;
        Ok(Self {
            bytes,
            requirements,
            placements,
            regions,
            image_size,
            image_alignment,
            core_size,
            init_size,
        })
    }

    pub const fn image_size(&self) -> usize {
        self.image_size
    }

    pub const fn image_alignment(&self) -> usize {
        self.image_alignment
    }

    pub const fn core_size(&self) -> usize {
        self.core_size
    }

    pub const fn init_size(&self) -> usize {
        self.init_size
    }

    pub fn sections(&self) -> &[LinuxKoSectionPlacement] {
        &self.placements
    }

    pub fn regions(&self) -> &[LinuxKoMemoryRegion] {
        &self.regions
    }

    pub fn bind<R: LinuxKernelSymbolResolver + ?Sized>(
        self,
        image_virtual_address: u64,
        expected_vermagic: &[u8],
        resolver: &R,
    ) -> Result<LinuxKoLoadPlan<'a>, LinuxKoLoadError> {
        if image_virtual_address == 0
            || image_virtual_address % self.image_alignment as u64 != 0
            || image_virtual_address
                .checked_add(self.image_size as u64)
                .is_none()
        {
            return Err(LinuxKoLoadError::InvalidImageAddress);
        }
        let resolution = self
            .requirements
            .resolve(expected_vermagic, resolver)
            .map_err(LinuxKoLoadError::Admission)?;
        let module = ElfModule::parse(self.bytes).map_err(LinuxKoLoadError::Elf)?;
        let (symbol_table_index, local_symbol_count, symbols, strings) =
            find_symbol_table(&module)?;
        validate_symbols(
            &module,
            local_symbol_count,
            symbols,
            strings,
            &self.placements,
        )?;
        let symbol_addresses = freeze_symbol_addresses(
            &module,
            symbols,
            strings,
            &self.placements,
            &resolution,
            image_virtual_address,
        )?;
        let init_address = resolve_lifecycle_symbol(
            symbols,
            strings,
            &self.placements,
            &symbol_addresses,
            b"init_module",
            true,
        )?
        .ok_or(LinuxKoLoadError::MissingInit)?;
        let cleanup_address = resolve_lifecycle_symbol(
            symbols,
            strings,
            &self.placements,
            &symbol_addresses,
            b"cleanup_module",
            false,
        )?;
        if self.requirements.manifest.has_cleanup != cleanup_address.is_some() {
            return Err(LinuxKoLoadError::InvalidCleanup);
        }
        let patches = prepare_relocations(
            &module,
            symbol_table_index,
            symbols,
            &self.placements,
            &symbol_addresses,
            image_virtual_address,
        )?;
        Ok(LinuxKoLoadPlan {
            bytes: self.bytes,
            name: self.requirements.name,
            admission: resolution.admission,
            image_virtual_address,
            image_size: self.image_size,
            image_alignment: self.image_alignment,
            core_size: self.core_size,
            init_size: self.init_size,
            init_address,
            cleanup_address,
            placements: self.placements,
            regions: self.regions,
            patches,
        })
    }
}

/// Fully frozen Linux module load transaction.
pub struct LinuxKoLoadPlan<'a> {
    bytes: &'a [u8],
    name: &'a [u8],
    admission: LinuxKoAdmission,
    image_virtual_address: u64,
    image_size: usize,
    image_alignment: usize,
    core_size: usize,
    init_size: usize,
    init_address: u64,
    cleanup_address: Option<u64>,
    placements: Vec<LinuxKoSectionPlacement>,
    regions: Vec<LinuxKoMemoryRegion>,
    patches: Vec<PreparedPatch>,
}

impl LinuxKoLoadPlan<'_> {
    /// Returns the immutable admitted ELF source. Runtime processors must read
    /// relocated values through the backend staging image, not this source.
    pub const fn source_bytes(&self) -> &[u8] {
        self.bytes
    }

    pub const fn name(&self) -> &[u8] {
        self.name
    }

    pub const fn admission(&self) -> LinuxKoAdmission {
        self.admission
    }

    pub const fn image_virtual_address(&self) -> u64 {
        self.image_virtual_address
    }

    pub const fn image_size(&self) -> usize {
        self.image_size
    }

    pub const fn image_alignment(&self) -> usize {
        self.image_alignment
    }

    pub const fn core_size(&self) -> usize {
        self.core_size
    }

    pub const fn init_size(&self) -> usize {
        self.init_size
    }

    pub const fn init_address(&self) -> u64 {
        self.init_address
    }

    pub const fn cleanup_address(&self) -> Option<u64> {
        self.cleanup_address
    }

    pub fn sections(&self) -> &[LinuxKoSectionPlacement] {
        &self.placements
    }

    /// Returns the immutable ELF name for one allocated placement.
    pub fn section_name<'a>(
        &'a self,
        placement: &LinuxKoSectionPlacement,
    ) -> Result<&'a [u8], LinuxKoLoadError> {
        if !self
            .placements
            .iter()
            .any(|candidate| candidate == placement)
        {
            return Err(LinuxKoLoadError::InvalidSectionLayout);
        }
        let module = ElfModule::parse(self.bytes).map_err(LinuxKoLoadError::Elf)?;
        let section = module
            .section(placement.section_index)
            .ok_or(LinuxKoLoadError::InvalidSectionLayout)?;
        module.section_name(section).map_err(LinuxKoLoadError::Elf)
    }

    /// Inventories every measured Linux/x86-64 section that requires
    /// pre-publication transformation or runtime registration.
    pub fn special_sections(&self) -> Result<Vec<LinuxKoSpecialSection<'_>>, LinuxKoLoadError> {
        let module = ElfModule::parse(self.bytes).map_err(LinuxKoLoadError::Elf)?;
        let mut special = Vec::new();
        special
            .try_reserve_exact(self.placements.len())
            .map_err(|_| LinuxKoLoadError::PlanAllocationFailed)?;
        for placement in &self.placements {
            let section = module
                .section(placement.section_index)
                .ok_or(LinuxKoLoadError::InvalidSectionLayout)?;
            let name = module
                .section_name(section)
                .map_err(LinuxKoLoadError::Elf)?;
            if let Some(kind) = classify_special_section(name) {
                special.push(LinuxKoSpecialSection {
                    section_index: placement.section_index,
                    name,
                    image_offset: placement.image_offset,
                    size: placement.memory_size,
                    kind,
                });
            }
        }
        Ok(special)
    }

    pub fn regions(&self) -> &[LinuxKoMemoryRegion] {
        &self.regions
    }

    pub fn relocation_count(&self) -> usize {
        self.patches.len()
    }

    /// Materializes the exact image into a software buffer. Kernel backends
    /// use the streaming installer below to avoid a second large allocation.
    pub fn commit(&self, image: &mut [u8]) -> Result<(), LinuxKoLoadError> {
        if image.len() != self.image_size {
            return Err(LinuxKoLoadError::ImageSizeMismatch);
        }
        image.fill(0);
        for placement in &self.placements {
            if placement.file_size == 0 {
                continue;
            }
            let source = self
                .bytes
                .get(placement.file_offset..placement.file_offset + placement.file_size)
                .ok_or(LinuxKoLoadError::InvalidSectionLayout)?;
            image[placement.image_offset..placement.image_offset + placement.file_size]
                .copy_from_slice(source);
        }
        for patch in &self.patches {
            image[patch.image_offset..patch.image_offset + patch.value().len()]
                .copy_from_slice(patch.value());
        }
        Ok(())
    }
}

fn classify_special_section(name: &[u8]) -> Option<LinuxKoSpecialSectionKind> {
    use LinuxKoSpecialSectionKind as Kind;

    Some(match name {
        b".gnu.linkonce.this_module" => Kind::ModuleIdentity,
        b".altinstructions" | b".altinstr_replacement" | b".altinstr_aux" => Kind::Alternatives,
        b"__jump_table" => Kind::JumpLabels,
        b".static_call_sites" | b".static_call.text" | b".static_call_tramp_key" => {
            Kind::StaticCalls
        }
        b"__mcount_loc" | b"__patchable_function_entries" | b"_ftrace_events" => {
            Kind::DynamicTracing
        }
        b".smp_locks" => Kind::CpuLockPatching,
        b".retpoline_sites" | b".return_sites" | b".call_sites" | b".ibt_endbr_seal" => {
            Kind::CallSitePatching
        }
        b".orc_unwind" | b".orc_unwind_ip" | b".orc_header" => Kind::OrcUnwind,
        b"__bug_table" => Kind::BugTable,
        b"__param" => Kind::Parameters,
        b"__tracepoints"
        | b"__tracepoints_ptrs"
        | b"__tracepoints_strings"
        | b"__bpf_raw_tp_map" => Kind::Tracepoints,
        b"__ksymtab" | b"__ksymtab_gpl" | b"__kcrctab" | b"__kcrctab_gpl"
        | b"__ksymtab_strings" => Kind::SymbolExports,
        b".data..percpu" => Kind::PerCpu,
        b".codetag.alloc_tags" => Kind::AllocationTags,
        b".printk_index" => Kind::PrintkIndex,
        _ => return None,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxKoLoadError {
    Requirements(LinuxKoError),
    Admission(LinuxKoAdmissionError),
    Elf(ElfError),
    UnsupportedAllocatedSection(u32),
    UnsupportedAllocatedFlags(u64),
    WriteExecuteSection,
    InvalidSectionLayout,
    ImageTooLarge,
    InvalidImageAddress,
    MissingSymbolTable,
    DuplicateSymbolTable,
    InvalidSymbolTable,
    InvalidSymbol,
    MissingInit,
    DuplicateLifecycleSymbol,
    InvalidInit,
    InvalidCleanup,
    InvalidRelocation,
    UnsupportedRelocation(u32),
    RelocationValueOutOfRange,
    OverlappingRelocations,
    TooManyRelocations,
    PlanAllocationFailed,
    ImageSizeMismatch,
}

/// Kernel-memory and execution boundary used by the transactional installer.
///
/// `reserve_zeroed` must return inaccessible, zero-filled staging memory.
/// `prepare_for_seal` processes architecture and Linux special sections while
/// the relocated image is still writable but inaccessible to execution.
/// `seal` must publish exactly the supplied page-separated permissions and
/// reject writable+executable aliases. `abort`, `discard_init`, and `release`
/// must synchronously revoke addressability; physical reclamation debt may be
/// retained internally in a bounded quarantine.
pub trait LinuxKoBackend {
    type Error;
    type Reservation: Copy;
    type Module;

    fn reserve_zeroed(
        &mut self,
        size: usize,
        alignment: usize,
    ) -> Result<(Self::Reservation, u64), Self::Error>;

    fn write(
        &mut self,
        reservation: Self::Reservation,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), Self::Error>;

    fn verify(
        &mut self,
        reservation: Self::Reservation,
        offset: usize,
        expected: &[u8],
    ) -> Result<bool, Self::Error>;

    /// Performs every required pre-publication transformation and runtime
    /// registration against the fully relocated staging image.
    ///
    /// On failure the reservation remains owned by the backend and the
    /// installer calls `abort` exactly once. Implementations must reject every
    /// required special section they do not understand.
    fn prepare_for_seal(
        &mut self,
        reservation: Self::Reservation,
        plan: &LinuxKoLoadPlan<'_>,
    ) -> Result<(), Self::Error>;

    fn seal(
        &mut self,
        reservation: Self::Reservation,
        regions: &[LinuxKoMemoryRegion],
    ) -> Result<(), Self::Error>;

    /// Publishes the sealed image and transfers reservation ownership into a
    /// module handle. On `Err`, ownership remains with `reservation` and the
    /// installer will call `abort` exactly once.
    fn commit(
        &mut self,
        reservation: Self::Reservation,
        name: &[u8],
    ) -> Result<Self::Module, Self::Error>;

    /// Calls the sealed module initialization address. `Err` guarantees that
    /// control never entered the module; a module-reported failure is `Ok(n)`
    /// with nonzero `n`.
    ///
    /// # Safety
    ///
    /// The address must come from the committed module represented by
    /// `module`, and the kernel must serialize module lifecycle transitions.
    unsafe fn invoke_init(
        &mut self,
        module: &mut Self::Module,
        address: u64,
    ) -> Result<i32, Self::Error>;

    /// Revokes and schedules reclamation of the init-only mapping.
    fn discard_init(&mut self, module: &mut Self::Module, offset: usize, size: usize);

    /// Calls the sealed cleanup address. `Err` guarantees the callback was not
    /// entered, allowing the caller to retain and retry the live module.
    ///
    /// # Safety
    ///
    /// The address and handle must belong to the same live module and no new
    /// users may be admitted while cleanup is in progress.
    unsafe fn invoke_cleanup(
        &mut self,
        module: &mut Self::Module,
        address: u64,
    ) -> Result<(), Self::Error>;

    fn abort(&mut self, reservation: Self::Reservation);
    fn release(&mut self, module: Self::Module);
}

pub struct LiveLinuxModule<Module> {
    handle: Module,
    cleanup_address: Option<u64>,
}

impl<Module> LiveLinuxModule<Module> {
    pub const fn handle(&self) -> &Module {
        &self.handle
    }

    pub const fn cleanup_address(&self) -> Option<u64> {
        self.cleanup_address
    }

    /// Runs cleanup and revokes the module image. A backend dispatch failure
    /// returns ownership of the still-live module so cleanup can be retried.
    ///
    /// # Safety
    ///
    /// The caller must prevent new references and wait for all existing module
    /// users before calling this method.
    pub unsafe fn unload<Backend>(
        mut self,
        backend: &mut Backend,
    ) -> Result<(), (Self, Backend::Error)>
    where
        Backend: LinuxKoBackend<Module = Module>,
    {
        if let Some(address) = self.cleanup_address {
            if let Err(error) = unsafe { backend.invoke_cleanup(&mut self.handle, address) } {
                return Err((self, error));
            }
        }
        backend.release(self.handle);
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum LinuxKoInstallError<BackendError> {
    Load(LinuxKoLoadError),
    Backend(BackendError),
    VerificationFailed,
    InitFailed(i32),
}

/// Reserves, binds, relocates, seals and initializes one Linux module.
///
/// # Safety
///
/// The resolver must expose live kernel KPI addresses with the admitted ABI,
/// and the caller must serialize module loading while the backend executes the
/// module's initialization callback.
pub unsafe fn install_linux_module<'a, Resolver, Backend>(
    bytes: &'a [u8],
    expected_vermagic: &[u8],
    resolver: &Resolver,
    backend: &mut Backend,
) -> Result<LiveLinuxModule<Backend::Module>, LinuxKoInstallError<Backend::Error>>
where
    Resolver: LinuxKernelSymbolResolver + ?Sized,
    Backend: LinuxKoBackend,
{
    let blueprint = LinuxKoLoadBlueprint::parse(bytes).map_err(LinuxKoInstallError::Load)?;
    let (reservation, image_virtual_address) = backend
        .reserve_zeroed(blueprint.image_size(), blueprint.image_alignment())
        .map_err(LinuxKoInstallError::Backend)?;
    let plan = match blueprint.bind(image_virtual_address, expected_vermagic, resolver) {
        Ok(plan) => plan,
        Err(error) => {
            backend.abort(reservation);
            return Err(LinuxKoInstallError::Load(error));
        }
    };

    for placement in &plan.placements {
        if placement.file_size == 0 {
            continue;
        }
        let source =
            &plan.bytes[placement.file_offset..placement.file_offset + placement.file_size];
        if let Err(error) = write_verified(backend, reservation, placement.image_offset, source) {
            backend.abort(reservation);
            return Err(error);
        }
    }
    for patch in &plan.patches {
        if let Err(error) = write_verified(backend, reservation, patch.image_offset, patch.value())
        {
            backend.abort(reservation);
            return Err(error);
        }
    }
    if let Err(error) = backend.prepare_for_seal(reservation, &plan) {
        backend.abort(reservation);
        return Err(LinuxKoInstallError::Backend(error));
    }
    if let Err(error) = backend.seal(reservation, &plan.regions) {
        backend.abort(reservation);
        return Err(LinuxKoInstallError::Backend(error));
    }
    let mut module = match backend.commit(reservation, plan.name) {
        Ok(module) => module,
        Err(error) => {
            backend.abort(reservation);
            return Err(LinuxKoInstallError::Backend(error));
        }
    };
    let status = match unsafe { backend.invoke_init(&mut module, plan.init_address) } {
        Ok(status) => status,
        Err(error) => {
            backend.release(module);
            return Err(LinuxKoInstallError::Backend(error));
        }
    };
    if status != 0 {
        backend.release(module);
        return Err(LinuxKoInstallError::InitFailed(status));
    }
    if plan.init_size != 0 {
        backend.discard_init(&mut module, plan.core_size, plan.init_size);
    }
    Ok(LiveLinuxModule {
        handle: module,
        cleanup_address: plan.cleanup_address,
    })
}

fn write_verified<Backend: LinuxKoBackend>(
    backend: &mut Backend,
    reservation: Backend::Reservation,
    offset: usize,
    bytes: &[u8],
) -> Result<(), LinuxKoInstallError<Backend::Error>> {
    backend
        .write(reservation, offset, bytes)
        .map_err(LinuxKoInstallError::Backend)?;
    match backend.verify(reservation, offset, bytes) {
        Ok(true) => Ok(()),
        Ok(false) => Err(LinuxKoInstallError::VerificationFailed),
        Err(error) => Err(LinuxKoInstallError::Backend(error)),
    }
}

fn plan_allocated_sections(
    module: &ElfModule<'_>,
) -> Result<
    (
        Vec<LinuxKoSectionPlacement>,
        Vec<LinuxKoMemoryRegion>,
        usize,
        usize,
        usize,
    ),
    LinuxKoLoadError,
> {
    let mut placements = Vec::new();
    placements
        .try_reserve_exact(module.section_count())
        .map_err(|_| LinuxKoLoadError::PlanAllocationFailed)?;
    let mut regions = Vec::new();
    regions
        .try_reserve_exact(LinuxKoRegionKind::ORDER.len())
        .map_err(|_| LinuxKoLoadError::PlanAllocationFailed)?;
    let mut image_size = 0_usize;
    let mut image_alignment = PAGE_BYTES;
    let mut core_size = 0_usize;

    for kind in LinuxKoRegionKind::ORDER {
        let region_start =
            align_up(image_size, PAGE_BYTES).ok_or(LinuxKoLoadError::ImageTooLarge)?;
        let placement_start = placements.len();
        let mut cursor = region_start;
        for section_index in 1..module.section_count() {
            let section = module
                .section(section_index)
                .ok_or(LinuxKoLoadError::InvalidSectionLayout)?;
            if section.flags & SECTION_ALLOCATE == 0 {
                continue;
            }
            validate_allocated_section(module, section)?;
            let name = module
                .section_name(section)
                .map_err(LinuxKoLoadError::Elf)?;
            if classify_region(name, section) != kind || section.size == 0 {
                continue;
            }
            let memory_size = usize::try_from(section.size)
                .map_err(|_| LinuxKoLoadError::InvalidSectionLayout)?;
            let alignment = usize::try_from(section.alignment.max(1))
                .map_err(|_| LinuxKoLoadError::InvalidSectionLayout)?;
            image_alignment = image_alignment.max(alignment);
            cursor = align_up(cursor, alignment).ok_or(LinuxKoLoadError::ImageTooLarge)?;
            let end = cursor
                .checked_add(memory_size)
                .filter(|end| *end <= MAXIMUM_IMAGE_BYTES)
                .ok_or(LinuxKoLoadError::ImageTooLarge)?;
            let file_size = if section.section_type == SECTION_TYPE_NOBITS {
                0
            } else {
                memory_size
            };
            let file_offset = usize::try_from(section.offset)
                .map_err(|_| LinuxKoLoadError::InvalidSectionLayout)?;
            placements.push(LinuxKoSectionPlacement {
                section_index,
                image_offset: cursor,
                memory_size,
                region: kind,
                file_offset,
                file_size,
            });
            cursor = end;
        }
        if placements.len() != placement_start {
            image_size = align_up(cursor, PAGE_BYTES).ok_or(LinuxKoLoadError::ImageTooLarge)?;
            regions.push(LinuxKoMemoryRegion {
                kind,
                image_offset: region_start,
                size: image_size - region_start,
                readable: true,
                writable: kind.writable(),
                executable: kind.executable(),
                discard_after_init: kind.is_init(),
            });
        }
        if kind == LinuxKoRegionKind::CoreWritable {
            core_size = image_size;
        }
    }
    if placements.is_empty()
        || image_size == 0
        || image_size > MAXIMUM_IMAGE_BYTES
        || !placements.iter().any(|placement| {
            matches!(
                placement.region,
                LinuxKoRegionKind::CoreText | LinuxKoRegionKind::InitText
            )
        })
    {
        return Err(LinuxKoLoadError::InvalidSectionLayout);
    }
    Ok((placements, regions, image_size, image_alignment, core_size))
}

fn validate_allocated_section(
    module: &ElfModule<'_>,
    section: SectionHeader,
) -> Result<(), LinuxKoLoadError> {
    if section.flags & !SUPPORTED_ALLOCATED_FLAGS != 0 {
        return Err(LinuxKoLoadError::UnsupportedAllocatedFlags(section.flags));
    }
    if section.flags & (SECTION_WRITE | SECTION_EXECUTE) == (SECTION_WRITE | SECTION_EXECUTE) {
        return Err(LinuxKoLoadError::WriteExecuteSection);
    }
    if !matches!(
        section.section_type,
        SECTION_TYPE_PROGRAM_BITS | SECTION_TYPE_NOBITS | SECTION_TYPE_NOTE
    ) {
        return Err(LinuxKoLoadError::UnsupportedAllocatedSection(
            section.section_type,
        ));
    }
    if section.section_type == SECTION_TYPE_NOTE
        && section.flags & (SECTION_WRITE | SECTION_EXECUTE) != 0
    {
        return Err(LinuxKoLoadError::InvalidSectionLayout);
    }
    if section.flags & (SECTION_MERGE | SECTION_STRINGS) != 0
        && (section.section_type != SECTION_TYPE_PROGRAM_BITS || section.entry_size == 0)
    {
        return Err(LinuxKoLoadError::InvalidSectionLayout);
    }
    if section.flags & SECTION_LINK_ORDER != 0 {
        let linked = module
            .section(section.link as usize)
            .filter(|_| section.link != 0)
            .ok_or(LinuxKoLoadError::InvalidSectionLayout)?;
        if linked.flags & SECTION_ALLOCATE == 0 {
            return Err(LinuxKoLoadError::InvalidSectionLayout);
        }
    }
    Ok(())
}

fn classify_region(name: &[u8], section: SectionHeader) -> LinuxKoRegionKind {
    let init = name.starts_with(b".init");
    let executable = section.flags & SECTION_EXECUTE != 0;
    let writable = section.flags & SECTION_WRITE != 0;
    match (init, executable, writable) {
        (false, true, _) => LinuxKoRegionKind::CoreText,
        (false, false, false) => LinuxKoRegionKind::CoreReadOnly,
        (false, false, true) => LinuxKoRegionKind::CoreWritable,
        (true, true, _) => LinuxKoRegionKind::InitText,
        (true, false, false) => LinuxKoRegionKind::InitReadOnly,
        (true, false, true) => LinuxKoRegionKind::InitWritable,
    }
}

fn find_symbol_table<'a>(
    module: &ElfModule<'a>,
) -> Result<(usize, usize, &'a [u8], &'a [u8]), LinuxKoLoadError> {
    let mut found = None;
    for index in 1..module.section_count() {
        let section = module
            .section(index)
            .ok_or(LinuxKoLoadError::InvalidSymbolTable)?;
        if section.section_type != SECTION_TYPE_SYMBOL_TABLE {
            continue;
        }
        if found.is_some() {
            return Err(LinuxKoLoadError::DuplicateSymbolTable);
        }
        if section.entry_size != core::mem::size_of::<SymbolEntry>() as u64
            || section.size == 0
            || section.size % section.entry_size != 0
            || section.link == 0
        {
            return Err(LinuxKoLoadError::InvalidSymbolTable);
        }
        let strings = module
            .section(section.link as usize)
            .ok_or(LinuxKoLoadError::InvalidSymbolTable)?;
        if strings.section_type != SECTION_TYPE_STRING_TABLE {
            return Err(LinuxKoLoadError::InvalidSymbolTable);
        }
        let symbols = module
            .section_data(section)
            .map_err(|_| LinuxKoLoadError::InvalidSymbolTable)?;
        let strings = module
            .section_data(strings)
            .map_err(|_| LinuxKoLoadError::InvalidSymbolTable)?;
        let local_symbol_count = section.info as usize;
        if local_symbol_count == 0
            || local_symbol_count > symbols.len() / core::mem::size_of::<SymbolEntry>()
        {
            return Err(LinuxKoLoadError::InvalidSymbolTable);
        }
        found = Some((index, local_symbol_count, symbols, strings));
    }
    found.ok_or(LinuxKoLoadError::MissingSymbolTable)
}

fn validate_symbols(
    module: &ElfModule<'_>,
    local_symbol_count: usize,
    symbols: &[u8],
    strings: &[u8],
    placements: &[LinuxKoSectionPlacement],
) -> Result<(), LinuxKoLoadError> {
    if symbols.is_empty()
        || symbols.len() % core::mem::size_of::<SymbolEntry>() != 0
        || strings.first() != Some(&0)
    {
        return Err(LinuxKoLoadError::InvalidSymbolTable);
    }
    let null = parse_symbol(symbols, 0).ok_or(LinuxKoLoadError::InvalidSymbolTable)?;
    if null.name_offset != 0
        || null.information != 0
        || null.visibility != 0
        || null.section_index != 0
        || null.value != 0
        || null.size != 0
    {
        return Err(LinuxKoLoadError::InvalidSymbolTable);
    }
    for index in 0..symbols.len() / core::mem::size_of::<SymbolEntry>() {
        let symbol = parse_symbol(symbols, index).ok_or(LinuxKoLoadError::InvalidSymbol)?;
        let binding = symbol.information >> 4;
        if (index < local_symbol_count) != (binding == 0) || symbol.visibility & !0x3 != 0 {
            return Err(LinuxKoLoadError::InvalidSymbol);
        }
        let _ = string_at(strings, symbol.name_offset as usize)
            .ok_or(LinuxKoLoadError::InvalidSymbol)?;
        match symbol.section_index {
            SECTION_UNDEFINED => {
                if index != 0 && (symbol.value != 0 || symbol.size != 0) {
                    return Err(LinuxKoLoadError::InvalidSymbol);
                }
            }
            SECTION_ABSOLUTE => {}
            reserved if reserved >= RESERVED_SECTION_START => {
                return Err(LinuxKoLoadError::InvalidSymbol);
            }
            section_index => {
                let section = module
                    .section(section_index as usize)
                    .ok_or(LinuxKoLoadError::InvalidSymbol)?;
                if symbol
                    .value
                    .checked_add(symbol.size)
                    .is_none_or(|end| end > section.size)
                {
                    return Err(LinuxKoLoadError::InvalidSymbol);
                }
                if section.flags & SECTION_ALLOCATE != 0
                    && placement_for(placements, section_index as usize).is_none()
                    && section.size != 0
                {
                    return Err(LinuxKoLoadError::InvalidSymbol);
                }
            }
        }
    }
    Ok(())
}

fn freeze_symbol_addresses(
    module: &ElfModule<'_>,
    symbols: &[u8],
    strings: &[u8],
    placements: &[LinuxKoSectionPlacement],
    resolution: &LinuxKoResolution<'_>,
    image_virtual_address: u64,
) -> Result<Vec<Option<u64>>, LinuxKoLoadError> {
    let count = symbols.len() / core::mem::size_of::<SymbolEntry>();
    let mut addresses = Vec::new();
    addresses
        .try_reserve_exact(count)
        .map_err(|_| LinuxKoLoadError::PlanAllocationFailed)?;
    for index in 0..count {
        let symbol = parse_symbol(symbols, index).ok_or(LinuxKoLoadError::InvalidSymbol)?;
        let address = match symbol.section_index {
            SECTION_UNDEFINED if index == 0 => None,
            SECTION_UNDEFINED | SECTION_ABSOLUTE => Some(resolve_symbol_address(
                module,
                symbol,
                strings,
                placements,
                resolution,
                image_virtual_address,
            )?),
            section_index if placement_for(placements, section_index as usize).is_some() => {
                Some(resolve_symbol_address(
                    module,
                    symbol,
                    strings,
                    placements,
                    resolution,
                    image_virtual_address,
                )?)
            }
            _ => None,
        };
        addresses.push(address);
    }
    Ok(addresses)
}

fn resolve_lifecycle_symbol(
    symbols: &[u8],
    strings: &[u8],
    placements: &[LinuxKoSectionPlacement],
    symbol_addresses: &[Option<u64>],
    requested: &[u8],
    require_init: bool,
) -> Result<Option<u64>, LinuxKoLoadError> {
    let mut found = None;
    for index in 1..symbols.len() / core::mem::size_of::<SymbolEntry>() {
        let symbol = parse_symbol(symbols, index).ok_or(LinuxKoLoadError::InvalidSymbol)?;
        if string_at(strings, symbol.name_offset as usize) != Some(requested) {
            continue;
        }
        if found.is_some() {
            return Err(LinuxKoLoadError::DuplicateLifecycleSymbol);
        }
        let placement = placement_for(placements, symbol.section_index as usize)
            .filter(|placement| {
                placement.region
                    == if require_init {
                        LinuxKoRegionKind::InitText
                    } else {
                        LinuxKoRegionKind::CoreText
                    }
            })
            .ok_or(if require_init {
                LinuxKoLoadError::InvalidInit
            } else {
                LinuxKoLoadError::InvalidCleanup
            })?;
        if symbol.information >> 4 != SYMBOL_BINDING_GLOBAL
            || symbol.information & 0xf != SYMBOL_TYPE_FUNCTION
            || symbol.value >= placement.memory_size as u64
            || symbol.size == 0
        {
            return Err(if require_init {
                LinuxKoLoadError::InvalidInit
            } else {
                LinuxKoLoadError::InvalidCleanup
            });
        }
        found = Some(
            symbol_addresses
                .get(index)
                .copied()
                .flatten()
                .ok_or(if require_init {
                    LinuxKoLoadError::InvalidInit
                } else {
                    LinuxKoLoadError::InvalidCleanup
                })?,
        );
    }
    Ok(found)
}

fn prepare_relocations(
    module: &ElfModule<'_>,
    symbol_table_index: usize,
    symbols: &[u8],
    placements: &[LinuxKoSectionPlacement],
    symbol_addresses: &[Option<u64>],
    image_virtual_address: u64,
) -> Result<Vec<PreparedPatch>, LinuxKoLoadError> {
    let mut patches = Vec::new();
    for index in 1..module.section_count() {
        let relocation_section = module
            .section(index)
            .ok_or(LinuxKoLoadError::InvalidRelocation)?;
        if relocation_section.section_type != SECTION_TYPE_RELA {
            continue;
        }
        let Some(target) = placement_for(placements, relocation_section.info as usize) else {
            continue;
        };
        if relocation_section.link as usize != symbol_table_index
            || relocation_section.entry_size != core::mem::size_of::<RelocationEntry>() as u64
            || relocation_section.size % relocation_section.entry_size != 0
        {
            return Err(LinuxKoLoadError::InvalidRelocation);
        }
        let bytes = module
            .section_data(relocation_section)
            .map_err(|_| LinuxKoLoadError::InvalidRelocation)?;
        let count = bytes.len() / core::mem::size_of::<RelocationEntry>();
        if patches
            .len()
            .checked_add(count)
            .is_none_or(|count| count > MAXIMUM_RELOCATIONS)
        {
            return Err(LinuxKoLoadError::TooManyRelocations);
        }
        patches
            .try_reserve(count)
            .map_err(|_| LinuxKoLoadError::PlanAllocationFailed)?;
        for relocation_index in 0..count {
            let relocation = parse_relocation(bytes, relocation_index)
                .ok_or(LinuxKoLoadError::InvalidRelocation)?;
            patches.push(prepare_patch(
                relocation,
                target,
                symbols,
                symbol_addresses,
                image_virtual_address,
            )?);
        }
    }
    patches.sort_unstable_by_key(|patch| patch.image_offset);
    if patches.windows(2).any(|pair| {
        pair[0]
            .image_offset
            .checked_add(usize::from(pair[0].width))
            .is_none_or(|end| end > pair[1].image_offset)
    }) {
        return Err(LinuxKoLoadError::OverlappingRelocations);
    }
    Ok(patches)
}

fn prepare_patch(
    relocation: RelocationEntry,
    target: &LinuxKoSectionPlacement,
    symbols: &[u8],
    symbol_addresses: &[Option<u64>],
    image_virtual_address: u64,
) -> Result<PreparedPatch, LinuxKoLoadError> {
    let symbol_index = usize::try_from(relocation.information >> 32)
        .map_err(|_| LinuxKoLoadError::InvalidRelocation)?;
    let _ = parse_symbol(symbols, symbol_index).ok_or(LinuxKoLoadError::InvalidRelocation)?;
    let symbol_address = symbol_addresses
        .get(symbol_index)
        .copied()
        .flatten()
        .ok_or(LinuxKoLoadError::InvalidSymbol)?;
    let relative_offset =
        usize::try_from(relocation.offset).map_err(|_| LinuxKoLoadError::InvalidRelocation)?;
    let image_offset = target
        .image_offset
        .checked_add(relative_offset)
        .ok_or(LinuxKoLoadError::InvalidRelocation)?;
    let place = image_virtual_address
        .checked_add(image_offset as u64)
        .ok_or(LinuxKoLoadError::RelocationValueOutOfRange)?;
    let absolute = i128::from(symbol_address) + i128::from(relocation.addend);
    let mut bytes = [0_u8; 8];
    let width = match relocation.information as u32 {
        R_X86_64_64 => {
            check_patch(target, relative_offset, 8)?;
            bytes.copy_from_slice(
                &u64::try_from(absolute)
                    .map_err(|_| LinuxKoLoadError::RelocationValueOutOfRange)?
                    .to_le_bytes(),
            );
            8
        }
        R_X86_64_PC32 | R_X86_64_PLT32 => {
            check_patch(target, relative_offset, 4)?;
            bytes[..4].copy_from_slice(
                &i32::try_from(absolute - i128::from(place))
                    .map_err(|_| LinuxKoLoadError::RelocationValueOutOfRange)?
                    .to_le_bytes(),
            );
            4
        }
        R_X86_64_32 => {
            check_patch(target, relative_offset, 4)?;
            bytes[..4].copy_from_slice(
                &u32::try_from(absolute)
                    .map_err(|_| LinuxKoLoadError::RelocationValueOutOfRange)?
                    .to_le_bytes(),
            );
            4
        }
        R_X86_64_32S => {
            check_patch(target, relative_offset, 4)?;
            bytes[..4].copy_from_slice(
                &i32::try_from(absolute)
                    .map_err(|_| LinuxKoLoadError::RelocationValueOutOfRange)?
                    .to_le_bytes(),
            );
            4
        }
        R_X86_64_PC64 => {
            check_patch(target, relative_offset, 8)?;
            bytes.copy_from_slice(
                &i64::try_from(absolute - i128::from(place))
                    .map_err(|_| LinuxKoLoadError::RelocationValueOutOfRange)?
                    .to_le_bytes(),
            );
            8
        }
        unsupported => return Err(LinuxKoLoadError::UnsupportedRelocation(unsupported)),
    };
    Ok(PreparedPatch {
        image_offset,
        bytes,
        width,
    })
}

fn resolve_symbol_address(
    module: &ElfModule<'_>,
    symbol: SymbolEntry,
    strings: &[u8],
    placements: &[LinuxKoSectionPlacement],
    resolution: &LinuxKoResolution<'_>,
    image_virtual_address: u64,
) -> Result<u64, LinuxKoLoadError> {
    match symbol.section_index {
        SECTION_UNDEFINED => {
            if symbol.information >> 4 != SYMBOL_BINDING_GLOBAL || symbol.visibility != 0 {
                return Err(LinuxKoLoadError::InvalidSymbol);
            }
            let name = string_at(strings, symbol.name_offset as usize)
                .filter(|name| !name.is_empty())
                .ok_or(LinuxKoLoadError::InvalidSymbol)?;
            resolution
                .address(name)
                .ok_or(LinuxKoLoadError::InvalidSymbol)
        }
        SECTION_ABSOLUTE => Ok(symbol.value),
        reserved if reserved >= RESERVED_SECTION_START => Err(LinuxKoLoadError::InvalidSymbol),
        section_index => {
            let placement = placement_for(placements, section_index as usize)
                .ok_or(LinuxKoLoadError::InvalidSymbol)?;
            let section = module
                .section(section_index as usize)
                .ok_or(LinuxKoLoadError::InvalidSymbol)?;
            if symbol.value > section.size {
                return Err(LinuxKoLoadError::InvalidSymbol);
            }
            image_virtual_address
                .checked_add(placement.image_offset as u64)
                .and_then(|address| address.checked_add(symbol.value))
                .ok_or(LinuxKoLoadError::RelocationValueOutOfRange)
        }
    }
}

fn check_patch(
    target: &LinuxKoSectionPlacement,
    offset: usize,
    width: usize,
) -> Result<(), LinuxKoLoadError> {
    if offset
        .checked_add(width)
        .is_none_or(|end| end > target.memory_size)
    {
        Err(LinuxKoLoadError::InvalidRelocation)
    } else {
        Ok(())
    }
}

fn placement_for(
    placements: &[LinuxKoSectionPlacement],
    section_index: usize,
) -> Option<&LinuxKoSectionPlacement> {
    placements
        .iter()
        .find(|placement| placement.section_index == section_index)
}

fn parse_symbol(bytes: &[u8], index: usize) -> Option<SymbolEntry> {
    let offset = index.checked_mul(core::mem::size_of::<SymbolEntry>())?;
    Some(SymbolEntry {
        name_offset: read_u32(bytes, offset)?,
        information: *bytes.get(offset + 4)?,
        visibility: *bytes.get(offset + 5)?,
        section_index: read_u16(bytes, offset + 6)?,
        value: read_u64(bytes, offset + 8)?,
        size: read_u64(bytes, offset + 16)?,
    })
}

fn parse_relocation(bytes: &[u8], index: usize) -> Option<RelocationEntry> {
    let offset = index.checked_mul(core::mem::size_of::<RelocationEntry>())?;
    Some(RelocationEntry {
        offset: read_u64(bytes, offset)?,
        information: read_u64(bytes, offset + 8)?,
        addend: read_i64(bytes, offset + 16)?,
    })
}

fn string_at(bytes: &[u8], offset: usize) -> Option<&[u8]> {
    let suffix = bytes.get(offset..)?;
    let length = suffix.iter().position(|byte| *byte == 0)?;
    Some(&suffix[..length])
}

fn align_up(value: usize, alignment: usize) -> Option<usize> {
    debug_assert!(alignment.is_power_of_two());
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn read_i64(bytes: &[u8], offset: usize) -> Option<i64> {
    Some(i64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::module::linux_ko::{LinuxExportClass, LinuxKernelSymbol};

    const IMAGE_BASE: u64 = 0x20_0000;
    const EXTERNAL_ADDRESS: u64 = 0x1234_5678;

    struct Resolver;

    impl LinuxKernelSymbolResolver for Resolver {
        fn resolve<'a>(&'a self, name: &[u8]) -> Option<LinuxKernelSymbol<'a>> {
            let (address, crc) = match name {
                b"module_layout" => (0x10_0000, 0x1122_3344),
                b"external" => (EXTERNAL_ADDRESS, 0xaabb_ccdd),
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

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum BackendError {
        InvalidOperation,
        PrepareUnavailable,
        CleanupUnavailable,
    }

    struct DryModule {
        image: Vec<u8>,
        base: u64,
    }

    struct DryBackend {
        staging: Option<Vec<u8>>,
        base: u64,
        sealed: bool,
        prepared: bool,
        committed: bool,
        aborted: usize,
        released: usize,
        discarded: Option<(usize, usize)>,
        init_calls: usize,
        prepare_calls: usize,
        prepare_failures: usize,
        cleanup_calls: usize,
        init_status: i32,
        cleanup_failures: usize,
    }

    impl DryBackend {
        fn new() -> Self {
            Self {
                staging: None,
                base: IMAGE_BASE,
                sealed: false,
                prepared: false,
                committed: false,
                aborted: 0,
                released: 0,
                discarded: None,
                init_calls: 0,
                prepare_calls: 0,
                prepare_failures: 0,
                cleanup_calls: 0,
                init_status: 0,
                cleanup_failures: 0,
            }
        }
    }

    impl LinuxKoBackend for DryBackend {
        type Error = BackendError;
        type Reservation = u64;
        type Module = DryModule;

        fn reserve_zeroed(
            &mut self,
            size: usize,
            alignment: usize,
        ) -> Result<(Self::Reservation, u64), Self::Error> {
            if self.staging.is_some()
                || size == 0
                || alignment < PAGE_BYTES
                || self.base % alignment as u64 != 0
            {
                return Err(BackendError::InvalidOperation);
            }
            self.staging = Some(vec![0; size]);
            Ok((1, self.base))
        }

        fn write(
            &mut self,
            reservation: Self::Reservation,
            offset: usize,
            bytes: &[u8],
        ) -> Result<(), Self::Error> {
            let image = self
                .staging
                .as_mut()
                .filter(|_| reservation == 1 && !self.sealed)
                .ok_or(BackendError::InvalidOperation)?;
            let target = image
                .get_mut(offset..offset + bytes.len())
                .ok_or(BackendError::InvalidOperation)?;
            target.copy_from_slice(bytes);
            Ok(())
        }

        fn verify(
            &mut self,
            reservation: Self::Reservation,
            offset: usize,
            expected: &[u8],
        ) -> Result<bool, Self::Error> {
            let image = self
                .staging
                .as_ref()
                .filter(|_| reservation == 1 && !self.sealed)
                .ok_or(BackendError::InvalidOperation)?;
            Ok(image.get(offset..offset + expected.len()) == Some(expected))
        }

        fn prepare_for_seal(
            &mut self,
            reservation: Self::Reservation,
            plan: &LinuxKoLoadPlan<'_>,
        ) -> Result<(), Self::Error> {
            if reservation != 1
                || self.staging.is_none()
                || self.sealed
                || self.prepared
                || plan.image_virtual_address() != self.base
            {
                return Err(BackendError::InvalidOperation);
            }
            self.prepare_calls += 1;
            if self.prepare_failures != 0 {
                self.prepare_failures -= 1;
                return Err(BackendError::PrepareUnavailable);
            }
            self.prepared = true;
            Ok(())
        }

        fn seal(
            &mut self,
            reservation: Self::Reservation,
            regions: &[LinuxKoMemoryRegion],
        ) -> Result<(), Self::Error> {
            if reservation != 1
                || self.staging.is_none()
                || !self.prepared
                || self.sealed
                || regions.is_empty()
                || regions.iter().any(|region| {
                    region.image_offset % PAGE_BYTES != 0
                        || region.size % PAGE_BYTES != 0
                        || !region.readable
                        || region.writable && region.executable
                })
                || regions
                    .windows(2)
                    .any(|pair| pair[0].image_offset + pair[0].size != pair[1].image_offset)
            {
                return Err(BackendError::InvalidOperation);
            }
            self.sealed = true;
            Ok(())
        }

        fn commit(
            &mut self,
            reservation: Self::Reservation,
            name: &[u8],
        ) -> Result<Self::Module, Self::Error> {
            if reservation != 1 || !self.sealed || self.committed || name != b"smoke" {
                return Err(BackendError::InvalidOperation);
            }
            self.committed = true;
            Ok(DryModule {
                image: self.staging.take().ok_or(BackendError::InvalidOperation)?,
                base: self.base,
            })
        }

        unsafe fn invoke_init(
            &mut self,
            module: &mut Self::Module,
            address: u64,
        ) -> Result<i32, Self::Error> {
            if address < module.base || address >= module.base + module.image.len() as u64 {
                return Err(BackendError::InvalidOperation);
            }
            self.init_calls += 1;
            Ok(self.init_status)
        }

        fn discard_init(&mut self, module: &mut Self::Module, offset: usize, size: usize) {
            module.image[offset..offset + size].fill(0);
            self.discarded = Some((offset, size));
        }

        unsafe fn invoke_cleanup(
            &mut self,
            module: &mut Self::Module,
            address: u64,
        ) -> Result<(), Self::Error> {
            if address < module.base || address >= module.base + module.image.len() as u64 {
                return Err(BackendError::InvalidOperation);
            }
            self.cleanup_calls += 1;
            if self.cleanup_failures != 0 {
                self.cleanup_failures -= 1;
                return Err(BackendError::CleanupUnavailable);
            }
            Ok(())
        }

        fn abort(&mut self, reservation: Self::Reservation) {
            assert_eq!(reservation, 1);
            self.staging = None;
            self.prepared = false;
            self.sealed = false;
            self.aborted += 1;
        }

        fn release(&mut self, _module: Self::Module) {
            self.released += 1;
        }
    }

    #[test]
    fn plans_page_separated_wx_regions_and_freezes_relocations() {
        let bytes = super::linux_ko::tests::fixture();
        let blueprint = LinuxKoLoadBlueprint::parse(&bytes).unwrap();
        assert_eq!(blueprint.image_alignment(), PAGE_BYTES);
        assert!(blueprint.core_size() > 0);
        assert!(blueprint.init_size() > 0);
        assert!(blueprint.regions().iter().all(|region| {
            region.image_offset % PAGE_BYTES == 0
                && region.size % PAGE_BYTES == 0
                && !(region.writable && region.executable)
        }));

        let plan = blueprint.bind(IMAGE_BASE, b"6.12", &Resolver).unwrap();
        assert_eq!(plan.relocation_count(), 1);
        let init = plan
            .sections()
            .iter()
            .find(|section| section.section_index == 5)
            .unwrap();
        let cleanup = plan
            .sections()
            .iter()
            .find(|section| section.section_index == 6)
            .unwrap();
        assert_eq!(init.region, LinuxKoRegionKind::InitText);
        assert_eq!(cleanup.region, LinuxKoRegionKind::CoreText);
        assert_eq!(plan.init_address(), IMAGE_BASE + init.image_offset as u64);
        assert_eq!(
            plan.cleanup_address(),
            Some(IMAGE_BASE + cleanup.image_offset as u64)
        );

        let target = plan
            .sections()
            .iter()
            .find(|section| section.section_index == 3)
            .unwrap();
        let mut image = vec![0xaa; plan.image_size()];
        plan.commit(&mut image).unwrap();
        assert_eq!(
            &image[target.image_offset..target.image_offset + 8],
            &EXTERNAL_ADDRESS.to_le_bytes()
        );
    }

    #[test]
    fn inventories_runtime_special_sections_without_marking_admission_metadata() {
        let bytes = super::linux_ko::tests::fixture();
        let plan = LinuxKoLoadBlueprint::parse(&bytes)
            .unwrap()
            .bind(IMAGE_BASE, b"6.12", &Resolver)
            .unwrap();
        let special = plan.special_sections().unwrap();

        assert_eq!(special.len(), 1);
        assert_eq!(special[0].name, b".gnu.linkonce.this_module");
        assert_eq!(special[0].kind, LinuxKoSpecialSectionKind::ModuleIdentity);
        assert!(special[0].size > 0);
        assert_eq!(
            plan.section_name(
                plan.sections()
                    .iter()
                    .find(|section| section.section_index == 2)
                    .unwrap()
            )
            .unwrap(),
            b".modinfo"
        );
    }

    #[test]
    fn classifies_measured_rhel_and_nvidia_runtime_sections() {
        use LinuxKoSpecialSectionKind as Kind;

        let cases: &[(&[u8], Kind)] = &[
            (b".altinstructions", Kind::Alternatives),
            (b"__jump_table", Kind::JumpLabels),
            (b".static_call_sites", Kind::StaticCalls),
            (b"__patchable_function_entries", Kind::DynamicTracing),
            (b".smp_locks", Kind::CpuLockPatching),
            (b".return_sites", Kind::CallSitePatching),
            (b".orc_unwind_ip", Kind::OrcUnwind),
            (b"__bug_table", Kind::BugTable),
            (b"__param", Kind::Parameters),
            (b"__tracepoints_ptrs", Kind::Tracepoints),
            (b"__ksymtab_gpl", Kind::SymbolExports),
            (b".data..percpu", Kind::PerCpu),
            (b".codetag.alloc_tags", Kind::AllocationTags),
            (b".printk_index", Kind::PrintkIndex),
        ];
        for (name, expected) in cases {
            assert_eq!(classify_special_section(name), Some(*expected));
        }
        assert_eq!(classify_special_section(b".text"), None);
        assert_eq!(classify_special_section(b".modinfo"), None);
        assert_eq!(classify_special_section(b"__versions"), None);
    }

    #[test]
    fn install_init_discard_cleanup_and_release_are_transactional() {
        let bytes = super::linux_ko::tests::fixture();
        let mut backend = DryBackend::new();
        let live =
            unsafe { install_linux_module(&bytes, b"6.12", &Resolver, &mut backend).unwrap() };
        assert_eq!(backend.init_calls, 1);
        assert_eq!(backend.prepare_calls, 1);
        assert!(backend.discarded.is_some_and(|(_, size)| size > 0));
        assert_eq!(backend.aborted, 0);
        assert_eq!(backend.released, 0);

        assert!(unsafe { live.unload(&mut backend) }.is_ok());
        assert_eq!(backend.cleanup_calls, 1);
        assert_eq!(backend.released, 1);
    }

    #[test]
    fn failed_init_releases_committed_image_without_publishing_it() {
        let bytes = super::linux_ko::tests::fixture();
        let mut backend = DryBackend::new();
        backend.init_status = -17;
        let result = unsafe { install_linux_module(&bytes, b"6.12", &Resolver, &mut backend) };
        assert!(matches!(result, Err(LinuxKoInstallError::InitFailed(-17))));
        assert_eq!(backend.init_calls, 1);
        assert_eq!(backend.released, 1);
        assert_eq!(backend.aborted, 0);
        assert!(backend.discarded.is_none());
    }

    #[test]
    fn failed_pre_seal_processing_aborts_without_publishing_pages() {
        let bytes = super::linux_ko::tests::fixture();
        let mut backend = DryBackend::new();
        backend.prepare_failures = 1;
        let result = unsafe { install_linux_module(&bytes, b"6.12", &Resolver, &mut backend) };
        assert!(matches!(
            result,
            Err(LinuxKoInstallError::Backend(
                BackendError::PrepareUnavailable
            ))
        ));
        assert_eq!(backend.prepare_calls, 1);
        assert_eq!(backend.aborted, 1);
        assert_eq!(backend.init_calls, 0);
        assert_eq!(backend.released, 0);
    }

    #[test]
    fn cleanup_dispatch_failure_preserves_ownership_for_retry() {
        let bytes = super::linux_ko::tests::fixture();
        let mut backend = DryBackend::new();
        backend.cleanup_failures = 1;
        let live =
            unsafe { install_linux_module(&bytes, b"6.12", &Resolver, &mut backend).unwrap() };
        let live = match unsafe { live.unload(&mut backend) } {
            Err((live, BackendError::CleanupUnavailable)) => live,
            _ => panic!("cleanup failure did not preserve the live module"),
        };
        assert_eq!(backend.released, 0);
        assert!(unsafe { live.unload(&mut backend) }.is_ok());
        assert_eq!(backend.cleanup_calls, 2);
        assert_eq!(backend.released, 1);
    }

    #[test]
    fn writable_executable_allocated_sections_fail_closed() {
        let mut bytes = super::linux_ko::tests::fixture();
        let section_table = bytes.len() - 10 * 64;
        let flags = section_table + 5 * 64 + 8;
        bytes[flags..flags + 8].copy_from_slice(&7_u64.to_le_bytes());
        assert!(matches!(
            LinuxKoLoadBlueprint::parse(&bytes),
            Err(LinuxKoLoadError::WriteExecuteSection)
        ));
    }
}
