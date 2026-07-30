#![no_std]
#![no_main]

extern crate alloc;

use ::blacklab::oureboros::{ArtifactManifest, FractalClass, TargetArchitecture, verify_artifact};
use abyss::allocator::BumpAllocator;
use abyss::frame::BitmapFrameAllocator;
use abyss::memory::MemoryRegionKind;
use abyss::paging::PhysicalAddress;
use abyss::reservation::{Reservation, ReservationKind, ReservationTable};
use alloc::boxed::Box;
use arach::arch::x86_64::{active_page_table_root, enable_execute_disable, halt, privilege};
use arach::boot::acpi::{discover_dmar, discover_madt};
use arach::boot::multiboot2::BootInformation;
use arach::capability::{
    ArtifactSynthesisControl, Authority, DeviceMemoryControl, DmaControl, FabricControl,
    FaultPolicyControl, LearningControl, MachineProfileControl, MemorySharingControl,
    PciConfigurationControl, PhysicalMemoryControl, PolicyControl, ProcessInstallControl,
    ResonanceControl, UserlandImageControl,
};
use arach::cpu::topology::{self, ExecutionClass, TopologyPolicy};
use arach::drivers::device_census::{
    AUTHORITY_CLOCK, AUTHORITY_DELEGATE, AUTHORITY_DMA, AUTHORITY_MMIO, AUTHORITY_PCI_CONFIG,
    BootDeviceCensus, DeviceState, DriverBindingManifest, EVIDENCE_CLASS_TUPLE, EVIDENCE_IDENTITY,
    EVIDENCE_PCI_CONFIGURATION, MAXIMUM_DISPLAY_CLAIMS, boot_device_record,
};
use arach::drivers::drivernet::fingerprint::LegacyConfigurationReader;
use arach::drivers::e1000::{
    DmaRings as E1000DmaRings, FRAME_BYTES as E1000_FRAME_BYTES,
    INTEL_VENDOR_ID as E1000_INTEL_VENDOR_ID, LinkInfo as E1000LinkInfo, QEMU_E1000_DEVICE_ID,
    RING_LENGTH as E1000_RING_LENGTH, ReceiveDescriptor as E1000ReceiveDescriptor,
    TransmitDescriptor as E1000TransmitDescriptor, acquire_dhcp as acquire_e1000_dhcp,
    initialize as initialize_e1000, publish as publish_e1000, quiesce as quiesce_e1000,
};
use arach::drivers::nvidia_gsp_bootstrap::TuringGspStagedBundle;
use arach::drivers::nvidia_gsp_firmware::TuringGspBootstrapMaterial;
use arach::drivers::xhci::{
    XHCI_PROBE_DRIVER_ID, XhciMutationDebt, XhciProbeCensus, XhciRegisterTransport,
    XhciResetReadyController, activate_reset_ready,
    activation_containment_root as xhci_activation_containment_root, boot_xhci_port_survey,
    boot_xhci_snapshot, boot_xhci_summary, boot_xhci_terminal_root,
    containment_root as xhci_containment_root, probe_bootstrap, publish_boot_xhci,
};
use arach::drivers::xhci_dma::{
    IdentityDmaObservation, IdentityDmaWindow, XHCI_MAXIMUM_DMA_PAGES, XHCI_MAXIMUM_REGION_COUNT,
    XHCI_MAXIMUM_SCRATCHPAD_BUFFERS, XhciDmaArena, XhciDmaPurpose,
};
use arach::drivers::xhci_ports::survey_halted_ports;
use arach::drivers::xhci_runtime::{
    bind_halted_dma, halted_event_dequeue_page, prepare_halted_from_evidence,
    reset_halted_from_evidence, scrub_halted_from_evidence,
};
use arach::drivers::xhci_takeover::ResetPolicy;
use arach::fabric::{
    Completion, KERNEL_FABRIC, NodeCapabilities, NodeClass, WorkDescriptor, opcode,
};
use arach::hw::iommu::{DmaAccess, IommuDomain};
use arach::hw::iova::IovaRange;
use arach::hw::pci;
use arach::hw::vtd_backend::{VtdDmaBackend, select_requester_scope};
use arach::hw::vtd_memory::{DirectMapSlptMemory, DirectMapVtdTables};
use arach::hw::vtd_slpt::SlptPageMemory;
use arach::ignition::{BootProtocol, IgnitionSequence};
use arach::interrupts::{self, DeadlineClock, DeadlineState};
use arach::memory::frame_pool::PhysicalFramePool;
use arach::mmio::{
    EARLY_MAPPED_PHYSICAL_LIMIT, HIGHER_HALF_DIRECT_MAP_BASE, KERNEL_VIRTUAL_BASE,
    direct_map_address, kernel_mmio, kernel_virtual_to_physical,
};
use arach::process::image::prepare_user_image;
use arach::process::install::{UserAddressSpaceBackend, install_user_image};
use arach::process::lifecycle::{self, ProcessLaunch};
use arach::process::package_manifest::{
    NATIVE_PACKAGE_ABI_VERSION, NativePackageManifest, package_name_hash,
};
use arach::process::runtime;
use arach::process::service_registry::{self, CREST_SERVICE_CLASS};
use arach::process::x86_64::{
    DirectMapFrameMemory, FrameBackedAddressSpace, INITIAL_USER_STACK_PAGES,
};
use arach::ring_authority::{
    DomainDescriptor, DomainRegistry, DomainRole, HardwareAuthority, TransitionFrontier,
    TransitionGate,
};
use arach::serial::SerialPort;
use arach::shim::{
    AbyssAllocator, DriverHost, DriverServices, IrqService, LogService, MmioService,
};
use arach::sync::SpinLock;
use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::fmt::Write;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering, compiler_fence};

core::arch::global_asm!(include_str!("bootstrap.S"), options(att_syntax));

const COM1: u16 = 0x3f8;
/// Crest's bounded first-light compositor and application state require a
/// 1.5 MiB native stack. This is measured boot-time capacity, never pageable
/// or influenced by Ring 3.
const CREST_INITIAL_STACK_PAGES: usize = 384;
const IDENTITY_MAP_END: u64 = 1024 * 1024 * 1024;
const KERNEL_PHYSICAL_LOAD_BASE: u64 = 1024 * 1024;
const MINIMUM_HEAP_SIZE: u64 = 64 * 1024;
const MAXIMUM_HEAP_SIZE: u64 = 4 * 1024 * 1024;
const E1000_DRIVER_ID: u64 = 0x4531_3030_305f_4e45;
const MAXIMUM_E1000_CONTROLLERS: usize = 1;

#[repr(C, align(16))]
struct E1000DmaStorage {
    receive_descriptors: [E1000ReceiveDescriptor; E1000_RING_LENGTH],
    transmit_descriptors: [E1000TransmitDescriptor; E1000_RING_LENGTH],
    receive_buffers: [[u8; E1000_FRAME_BYTES]; E1000_RING_LENGTH],
    transmit_buffers: [[u8; E1000_FRAME_BYTES]; E1000_RING_LENGTH],
}

impl E1000DmaStorage {
    const EMPTY: Self = Self {
        receive_descriptors: [E1000ReceiveDescriptor::EMPTY; E1000_RING_LENGTH],
        transmit_descriptors: [E1000TransmitDescriptor::EMPTY; E1000_RING_LENGTH],
        receive_buffers: [[0; E1000_FRAME_BYTES]; E1000_RING_LENGTH],
        transmit_buffers: [[0; E1000_FRAME_BYTES]; E1000_RING_LENGTH],
    };
}

struct E1000DmaCell(UnsafeCell<E1000DmaStorage>);

// SAFETY: the only mutable access happens during single-threaded boot before
// the e1000 function is published or its bus-master bit is enabled.
unsafe impl Sync for E1000DmaCell {}

static E1000_DMA: E1000DmaCell = E1000DmaCell(UnsafeCell::new(E1000DmaStorage::EMPTY));

#[cfg(target_os = "none")]
const PUSH_EXPECTED_SHA256: [u8; 32] = parse_sha256(env!("SISYPHUS_PUSH_SHA256"));
#[cfg(not(target_os = "none"))]
const PUSH_EXPECTED_SHA256: [u8; 32] = [0; 32];
#[cfg(target_os = "none")]
const PUSH_EXPECTED_BYTES: usize = parse_decimal(env!("SISYPHUS_PUSH_BYTES"));
#[cfg(not(target_os = "none"))]
const PUSH_EXPECTED_BYTES: usize = 0;
#[cfg(target_os = "none")]
const PUSH_ENTRY_FILE_OFFSET: usize = parse_decimal(env!("SISYPHUS_PUSH_ENTRY_FILE_OFFSET"));
#[cfg(not(target_os = "none"))]
const PUSH_ENTRY_FILE_OFFSET: usize = 0;
#[cfg(target_os = "none")]
const CREST_EXPECTED_SHA256: [u8; 32] = parse_sha256(env!("SISYPHUS_CREST_SHA256"));
#[cfg(not(target_os = "none"))]
const CREST_EXPECTED_SHA256: [u8; 32] = [0; 32];
#[cfg(target_os = "none")]
const CREST_EXPECTED_BYTES: usize = parse_decimal(env!("SISYPHUS_CREST_BYTES"));
#[cfg(not(target_os = "none"))]
const CREST_EXPECTED_BYTES: usize = 0;
#[cfg(target_os = "none")]
const CREST_ENTRY_FILE_OFFSET: usize = parse_decimal(env!("SISYPHUS_CREST_ENTRY_FILE_OFFSET"));
#[cfg(not(target_os = "none"))]
const CREST_ENTRY_FILE_OFFSET: usize = 0;
#[cfg(target_os = "none")]
const CREST_PACKAGE_VERSION: u16 = parse_decimal(env!("SISYPHUS_CREST_PACKAGE_VERSION")) as u16;
#[cfg(not(target_os = "none"))]
const CREST_PACKAGE_VERSION: u16 = 0;
#[cfg(target_os = "none")]
const CREST_PACKAGE_SERVICE_CLASS: u16 = parse_decimal(env!("SISYPHUS_CREST_SERVICE_CLASS")) as u16;
#[cfg(not(target_os = "none"))]
const CREST_PACKAGE_SERVICE_CLASS: u16 = 0;
#[cfg(target_os = "none")]
const CREST_PROVENANCE_ROOT: u64 = parse_decimal(env!("SISYPHUS_CREST_PROVENANCE_ROOT")) as u64;
#[cfg(not(target_os = "none"))]
const CREST_PROVENANCE_ROOT: u64 = 0;

#[global_allocator]
static KERNEL_HEAP: BumpAllocator = BumpAllocator::empty();
static IRQ_TEST_HITS: AtomicUsize = AtomicUsize::new(0);

struct BootDriverLogger<'a> {
    serial: SpinLock<&'a mut SerialPort>,
}

impl<'a> BootDriverLogger<'a> {
    fn new(serial: &'a mut SerialPort) -> Self {
        Self {
            serial: SpinLock::new(serial),
        }
    }
}

impl LogService for BootDriverLogger<'_> {
    fn log(&self, level: u32, message: &[u8]) -> sisyphus_driver_abi::Status {
        let mut serial = self.serial.lock();
        let _ = write!(serial, "Arach: C driver log level {level}: ");
        serial.write_bytes(message);
        serial.write_bytes(b"\n");
        sisyphus_driver_abi::STATUS_OK
    }
}

#[cfg(target_os = "none")]
const fn parse_sha256(encoded: &str) -> [u8; 32] {
    assert!(encoded.len() == 64, "invalid embedded Push digest");
    let bytes = encoded.as_bytes();
    let mut digest = [0_u8; 32];
    let mut index = 0;
    while index < digest.len() {
        digest[index] = (hex_nibble(bytes[index * 2]) << 4) | hex_nibble(bytes[index * 2 + 1]);
        index += 1;
    }
    digest
}

#[cfg(target_os = "none")]
const fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("invalid embedded Push digest"),
    }
}

#[cfg(target_os = "none")]
const fn parse_decimal(encoded: &str) -> usize {
    assert!(!encoded.is_empty(), "invalid embedded Push size");
    let bytes = encoded.as_bytes();
    let mut value = 0_usize;
    let mut index = 0;
    while index < bytes.len() {
        assert!(bytes[index].is_ascii_digit(), "invalid embedded Push size");
        value = match value.checked_mul(10) {
            Some(value) => value,
            None => panic!("embedded Push size overflow"),
        };
        value = match value.checked_add((bytes[index] - b'0') as usize) {
            Some(value) => value,
            None => panic!("embedded Push size overflow"),
        };
        index += 1;
    }
    value
}

unsafe extern "C" {
    static __kernel_start: u8;
    static __kernel_end: u8;
}

unsafe extern "C" fn irq_test_handler(context: *mut c_void) {
    let counter = context.cast::<AtomicUsize>();
    if let Some(counter) = unsafe { counter.as_ref() } {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

fn map_acpi_region(physical_address: u64, length: usize) -> Option<*const u8> {
    if length == 0
        || physical_address
            .checked_add(length as u64)
            .is_none_or(|end| end > EARLY_MAPPED_PHYSICAL_LIMIT)
    {
        return None;
    }
    direct_map_address(physical_address).map(|address| address as *const u8)
}

/// Binds the e1000 to exactly the fixed DMA memory retained in Arach's
/// measured image.  This runs before bus mastering is enabled and is never
/// callable from a user-controlled path.
fn prepare_e1000_dma_rings() -> Option<E1000DmaRings> {
    // SAFETY: boot is still single-threaded, the static arena has not been
    // published to the device, and this function is called once before PCI
    // bus mastering is enabled for the e1000 function.
    let storage = unsafe { &mut *E1000_DMA.0.get() };
    for index in 0..E1000_RING_LENGTH {
        let receive_buffer = &mut storage.receive_buffers[index];
        let transmit_buffer = &mut storage.transmit_buffers[index];
        let receive_address =
            kernel_virtual_to_physical(receive_buffer.as_mut_ptr() as usize, receive_buffer.len())?;
        let transmit_address = kernel_virtual_to_physical(
            transmit_buffer.as_mut_ptr() as usize,
            transmit_buffer.len(),
        )?;
        storage.receive_descriptors[index] = E1000ReceiveDescriptor {
            buffer_address: receive_address,
            ..E1000ReceiveDescriptor::EMPTY
        };
        storage.transmit_descriptors[index] = E1000TransmitDescriptor {
            buffer_address: transmit_address,
            // The hardware writes this bit after a completed transmission.
            // Initializing it means no stale completion is mistaken for an
            // in-flight frame before the first producer publication.
            status: 1,
            ..E1000TransmitDescriptor::EMPTY
        };
    }
    let receive_descriptors = kernel_virtual_to_physical(
        core::ptr::addr_of!(storage.receive_descriptors) as usize,
        core::mem::size_of_val(&storage.receive_descriptors),
    )?;
    let transmit_descriptors = kernel_virtual_to_physical(
        core::ptr::addr_of!(storage.transmit_descriptors) as usize,
        core::mem::size_of_val(&storage.transmit_descriptors),
    )?;
    compiler_fence(Ordering::SeqCst);
    E1000DmaRings::new(receive_descriptors, transmit_descriptors).ok()
}

#[unsafe(no_mangle)]
pub extern "C" fn arach_main(multiboot_address: usize, multiboot_physical_address: usize) -> ! {
    // SAFETY: The PC-compatible boot environment reserves COM1 for the early
    // kernel console before other drivers are initialized.
    let mut serial = unsafe { SerialPort::initialize(COM1) };
    let _ = writeln!(serial, "Arach: entering Rust in long mode");
    // SAFETY: Serialized BSP bootstrap owns CR3, and the bootstrap direct map
    // covers the physical root frame used for this read-only transition gate.
    let bootstrap_root = unsafe { active_page_table_root() };
    let Some(bootstrap_root_virtual) = direct_map_address(bootstrap_root) else {
        let _ = writeln!(
            serial,
            "Arach: bootstrap page-table root is outside the direct map"
        );
        halt();
    };
    // SAFETY: The active root frame is mapped for inspection through the
    // stable higher-half direct map during serialized bootstrap.
    let low_pml4_entry = unsafe { (bootstrap_root_virtual as *const u64).read_volatile() };
    let stack_address = core::ptr::addr_of!(serial) as usize;
    if low_pml4_entry != 0
        || (arach_main as *const () as usize) < KERNEL_VIRTUAL_BASE
        || stack_address < HIGHER_HALF_DIRECT_MAP_BASE
    {
        let _ = writeln!(
            serial,
            "Arach: higher-half transition gate failed: low={low_pml4_entry:#x}, code={:#x}, stack={stack_address:#x}",
            arach_main as *const () as usize,
        );
        halt();
    }
    let _ = writeln!(
        serial,
        "Arach: higher-half transition verified, low PML4 entry absent"
    );
    // SAFETY: BSP bootstrap is serialized with interrupts disabled, and every
    // process root inherits the higher-half descriptor and RSP0 storage.
    let privilege_info = match unsafe { privilege::initialize() } {
        Ok(info) => info,
        Err(error) => {
            let _ = writeln!(serial, "Arach: privilege tables failed: {error:?}");
            halt();
        }
    };
    let _ = writeln!(
        serial,
        "Arach: TSS active RSP0={:#x}, user selectors={:#x}/{:#x}",
        privilege_info.kernel_stack_top,
        privilege_info.user_code_selector,
        privilege_info.user_data_selector,
    );
    let mut ignition = IgnitionSequence::new(BootProtocol::Multiboot2);

    // SAFETY: Bootstrap assembly enters with interrupts disabled and installs
    // the GDT selector expected by Arach's interrupt gates.
    let idt_info = match unsafe { interrupts::initialize() } {
        Ok(info) => info,
        Err(error) => {
            let _ = writeln!(serial, "Arach: interrupt tables failed: {error:?}");
            halt();
        }
    };
    if !interrupts::trigger_ist_probe() {
        let _ = writeln!(serial, "Arach: IST runtime probe failed");
        halt();
    }
    interrupts::trigger_breakpoint();
    if interrupts::breakpoint_hits() != 1 {
        let _ = writeln!(serial, "Arach: breakpoint exception test failed");
        halt();
    }
    let (local_apic, x2apic) = interrupts::apic_capabilities();
    let _ = writeln!(
        serial,
        "Arach: IDT active, IST runtime probe verified, DF/NMI/MC={}@{:#x}/{}@{:#x}/{}@{:#x}, local APIC={}, x2APIC={}",
        idt_info.double_fault_ist,
        idt_info.fault_stacks.double_fault.top,
        idt_info.non_maskable_interrupt_ist,
        idt_info.fault_stacks.non_maskable_interrupt.top,
        idt_info.machine_check_ist,
        idt_info.fault_stacks.machine_check.top,
        local_apic,
        x2apic
    );

    let kernel_start = core::ptr::addr_of!(__kernel_start) as usize;
    let kernel_end = core::ptr::addr_of!(__kernel_end) as usize;
    let Some(kernel_physical_start) = kernel_start.checked_sub(KERNEL_VIRTUAL_BASE) else {
        let _ = writeln!(serial, "Arach: kernel start is outside the higher half");
        halt();
    };
    let Some(kernel_physical_end) = kernel_end.checked_sub(KERNEL_VIRTUAL_BASE) else {
        let _ = writeln!(serial, "Arach: kernel end is outside the higher half");
        halt();
    };
    let _ = writeln!(
        serial,
        "Arach: kernel virtual {kernel_start:#x}..{kernel_end:#x}, physical {kernel_physical_start:#x}..{kernel_physical_end:#x}"
    );

    // SAFETY: The bootstrap preserves GRUB's physical Multiboot2 pointer and
    // passes its mapped higher-half direct-map alias in the first argument.
    let boot = match unsafe { BootInformation::load(multiboot_address) } {
        Ok(boot) => boot,
        Err(error) => {
            let _ = writeln!(serial, "Arach: invalid boot information: {error:?}");
            halt();
        }
    };
    let _ = writeln!(
        serial,
        "Arach: Multiboot2 physical data {:#x}..{:#x}",
        multiboot_physical_address,
        multiboot_physical_address + boot.total_size()
    );
    let boot_framebuffer = match boot.framebuffer() {
        Ok(framebuffer) => framebuffer,
        Err(error @ arach::boot::multiboot2::BootError::UnsupportedFramebuffer { .. }) => {
            let _ = writeln!(
                serial,
                "Arach: firmware framebuffer format unsupported {error:?}; continuing headless"
            );
            None
        }
        Err(error) => {
            let _ = writeln!(serial, "Arach: framebuffer tag rejected: {error:?}");
            halt();
        }
    };
    if let Some(framebuffer) = boot_framebuffer {
        let _ = writeln!(
            serial,
            "Arach: firmware framebuffer {:#x}..{:#x} {}x{} pitch={} format={}",
            framebuffer.physical_address,
            framebuffer.end().unwrap_or(framebuffer.physical_address),
            framebuffer.width,
            framebuffer.height,
            framebuffer.pitch,
            framebuffer.format,
        );
    } else {
        let _ = writeln!(serial, "Arach: no supported firmware framebuffer");
    }
    let push_module = match boot.module(b"push") {
        Ok(module) => module,
        Err(error) => {
            let _ = writeln!(serial, "Arach: Push boot module error: {error:?}");
            halt();
        }
    };
    if push_module.length() as usize != PUSH_EXPECTED_BYTES
        || push_module.end.as_u64() > EARLY_MAPPED_PHYSICAL_LIMIT
    {
        let _ = writeln!(serial, "Arach: Push boot module size or range mismatch");
        halt();
    }
    let Some(push_virtual) = direct_map_address(push_module.start.as_u64()) else {
        let _ = writeln!(serial, "Arach: Push boot module is outside the direct map");
        halt();
    };
    // SAFETY: The validated module range is immutable bootloader-owned memory
    // covered by the retained direct map and reserved below before allocation.
    let push_bytes = unsafe {
        core::slice::from_raw_parts(push_virtual as *const u8, push_module.length() as usize)
    };
    let _ = writeln!(
        serial,
        "Arach: measured Push module {} bytes at {:#x}..{:#x}",
        push_bytes.len(),
        push_module.start.as_u64(),
        push_module.end.as_u64(),
    );
    let crest_module = match boot.module(b"crest") {
        Ok(module) => module,
        Err(error) => {
            let _ = writeln!(serial, "Arach: Crest boot module error: {error:?}");
            halt();
        }
    };
    if crest_module.length() as usize != CREST_EXPECTED_BYTES
        || crest_module.end.as_u64() > EARLY_MAPPED_PHYSICAL_LIMIT
    {
        let _ = writeln!(serial, "Arach: Crest boot module size or range mismatch");
        halt();
    }
    let Some(crest_virtual) = direct_map_address(crest_module.start.as_u64()) else {
        let _ = writeln!(serial, "Arach: Crest boot module is outside the direct map");
        halt();
    };
    // SAFETY: The validated module range is immutable bootloader-owned memory
    // covered by the retained direct map and reserved below before allocation.
    let crest_bytes = unsafe {
        core::slice::from_raw_parts(crest_virtual as *const u8, crest_module.length() as usize)
    };
    let _ = writeln!(
        serial,
        "Arach: measured Crest module {} bytes at {:#x}..{:#x}",
        crest_bytes.len(),
        crest_module.start.as_u64(),
        crest_module.end.as_u64(),
    );

    // GSP firmware remains a boot artifact, never host-executable code.  The
    // all-or-nothing lookup below prevents a partial bundle from looking like
    // a supported accelerator and rechecks every byte against Arach's
    // source-pinned T1000 manifest before any later native path can touch it.
    let hermes_gsp_present = match boot.module(b"hermes-gsp") {
        Ok(_) => true,
        Err(arach::boot::multiboot2::BootError::MissingModule) => false,
        Err(error) => {
            let _ = writeln!(serial, "Arach: Hermes GSP module tag rejected: {error:?}");
            halt();
        }
    };
    if hermes_gsp_present {
        macro_rules! hermes_gsp_module {
            ($name:literal, $limit:expr, $label:literal) => {{
                let module = match boot.module($name) {
                    Ok(module) => module,
                    Err(error) => {
                        let _ = writeln!(serial, "Arach: {} module error: {error:?}", $label);
                        halt();
                    }
                };
                if module.length() == 0
                    || module.length() > $limit as u64
                    || module.end.as_u64() > EARLY_MAPPED_PHYSICAL_LIMIT
                {
                    let _ = writeln!(serial, "Arach: {} module size or range mismatch", $label);
                    halt();
                }
                let Some(virtual_address) = direct_map_address(module.start.as_u64()) else {
                    let _ = writeln!(serial, "Arach: {} module is outside the direct map", $label);
                    halt();
                };
                // SAFETY: this bounded module range is supplied by Granite or
                // Limine, lies in the retained direct map, and is immediately
                // re-authenticated below before any device operation.
                unsafe {
                    core::slice::from_raw_parts(
                        virtual_address as *const u8,
                        module.length() as usize,
                    )
                }
            }};
        }

        let gsp_rm = hermes_gsp_module!(b"hermes-gsp", 32 * 1024 * 1024, "Hermes GSP-RM");
        let generic_sec2 =
            hermes_gsp_module!(b"hermes-sec2", 1024 * 1024, "Hermes SEC2 bootloader");
        let gsp_bootloader = hermes_gsp_module!(
            b"hermes-gsp-bootloader",
            1024 * 1024,
            "Hermes GSP bootloader"
        );
        let booter_load =
            hermes_gsp_module!(b"hermes-booter-load", 1024 * 1024, "Hermes Booter Load");
        let booter_unload =
            hermes_gsp_module!(b"hermes-booter-unload", 1024 * 1024, "Hermes Booter Unload");
        let staged = TuringGspStagedBundle {
            gsp_rm,
            bootstrap: TuringGspBootstrapMaterial {
                generic_sec2_bootloader: generic_sec2,
                gsp_bootloader,
                booter_load,
                booter_unload,
            },
        };
        match staged.begin_t1000_610_43_03_verification() {
            Ok(_) => {}
            Err(error) => {
                let _ = writeln!(
                    serial,
                    "Arach: T1000 GSP bundle length preflight rejected before DMA/MMIO: {error:?}"
                );
                halt();
            }
        }
        let _ = writeln!(
            serial,
            "Arach: T1000 610.43.03 GSP bundle staged; bounded remeasurement is mandatory before WPR/SEC2 DMA or MMIO",
        );
    } else {
        for name in [
            b"hermes-sec2".as_slice(),
            b"hermes-gsp-bootloader".as_slice(),
            b"hermes-booter-load".as_slice(),
            b"hermes-booter-unload".as_slice(),
        ] {
            match boot.module(name) {
                Err(arach::boot::multiboot2::BootError::MissingModule) => {}
                Ok(_) => {
                    let _ = writeln!(serial, "Arach: partial Hermes GSP bundle rejected");
                    halt();
                }
                Err(error) => {
                    let _ = writeln!(serial, "Arach: Hermes GSP module tag rejected: {error:?}");
                    halt();
                }
            }
        }
    }

    let memory_map = match boot.memory_map() {
        Ok(map) => map,
        Err(error) => {
            let _ = writeln!(serial, "Arach: memory map error: {error:?}");
            halt();
        }
    };
    if let Err(error) = ignition.validate_handoff(memory_map.regions().len()) {
        let _ = writeln!(serial, "Arach: ignition handoff failed: {error:?}");
        halt();
    }

    let mut usable_bytes = 0_u64;
    for region in memory_map.regions() {
        if region.kind == MemoryRegionKind::Usable {
            usable_bytes = usable_bytes.saturating_add(region.length());
        }
    }
    let _ = writeln!(
        serial,
        "Abyss: accepted {} regions, {} KiB usable",
        memory_map.regions().len(),
        usable_bytes / 1024
    );

    let protected_end = (kernel_physical_end as u64)
        .max((multiboot_physical_address + boot.total_size()) as u64)
        .max(push_module.end.as_u64())
        .max(crest_module.end.as_u64());
    let Some(heap_region) =
        memory_map.usable_range(protected_end, IDENTITY_MAP_END, MINIMUM_HEAP_SIZE)
    else {
        let _ = writeln!(serial, "Abyss: no safe bootstrap heap region");
        halt();
    };
    let heap_size = heap_region.length().min(MAXIMUM_HEAP_SIZE) as usize;
    let heap_start = heap_region.start.as_u64() as usize;
    let Some(heap_virtual_start) = direct_map_address(heap_start as u64) else {
        let _ = writeln!(serial, "Abyss: bootstrap heap is outside the direct map");
        halt();
    };
    // SAFETY: Abyss selected an identity-mapped usable region above the kernel
    // and boot data. It remains reserved for this allocator after selection.
    if let Err(error) = unsafe { KERNEL_HEAP.initialize(heap_virtual_start, heap_size) } {
        let _ = writeln!(serial, "Abyss: heap initialization failed: {error:?}");
        halt();
    }
    let _ = writeln!(
        serial,
        "Abyss: bootstrap heap {heap_start:#x}..{:#x}",
        heap_start + heap_size
    );

    let storage_words = match BitmapFrameAllocator::storage_words(IDENTITY_MAP_END) {
        Ok(words) => words,
        Err(error) => {
            let _ = writeln!(serial, "Abyss: frame bitmap sizing failed: {error:?}");
            halt();
        }
    };
    let storage_layout = match Layout::array::<u64>(storage_words) {
        Ok(layout) => layout,
        Err(_) => {
            let _ = writeln!(serial, "Abyss: invalid frame bitmap layout");
            halt();
        }
    };
    // SAFETY: KERNEL_HEAP is initialized above and the returned allocation is
    // retained exclusively by the frame allocator for the rest of boot.
    let storage_pointer = unsafe { KERNEL_HEAP.alloc(storage_layout) };
    if storage_pointer.is_null() {
        let _ = writeln!(serial, "Abyss: frame bitmap allocation failed");
        halt();
    }
    let Some(storage_physical) =
        (storage_pointer as usize).checked_sub(HIGHER_HALF_DIRECT_MAP_BASE)
    else {
        let _ = writeln!(serial, "Abyss: frame bitmap is outside the direct map");
        halt();
    };
    // SAFETY: The allocation has exactly this many aligned u64 elements and is
    // not accessed through any other reference afterward.
    let storage: &'static mut [u64] =
        unsafe { core::slice::from_raw_parts_mut(storage_pointer.cast::<u64>(), storage_words) };

    let mut reservations = ReservationTable::<8>::new();
    let required_reservations = [
        Reservation::new(
            PhysicalAddress::new(0),
            PhysicalAddress::new(0x10_0000),
            ReservationKind::LowMemory,
        ),
        Reservation::new(
            PhysicalAddress::new(KERNEL_PHYSICAL_LOAD_BASE),
            PhysicalAddress::new(kernel_physical_end as u64),
            ReservationKind::KernelImage,
        ),
        Reservation::new(
            PhysicalAddress::new(multiboot_physical_address as u64),
            PhysicalAddress::new((multiboot_physical_address + boot.total_size()) as u64),
            ReservationKind::BootInformation,
        ),
        Reservation::new(
            push_module.start,
            push_module.end,
            ReservationKind::BootModule,
        ),
        Reservation::new(
            crest_module.start,
            crest_module.end,
            ReservationKind::BootModule,
        ),
        Reservation::new(
            PhysicalAddress::new(heap_start as u64),
            PhysicalAddress::new((heap_start + heap_size) as u64),
            ReservationKind::BootstrapHeap,
        ),
        Reservation::new(
            PhysicalAddress::new(storage_physical as u64),
            PhysicalAddress::new(storage_physical as u64 + storage_layout.size() as u64),
            ReservationKind::AllocatorMetadata,
        ),
    ];
    for reservation in required_reservations {
        if let Err(error) = reservations.push(reservation) {
            let _ = writeln!(serial, "Abyss: reservation table failed: {error:?}");
            halt();
        }
    }

    if let Some(framebuffer) = boot_framebuffer {
        if framebuffer.physical_address < IDENTITY_MAP_END {
            let end = framebuffer
                .end()
                .unwrap_or(framebuffer.physical_address)
                .min(IDENTITY_MAP_END);
            if end > framebuffer.physical_address {
                if let Err(error) = reservations.push(Reservation::new(
                    PhysicalAddress::new(framebuffer.physical_address),
                    PhysicalAddress::new(end),
                    ReservationKind::DeviceMemory,
                )) {
                    let _ = writeln!(serial, "Abyss: framebuffer reservation failed: {error:?}");
                    halt();
                }
            }
        }
    }

    let mut frames = match BitmapFrameAllocator::new(&memory_map, IDENTITY_MAP_END, storage) {
        Ok(allocator) => allocator,
        Err(error) => {
            let _ = writeln!(serial, "Abyss: frame allocator failed: {error:?}");
            halt();
        }
    };
    frames.apply_reservations(&reservations);
    let _ = writeln!(
        serial,
        "Abyss: {} free of {} identity-mapped frames",
        frames.free_frames(),
        frames.managed_frames()
    );
    let Some(test_frame) = frames.allocate() else {
        let _ = writeln!(serial, "Abyss: no frame available for reclaim test");
        halt();
    };
    if let Err(error) = frames.deallocate(test_frame) {
        let _ = writeln!(serial, "Abyss: frame reclaim failed: {error:?}");
        halt();
    }
    let _ = writeln!(
        serial,
        "Abyss: reclaimed test frame at {:#x}",
        test_frame.as_u64()
    );
    let frame_pool: &'static PhysicalFramePool<'static> =
        Box::leak(Box::new(PhysicalFramePool::new(frames)));

    let Some(direct_kernel) = direct_map_address(kernel_physical_start as u64) else {
        let _ = writeln!(serial, "Abyss: kernel is outside the direct map");
        halt();
    };
    // SAFETY: Bootstrap assembly maps the same first-GiB physical page at both
    // the identity and higher-half direct-map addresses.
    let direct_map_matches = unsafe {
        (kernel_start as *const u8).read_volatile() == (direct_kernel as *const u8).read_volatile()
    };
    if !direct_map_matches {
        let _ = writeln!(serial, "Abyss: higher-half direct map mismatch");
        halt();
    }
    let _ = writeln!(serial, "Abyss: higher-half direct map verified");
    if let Err(error) = ignition.memory_ready(frame_pool.managed_frames(), frame_pool.free_frames())
    {
        let _ = writeln!(serial, "Arach: ignition memory phase failed: {error:?}");
        halt();
    }

    let rsdp = match boot.rsdp() {
        Ok(rsdp) => rsdp,
        Err(error) => {
            let _ = writeln!(serial, "Arach: ACPI root pointer error: {error:?}");
            halt();
        }
    };
    // SAFETY: Bootstrap paging keeps the first GiB stable in the direct map,
    // and the mapper rejects every ACPI range outside that mapped window.
    let madt = match unsafe { discover_madt(rsdp, map_acpi_region) } {
        Ok(madt) => madt,
        Err(error) => {
            let _ = writeln!(serial, "Arach: ACPI MADT discovery failed: {error:?}");
            halt();
        }
    };
    let _ = writeln!(
        serial,
        "Arach: ACPI revision={} LAPIC={:#x}, I/O APICs={}, overrides={}",
        rsdp.revision,
        madt.local_apic_address,
        madt.io_apics().len(),
        madt.interrupt_source_overrides().len()
    );
    // SAFETY: Uses the same bounded, stable ACPI mapping as MADT discovery.
    // A malformed optional table disables remapping evidence instead of
    // manufacturing isolation or preventing a firmware-only boot.
    let dmar = match unsafe { discover_dmar(rsdp, map_acpi_region) } {
        Ok(dmar) => dmar,
        Err(error) => {
            let _ = writeln!(
                serial,
                "Arach: ACPI DMAR rejected; native DMA remains disabled: {error:?}"
            );
            None
        }
    };
    if let Some(dmar) = dmar.as_ref() {
        let _ = writeln!(
            serial,
            "Arach: DMAR host-width={} units={}, presence-only",
            dmar.host_address_width,
            dmar.remapping_units().len(),
        );
        for unit in dmar.remapping_units().iter().copied() {
            let endpoints = dmar
                .explicit_endpoints_for(unit)
                .map_or(0, |endpoints| endpoints.len());
            let _ = writeln!(
                serial,
                "Arach: DMAR unit segment={} base={:#x} include-all={} endpoints={} unresolved-requester-scopes={}",
                unit.segment,
                unit.register_base,
                unit.include_all,
                endpoints,
                unit.has_unresolved_scopes(),
            );
        }
    }

    let mmio = kernel_mmio();
    let mapping = match mmio.map(0xb8000, 2, 0) {
        Ok(mapping) => mapping,
        Err(status) => {
            let _ = writeln!(serial, "Arach: VGA MMIO map failed: {status}");
            halt();
        }
    };
    // SAFETY: The MMIO service returned a live writable mapping for VGA text
    // memory. The mapping remains active through both volatile writes.
    unsafe {
        mapping.pointer.as_ptr().write_volatile(b'S');
        mapping.pointer.as_ptr().add(1).write_volatile(0x0f);
    }
    let _ = writeln!(
        serial,
        "Arach: MMIO window mapped VGA at {:#x}",
        mapping.pointer.as_ptr() as usize
    );
    let status = mmio.unmap(mapping.handle);
    if status != sisyphus_driver_abi::STATUS_OK {
        let _ = writeln!(serial, "Arach: VGA MMIO unmap failed: {status}");
        halt();
    }
    if mmio.unmap(mapping.handle) != sisyphus_driver_abi::STATUS_NOT_FOUND {
        let _ = writeln!(serial, "Arach: stale MMIO handle was accepted");
        halt();
    }
    let _ = writeln!(serial, "Arach: stale MMIO handle rejected");

    let local_apic = match unsafe { interrupts::initialize_local_apic(mmio) } {
        Ok(info) => info,
        Err(status) => {
            let _ = writeln!(serial, "Arach: local APIC initialization failed: {status}");
            halt();
        }
    };
    interrupts::enable();
    let ipi_status = interrupts::send_apic_test_ipi();
    for _ in 0..1_000_000 {
        if interrupts::apic_test_hits() != 0 {
            break;
        }
        core::hint::spin_loop();
    }
    interrupts::disable();
    if ipi_status != sisyphus_driver_abi::STATUS_OK || interrupts::apic_test_hits() != 1 {
        let _ = writeln!(serial, "Arach: local APIC self-IPI failed: {ipi_status}");
        halt();
    }
    let _ = writeln!(
        serial,
        "Arach: local APIC id={} version={:#x} at {:#x}, self-IPI verified",
        local_apic.id, local_apic.version, local_apic.physical_address
    );
    if local_apic.physical_address != madt.local_apic_address {
        let _ = writeln!(
            serial,
            "Arach: local APIC address disagrees with ACPI ({:#x})",
            madt.local_apic_address
        );
        halt();
    }
    // SAFETY: The self-IPI test restored disabled interrupts, and no subsystem
    // has claimed PIT channel 2 or the local APIC timer. Retain this one-shot
    // owner across hardware discovery so bounded takeover work can be inserted
    // without calibrating a second, unrelated clock.
    let mut deadline_clock = match unsafe { interrupts::initialize_local_apic_deadline_clock() } {
        Ok(clock) => clock,
        Err(error) => {
            let _ = writeln!(
                serial,
                "Arach: local APIC deadline calibration failed: {error:?}"
            );
            halt();
        }
    };
    let _ = writeln!(
        serial,
        "Arach: local APIC deadline clock {} Hz reserved",
        deadline_clock.ticks_per_second()
    );
    let cpu_topology =
        match topology::initialize(&madt, u32::from(local_apic.id), TopologyPolicy::default()) {
            Ok(info) => info,
            Err(error) => {
                let _ = writeln!(serial, "Arach: CPU topology failed: {error:?}");
                halt();
            }
        };
    if topology::authorize_execution(u32::from(local_apic.id), ExecutionClass::KernelControl)
        .is_err()
    {
        let _ = writeln!(serial, "Arach: BSP was not assigned the Aegis role");
        halt();
    }
    let _ = writeln!(
        serial,
        "Arach: CPU topology processors={}, online={}, enclave={}, compute={}",
        cpu_topology.processor_count,
        cpu_topology.online_cores,
        cpu_topology.enclave_cores,
        cpu_topology.compute_cores
    );
    if let Err(error) = ignition.topology_ready(cpu_topology.processor_count) {
        let _ = writeln!(serial, "Arach: ignition topology phase failed: {error:?}");
        halt();
    }

    // SAFETY: This is the single trusted bootstrap path. Subsystems receive
    // scoped rights from this root instead of constructing authority directly.
    let authority = unsafe { Authority::assume_root() };
    if let Some(dmar) = dmar.as_ref() {
        let device_memory = authority.grant::<DeviceMemoryControl>();
        for unit in dmar.remapping_units().iter().copied() {
            let registers = match arach::hw::vtd::VtdMmioRegisters::map(unit, &device_memory) {
                Ok(registers) => registers,
                Err(error) => {
                    let _ = writeln!(
                        serial,
                        "Arach: VT-d unit {:#x} MMIO rejected: {error:?}",
                        unit.register_base
                    );
                    continue;
                }
            };
            let engine = match registers.into_engine() {
                Ok(engine) => engine,
                Err(failure) => {
                    let fault = failure.fault();
                    let registers = failure.into_registers();
                    let close = registers.close(&device_memory);
                    let _ = writeln!(
                        serial,
                        "Arach: VT-d unit {:#x} probe rejected: {fault:?}, close={close:?}",
                        unit.register_base
                    );
                    continue;
                }
            };
            let version = engine.version();
            let capabilities = engine.capabilities();
            let state = engine.state();
            let registers = match engine.into_registers() {
                Ok(registers) => registers,
                Err(_) => {
                    let _ = writeln!(
                        serial,
                        "Arach: VT-d unit {:#x} retained unexpected live authority",
                        unit.register_base
                    );
                    continue;
                }
            };
            let close = registers.close(&device_memory);
            let _ = writeln!(
                serial,
                "Arach: VT-d unit {:#x} v{}.{} state={state:?} sagaw={:#x} mgaw={} close={close:?}",
                unit.register_base,
                version.major,
                version.minor,
                capabilities.supported_adjusted_guest_widths,
                capabilities.maximum_guest_address_width,
            );
        }
    }
    let fabric_control = authority.grant::<FabricControl>();
    let cpu_node = match KERNEL_FABRIC.register_node(
        NodeClass::Cpu,
        0,
        NodeCapabilities::empty(),
        &fabric_control,
    ) {
        Ok(node) => node,
        Err(error) => {
            let _ = writeln!(serial, "Arach: fabric CPU registration failed: {error:?}");
            halt();
        }
    };
    let fabric_work = match KERNEL_FABRIC.submit(
        WorkDescriptor::new(opcode::NOP, 0, 0, 0),
        NodeClass::Cpu,
        0,
        NodeCapabilities::empty(),
        &fabric_control,
    ) {
        Ok(handle) => handle,
        Err(error) => {
            let _ = writeln!(serial, "Arach: fabric submission failed: {error:?}");
            halt();
        }
    };
    let taken_work = match KERNEL_FABRIC.take(cpu_node) {
        Ok(Some(work)) => work,
        Ok(None) => {
            let _ = writeln!(serial, "Arach: fabric CPU queue was unexpectedly empty");
            halt();
        }
        Err(error) => {
            let _ = writeln!(serial, "Arach: fabric work retrieval failed: {error:?}");
            halt();
        }
    };
    if taken_work.0 != fabric_work || taken_work.1.opcode != opcode::NOP {
        let _ = writeln!(serial, "Arach: fabric returned the wrong work item");
        halt();
    }
    if let Err(error) = KERNEL_FABRIC.complete(fabric_work, Ok(())) {
        let _ = writeln!(serial, "Arach: fabric completion failed: {error:?}");
        halt();
    }
    if KERNEL_FABRIC.completion(fabric_work) != Ok(Completion::Succeeded) {
        let _ = writeln!(serial, "Arach: fabric completion state was not published");
        halt();
    }
    if let Err(error) = KERNEL_FABRIC.release(fabric_work, &fabric_control) {
        let _ = writeln!(serial, "Arach: fabric release failed: {error:?}");
        halt();
    }
    let _ = writeln!(serial, "Arach: capability-gated fabric work cycle verified");

    let policy_control = authority.grant::<PolicyControl>();
    if let Err(error) = arach::aether::initialize(&policy_control) {
        let _ = writeln!(serial, "Arach: Aether initialization failed: {error:?}");
        halt();
    }
    if arach::aether::policy_allows_page_count(512) != Ok(true)
        || arach::aether::policy_allows_page_count(513) != Ok(false)
        || arach::aether::recorded_events() < 3
    {
        let _ = writeln!(serial, "Arach: Aether policy or recorder test failed");
        halt();
    }
    let _ = writeln!(
        serial,
        "Arach: Aether policy and bounded flight recorder verified"
    );

    let resonance_control = authority.grant::<ResonanceControl>();
    let learning_control = authority.grant::<LearningControl>();
    let memory_sharing = authority.grant::<MemorySharingControl>();
    let fault_policy = authority.grant::<FaultPolicyControl>();
    let artifact_synthesis = authority.grant::<ArtifactSynthesisControl>();
    let userland_image = authority.grant::<UserlandImageControl>();
    let process_install = authority.grant::<ProcessInstallControl>();
    let physical_memory = authority.grant::<PhysicalMemoryControl>();
    // SAFETY: Bootstrap is serialized at ring 0 and no process page tables
    // containing NX entries can be activated before this feature gate.
    if let Err(error) = unsafe { enable_execute_disable() } {
        let _ = writeln!(serial, "Arach: execute-disable unavailable: {error:?}");
        halt();
    }
    // SAFETY: CR3 is read during serialized BSP bootstrap and only used as an
    // immutable source for the kernel half of a new, inactive hierarchy.
    let kernel_page_table_root = PhysicalAddress::new(unsafe { active_page_table_root() });
    // SAFETY: The bitmap allocator manages only the first GiB, which the
    // bootstrap maps at this stable writable higher-half direct-map base.
    let frame_memory = unsafe {
        DirectMapFrameMemory::new(
            &frame_pool,
            HIGHER_HALF_DIRECT_MAP_BASE,
            EARLY_MAPPED_PHYSICAL_LIMIT,
            &physical_memory,
        )
    };
    let mut process_backend =
        FrameBackedAddressSpace::new(frame_memory, kernel_page_table_root, &process_install);
    let controls = arach::blacklab::Controls {
        resonance: &resonance_control,
        learning: &learning_control,
        memory_sharing: &memory_sharing,
        fault_policy: &fault_policy,
        artifact_synthesis: &artifact_synthesis,
        userland_image: &userland_image,
        process_install: &process_install,
    };
    let initialized = match arach::blacklab::initialize(
        controls,
        &mut process_backend,
        arach::blacklab::Pid1Source {
            bytes: push_bytes,
            expected_sha256: PUSH_EXPECTED_SHA256,
            entry_file_offset: PUSH_ENTRY_FILE_OFFSET,
        },
    ) {
        Ok(initialized) => initialized,
        Err(error) => {
            let _ = writeln!(serial, "Arach: Black Lab initialization failed: {error:?}");
            halt();
        }
    };
    let blacklab = initialized.summary;
    let pid1 = initialized.pid1;
    if blacklab.pid1_page_table_root.is_none()
        || blacklab.pid1_owned_frames == 0
        || !blacklab.pid1_activation_validated
        || process_backend.owned_frame_count() != blacklab.pid1_owned_frames
    {
        let _ = writeln!(serial, "Arach: PID1 retained ownership failed");
        halt();
    }
    let _stack_top = match process_backend.install_initial_stack(&pid1, &process_install) {
        Ok(stack) => stack,
        Err(error) => {
            let _ = writeln!(serial, "Arach: PID1 stack installation failed: {error:?}");
            halt();
        }
    };
    if let Err(error) = process_backend.install_thermal_page(&pid1, &process_install) {
        let _ = writeln!(serial, "Arach: PID1 thermal page mapping failed: {error:?}");
        halt();
    }

    let cerebral_lease = match arach::nexus_runtime::initialize(&resonance_control) {
        Ok(token) => token,
        Err(error) => {
            let _ = writeln!(
                serial,
                "Arach: Nexus runtime initialization failed: {error:?}"
            );
            halt();
        }
    };
    if let Err(error) = arach::nexus_plane::initialize(&learning_control, cerebral_lease) {
        let _ = writeln!(
            serial,
            "Arach: Nexus plane initialization failed: {error:?}"
        );
        halt();
    }

    {
        if let Err(error) = process_backend.install_nexus_plane(&pid1, &process_install) {
            let _ = writeln!(serial, "Arach: PID1 nexus plane mapping failed: {error:?}");
            halt();
        }
    }

    let pid1_stack = match process_backend.prepare_initial_stack(
        &pid1,
        &[b"push"],
        &[b"SISYPHUS_PROCESS=push", b"SISYPHUS_ABI=1"],
    ) {
        Ok(stack) => stack,
        Err(error) => {
            let _ = writeln!(
                serial,
                "Arach: PID1 argv/envp preparation failed: {error:?}"
            );
            halt();
        }
    };
    let Some(pid1_info) = process_backend.process_info(&pid1) else {
        let _ = writeln!(serial, "Arach: retained PID1 handle became stale");
        halt();
    };
    let Some(pid1_root) = pid1_info.address_space_root else {
        let _ = writeln!(serial, "Arach: retained PID1 has no page-table root");
        halt();
    };
    if pid1_info.initial_stack_pointer != Some(pid1_stack)
        || pid1_info.owned_frames < blacklab.pid1_owned_frames + INITIAL_USER_STACK_PAGES
    {
        let _ = writeln!(
            serial,
            "Arach: retained PID1 stack metadata is inconsistent"
        );
        halt();
    }
    let crest_manifest = NativePackageManifest {
        schema_version: 1,
        name_hash: package_name_hash(b"crest"),
        version: CREST_PACKAGE_VERSION,
        abi_version: NATIVE_PACKAGE_ABI_VERSION,
        service_class: CREST_PACKAGE_SERVICE_CLASS,
        artifact_bytes: CREST_EXPECTED_BYTES,
        entry_file_offset: CREST_ENTRY_FILE_OFFSET,
        artifact_sha256: CREST_EXPECTED_SHA256,
        provenance_root: CREST_PROVENANCE_ROOT,
    };
    if let Err(error) = crest_manifest.validate_artifact(
        CREST_EXPECTED_BYTES,
        CREST_ENTRY_FILE_OFFSET,
        CREST_EXPECTED_SHA256,
    ) {
        let _ = writeln!(serial, "Arach: Crest package manifest rejected: {error:?}");
        halt();
    }
    if crest_manifest.service_class != CREST_SERVICE_CLASS {
        let _ = writeln!(
            serial,
            "Arach: Crest package service class is not boot-admitted"
        );
        halt();
    }
    let crest_artifact = match verify_artifact(
        ArtifactManifest {
            inode_id: 3,
            class: FractalClass::Executable,
            architecture: TargetArchitecture::X86_64,
            entry_offset: CREST_ENTRY_FILE_OFFSET,
            expected_sha256: CREST_EXPECTED_SHA256,
        },
        crest_bytes,
    ) {
        Ok(artifact) => artifact,
        Err(error) => {
            let _ = writeln!(serial, "Arach: Crest measurement failed: {error:?}");
            halt();
        }
    };
    let crest_image = match prepare_user_image(crest_artifact, &userland_image) {
        Ok(image) => image,
        Err(error) => {
            let _ = writeln!(serial, "Arach: Crest load plan rejected: {error:?}");
            halt();
        }
    };
    let installed_crest =
        match install_user_image(crest_image, &mut process_backend, &process_install) {
            Ok(image) => image,
            Err(error) => {
                let _ = writeln!(serial, "Arach: Crest installation failed: {error:?}");
                halt();
            }
        };
    if installed_crest.measurement.bytes_written != crest_manifest.artifact_bytes
        || installed_crest.measurement.entry_offset != crest_manifest.entry_file_offset
        || installed_crest.measurement.sha256 != crest_manifest.artifact_sha256
    {
        let _ = writeln!(
            serial,
            "Arach: Crest package identity diverged after install"
        );
        halt();
    }
    if let Err(error) = process_backend.install_initial_stack_pages(
        &installed_crest.process,
        CREST_INITIAL_STACK_PAGES,
        &process_install,
    ) {
        let _ = writeln!(serial, "Arach: Crest stack installation failed: {error:?}");
        halt();
    }
    let crest_stack = match process_backend.prepare_initial_stack(
        &installed_crest.process,
        &[b"crest"],
        &[b"SISYPHUS_PROCESS=crest", b"SISYPHUS_ABI=1"],
    ) {
        Ok(stack) => stack,
        Err(error) => {
            let _ = writeln!(
                serial,
                "Arach: Crest argv/envp preparation failed: {error:?}"
            );
            halt();
        }
    };
    // SAFETY: Crest is fully installed but not yet published to the lifecycle;
    // bootstrap still owns the only execution thread and restores the kernel root.
    if let Err(error) =
        unsafe { process_backend.validate_activation(&installed_crest.process, &process_install) }
    {
        let _ = writeln!(serial, "Arach: Crest CR3 activation failed: {error:?}");
        halt();
    }
    let Some(crest_info) = process_backend.process_info(&installed_crest.process) else {
        let _ = writeln!(serial, "Arach: retained Crest handle became stale");
        halt();
    };
    let Some(crest_root) = crest_info.address_space_root else {
        let _ = writeln!(serial, "Arach: retained Crest has no page-table root");
        halt();
    };
    if crest_info.initial_stack_pointer != Some(crest_stack)
        || crest_info.entry_point != installed_crest.entry_point
        || crest_info.segment_count == 0
    {
        let _ = writeln!(
            serial,
            "Arach: retained Crest image metadata is inconsistent"
        );
        halt();
    }
    let _ = writeln!(
        serial,
        "Arach: Crest measured image root={crest_root:#x}, frames={}, segments={}, launch=sealed",
        crest_info.owned_frames, crest_info.segment_count,
    );
    let _ = writeln!(
        serial,
        "Arach: Black Lab time={} ns, heat={}, predictions={}, epoch={}, generation={}, faults={}, artifact={} bytes, PID1 plan entry={:#x}, install=frame-backed:{}",
        blacklab.logical_nanoseconds,
        blacklab.semantic_heat,
        blacklab.predictions,
        blacklab.next_epoch,
        blacklab.evolution_generation,
        blacklab.quarantined_faults,
        blacklab.materialized_bytes,
        blacklab.pid1_entry_point,
        blacklab.pid1_install_generation
    );
    let _ = writeln!(
        serial,
        "Arach: PID1 page-table root={:#x}, frames={}, segments={}, retained=true, cr3_activation=validated, argv_envp=prepared, launch=pending",
        pid1_root, pid1_info.owned_frames, pid1_info.segment_count,
    );

    // SAFETY: ACPI described the active controllers, the local APIC is live,
    // and interrupts are disabled after the completed self-IPI test.
    let io_apics = match unsafe { interrupts::initialize_io_apics(&madt, mmio, local_apic.id) } {
        Ok(info) => info,
        Err(error) => {
            let _ = writeln!(serial, "Arach: I/O APIC initialization failed: {error:?}");
            halt();
        }
    };
    let _ = writeln!(
        serial,
        "Arach: {} I/O APIC(s), {} redirection entries, {} source override(s)",
        io_apics.controller_count,
        io_apics.redirection_entries,
        io_apics.interrupt_source_overrides
    );

    // SAFETY: The x86 PC boot platform exposes PCI configuration mechanism
    // one, and no driver can access its ports before this early inventory.
    let pci_inventory = unsafe { pci::scan_buses() };
    if pci_inventory.overflowed() {
        let _ = writeln!(serial, "Arach: PCI inventory capacity exceeded");
        halt();
    }
    let _ = writeln!(
        serial,
        "Arach: discovered {} PCI function(s)",
        pci_inventory.devices().len()
    );

    // Drivernet: derive a per-boot, measurement-bound control domain before
    // collapsing the GPU strategy set. No driver key is a repeated literal.
    let gpu_boot_counter = <arach::arch::Active as arach::arch::Architecture>::counter_sample();
    let gpu_domains = match arach::drivernet_host::derive_gpu_boot_domains(
        PUSH_EXPECTED_SHA256,
        gpu_boot_counter,
        &pci_inventory,
        boot_framebuffer,
    ) {
        Ok(domains) => domains,
        Err(error) => {
            let _ = writeln!(
                serial,
                "Arach: GPU boot-domain derivation failed: {error:?}"
            );
            halt();
        }
    };
    let census_secret = gpu_domains.drivernet.fingerprint.rotate_left(17) | 1;
    let mut device_census =
        match BootDeviceCensus::measure_pci(&pci_inventory, dmar.as_ref(), census_secret) {
            Ok(census) => census,
            Err(error) => {
                let _ = writeln!(serial, "Arach: device census failed: {error:?}");
                halt();
            }
        };
    let display_route = DriverBindingManifest {
        driver_id: 0x4452_4956_4552_4e45,
        family: arach::drivers::device_census::DeviceFamily::DisplayAdapter,
        vendor_id: 0xffff,
        device_id_mask: 0,
        device_id_value: 0,
        class_code_mask: u8::MAX,
        class_code_value: 0x03,
        subclass_mask: 0,
        subclass_value: 0,
        programming_interface_mask: 0,
        programming_interface_value: 0,
        revision_minimum: 0,
        revision_maximum: u8::MAX,
        required_evidence: EVIDENCE_IDENTITY | EVIDENCE_CLASS_TUPLE | EVIDENCE_PCI_CONFIGURATION,
        requested_authority: AUTHORITY_DELEGATE,
    };
    let display_claims = match device_census
        .claim_family::<MAXIMUM_DISPLAY_CLAIMS>(display_route, AUTHORITY_DELEGATE)
    {
        Ok(claims) => claims,
        Err(error) => {
            let _ = writeln!(serial, "Arach: display routing claim failed: {error:?}");
            halt();
        }
    };
    let xhci_route = DriverBindingManifest {
        driver_id: XHCI_PROBE_DRIVER_ID,
        family: arach::drivers::device_census::DeviceFamily::UsbHostController,
        vendor_id: 0xffff,
        device_id_mask: 0,
        device_id_value: 0,
        class_code_mask: u8::MAX,
        class_code_value: 0x0c,
        subclass_mask: u8::MAX,
        subclass_value: 0x03,
        programming_interface_mask: u8::MAX,
        programming_interface_value: 0x30,
        revision_minimum: 0,
        revision_maximum: u8::MAX,
        required_evidence: EVIDENCE_IDENTITY | EVIDENCE_CLASS_TUPLE | EVIDENCE_PCI_CONFIGURATION,
        requested_authority: AUTHORITY_MMIO
            | AUTHORITY_DMA
            | AUTHORITY_CLOCK
            | AUTHORITY_PCI_CONFIG,
    };
    let xhci_claims = match device_census
        .claim_family::<{ arach::drivers::xhci::MAXIMUM_XHCI_CONTROLLERS }>(
            xhci_route,
            AUTHORITY_MMIO | AUTHORITY_DMA | AUTHORITY_CLOCK | AUTHORITY_PCI_CONFIG,
        ) {
        Ok(claims) => claims,
        Err(error) => {
            let _ = writeln!(serial, "Arach: xHCI routing claim failed: {error:?}");
            halt();
        }
    };
    let e1000_route = DriverBindingManifest {
        driver_id: E1000_DRIVER_ID,
        family: arach::drivers::device_census::DeviceFamily::NetworkController,
        vendor_id: E1000_INTEL_VENDOR_ID,
        device_id_mask: u16::MAX,
        device_id_value: QEMU_E1000_DEVICE_ID,
        class_code_mask: u8::MAX,
        class_code_value: 0x02,
        subclass_mask: 0,
        subclass_value: 0,
        programming_interface_mask: 0,
        programming_interface_value: 0,
        revision_minimum: 0,
        revision_maximum: u8::MAX,
        required_evidence: EVIDENCE_IDENTITY | EVIDENCE_CLASS_TUPLE | EVIDENCE_PCI_CONFIGURATION,
        requested_authority: AUTHORITY_MMIO | AUTHORITY_DMA | AUTHORITY_PCI_CONFIG,
    };
    let e1000_claims = match device_census.claim_family::<MAXIMUM_E1000_CONTROLLERS>(
        e1000_route,
        AUTHORITY_MMIO | AUTHORITY_DMA | AUTHORITY_PCI_CONFIG,
    ) {
        Ok(claims) => claims,
        Err(error) => {
            let _ = writeln!(serial, "Arach: e1000 routing claim failed: {error:?}");
            halt();
        }
    };
    let detected_devices = device_census.summary();
    let _ = writeln!(
        serial,
        "Arach: device census detected total={} display={} audio={} multimedia-video={} network={} wireless={} usb-host={} input={} other={} root={:#x}",
        detected_devices.total,
        detected_devices.display,
        detected_devices.audio,
        detected_devices.multimedia_video,
        detected_devices.network,
        detected_devices.wireless,
        detected_devices.usb_hosts,
        detected_devices.input,
        detected_devices.other,
        detected_devices.root,
    );
    let e1000_mmio = authority.grant::<DeviceMemoryControl>();
    let e1000_pci_configuration = authority.grant::<PciConfigurationControl>();
    let e1000_dma_authority = authority.grant::<DmaControl>();
    for claim in e1000_claims.claims().iter().copied() {
        let address = claim.address();
        let Some(evidence) = device_census
            .evidence()
            .find(|evidence| evidence.address == address)
            .copied()
        else {
            let _ = writeln!(serial, "Arach: e1000 claim lost its device evidence");
            halt();
        };
        if evidence.vendor_id != E1000_INTEL_VENDOR_ID || evidence.device_id != QEMU_E1000_DEVICE_ID
        {
            let _ = writeln!(serial, "Arach: e1000 identity changed after claim");
            halt();
        }
        let _authorization = match device_census.authorize(
            claim,
            E1000_DRIVER_ID,
            AUTHORITY_MMIO | AUTHORITY_DMA | AUTHORITY_PCI_CONFIG,
        ) {
            Ok(authorization) => authorization,
            Err(error) => {
                let _ = writeln!(serial, "Arach: e1000 live authorization failed: {error:?}");
                halt();
            }
        };
        let Some(pci_address) = pci::PciAddress::new(address.bus, address.slot, address.function)
        else {
            let _ = writeln!(serial, "Arach: e1000 PCI address was malformed");
            halt();
        };
        let Some(device) = pci_inventory
            .devices()
            .iter()
            .copied()
            .find(|device| device.address == pci_address)
        else {
            let _ = writeln!(serial, "Arach: e1000 PCI function disappeared");
            halt();
        };
        let Some(expected) = pci::PciExpectedConfiguration::from_device(device) else {
            let _ = writeln!(serial, "Arach: e1000 PCI configuration was incomplete");
            halt();
        };
        let interrupt_guard = arach::capability::InterruptGuard::<arach::arch::Active>::enter();
        // SAFETY: this is the sole boot-time owner of the measured function;
        // bus mastering is still clear and no e1000 interrupt source is live.
        let quiescence = unsafe {
            pci::BarProbeQuiescence::asserted(
                expected.address(),
                e1000_pci_configuration.reborrow(),
                interrupt_guard.proof(),
            )
        };
        let aperture = match pci::measure_bar0_aperture(quiescence, expected) {
            Ok(aperture) => aperture,
            Err(error) => {
                let _ = writeln!(serial, "Arach: e1000 BAR measurement rejected: {error:?}");
                halt();
            }
        };
        drop(interrupt_guard);
        let bus_master = match pci::enable_bus_master(
            aperture,
            expected,
            e1000_dma_authority.reborrow(),
            e1000_pci_configuration.reborrow(),
        ) {
            Ok(lease) => lease,
            Err(error) => {
                let _ = writeln!(serial, "Arach: e1000 bus-master enable rejected: {error:?}");
                halt();
            }
        };
        let window_length = match usize::try_from(bus_master.aperture().length()) {
            Ok(length) => length,
            Err(_) => {
                let _ = pci::revoke_bus_master(
                    bus_master,
                    e1000_dma_authority.reborrow(),
                    e1000_pci_configuration.reborrow(),
                );
                let _ = writeln!(
                    serial,
                    "Arach: e1000 BAR length did not fit the MMIO mapper"
                );
                halt();
            }
        };
        let window = match arach::mmio::MmioWindow::map(
            bus_master.aperture().physical_base(),
            window_length,
            &e1000_mmio,
        ) {
            Ok(window) => window,
            Err(error) => {
                let _ = pci::revoke_bus_master(
                    bus_master,
                    e1000_dma_authority.reborrow(),
                    e1000_pci_configuration.reborrow(),
                );
                let _ = writeln!(serial, "Arach: e1000 MMIO map rejected: {error:?}");
                halt();
            }
        };
        let Some(rings) = prepare_e1000_dma_rings() else {
            let _ = quiesce_e1000(&window);
            let _ = window.close(&e1000_mmio);
            let _ = pci::revoke_bus_master(
                bus_master,
                e1000_dma_authority.reborrow(),
                e1000_pci_configuration.reborrow(),
            );
            let _ = writeln!(serial, "Arach: e1000 DMA arena was not physically retained");
            halt();
        };
        let info = match initialize_e1000(&window, rings) {
            Ok(info) => info,
            Err(error) => {
                let _ = quiesce_e1000(&window);
                let _ = window.close(&e1000_mmio);
                let _ = pci::revoke_bus_master(
                    bus_master,
                    e1000_dma_authority.reborrow(),
                    e1000_pci_configuration.reborrow(),
                );
                let _ = writeln!(serial, "Arach: e1000 initialization rejected: {error:?}");
                halt();
            }
        };
        let operational_root = u64::from_le_bytes([
            info.mac_address[0],
            info.mac_address[1],
            info.mac_address[2],
            info.mac_address[3],
            info.mac_address[4],
            info.mac_address[5],
            b'E',
            b'1',
        ]) | 1;
        if let Err(error) = device_census.commit(claim, operational_root) {
            let _ = quiesce_e1000(&window);
            let _ = window.close(&e1000_mmio);
            let _ = pci::revoke_bus_master(
                bus_master,
                e1000_dma_authority.reborrow(),
                e1000_pci_configuration.reborrow(),
            );
            let _ = writeln!(
                serial,
                "Arach: e1000 operational commit rejected: {error:?}"
            );
            halt();
        }
        let E1000LinkInfo {
            mac_address,
            link_up,
        } = info;
        let _ = writeln!(
            serial,
            "Arach: e1000 link authority online mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} link-up={}",
            mac_address[0],
            mac_address[1],
            mac_address[2],
            mac_address[3],
            mac_address[4],
            mac_address[5],
            link_up,
        );
        // SAFETY: this same static arena supplied the exact physical ring
        // addresses before bus mastering was enabled. It is retained for the
        // whole kernel lifetime and publication transfers sole MMIO ownership
        // to Arach's serialized link-layer broker.
        let storage = unsafe { &mut *E1000_DMA.0.get() };
        unsafe {
            publish_e1000(
                window,
                core::ptr::addr_of_mut!(storage.receive_descriptors).cast(),
                core::ptr::addr_of_mut!(storage.transmit_descriptors).cast(),
                core::ptr::addr_of_mut!(storage.receive_buffers).cast(),
                core::ptr::addr_of_mut!(storage.transmit_buffers).cast(),
            );
        }
        let dhcp_transaction =
            <arach::arch::Active as arach::arch::Architecture>::counter_sample() as u32 | 1;
        match acquire_e1000_dhcp(mac_address, dhcp_transaction) {
            Ok(Some(configuration)) => {
                let _ = writeln!(
                    serial,
                    "Arach: e1000 DHCP lease address={}.{}.{}.{} router={:?} dns={:?}",
                    configuration.address[0],
                    configuration.address[1],
                    configuration.address[2],
                    configuration.address[3],
                    configuration.router,
                    configuration.dns_server,
                );
                match (configuration.router, configuration.gateway_hardware_address) {
                    (Some(router), Some(gateway)) => {
                        let _ = writeln!(
                            serial,
                            "Arach: e1000 ARP gateway={}.{}.{}.{} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} icmp-echo={}",
                            router[0],
                            router[1],
                            router[2],
                            router[3],
                            gateway[0],
                            gateway[1],
                            gateway[2],
                            gateway[3],
                            gateway[4],
                            gateway[5],
                            configuration.gateway_echo_reply,
                        );
                    }
                    (Some(router), None) => {
                        let _ = writeln!(
                            serial,
                            "Arach: e1000 ARP gateway={}.{}.{}.{} unavailable within bounded poll window",
                            router[0], router[1], router[2], router[3],
                        );
                    }
                    (None, _) => {}
                }
                match (
                    configuration.dns_server,
                    configuration.dns_hardware_address,
                    configuration.dns_probe_address,
                ) {
                    (Some(server), Some(hardware), Some(answer)) => {
                        let _ = writeln!(
                            serial,
                            "Arach: e1000 DNS server={}.{}.{}.{} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} example.com={}.{}.{}.{}",
                            server[0],
                            server[1],
                            server[2],
                            server[3],
                            hardware[0],
                            hardware[1],
                            hardware[2],
                            hardware[3],
                            hardware[4],
                            hardware[5],
                            answer[0],
                            answer[1],
                            answer[2],
                            answer[3],
                        );
                    }
                    (Some(server), Some(hardware), None) => {
                        let _ = writeln!(
                            serial,
                            "Arach: e1000 DNS server={}.{}.{}.{} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} response unavailable within bounded poll window",
                            server[0],
                            server[1],
                            server[2],
                            server[3],
                            hardware[0],
                            hardware[1],
                            hardware[2],
                            hardware[3],
                            hardware[4],
                            hardware[5],
                        );
                    }
                    (Some(server), None, _) => {
                        let _ = writeln!(
                            serial,
                            "Arach: e1000 DNS server={}.{}.{}.{} ARP unavailable within bounded poll window",
                            server[0], server[1], server[2], server[3],
                        );
                    }
                    (None, _, _) => {}
                }
            }
            Ok(None) => {
                let _ = writeln!(
                    serial,
                    "Arach: e1000 DHCP lease unavailable within bounded poll window"
                );
            }
            Err(error) => {
                let _ = writeln!(serial, "Arach: e1000 DHCP acquisition rejected: {error:?}");
            }
        }
        // The retained bus-master lease names the exact same kernel-only DMA
        // arena now owned by the published link controller.
        core::mem::forget(bus_master);
    }
    let xhci_secret = census_secret.rotate_left(23) | 1;
    let mut xhci_census = match XhciProbeCensus::new(xhci_secret) {
        Ok(census) => census,
        Err(error) => {
            let _ = writeln!(serial, "Arach: xHCI census creation failed: {error:?}");
            halt();
        }
    };
    let configuration = LegacyConfigurationReader;
    let xhci_mmio = authority.grant::<DeviceMemoryControl>();
    let xhci_pci_configuration = authority.grant::<PciConfigurationControl>();
    let xhci_dma_authority = authority.grant::<DmaControl>();
    for claim in xhci_claims.claims().iter().copied() {
        let address = claim.address();
        let vtd_scope = if let Some(dmar) = dmar.as_ref() {
            let requester = (address.segment == 0)
                .then(|| pci::PciAddress::new(address.bus, address.slot, address.function))
                .flatten();
            match requester.map(|requester| select_requester_scope(dmar, requester)) {
                Some(Ok(scope)) => {
                    let unit = scope.unit();
                    let _ = writeln!(
                        serial,
                        "Arach: xHCI VT-d requester candidate {:?} policy={} unit={:#x} include-all={}",
                        scope.requester(),
                        scope.policy_name(),
                        unit.register_base,
                        unit.include_all,
                    );
                    Some(scope)
                }
                Some(Err(error)) => {
                    let _ = writeln!(
                        serial,
                        "Arach: xHCI VT-d requester proof unavailable {:?}: {error:?}",
                        address
                    );
                    None
                }
                None => {
                    let _ = writeln!(
                        serial,
                        "Arach: xHCI VT-d requester proof unavailable {:?}: nonzero PCI segment",
                        address
                    );
                    None
                }
            }
        } else {
            None
        };
        let Some(evidence) = device_census
            .evidence()
            .find(|evidence| evidence.address == address)
            .copied()
        else {
            let _ = writeln!(serial, "Arach: xHCI claim lost its device evidence");
            halt();
        };
        let authorization = match device_census.authorize(
            claim,
            XHCI_PROBE_DRIVER_ID,
            AUTHORITY_MMIO | AUTHORITY_DMA | AUTHORITY_CLOCK | AUTHORITY_PCI_CONFIG,
        ) {
            Ok(authorization) => authorization,
            Err(error) => {
                let _ = writeln!(serial, "Arach: xHCI live authorization failed: {error:?}");
                halt();
            }
        };
        match probe_bootstrap(
            authorization,
            evidence,
            &configuration,
            &xhci_mmio,
            xhci_secret,
        ) {
            Ok(bootstrap) => {
                // A Q35-style IOMMU can reject the controller's internally
                // generated reset DMA before the guest has installed its sole
                // requester context.  Defer that reset only after the routed
                // unit itself has been freshly proven disabled; the runtime
                // epoch later performs and observes the reset while the exact
                // xHCI mappings remain live.
                let reset_policy = match vtd_scope {
                    Some(scope) => {
                        let unit = scope.unit();
                        match arach::hw::vtd::VtdMmioRegisters::map(unit, &xhci_mmio) {
                            Ok(registers) => match registers.into_engine() {
                                Ok(engine) => {
                                    let disabled = matches!(
                                        engine.state(),
                                        arach::hw::vtd::VtdEngineState::Disabled
                                    );
                                    let close_ok = match engine.into_registers() {
                                        Ok(registers) => registers.close(&xhci_mmio).is_ok(),
                                        Err(_) => false,
                                    };
                                    if disabled && close_ok {
                                        ResetPolicy::DeferUntilMappedRuntime
                                    } else {
                                        let _ = writeln!(
                                            serial,
                                            "Arach: xHCI pre-activation VT-d state was not safely closed; retaining initial reset"
                                        );
                                        ResetPolicy::BeforeReady
                                    }
                                }
                                Err(failure) => {
                                    let fault = failure.fault();
                                    let close = failure.into_registers().close(&xhci_mmio);
                                    let _ = writeln!(
                                        serial,
                                        "Arach: xHCI pre-activation VT-d check rejected unit={:#x}: {fault:?}, close={close:?}; retaining initial reset",
                                        unit.register_base,
                                    );
                                    ResetPolicy::BeforeReady
                                }
                            },
                            Err(error) => {
                                let _ = writeln!(
                                    serial,
                                    "Arach: xHCI pre-activation VT-d map rejected unit={:#x}: {error:?}; retaining initial reset",
                                    unit.register_base,
                                );
                                ResetPolicy::BeforeReady
                            }
                        }
                    }
                    None => ResetPolicy::BeforeReady,
                };
                match activate_reset_ready(
                    bootstrap,
                    &mut deadline_clock,
                    &xhci_mmio,
                    &xhci_pci_configuration,
                    reset_policy,
                    xhci_secret,
                ) {
                    Ok(controller) => {
                        // This option is consumed only while a translated,
                        // bus-master-owned runtime is live. Every successful
                        // path must restore it from the exact returned BAR
                        // aperture before port inspection can continue.
                        let mut controller = Some(controller);
                        let retained_controller = match controller.as_ref() {
                            Some(controller) => controller,
                            None => halt(),
                        };
                        let snapshot = retained_controller.snapshot();
                        let reset_ready_root = retained_controller.reset_ready_root();
                        let aperture_bytes = retained_controller.aperture().length();
                        let legacy = retained_controller.ready().legacy_handoff_performed();
                        let protocol_count = retained_controller.protocols().protocol_count();
                        let usb2_ports = retained_controller
                            .protocols()
                            .usb2_protocols()
                            .map(|protocol| usize::from(protocol.port_count))
                            .sum::<usize>();
                        let usb3_ports = retained_controller
                            .protocols()
                            .usb3_protocols()
                            .map(|protocol| usize::from(protocol.port_count))
                            .sum::<usize>();
                        if let Some(scope) = vtd_scope {
                            let unit = scope.unit();
                            let unit_disabled = match arach::hw::vtd::VtdMmioRegisters::map(
                                unit, &xhci_mmio,
                            ) {
                                Ok(registers) => match registers.into_engine() {
                                    Ok(engine) => {
                                        let disabled = matches!(
                                            engine.state(),
                                            arach::hw::vtd::VtdEngineState::Disabled
                                        );
                                        match engine.into_registers() {
                                            Ok(registers) => {
                                                let close = registers.close(&xhci_mmio);
                                                if close.is_err() {
                                                    let _ = writeln!(
                                                        serial,
                                                        "Arach: xHCI VT-d recheck close failed unit={:#x}: {close:?}",
                                                        unit.register_base,
                                                    );
                                                }
                                                disabled && close.is_ok()
                                            }
                                            Err(_) => false,
                                        }
                                    }
                                    Err(failure) => {
                                        let fault = failure.fault();
                                        let registers = failure.into_registers();
                                        let close = registers.close(&xhci_mmio);
                                        let _ = writeln!(
                                            serial,
                                            "Arach: xHCI VT-d recheck rejected unit={:#x}: {fault:?}, close={close:?}",
                                            unit.register_base,
                                        );
                                        false
                                    }
                                },
                                Err(error) => {
                                    let _ = writeln!(
                                        serial,
                                        "Arach: xHCI VT-d recheck MMIO rejected unit={:#x}: {error:?}",
                                        unit.register_base,
                                    );
                                    false
                                }
                            };
                            if !unit_disabled {
                                if reset_policy == ResetPolicy::DeferUntilMappedRuntime {
                                    let _ = writeln!(
                                        serial,
                                        "Arach: xHCI VT-d state changed after deferred reset authorization; refusing an unreset controller"
                                    );
                                    halt();
                                }
                                let _ = writeln!(
                                    serial,
                                    "Arach: xHCI reversible DMA preparation deferred: routed VT-d unit is not proven disabled"
                                );
                            } else {
                                let runtime_evidence = match retained_controller
                                    .runtime_evidence(xhci_secret)
                                {
                                    Ok(evidence) => evidence,
                                    Err(error) => {
                                        let _ = writeln!(
                                            serial,
                                            "Arach: xHCI runtime evidence revalidation failed: {error:?}"
                                        );
                                        halt();
                                    }
                                };
                                // SAFETY: The exact routed VT-d unit was freshly observed
                                // disabled, the controller is reset-ready and HCHalted with
                                // bus mastering clear, and the frame pool is wholly covered
                                // by Arach's stable cache-coherent direct map.
                                let identity = unsafe {
                                    IdentityDmaWindow::establish(
                                        scope.requester(),
                                        0,
                                        EARLY_MAPPED_PHYSICAL_LIMIT,
                                        HIGHER_HALF_DIRECT_MAP_BASE,
                                        if snapshot.supports_64_bit_addresses {
                                            u64::MAX
                                        } else {
                                            u64::from(u32::MAX)
                                        },
                                        runtime_evidence.generation,
                                        runtime_evidence.reset_ready_root,
                                        IdentityDmaObservation {
                                            x86_cache_coherent: true,
                                            requester_remapping_active: false,
                                        },
                                    )
                                };
                                let identity = match identity {
                                    Ok(identity) => identity,
                                    Err(error) => {
                                        let _ = writeln!(
                                            serial,
                                            "Arach: xHCI reversible DMA identity proof failed: {error:?}"
                                        );
                                        halt();
                                    }
                                };
                                let arena = match XhciDmaArena::allocate(
                                    &frame_pool,
                                    &xhci_dma_authority,
                                    identity,
                                    snapshot.maximum_scratchpad_buffers,
                                    snapshot.supports_64_bit_addresses,
                                    xhci_secret,
                                ) {
                                    Ok(arena) => arena,
                                    Err(failure) => {
                                        let _ = writeln!(
                                            serial,
                                            "Arach: xHCI reversible DMA allocation failed: {failure:?}"
                                        );
                                        halt();
                                    }
                                };
                                let arena_root = arena.arena_root();
                                let stale_event_page = {
                                    let mut registers = XhciRegisterTransport::measured(
                                        retained_controller.aperture(),
                                        &xhci_mmio,
                                    );
                                    halted_event_dequeue_page(
                                        runtime_evidence,
                                        retained_controller.aperture().length(),
                                        &mut registers,
                                    )
                                };
                                let stale_event_page = match stale_event_page {
                                    Ok(page) => page,
                                    Err(error) => {
                                        let _ = writeln!(
                                            serial,
                                            "Arach: xHCI stale event-dequeue capture failed; retaining controller authority: {error:?}"
                                        );
                                        halt();
                                    }
                                };
                                let stale_runtime_scrub = {
                                    let mut registers = XhciRegisterTransport::measured(
                                        retained_controller.aperture(),
                                        &xhci_mmio,
                                    );
                                    scrub_halted_from_evidence(
                                        runtime_evidence,
                                        retained_controller.aperture().length(),
                                        &mut registers,
                                    )
                                };
                                if let Err(error) = stale_runtime_scrub {
                                    let _ = writeln!(
                                        serial,
                                        "Arach: xHCI stale halted-runtime scrub failed; retaining controller authority: {error:?}"
                                    );
                                    halt();
                                }
                                // SAFETY: The common frame ledger is covered by the
                                // stable higher-half direct map. The VT-d adapters own
                                // only their allocated frames and this controller is
                                // still HCHalted with PCI bus mastering disabled.
                                let mut slpt_memory = unsafe {
                                    DirectMapSlptMemory::<16>::new(
                                        &frame_pool,
                                        HIGHER_HALF_DIRECT_MAP_BASE,
                                        EARLY_MAPPED_PHYSICAL_LIMIT,
                                        &physical_memory,
                                    )
                                };
                                let slpt_root = match slpt_memory.allocate_table() {
                                    Ok(root) => root,
                                    Err(error) => {
                                        let _ = writeln!(
                                            serial,
                                            "Arach: xHCI VT-d SLPT root allocation failed: {error:?}"
                                        );
                                        halt();
                                    }
                                };
                                if let Err(error) = slpt_memory.zero_table(slpt_root) {
                                    let _ = writeln!(
                                        serial,
                                        "Arach: xHCI VT-d SLPT root initialization failed: {error:?}"
                                    );
                                    halt();
                                }
                                // SAFETY: The same direct-map and frame-ledger proof
                                // applies to the exclusive root/context pair.
                                let tables = match unsafe {
                                    DirectMapVtdTables::allocate(
                                        &frame_pool,
                                        HIGHER_HALF_DIRECT_MAP_BASE,
                                        EARLY_MAPPED_PHYSICAL_LIMIT,
                                        &physical_memory,
                                    )
                                } {
                                    Ok(tables) => tables,
                                    Err(error) => {
                                        let _ = writeln!(
                                            serial,
                                            "Arach: xHCI VT-d root/context allocation failed: {error:?}"
                                        );
                                        halt();
                                    }
                                };
                                let vtd_registers = match arach::hw::vtd::VtdMmioRegisters::map(
                                    unit, &xhci_mmio,
                                ) {
                                    Ok(registers) => registers,
                                    Err(error) => {
                                        let _ = writeln!(
                                            serial,
                                            "Arach: xHCI VT-d activation MMIO map failed: {error:?}"
                                        );
                                        halt();
                                    }
                                };
                                let backend = match VtdDmaBackend::<
                                    _,
                                    _,
                                    _,
                                    XHCI_MAXIMUM_DMA_PAGES,
                                    XHCI_MAXIMUM_REGION_COUNT,
                                    XHCI_MAXIMUM_SCRATCHPAD_BUFFERS,
                                >::build(
                                    scope,
                                    vtd_registers,
                                    slpt_memory,
                                    tables,
                                    slpt_root,
                                    1,
                                    1_000_000,
                                ) {
                                    Ok(backend) => backend,
                                    Err(failure) => {
                                        let _ = writeln!(
                                            serial,
                                            "Arach: xHCI VT-d backend activation failed; retaining resources: {failure:?}"
                                        );
                                        halt();
                                    }
                                };
                                let iova_aperture =
                                    match IovaRange::new(0, EARLY_MAPPED_PHYSICAL_LIMIT) {
                                        Ok(aperture) => aperture,
                                        Err(error) => {
                                            let _ = writeln!(
                                                serial,
                                                "Arach: xHCI VT-d IOVA aperture rejected: {error:?}"
                                            );
                                            halt();
                                        }
                                    };
                                let mut domain = match IommuDomain::isolate_device(
                                    &backend,
                                    scope.requester(),
                                    iova_aperture,
                                    &[],
                                ) {
                                    Ok(domain) => domain,
                                    Err(status) => {
                                        let _ = writeln!(
                                            serial,
                                            "Arach: xHCI VT-d domain isolation failed; retaining backend: {status}"
                                        );
                                        halt();
                                    }
                                };
                                let stale_event_guard = match stale_event_page {
                                    Some(page) => {
                                        let Some(event_ring) =
                                            arena.region(XhciDmaPurpose::EventRing)
                                        else {
                                            let _ = writeln!(
                                                serial,
                                                "Arach: xHCI event-ring guard source is absent"
                                            );
                                            halt();
                                        };
                                        match domain.map_dma_at(
                                            page,
                                            event_ring.physical_start,
                                            abyss::paging::PAGE_SIZE,
                                            DmaAccess::READ_WRITE,
                                        ) {
                                            Ok(mapping) => Some(mapping),
                                            Err(status) => {
                                                let _ = writeln!(
                                                    serial,
                                                    "Arach: xHCI stale event-dequeue guard mapping failed: {status}"
                                                );
                                                halt();
                                            }
                                        }
                                    }
                                    None => None,
                                };
                                let initial_reset = {
                                    let mut registers = XhciRegisterTransport::measured(
                                        retained_controller.aperture(),
                                        &xhci_mmio,
                                    );
                                    reset_halted_from_evidence(
                                        runtime_evidence,
                                        &mut registers,
                                        1_000_000,
                                    )
                                };
                                if let Err(error) = initial_reset {
                                    let _ = writeln!(
                                        serial,
                                        "Arach: xHCI translated initial reset failed; retaining domain authority: {error:?}"
                                    );
                                    halt();
                                }
                                if let Some(mapping) = stale_event_guard
                                    && domain.revoke_dma(mapping) != sisyphus_driver_abi::STATUS_OK
                                {
                                    let _ = writeln!(
                                        serial,
                                        "Arach: xHCI stale event-dequeue guard revocation failed; retaining domain authority"
                                    );
                                    halt();
                                }
                                let expected_mapping_count = arena.region_count();
                                let binding = match bind_halted_dma(
                                    runtime_evidence,
                                    &mut domain,
                                    &arena,
                                    xhci_secret,
                                ) {
                                    Ok(binding)
                                        if binding.mapping_count() == expected_mapping_count =>
                                    {
                                        binding
                                    }
                                    Ok(binding) => {
                                        let _ = writeln!(
                                            serial,
                                            "Arach: xHCI VT-d binding count invalid; retaining mapping authority: observed={} expected={}",
                                            binding.mapping_count(),
                                            expected_mapping_count,
                                        );
                                        halt();
                                    }
                                    Err(failure) => {
                                        let _ = writeln!(
                                            serial,
                                            "Arach: xHCI VT-d binding failed; retaining authority: {failure:?}"
                                        );
                                        halt();
                                    }
                                };
                                let owned_controller = match controller.take() {
                                    Some(controller) => controller,
                                    None => {
                                        let _ = writeln!(
                                            serial,
                                            "Arach: xHCI persistent runtime ownership was already consumed"
                                        );
                                        halt();
                                    }
                                };
                                let seed = match owned_controller.into_runtime_seed(xhci_secret) {
                                    Ok(seed) => seed,
                                    Err(error) => {
                                        let _ = writeln!(
                                            serial,
                                            "Arach: xHCI persistent runtime seed retention failed: {error:?}"
                                        );
                                        halt();
                                    }
                                };
                                let (seed_evidence, bootstrap, aperture, ready, protocols) =
                                    seed.into_parts();
                                if seed_evidence != runtime_evidence {
                                    let _ = writeln!(
                                        serial,
                                        "Arach: xHCI persistent runtime evidence diverged before bus-master enable"
                                    );
                                    halt();
                                }
                                // Exact translated mappings are live while the controller
                                // remains HCHalted. Some xHCs fetch ERST immediately when
                                // its high dword is published, which requires PCI bus-master
                                // permission before the halted register transaction.
                                let bus_master = match pci::enable_bus_master(
                                    aperture,
                                    seed_evidence.expected,
                                    xhci_dma_authority.reborrow(),
                                    xhci_pci_configuration.reborrow(),
                                ) {
                                    Ok(lease) => lease,
                                    Err(pci::BusMasterEnableFailure::Rejected {
                                        fault, ..
                                    }) => {
                                        let _ = writeln!(
                                            serial,
                                            "Arach: xHCI persistent bus-master enable rejected without mutation: {fault:?}"
                                        );
                                        halt();
                                    }
                                    Err(pci::BusMasterEnableFailure::Debt(debt)) => {
                                        let _ = writeln!(
                                            serial,
                                            "Arach: xHCI persistent bus-master enablement debt retained: {debt:?}"
                                        );
                                        halt();
                                    }
                                };
                                let prepared = {
                                    let mut registers = XhciRegisterTransport::measured(
                                        bus_master.aperture(),
                                        &xhci_mmio,
                                    );
                                    prepare_halted_from_evidence(
                                        runtime_evidence,
                                        bus_master.aperture().length(),
                                        &arena,
                                        &mut registers,
                                        xhci_secret,
                                    )
                                };
                                let prepared = match prepared {
                                    Ok(prepared) => prepared,
                                    Err(error) => {
                                        let _ = writeln!(
                                            serial,
                                            "Arach: xHCI translated runtime preparation failed; retaining domain authority: {error:?}"
                                        );
                                        halt();
                                    }
                                };
                                let binding_root = binding.root();
                                let domain_handle = domain.handle();
                                let runtime_root = prepared.runtime_root();
                                let mut registers = XhciRegisterTransport::measured(
                                    bus_master.aperture(),
                                    &xhci_mmio,
                                );
                                let halted_runtime = match prepared
                                    .start_session(&mut registers, 1_000_000)
                                {
                                    Ok(mut runtime) => {
                                        let no_op = match runtime
                                            .submit_no_op(&arena, &mut registers)
                                        {
                                            Ok(receipt) => receipt,
                                            Err(error) => {
                                                let _ = writeln!(
                                                    serial,
                                                    "Arach: xHCI live No-Op publication failed; retaining runtime authority: {error:?}"
                                                );
                                                halt();
                                            }
                                        };
                                        let mut completion_deadline = match deadline_clock
                                            .arm(10_000_000)
                                        {
                                            Ok(lease) => lease,
                                            Err(error) => {
                                                let _ = writeln!(
                                                    serial,
                                                    "Arach: xHCI live command deadline arm failed; retaining runtime authority: {error:?}"
                                                );
                                                halt();
                                            }
                                        };
                                        let mut completion = None;
                                        loop {
                                            match runtime.poll_no_op_completion(
                                                &arena,
                                                &mut registers,
                                                &no_op,
                                            ) {
                                                Ok(Some(evidence)) => {
                                                    completion = Some(evidence);
                                                    break;
                                                }
                                                Ok(None) => {}
                                                Err(error) => {
                                                    let _ = writeln!(
                                                        serial,
                                                        "Arach: xHCI live No-Op completion failed; retaining runtime authority: {error:?}"
                                                    );
                                                    halt();
                                                }
                                            }
                                            match deadline_clock.poll(&mut completion_deadline) {
                                                Ok(DeadlineState::Pending) => {
                                                    core::hint::spin_loop();
                                                }
                                                Ok(DeadlineState::Expired) => break,
                                                Err(error) => {
                                                    let _ = writeln!(
                                                        serial,
                                                        "Arach: xHCI live command deadline poll failed; retaining runtime authority: {error:?}"
                                                    );
                                                    halt();
                                                }
                                            }
                                        }
                                        let completion = match completion {
                                            Some(completion) if completion.successful() => {
                                                if let Err(error) =
                                                    deadline_clock.cancel(completion_deadline)
                                                {
                                                    let _ = writeln!(
                                                        serial,
                                                        "Arach: xHCI live command deadline cancel failed; retaining runtime authority: {error:?}"
                                                    );
                                                    halt();
                                                }
                                                completion
                                            }
                                            Some(completion) => {
                                                let _ = writeln!(
                                                    serial,
                                                    "Arach: xHCI live No-Op completed with non-success code={}; retaining runtime authority",
                                                    completion.completion_code,
                                                );
                                                halt();
                                            }
                                            None => {
                                                let _ = writeln!(
                                                    serial,
                                                    "Arach: xHCI live No-Op did not complete before its owned deadline; retaining runtime authority"
                                                );
                                                halt();
                                            }
                                        };
                                        let _ = writeln!(
                                            serial,
                                            "Arach: xHCI live No-Op completion sequence={} event={} root={:#x}",
                                            completion.sequence,
                                            completion.consumed_event_index,
                                            completion.completion_root,
                                        );
                                        match runtime.halt(&mut registers, 1_000_000) {
                                            Ok(halted) => halted,
                                            Err(failure) => {
                                                let _ = writeln!(
                                                    serial,
                                                    "Arach: xHCI reversible Run/Stop halt failed; retaining runtime authority: {:?}",
                                                    failure.cause(),
                                                );
                                                halt();
                                            }
                                        }
                                    }
                                    Err(failure) => {
                                        let _ = writeln!(
                                            serial,
                                            "Arach: xHCI reversible Run/Stop start failed; retaining runtime authority: {:?}",
                                            failure.cause(),
                                        );
                                        halt();
                                    }
                                };
                                let run_stop = halted_runtime.halt_receipt();
                                let scrubbed_runtime = match halted_runtime.scrub(&mut registers) {
                                    Ok(runtime) => runtime,
                                    Err(failure) => {
                                        let _ = writeln!(
                                            serial,
                                            "Arach: xHCI reversible DMA scrub failed; retaining DMA and VT-d authority: {:?}",
                                            failure.cause(),
                                        );
                                        halt();
                                    }
                                };
                                let reset_recovered_runtime = match scrubbed_runtime
                                    .reset_controller(&mut registers, 1_000_000)
                                {
                                    Ok(runtime) => runtime,
                                    Err(failure) => {
                                        let _ = writeln!(
                                            serial,
                                            "Arach: xHCI post-runtime controller reset failed; retaining DMA and VT-d authority: {:?}",
                                            failure.cause(),
                                        );
                                        halt();
                                    }
                                };
                                let reset_receipt = reset_recovered_runtime.reset_receipt();
                                let _ = writeln!(
                                    serial,
                                    "Arach: xHCI persistent VT-d/bus-master Run/Stop/reset epoch started/halted/reset-ready start-polls={} halt-polls={} reset-polls={} ready-polls={} root={:#x}",
                                    run_stop.start_polls,
                                    run_stop.halt_polls,
                                    reset_receipt.reset_polls,
                                    reset_receipt.ready_polls,
                                    reset_receipt.root,
                                );
                                drop(registers);
                                let returned_aperture = match pci::revoke_bus_master(
                                    bus_master,
                                    xhci_dma_authority.reborrow(),
                                    xhci_pci_configuration.reborrow(),
                                ) {
                                    Ok(aperture) => aperture,
                                    Err(debt) => {
                                        let _ = writeln!(
                                            serial,
                                            "Arach: xHCI persistent bus-master revocation debt retained: {debt:?}"
                                        );
                                        halt();
                                    }
                                };
                                controller = Some(
                                    match XhciResetReadyController::restore_runtime_parts(
                                        seed_evidence,
                                        bootstrap,
                                        returned_aperture,
                                        ready,
                                        protocols,
                                        xhci_secret,
                                    ) {
                                        Ok(controller) => controller,
                                        Err(error) => {
                                            let _ = writeln!(
                                                serial,
                                                "Arach: xHCI persistent runtime restoration failed: {error:?}"
                                            );
                                            halt();
                                        }
                                    },
                                );
                                let _ = writeln!(
                                    serial,
                                    "Arach: xHCI persistent bus-master epoch enabled/readback/runtime/revoked/restored bus-master=false"
                                );
                                if let Err(debt) = binding.revoke(&mut domain) {
                                    let _ = writeln!(
                                        serial,
                                        "Arach: xHCI VT-d mapping revocation debt retained: {debt:?}"
                                    );
                                    halt();
                                }
                                if let Err(failure) = domain.release() {
                                    let _ = writeln!(
                                        serial,
                                        "Arach: xHCI VT-d domain release failed; retaining backend: status={}",
                                        failure.status(),
                                    );
                                    halt();
                                }
                                let released = match backend.shutdown() {
                                    Ok(released) => released,
                                    Err(failure) => {
                                        let _ = writeln!(
                                            serial,
                                            "Arach: xHCI VT-d backend shutdown failed; retaining resources: {failure:?}"
                                        );
                                        halt();
                                    }
                                };
                                if released.memory.owned_table_count() != 1 {
                                    let _ = writeln!(
                                        serial,
                                        "Arach: xHCI VT-d SLPT teardown retained unexpected table count={}",
                                        released.memory.owned_table_count(),
                                    );
                                    halt();
                                }
                                let root = released.slpt.root();
                                let mut memory = released.memory;
                                if let Err(error) = memory.release_table(root) {
                                    let _ = writeln!(
                                        serial,
                                        "Arach: xHCI VT-d SLPT root release failed; retaining resources: {error:?}"
                                    );
                                    halt();
                                }
                                if let Err(failure) = released.tables.close() {
                                    let _ = writeln!(
                                        serial,
                                        "Arach: xHCI VT-d root/context release failed; retaining tables: {failure:?}"
                                    );
                                    halt();
                                }
                                let registers = match released.engine.into_registers() {
                                    Ok(registers) => registers,
                                    Err(_) => {
                                        let _ = writeln!(
                                            serial,
                                            "Arach: xHCI VT-d engine retained unexpected authority after shutdown"
                                        );
                                        halt();
                                    }
                                };
                                if let Err(error) = registers.close(&xhci_mmio) {
                                    let _ = writeln!(
                                        serial,
                                        "Arach: xHCI VT-d MMIO close failed after shutdown: {error:?}"
                                    );
                                    halt();
                                }
                                let _ = writeln!(
                                    serial,
                                    "Arach: xHCI scoped VT-d epoch enabled/mapped/revoked/released domain={} mappings={} binding-root={:#x}",
                                    domain_handle, expected_mapping_count, binding_root,
                                );
                                let quiescence = reset_recovered_runtime.into_dma_quiescence();
                                match arena.release(quiescence) {
                                    Ok(release) => {
                                        let _ = writeln!(
                                            serial,
                                            "Arach: xHCI reversible DMA epoch prepared/scrubbed/reclaimed regions={} pages={} runtime-root={:#x} arena-root={:#x} release-root={:#x}",
                                            4 + usize::from(
                                                snapshot.maximum_scratchpad_buffers != 0
                                            ) * 2,
                                            release.released_pages,
                                            runtime_root,
                                            arena_root,
                                            release.release_root,
                                        );
                                    }
                                    Err(debt) => {
                                        let _ = writeln!(
                                            serial,
                                            "Arach: xHCI DMA reclamation debt retained: {debt:?}"
                                        );
                                        halt();
                                    }
                                }
                            }
                        }
                        let controller = match controller {
                            Some(controller) => controller,
                            None => {
                                let _ = writeln!(
                                    serial,
                                    "Arach: xHCI controller ownership was not restored after runtime"
                                );
                                halt();
                            }
                        };
                        let port_survey = {
                            let mut registers =
                                XhciRegisterTransport::measured(controller.aperture(), &xhci_mmio);
                            survey_halted_ports(&controller, &mut registers, xhci_secret)
                        };
                        let port_survey = match port_survey {
                            Ok(survey) => {
                                let _ = writeln!(
                                    serial,
                                    "Arach: xHCI halted port census connected={} enabled={} resetting={} overcurrent={} root={:#x}",
                                    survey.connected_ports,
                                    survey.enabled_ports,
                                    survey.reset_active_ports,
                                    survey.overcurrent_ports,
                                    survey.root,
                                );
                                Some(survey)
                            }
                            Err(error) => {
                                let _ = writeln!(
                                    serial,
                                    "Arach: xHCI halted port census unavailable: {error:?}"
                                );
                                None
                            }
                        };
                        if let Err(error) =
                            xhci_census.insert_reset_ready_with_port_survey(controller, port_survey)
                        {
                            let _ = writeln!(
                                serial,
                                "Arach: xHCI reset-ready retention failed: {error:?}"
                            );
                            halt();
                        }
                        if let Err(error) = device_census.defer(claim, reset_ready_root) {
                            let _ = writeln!(serial, "Arach: xHCI deferral failed: {error:?}");
                            halt();
                        }
                        let _ = writeln!(
                            serial,
                            "Arach: xHCI reset-ready {:?} bar0-bytes={} legacy-handoff={} protocols={} usb2-ports={} usb3-ports={} halted=true bus-master=false root={:#x}",
                            snapshot.address,
                            aperture_bytes,
                            legacy,
                            protocol_count,
                            usb2_ports,
                            usb3_ports,
                            reset_ready_root,
                        );
                    }
                    Err(failure) => {
                        let snapshot = failure.snapshot();
                        let phase = failure.phase();
                        let debt_class = failure.debt_class();
                        let mutated = failure.mutated();
                        let _ = writeln!(
                            serial,
                            "Arach: xHCI takeover contained {:?} phase={phase:?} mutated={mutated}: {:?}",
                            snapshot.address,
                            failure.error(),
                        );
                        let containment_root = if mutated {
                            let (bootstrap, aperture) = failure.into_parts();
                            let debt = match XhciMutationDebt::retain(
                                bootstrap,
                                aperture,
                                phase,
                                debt_class,
                                xhci_secret,
                            ) {
                                Ok(debt) => debt,
                                Err(error) => {
                                    let _ = writeln!(
                                        serial,
                                        "Arach: xHCI mutation debt retention failed: {error:?}"
                                    );
                                    halt();
                                }
                            };
                            let root = debt.debt_root(xhci_secret);
                            if root == 0 {
                                let _ = writeln!(serial, "Arach: xHCI mutation debt audit failed");
                                halt();
                            }
                            if let Err(error) = xhci_census.insert_mutation_debt(debt) {
                                let _ = writeln!(
                                    serial,
                                    "Arach: xHCI mutation debt census failed: {error:?}"
                                );
                                halt();
                            }
                            root
                        } else {
                            let Some(root) = xhci_activation_containment_root(
                                xhci_secret,
                                snapshot,
                                phase,
                                debt_class,
                                false,
                            ) else {
                                let _ = writeln!(
                                    serial,
                                    "Arach: xHCI activation containment sealing failed"
                                );
                                halt();
                            };
                            if let Err(error) = xhci_census.insert(snapshot) {
                                let _ = writeln!(
                                    serial,
                                    "Arach: xHCI failed snapshot retention failed: {error:?}"
                                );
                                halt();
                            }
                            root
                        };
                        if let Err(error) = device_census.quarantine(claim, containment_root) {
                            let _ = writeln!(serial, "Arach: xHCI quarantine failed: {error:?}");
                            halt();
                        }
                    }
                }
            }
            Err(error) => {
                let _ = writeln!(
                    serial,
                    "Arach: xHCI read-only probe quarantined {:?}: {error:?}",
                    address,
                );
                let Some(containment_root) =
                    xhci_containment_root(xhci_secret, claim.evidence_root(), address, error)
                else {
                    let _ = writeln!(serial, "Arach: xHCI containment sealing failed");
                    halt();
                };
                if let Err(containment) = device_census.quarantine(claim, containment_root) {
                    let _ = writeln!(serial, "Arach: xHCI quarantine failed: {containment:?}");
                    halt();
                }
            }
        }
    }
    let xhci_summary = match publish_boot_xhci(xhci_census) {
        Ok(summary) => summary,
        Err(error) => {
            let _ = writeln!(serial, "Arach: xHCI census publication failed: {error:?}");
            halt();
        }
    };
    if boot_xhci_summary() != Some(xhci_summary) {
        let _ = writeln!(serial, "Arach: retained xHCI census verification failed");
        halt();
    }
    let _ = writeln!(
        serial,
        "Arach: xHCI capability census controllers={} ports={} slots={} bootstrap-headers={} legacy-capable={} reset-ready={} aperture-bytes={} protocols={} usb2-ports={} usb3-ports={} connected={} enabled={} overcurrent={} debt={} deferred=true root={:#x}",
        xhci_summary.controllers,
        xhci_summary.total_ports,
        xhci_summary.total_slots,
        xhci_summary.bootstrap_headers,
        xhci_summary.legacy_capable_controllers,
        xhci_summary.reset_ready_controllers,
        xhci_summary.measured_aperture_bytes,
        xhci_summary.supported_protocols,
        xhci_summary.usb2_ports,
        xhci_summary.usb3_ports,
        xhci_summary.connected_ports,
        xhci_summary.enabled_ports,
        xhci_summary.overcurrent_ports,
        xhci_summary.mutation_debts,
        xhci_summary.root,
    );
    let mut blacklab_complex =
        match arach::blacklab_bootstrap::KernelBlackLabComplex::new(gpu_domains.blacklab) {
            Ok(complex) => complex,
            Err(error) => {
                let _ = writeln!(serial, "Arach: Blacklab bootstrap failed: {error:?}");
                halt();
            }
        };
    let blacklab_policy = authority.grant::<arach::capability::PolicyControl>();
    if let Err(error) = blacklab_complex.install_default_rules(&blacklab_policy) {
        let _ = writeln!(serial, "Arach: Blacklab rule install failed: {error:?}");
        halt();
    }
    let drivernet = match arach::drivernet_host::resolve_drivernet(
        &pci_inventory,
        dmar.as_ref(),
        boot_framebuffer,
        gpu_domains.drivernet,
        &authority,
        &mut blacklab_complex,
    ) {
        Ok(summary) => summary,
        Err(error) => {
            let _ = writeln!(serial, "Arach: Drivernet resolution failed: {error:?}");
            halt();
        }
    };
    let _ = writeln!(
        serial,
        "Arach: drivernet resolved {} GPU slot(s), {} display function(s)",
        drivernet.length, drivernet.fingerprint_summary.display_functions
    );
    let hybrid_graphics = arach::drivers::hybrid_graphics::plan(drivernet.resolutions());
    let _ = writeln!(
        serial,
        "Arach: hybrid graphics mode={:?} scanout={:?} hermes={:?} intel-root={:#x} nvidia-root={:#x}",
        hybrid_graphics.mode,
        hybrid_graphics.scanout,
        hybrid_graphics.hermes,
        hybrid_graphics.intel_evidence_root,
        hybrid_graphics.nvidia_evidence_root,
    );
    for claim in display_claims.claims().iter().copied() {
        let address = claim.address();
        let resolution = drivernet.resolutions().iter().find(|resolution| {
            resolution.fingerprint.segment == address.segment
                && resolution.fingerprint.bus == address.bus
                && resolution.fingerprint.slot == address.slot
                && resolution.fingerprint.function == address.function
        });
        match resolution {
            Some(resolution)
                if resolution.status
                    == arach::drivers::drivernet::GpuResolutionStatus::Committed =>
            {
                if let Err(error) = device_census.commit(claim, resolution.resolution_root) {
                    let _ = writeln!(serial, "Arach: display binding commit failed: {error:?}");
                    halt();
                }
            }
            Some(resolution) => {
                let containment_root = if resolution.resolution_root != 0 {
                    resolution.resolution_root
                } else {
                    resolution.decision_root
                };
                if let Err(error) = device_census.quarantine(claim, containment_root) {
                    let _ = writeln!(
                        serial,
                        "Arach: display binding quarantine failed: {error:?}"
                    );
                    halt();
                }
            }
            None => {
                if let Err(error) = device_census.quarantine(claim, detected_devices.root) {
                    let _ = writeln!(
                        serial,
                        "Arach: unresolved display containment failed: {error:?}"
                    );
                    halt();
                }
            }
        }
    }
    let device_summary = match arach::drivers::device_census::publish_boot_census(device_census) {
        Ok(summary) => summary,
        Err(error) => {
            let _ = writeln!(serial, "Arach: device census publication failed: {error:?}");
            halt();
        }
    };
    if arach::drivers::device_census::boot_census_summary() != Some(device_summary) {
        let _ = writeln!(serial, "Arach: retained device census verification failed");
        halt();
    }
    for claim in xhci_claims.claims().iter().copied() {
        let address = claim.address();
        let Some(record) = boot_device_record(address) else {
            let _ = writeln!(serial, "Arach: retained xHCI device record missing");
            halt();
        };
        match boot_xhci_snapshot(address) {
            Some(snapshot)
                if matches!(
                    record.state,
                    DeviceState::Deferred | DeviceState::Quarantined
                ) && record.driver_id == XHCI_PROBE_DRIVER_ID
                    && record.authority
                        & (AUTHORITY_MMIO | AUTHORITY_CLOCK | AUTHORITY_PCI_CONFIG)
                        == (AUTHORITY_MMIO | AUTHORITY_CLOCK | AUTHORITY_PCI_CONFIG)
                    && boot_xhci_terminal_root(address) == Some(record.terminal_root)
                    && record.evidence.evidence_root == snapshot.evidence_root
                    && snapshot.binding_root != 0 =>
            {
                // The retained transport prerequisite and the retained device
                // binding name the same measured PCI function.
                if let Some(survey) = boot_xhci_port_survey(address)
                    && (survey.root == 0
                        || survey.observations().len() != usize::from(snapshot.maximum_ports))
                {
                    let _ = writeln!(serial, "Arach: retained xHCI port survey diverged");
                    halt();
                }
            }
            None if record.state == DeviceState::Quarantined => {}
            _ => {
                let _ = writeln!(serial, "Arach: retained xHCI evidence diverged");
                halt();
            }
        }
    }
    let _ = writeln!(
        serial,
        "Arach: device bindings retained detected={} claimed={} operational={} quarantined={} deferred={} root={:#x}",
        device_summary.detected,
        device_summary.claimed,
        device_summary.operational,
        device_summary.quarantined,
        device_summary.deferred,
        device_summary.root,
    );

    // The boot framebuffer is a retained firmware resource in its own right.
    // A native PCI strategy may legitimately win Drivernet arbitration, but it
    // must not make the already verified Crest first-light surface disappear.
    // Prefer the broker's object when it selected firmware fallback; otherwise
    // inspect and retain the immutable boot evidence under Arach's display
    // authority.
    let firmware_object = drivernet
        .resolutions()
        .iter()
        .find(|resolution| {
            resolution.strategy
                == arach::drivers::drivernet::model::DriverStrategy::FirmwareFramebuffer
                && resolution.framebuffer_object != 0
        })
        .map(|resolution| resolution.framebuffer_object)
        .or_else(|| {
            let framebuffer = boot_framebuffer?;
            let evidence = arach::drivers::drivernet::fingerprint::FirmwareFramebufferEvidence {
                kind: arach::drivers::drivernet::fingerprint::FirmwareFramebufferKind::Vbe,
                physical_address: framebuffer.physical_address,
                width: framebuffer.width,
                height: framebuffer.height,
                pitch: framebuffer.pitch,
                format: framebuffer.format,
                byte_length: framebuffer.byte_length,
                owner: None,
                retained: true,
            };
            let secret = gpu_domains.drivernet.fingerprint.rotate_left(29) ^ 0x4352_4553_545f_4652;
            let display = arach::drivers::firmware_display::inspect(evidence, secret).ok()?;
            arach::drivers::firmware_display::retain(display.object, secret)
                .ok()
                .map(|retained| retained.object)
        });

    if let Some(firmware_object) = firmware_object {
        let device_memory = authority.grant::<DeviceMemoryControl>();
        match arach::drivers::firmware_display::render_boot_signature(
            firmware_object,
            &device_memory,
        ) {
            Ok(report) => {
                let _ = writeln!(
                    serial,
                    "Arach: firmware scanout verified object={:#x} generation={} pixels={} samples={} root={:#x}",
                    report.object,
                    report.generation,
                    report.pixels_written,
                    report.pixels_verified,
                    report.image_root,
                );
            }
            Err(error) => {
                let _ = writeln!(
                    serial,
                    "Arach: firmware scanout verification failed: {error:?}"
                );
                halt();
            }
        }
        if let Err(error) = arach::drivers::firmware_display::bind_crest_presenter(firmware_object)
        {
            let _ = writeln!(serial, "Arach: Crest presenter binding failed: {error:?}");
            halt();
        }
        let _ = writeln!(
            serial,
            "Arach: Crest presentation capability bound to retained firmware scanout"
        );
    }

    // Manifold: PCI/drivernet → cluster quiver → Hodge Δ₁ → NTT64 fairq
    arach::manifold_orchestrator::boot_after_drivernet(
        &pci_inventory,
        &drivernet,
        PUSH_EXPECTED_SHA256,
        &mut serial,
    );

    let machine_profile_control = authority.grant::<MachineProfileControl>();
    let kairos = match arach::kairos::initialize(
        &madt,
        &memory_map,
        &pci_inventory,
        &machine_profile_control,
    ) {
        Ok(summary) => summary,
        Err(error) => {
            let _ = writeln!(serial, "Arach: Kairos initialization failed: {error:?}");
            halt();
        }
    };
    let _ = writeln!(
        serial,
        "Arach: Kairos profile CPUs={}, memory={}, I/O={}, domains={}",
        kairos.processors, kairos.memory_regions, kairos.io_devices, kairos.domains
    );
    if let Err(error) = ignition.subsystems_ready() {
        let _ = writeln!(serial, "Arach: ignition subsystem phase failed: {error:?}");
        halt();
    }

    let timer = match deadline_clock.start_periodic(interrupts::APIC_TIMER_VECTOR, 10) {
        Ok(timer) => timer,
        Err((error, _deadline_clock)) => {
            let _ = writeln!(
                serial,
                "Arach: local APIC periodic transition failed: {error:?}"
            );
            halt();
        }
    };
    interrupts::enable();
    for _ in 0..100_000_000 {
        if interrupts::apic_timer_hits() >= 2 {
            break;
        }
        core::hint::spin_loop();
    }
    interrupts::disable();
    if interrupts::apic_timer_hits() < 2 {
        let _ = writeln!(serial, "Arach: local APIC timer delivery timed out");
        halt();
    }
    let _ = writeln!(
        serial,
        "Arach: local APIC timer {} Hz, {} ms period verified",
        timer.ticks_per_second, timer.period_milliseconds
    );

    let driver_allocator = AbyssAllocator::new(&KERNEL_HEAP);
    let irq = interrupts::kernel_irq();
    IRQ_TEST_HITS.store(0, Ordering::Relaxed);
    let irq_handle = match irq.register(
        5,
        0,
        irq_test_handler,
        core::ptr::addr_of!(IRQ_TEST_HITS) as *mut c_void,
    ) {
        Ok(handle) => handle,
        Err(status) => {
            let _ = writeln!(serial, "Arach: IRQ registration failed: {status}");
            halt();
        }
    };
    if irq.set_enabled(irq_handle, true) != sisyphus_driver_abi::STATUS_OK {
        let _ = writeln!(serial, "Arach: IRQ enable failed");
        halt();
    }
    unsafe { core::arch::asm!("int 0x25", options(nomem, nostack)) };
    if IRQ_TEST_HITS.load(Ordering::Relaxed) != 1 {
        let _ = writeln!(serial, "Arach: IRQ gate test failed");
        halt();
    }
    if irq.unregister(irq_handle) != sisyphus_driver_abi::STATUS_OK {
        let _ = writeln!(serial, "Arach: IRQ unregister failed");
        halt();
    }
    if irq.set_enabled(irq_handle, true) != sisyphus_driver_abi::STATUS_NOT_FOUND {
        let _ = writeln!(serial, "Arach: stale IRQ handle was accepted");
        halt();
    }
    let _ = writeln!(serial, "Arach: IRQ 5 gate and stale handle verified");

    let driver_capabilities;
    #[cfg(feature = "reference-driver")]
    let reference_driver_result;
    {
        let driver_logger = BootDriverLogger::new(&mut serial);
        let driver_services = DriverServices::new()
            .with_logger(&driver_logger)
            .with_allocator(&driver_allocator)
            .with_mmio(mmio)
            .with_irq(irq);
        let driver_host = DriverHost::new(&driver_services);
        driver_capabilities = driver_host.api().capabilities;

        #[cfg(feature = "reference-driver")]
        {
            reference_driver_result = (|| {
                let module = arach::shim::linked_reference_driver(driver_host.api())?;
                let address = b"platform:reference0";
                let device = sisyphus_driver_abi::DeviceInfo {
                    struct_size: core::mem::size_of::<sisyphus_driver_abi::DeviceInfo>() as u32,
                    bus_type: sisyphus_driver_abi::BUS_PLATFORM,
                    kernel_handle: 1,
                    vendor_id: 0,
                    device_id: 0,
                    subsystem_vendor_id: 0,
                    subsystem_device_id: 0,
                    class_code: 0,
                    revision: 0,
                    address: address.as_ptr(),
                    address_len: address.len(),
                };
                let mut instance = module.probe_with_api(driver_host.api(), &device)?;
                if module
                    .remove_with_api(driver_host.api(), &device, &mut instance)
                    .is_err()
                {
                    module.remove_with_api(driver_host.api(), &device, &mut instance)?;
                }
                Ok::<(), arach::shim::DriverLoadError>(())
            })();
        }
    }
    let _ = writeln!(
        serial,
        "Arach: driver host capabilities {:#x}",
        driver_capabilities
    );
    #[cfg(feature = "reference-driver")]
    match reference_driver_result {
        Ok(()) => {
            let _ = writeln!(serial, "Arach: linked C driver lifecycle verified");
        }
        Err(error) => {
            let _ = writeln!(serial, "Arach: linked C driver failed: {error:?}");
            halt();
        }
    }
    if let Err(error) = ignition.interrupts_ready() {
        let _ = writeln!(serial, "Arach: ignition interrupt phase failed: {error:?}");
        halt();
    }
    if let Err(error) = ignition.userland_ready() {
        let _ = writeln!(serial, "Arach: ignition userland phase failed: {error:?}");
        halt();
    }
    interrupts::enable();
    let ignition_summary = match ignition.online() {
        Ok(summary) => summary,
        Err(error) => {
            let _ = writeln!(serial, "Arach: ignition online phase failed: {error:?}");
            halt();
        }
    };
    let _ = writeln!(
        serial,
        "Arach: ignition {:?} online, userland_ready={}",
        ignition_summary.protocol, ignition_summary.userland_ready
    );
    let _ = writeln!(serial, "Arach: interrupt-routing milestone complete");

    let formal_attestation = arach::formal_attestation::FormalAttestation::current();
    if !formal_attestation.validate() {
        let _ = writeln!(serial, "Arach: formal authority attestation rejected");
        halt();
    }
    let _ = writeln!(
        serial,
        "Arach: Idris/Agda authority root {:#x} bound to PID1",
        formal_attestation.authority_root,
    );

    let mut image_measurement_root = 0_u64;
    for (index, chunk) in PUSH_EXPECTED_SHA256.chunks_exact(8).enumerate() {
        let word = u64::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
        image_measurement_root ^= word.rotate_left((index as u32) * 13);
    }
    image_measurement_root = image_measurement_root.max(1);
    let capability_root = (image_measurement_root
        ^ blacklab.evolution_generation.rotate_left(29)
        ^ blacklab.next_epoch.rotate_left(47)
        ^ formal_attestation.authority_root.rotate_left(7)
        ^ u64::from(blacklab.pid1_install_generation))
    .max(1);
    let crest_package =
        match crest_manifest.bind_formal_authority(formal_attestation.authority_root) {
            Ok(package) => package,
            Err(error) => {
                let _ = writeln!(serial, "Arach: Crest package authority rejected: {error:?}");
                halt();
            }
        };
    let _ = writeln!(
        serial,
        "Arach: Crest package v{} ABI={} class={} provenance={:#x} manifest-root={:#x}",
        crest_manifest.version,
        crest_manifest.abi_version,
        crest_manifest.service_class,
        crest_manifest.provenance_root,
        crest_package.image_measurement_root,
    );
    let crest_launch = ProcessLaunch {
        address_space_root: crest_root,
        entry_point: crest_info.entry_point,
        user_stack_pointer: crest_stack,
        kernel_stack_pointer: privilege_info.kernel_stack_top as u64,
        image_measurement_root: crest_package.image_measurement_root,
        capability_root: crest_package.capability_root,
        service_class: CREST_SERVICE_CLASS,
        priority: 1,
    };
    if let Err(error) = service_registry::install_crest(crest_launch, installed_crest.process) {
        let _ = writeln!(serial, "Arach: Crest launch registry failed: {error:?}");
        halt();
    }
    let pid1_launch = ProcessLaunch {
        address_space_root: pid1_root,
        entry_point: pid1_info.entry_point,
        user_stack_pointer: pid1_stack,
        kernel_stack_pointer: privilege_info.kernel_stack_top as u64,
        image_measurement_root,
        capability_root,
        service_class: 1,
        priority: u8::MAX,
    };
    let pid1_handle = match lifecycle::register_init(pid1_launch) {
        Ok(handle) => handle,
        Err(error) => {
            let _ = writeln!(
                serial,
                "Arach: measured PID1 registration failed: {error:?}"
            );
            halt();
        }
    };
    let pid1_snapshot = match lifecycle::mark_running(pid1_handle) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let _ = writeln!(serial, "Arach: measured PID1 activation failed: {error:?}");
            halt();
        }
    };
    if pid1_snapshot.launch != pid1_launch
        || lifecycle::current_handle() != Some(pid1_handle)
        || pid1_handle.pid != lifecycle::INIT_PID
    {
        let _ = writeln!(serial, "Arach: measured PID1 authority publication failed");
        halt();
    }
    let mut ring_registry = match DomainRegistry::<4>::new(kernel_page_table_root.as_u64()) {
        Ok(registry) => registry,
        Err(error) => {
            let _ = writeln!(serial, "Arach: privilege-domain registry failed: {error:?}");
            halt();
        }
    };
    let pid1_domain = match ring_registry.register(DomainDescriptor {
        role: DomainRole::UserProcess,
        address_space_root: pid1_root,
        authority: HardwareAuthority::NONE,
    }) {
        Ok(domain) => domain,
        Err(error) => {
            let _ = writeln!(serial, "Arach: PID1 Ring 3 domain failed: {error:?}");
            halt();
        }
    };
    let mut ring_frontier = match TransitionFrontier::new(
        privilege_info.logical_cpu_id,
        privilege_info.cpu_generation,
        kernel_page_table_root.as_u64(),
    ) {
        Ok(frontier) => frontier,
        Err(error) => {
            let _ = writeln!(
                serial,
                "Arach: privilege transition frontier failed: {error:?}"
            );
            halt();
        }
    };
    let _ = writeln!(
        serial,
        "Arach: transferring to measured Push PID1 authority {}:{} through Ring 3 domain {}:{} at {:#x}, measurement={:#x}",
        pid1_handle.pid,
        pid1_handle.generation,
        pid1_domain.slot(),
        pid1_domain.generation(),
        pid1_snapshot.launch.entry_point,
        pid1_snapshot.launch.image_measurement_root,
    );
    interrupts::disable();
    if let Err(error) = runtime::install(process_backend) {
        let _ = writeln!(serial, "Arach: process runtime handoff failed: {error:?}");
        halt();
    }
    let transition_lease =
        match ring_frontier.prepare(&mut ring_registry, pid1_domain, TransitionGate::Iretq) {
            Ok(lease) => lease,
            Err(error) => {
                let _ = writeln!(serial, "Arach: PID1 Ring 3 preparation failed: {error:?}");
                halt();
            }
        };
    let observed_kernel_root = unsafe { active_page_table_root() };
    let committed_transition =
        match ring_frontier.commit(&ring_registry, &transition_lease, observed_kernel_root) {
            Ok(transition) => transition,
            Err(error) => {
                let _ = ring_frontier.abort(&mut ring_registry, transition_lease);
                let _ = writeln!(serial, "Arach: PID1 Ring 3 commit failed: {error:?}");
                halt();
            }
        };
    // SAFETY: Push's measured W^X image, retained hierarchy, and RW+NX stack
    // remain owned by the persistent process runtime, all kernel entry mappings are
    // inherited, and this terminal transfer intentionally abandons the
    // bootstrap stack without running destructors.
    if let Err(error) = unsafe {
        privilege::enter_user_process(
            pid1_info.entry_point as usize,
            pid1_stack as usize,
            committed_transition,
        )
    } {
        let _ = writeln!(serial, "Arach: persistent PID1 transfer failed: {error:?}");
    }
    halt()
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    // SAFETY: Panic handling occurs after the boot environment has made COM1
    // available, and no recovery path returns from this handler.
    let mut serial = unsafe { SerialPort::initialize(COM1) };
    let _ = writeln!(serial, "Arach panic: {info}");
    halt()
}
