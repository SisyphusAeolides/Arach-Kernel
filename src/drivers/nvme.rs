//! Bounded NVMe block transport.
//!
//! This driver deliberately keeps one polling submission/completion pair and
//! one 512-byte data buffer.  It is enough to make a measured namespace
//! available to the storage layer without handing queue memory or controller
//! registers to user space.  Interrupt-driven queues and multiple namespaces
//! are separate capacity and scheduling work.

use core::ptr::{self, NonNull};
use core::sync::atomic::{Ordering, compiler_fence};

use crate::capability::{Capability, DeviceMemoryRight};
use crate::mmio::{MmioAccessError, MmioWindow};
use crate::storage::{BlockDevice, BlockError, SECTOR_BYTES};
use sisyphus_driver_abi::STATUS_OK;

pub const PCI_CLASS_MASS_STORAGE: u8 = 0x01;
pub const PCI_SUBCLASS_NVM: u8 = 0x08;
pub const PCI_PROGRAMMING_INTERFACE_NVM: u8 = 0x02;
pub const PCI_VENDOR_ANY: u16 = 0xffff;
pub const NAMESPACE_ID_ONE: u32 = 1;
pub const QUEUE_DEPTH: u16 = 16;

const CAP: usize = 0x0000;
const VS: usize = 0x0008;
const CC: usize = 0x0014;
const CSTS: usize = 0x001c;
const AQA: usize = 0x0024;
const ASQ: usize = 0x0028;
const ACQ: usize = 0x0030;
const DOORBELL_BASE: usize = 0x1000;

const CC_ENABLE: u32 = 1 << 0;
const CC_IOSQES_SHIFT: u32 = 16;
const CC_IOCQES_SHIFT: u32 = 20;
const CSTS_READY: u32 = 1 << 0;
const CSTS_FATAL: u32 = 1 << 1;
const POLL_BUDGET: usize = 1_000_000;
const NAMESPACE_IDENTIFY_BYTES: usize = 4096;
const LBA_FORMAT_OFFSET: usize = 128;
const NAMESPACE_SIZE_OFFSET: usize = 0;
const NAMESPACE_FORMAT_OFFSET: usize = 26;
const IDENTIFY_NAMESPACE: u32 = 0;
const IDENTIFY_CONTROLLER: u32 = 1;

const OPCODE_FLUSH: u8 = 0x00;
const OPCODE_WRITE: u8 = 0x01;
const OPCODE_READ: u8 = 0x02;
const OPCODE_CREATE_IO_COMPLETION_QUEUE: u8 = 0x05;
const OPCODE_IDENTIFY: u8 = 0x06;
const OPCODE_CREATE_IO_SUBMISSION_QUEUE: u8 = 0x01;

/// A 64-byte NVMe command in controller-native dword order.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvmeCommand {
    pub dwords: [u32; 16],
}

impl NvmeCommand {
    pub const ZERO: Self = Self { dwords: [0; 16] };

    pub const fn opcode(&self) -> u8 {
        self.dwords[0] as u8
    }

    pub const fn cid(&self) -> u16 {
        (self.dwords[0] >> 16) as u16
    }

    pub fn with_opcode(opcode: u8, cid: u16) -> Self {
        let mut command = Self::ZERO;
        command.dwords[0] = u32::from(opcode) | (u32::from(cid) << 16);
        command
    }

    pub fn identify_namespace(cid: u16, buffer_physical: u64) -> Self {
        let mut command = Self::with_opcode(OPCODE_IDENTIFY, cid);
        command.dwords[1] = NAMESPACE_ID_ONE;
        command.dwords[10] = IDENTIFY_NAMESPACE;
        command.dwords[6] = buffer_physical as u32;
        command.dwords[7] = (buffer_physical >> 32) as u32;
        command
    }

    pub fn identify_controller(cid: u16, buffer_physical: u64) -> Self {
        let mut command = Self::with_opcode(OPCODE_IDENTIFY, cid);
        command.dwords[10] = IDENTIFY_CONTROLLER;
        command.dwords[6] = buffer_physical as u32;
        command.dwords[7] = (buffer_physical >> 32) as u32;
        command
    }

    pub fn create_io_completion_queue(
        cid: u16,
        queue_physical: u64,
        depth: u16,
    ) -> Result<Self, NvmeError> {
        if depth == 0 || depth > QUEUE_DEPTH {
            return Err(NvmeError::InvalidQueueDepth);
        }
        let mut command = Self::with_opcode(OPCODE_CREATE_IO_COMPLETION_QUEUE, cid);
        command.dwords[6] = queue_physical as u32;
        command.dwords[7] = (queue_physical >> 32) as u32;
        // CDW10 carries the zero-based queue size in the low half and queue
        // identifier 1 in the high half.
        command.dwords[10] = u32::from(depth - 1) | (1 << 16);
        // PC (physically contiguous) is bit 0 of the completion-queue flags.
        command.dwords[11] = 1;
        Ok(command)
    }

    pub fn create_io_submission_queue(
        cid: u16,
        queue_physical: u64,
        depth: u16,
    ) -> Result<Self, NvmeError> {
        if depth == 0 || depth > QUEUE_DEPTH {
            return Err(NvmeError::InvalidQueueDepth);
        }
        let mut command = Self::with_opcode(OPCODE_CREATE_IO_SUBMISSION_QUEUE, cid);
        command.dwords[6] = queue_physical as u32;
        command.dwords[7] = (queue_physical >> 32) as u32;
        // CDW10 carries the zero-based queue size in the low half and queue
        // identifier 1 in the high half.
        command.dwords[10] = u32::from(depth - 1) | (1 << 16);
        // PC is bit 0 and the completion-queue identifier occupies the high
        // half of the queue-flags dword.
        command.dwords[11] = 1 | (1 << 16);
        Ok(command)
    }

    pub fn transfer(opcode: u8, cid: u16, lba: u64, buffer_physical: u64) -> Self {
        let mut command = Self::with_opcode(opcode, cid);
        command.dwords[1] = NAMESPACE_ID_ONE;
        command.dwords[6] = buffer_physical as u32;
        command.dwords[7] = (buffer_physical >> 32) as u32;
        command.dwords[10] = lba as u32;
        command.dwords[11] = (lba >> 32) as u32;
        // NLB is zero-based; this driver submits one logical block at a time.
        command.dwords[12] = 0;
        command
    }

    pub fn flush(cid: u16) -> Self {
        Self::with_opcode(OPCODE_FLUSH, cid)
    }
}

/// A 16-byte NVMe completion entry.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvmeCompletion {
    pub dwords: [u32; 4],
}

impl NvmeCompletion {
    pub const ZERO: Self = Self { dwords: [0; 4] };

    pub const fn command_id(&self) -> u16 {
        self.dwords[3] as u16
    }

    pub const fn phase(&self) -> bool {
        (self.dwords[3] >> 16) & 1 != 0
    }

    pub const fn status_code(&self) -> u16 {
        ((self.dwords[3] >> 17) & 0x7ff) as u16
    }

    pub const fn success(&self, expected_phase: bool) -> bool {
        self.phase() == expected_phase && self.status_code() == 0
    }
}

/// Physical and virtual addresses for the fixed queue/data arena.
///
/// The pointers must refer to page-aligned, identity-coherent memory that
/// remains live until the controller is quiesced.  The physical addresses are
/// programmed into the controller; they are never inferred from a pointer.
#[derive(Clone, Copy)]
pub struct NvmeDmaLayout {
    pub admin_submission: NonNull<NvmeCommand>,
    pub admin_submission_physical: u64,
    pub admin_completion: NonNull<NvmeCompletion>,
    pub admin_completion_physical: u64,
    pub io_submission: NonNull<NvmeCommand>,
    pub io_submission_physical: u64,
    pub io_completion: NonNull<NvmeCompletion>,
    pub io_completion_physical: u64,
    pub identify: NonNull<u8>,
    pub identify_physical: u64,
    pub sector: NonNull<u8>,
    pub sector_physical: u64,
}

impl NvmeDmaLayout {
    pub fn validate(&self) -> Result<(), NvmeError> {
        let virtual_regions = [
            (
                self.admin_submission.as_ptr() as u64,
                (core::mem::size_of::<NvmeCommand>() * QUEUE_DEPTH as usize) as u64,
            ),
            (
                self.admin_completion.as_ptr() as u64,
                (core::mem::size_of::<NvmeCompletion>() * QUEUE_DEPTH as usize) as u64,
            ),
            (
                self.io_submission.as_ptr() as u64,
                (core::mem::size_of::<NvmeCommand>() * QUEUE_DEPTH as usize) as u64,
            ),
            (
                self.io_completion.as_ptr() as u64,
                (core::mem::size_of::<NvmeCompletion>() * QUEUE_DEPTH as usize) as u64,
            ),
            (
                self.identify.as_ptr() as u64,
                NAMESPACE_IDENTIFY_BYTES as u64,
            ),
            (self.sector.as_ptr() as u64, SECTOR_BYTES as u64),
        ];
        let physical_regions = [
            (
                self.admin_submission_physical,
                core::mem::size_of::<NvmeCommand>() as u64 * QUEUE_DEPTH as u64,
            ),
            (
                self.admin_completion_physical,
                core::mem::size_of::<NvmeCompletion>() as u64 * QUEUE_DEPTH as u64,
            ),
            (
                self.io_submission_physical,
                core::mem::size_of::<NvmeCommand>() as u64 * QUEUE_DEPTH as u64,
            ),
            (
                self.io_completion_physical,
                core::mem::size_of::<NvmeCompletion>() as u64 * QUEUE_DEPTH as u64,
            ),
            (self.identify_physical, NAMESPACE_IDENTIFY_BYTES as u64),
            (self.sector_physical, SECTOR_BYTES as u64),
        ];
        for (start, length) in virtual_regions {
            if !valid_dma_region(start, length) {
                return Err(NvmeError::InvalidDmaLayout);
            }
        }
        for (start, length) in physical_regions {
            if !valid_dma_region(start, length) {
                return Err(NvmeError::InvalidDmaLayout);
            }
        }
        for left in 0..virtual_regions.len() {
            for right in (left + 1)..virtual_regions.len() {
                if overlaps(virtual_regions[left], virtual_regions[right]) {
                    return Err(NvmeError::InvalidDmaLayout);
                }
            }
        }
        for left in 0..physical_regions.len() {
            for right in (left + 1)..physical_regions.len() {
                if overlaps(physical_regions[left], physical_regions[right]) {
                    return Err(NvmeError::InvalidDmaLayout);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NvmeError {
    Mmio,
    InvalidDmaLayout,
    UnsupportedVersion,
    InvalidQueueDepth,
    ControllerTimeout,
    ControllerFatal,
    CompletionTimeout,
    CompletionMismatch,
    CommandFailed(u16),
    InvalidNamespace,
    UnsupportedLogicalBlockSize,
    InvalidSector,
}

impl From<MmioAccessError> for NvmeError {
    fn from(_: MmioAccessError) -> Self {
        Self::Mmio
    }
}

impl From<NvmeError> for BlockError {
    fn from(error: NvmeError) -> Self {
        match error {
            NvmeError::InvalidSector => Self::InvalidSector,
            NvmeError::InvalidDmaLayout
            | NvmeError::InvalidQueueDepth
            | NvmeError::InvalidNamespace => Self::InvalidGeometry,
            NvmeError::UnsupportedLogicalBlockSize | NvmeError::UnsupportedVersion => {
                Self::UnsupportedMetadata
            }
            NvmeError::CommandFailed(_) | NvmeError::CompletionMismatch => Self::ReadFailure,
            NvmeError::Mmio | NvmeError::ControllerTimeout | NvmeError::CompletionTimeout => {
                Self::ReadFailure
            }
            NvmeError::ControllerFatal => Self::ReadFailure,
        }
    }
}

struct QueueState {
    submission_tail: u16,
    completion_head: u16,
    completion_phase: bool,
    next_cid: u16,
}

impl QueueState {
    const fn new() -> Self {
        Self {
            submission_tail: 0,
            completion_head: 0,
            completion_phase: true,
            next_cid: 1,
        }
    }

    fn next_cid(&mut self) -> u16 {
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1).max(1);
        cid
    }
}

/// One initialized namespace and its fixed queue pair.
pub struct NvmeController {
    mmio: MmioWindow,
    dma: NvmeDmaLayout,
    namespace_sectors: u64,
    doorbell_stride: usize,
    admin: QueueState,
    io: QueueState,
}

// SAFETY: the MMIO window and queue memory are owned by one controller and
// callers serialize access through the mutable controller reference.
unsafe impl Send for NvmeController {}

impl Drop for NvmeController {
    fn drop(&mut self) {
        // Initialization and publication are transactional.  If a later
        // identify or queue command fails, dropping the partially initialized
        // controller must stop it before its DMA lease can be reclaimed.
        let _ = self.quiesce();
    }
}

impl NvmeController {
    /// Initializes controller and I/O queue 1, then identifies namespace 1.
    ///
    /// The caller must have measured the exact PCI BAR, retained `dma`, and
    /// enabled bus mastering only for the regions described by that layout.
    pub fn initialize(mmio: MmioWindow, dma: NvmeDmaLayout) -> Result<Self, NvmeError> {
        dma.validate()?;
        let version = mmio.read_u32(VS)?;
        if version < 0x0001_0000 {
            return Err(NvmeError::UnsupportedVersion);
        }
        let capabilities = mmio.read_u64(CAP)?;
        let maximum_queue_entries = ((capabilities & 0xffff) as u16).saturating_add(1);
        if maximum_queue_entries < QUEUE_DEPTH {
            return Err(NvmeError::InvalidDmaLayout);
        }
        let doorbell_stride = 4usize
            .checked_shl(((capabilities >> 32) & 0xf) as u32)
            .ok_or(NvmeError::Mmio)?;
        if doorbell_stride == 0 || doorbell_stride > 4096 {
            return Err(NvmeError::Mmio);
        }
        let last_doorbell_end = DOORBELL_BASE
            .checked_add(
                3usize
                    .checked_mul(doorbell_stride)
                    .and_then(|offset| offset.checked_add(core::mem::size_of::<u32>()))
                    .ok_or(NvmeError::Mmio)?,
            )
            .ok_or(NvmeError::Mmio)?;
        if mmio.length() < last_doorbell_end {
            return Err(NvmeError::Mmio);
        }

        // The queue arena is reused only after a controller reset.  Clearing
        // every completion entry also prevents an old phase bit from being
        // mistaken for a fresh completion.
        unsafe {
            ptr::write_bytes(
                dma.admin_submission.as_ptr(),
                0,
                core::mem::size_of::<NvmeCommand>() * QUEUE_DEPTH as usize,
            );
            ptr::write_bytes(
                dma.admin_completion.as_ptr(),
                0,
                core::mem::size_of::<NvmeCompletion>() * QUEUE_DEPTH as usize,
            );
            ptr::write_bytes(
                dma.io_submission.as_ptr(),
                0,
                core::mem::size_of::<NvmeCommand>() * QUEUE_DEPTH as usize,
            );
            ptr::write_bytes(
                dma.io_completion.as_ptr(),
                0,
                core::mem::size_of::<NvmeCompletion>() * QUEUE_DEPTH as usize,
            );
            ptr::write_bytes(dma.identify.as_ptr(), 0, NAMESPACE_IDENTIFY_BYTES);
            ptr::write_bytes(dma.sector.as_ptr(), 0, SECTOR_BYTES);
        }
        compiler_fence(Ordering::SeqCst);

        let mut controller = Self {
            mmio,
            dma,
            namespace_sectors: 0,
            doorbell_stride,
            admin: QueueState::new(),
            io: QueueState::new(),
        };
        controller.reset()?;
        let controller_identify = NvmeCommand::identify_controller(
            controller.admin.next_cid(),
            controller.dma.identify_physical,
        );
        controller.submit_admin(controller_identify)?;
        let namespace_identify = NvmeCommand::identify_namespace(
            controller.admin.next_cid(),
            controller.dma.identify_physical,
        );
        controller.submit_admin(namespace_identify)?;
        controller.namespace_sectors = controller.parse_namespace_identify()?;

        let create_cq = NvmeCommand::create_io_completion_queue(
            controller.admin.next_cid(),
            controller.dma.io_completion_physical,
            QUEUE_DEPTH,
        )?;
        controller.submit_admin(create_cq)?;
        let create_sq = NvmeCommand::create_io_submission_queue(
            controller.admin.next_cid(),
            controller.dma.io_submission_physical,
            QUEUE_DEPTH,
        )?;
        controller.submit_admin(create_sq)?;
        Ok(controller)
    }

    pub const fn namespace_sectors(&self) -> u64 {
        self.namespace_sectors
    }

    pub fn quiesce(&mut self) -> Result<(), NvmeError> {
        self.mmio.write_u32(CC, 0)?;
        for _ in 0..POLL_BUDGET {
            let status = self.mmio.read_u32(CSTS)?;
            if status & CSTS_FATAL != 0 {
                return Err(NvmeError::ControllerFatal);
            }
            if status & CSTS_READY == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(NvmeError::ControllerTimeout)
    }

    /// Stops the controller and releases its MMIO mapping after a failed
    /// boot-time qualification.  If the controller cannot prove it is idle,
    /// ownership is retained by `self` and the mapping is deliberately left
    /// mapped so a caller cannot accidentally hand a live device back.
    pub fn shutdown(
        mut self,
        authority: &Capability<'_, DeviceMemoryRight>,
    ) -> Result<(), NvmeError> {
        self.quiesce()?;
        // `NvmeController` has a Drop implementation that repeats quiesce.
        // Move the already-quiesced window out without running that Drop
        // path, then close the exact mapping under device-memory authority.
        let mmio = unsafe { ptr::read(&self.mmio) };
        core::mem::forget(self);
        if mmio.close(authority) == STATUS_OK {
            Ok(())
        } else {
            Err(NvmeError::Mmio)
        }
    }

    fn reset(&mut self) -> Result<(), NvmeError> {
        if self.mmio.read_u32(CSTS)? & CSTS_FATAL != 0 {
            return Err(NvmeError::ControllerFatal);
        }
        if self.mmio.read_u32(CC)? & CC_ENABLE != 0 {
            self.mmio.write_u32(CC, 0)?;
            for _ in 0..POLL_BUDGET {
                let status = self.mmio.read_u32(CSTS)?;
                if status & CSTS_FATAL != 0 {
                    return Err(NvmeError::ControllerFatal);
                }
                if status & CSTS_READY == 0 {
                    break;
                }
                core::hint::spin_loop();
            }
            let status = self.mmio.read_u32(CSTS)?;
            if status & CSTS_FATAL != 0 {
                return Err(NvmeError::ControllerFatal);
            }
            if status & CSTS_READY != 0 {
                return Err(NvmeError::ControllerTimeout);
            }
        }

        self.mmio.write_u32(
            AQA,
            u32::from(QUEUE_DEPTH - 1) | (u32::from(QUEUE_DEPTH - 1) << 16),
        )?;
        self.mmio
            .write_u64(ASQ, self.dma.admin_submission_physical)?;
        self.mmio
            .write_u64(ACQ, self.dma.admin_completion_physical)?;
        let cc = CC_ENABLE | (6 << CC_IOSQES_SHIFT) | (4 << CC_IOCQES_SHIFT);
        self.mmio.write_u32(CC, cc)?;
        for _ in 0..POLL_BUDGET {
            let status = self.mmio.read_u32(CSTS)?;
            if status & CSTS_FATAL != 0 {
                return Err(NvmeError::ControllerFatal);
            }
            if status & CSTS_READY != 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(NvmeError::ControllerTimeout)
    }

    fn parse_namespace_identify(&self) -> Result<u64, NvmeError> {
        let bytes = unsafe {
            core::slice::from_raw_parts(self.dma.identify.as_ptr(), NAMESPACE_IDENTIFY_BYTES)
        };
        let sectors = u64::from_le_bytes(
            bytes[NAMESPACE_SIZE_OFFSET..NAMESPACE_SIZE_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        if sectors == 0 {
            return Err(NvmeError::InvalidNamespace);
        }
        let format = bytes[NAMESPACE_FORMAT_OFFSET] & 0x0f;
        let descriptor_offset = LBA_FORMAT_OFFSET
            .checked_add(
                usize::from(format)
                    .checked_mul(4)
                    .ok_or(NvmeError::InvalidNamespace)?,
            )
            .ok_or(NvmeError::InvalidNamespace)?;
        let descriptor = u32::from_le_bytes(
            bytes[descriptor_offset..descriptor_offset + 4]
                .try_into()
                .unwrap(),
        );
        let metadata_size = descriptor & 0xffff;
        let logical_block_exponent = (descriptor >> 16) as u8;
        if metadata_size != 0 || logical_block_exponent != 9 {
            return Err(NvmeError::UnsupportedLogicalBlockSize);
        }
        Ok(sectors)
    }

    fn submit_admin(&mut self, command: NvmeCommand) -> Result<NvmeCompletion, NvmeError> {
        Self::submit(
            &mut self.mmio,
            self.doorbell_stride,
            command,
            self.dma.admin_submission,
            self.dma.admin_completion,
            &mut self.admin,
            0,
            0,
        )
    }

    fn submit_io(&mut self, command: NvmeCommand) -> Result<NvmeCompletion, NvmeError> {
        Self::submit(
            &mut self.mmio,
            self.doorbell_stride,
            command,
            self.dma.io_submission,
            self.dma.io_completion,
            &mut self.io,
            1,
            2,
        )
    }

    fn submit(
        mmio: &mut MmioWindow,
        doorbell_stride: usize,
        command: NvmeCommand,
        submission: NonNull<NvmeCommand>,
        completion: NonNull<NvmeCompletion>,
        queue: &mut QueueState,
        queue_id: usize,
        doorbell_number: usize,
    ) -> Result<NvmeCompletion, NvmeError> {
        let cid = command.cid();
        if cid == 0 {
            return Err(NvmeError::CompletionMismatch);
        }
        let slot = usize::from(queue.submission_tail);
        unsafe { submission.as_ptr().add(slot).write_volatile(command) };
        compiler_fence(Ordering::SeqCst);
        queue.submission_tail = (queue.submission_tail + 1) % QUEUE_DEPTH;
        let doorbell = DOORBELL_BASE
            .checked_add(
                doorbell_number
                    .checked_mul(doorbell_stride)
                    .ok_or(NvmeError::Mmio)?,
            )
            .ok_or(NvmeError::Mmio)?;
        mmio.write_u32(doorbell, u32::from(queue.submission_tail))?;

        for _ in 0..POLL_BUDGET {
            let expected_phase = queue.completion_phase;
            let completion_entry = unsafe {
                completion
                    .as_ptr()
                    .add(usize::from(queue.completion_head))
                    .read_volatile()
            };
            if completion_entry.phase() != expected_phase {
                core::hint::spin_loop();
                continue;
            }
            if completion_entry.command_id() != cid {
                return Err(NvmeError::CompletionMismatch);
            }
            queue.completion_head = (queue.completion_head + 1) % QUEUE_DEPTH;
            if queue.completion_head == 0 {
                queue.completion_phase = !queue.completion_phase;
            }
            let completion_doorbell = DOORBELL_BASE
                .checked_add(
                    (queue_id * 2 + 1)
                        .checked_mul(doorbell_stride)
                        .ok_or(NvmeError::Mmio)?,
                )
                .ok_or(NvmeError::Mmio)?;
            mmio.write_u32(completion_doorbell, u32::from(queue.completion_head))?;
            if !completion_entry.success(expected_phase) {
                let status = completion_entry.status_code();
                return Err(NvmeError::CommandFailed(status));
            }
            return Ok(completion_entry);
        }
        Err(NvmeError::CompletionTimeout)
    }
}

impl BlockDevice for NvmeController {
    fn sector_count(&self) -> u64 {
        self.namespace_sectors
    }

    fn read_sector(&mut self, lba: u64, sector: &mut [u8; SECTOR_BYTES]) -> Result<(), BlockError> {
        if lba >= self.namespace_sectors {
            return Err(BlockError::InvalidSector);
        }
        let command = NvmeCommand::transfer(
            OPCODE_READ,
            self.io.next_cid(),
            lba,
            self.dma.sector_physical,
        );
        self.submit_io(command).map_err(BlockError::from)?;
        unsafe {
            ptr::copy_nonoverlapping(self.dma.sector.as_ptr(), sector.as_mut_ptr(), SECTOR_BYTES);
        }
        Ok(())
    }

    fn write_sector(&mut self, lba: u64, sector: &[u8; SECTOR_BYTES]) -> Result<(), BlockError> {
        if lba >= self.namespace_sectors {
            return Err(BlockError::InvalidSector);
        }
        unsafe {
            ptr::copy_nonoverlapping(sector.as_ptr(), self.dma.sector.as_ptr(), SECTOR_BYTES);
        }
        compiler_fence(Ordering::SeqCst);
        let command = NvmeCommand::transfer(
            OPCODE_WRITE,
            self.io.next_cid(),
            lba,
            self.dma.sector_physical,
        );
        self.submit_io(command).map_err(|error| match error {
            NvmeError::CommandFailed(_) | NvmeError::CompletionMismatch => BlockError::WriteFailure,
            NvmeError::InvalidSector => BlockError::InvalidSector,
            _ => BlockError::WriteFailure,
        })?;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        let cid = self.io.next_cid();
        self.submit_io(NvmeCommand::flush(cid))
            .map(|_| ())
            .map_err(BlockError::from)
    }
}

fn overlaps(left: (u64, u64), right: (u64, u64)) -> bool {
    let Some(left_end) = left.0.checked_add(left.1) else {
        return true;
    };
    let Some(right_end) = right.0.checked_add(right.1) else {
        return true;
    };
    left.0 < right_end && right.0 < left_end
}

fn valid_dma_region(start: u64, length: u64) -> bool {
    start != 0 && start % 4096 == 0 && length != 0 && start.checked_add(length).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_layout_binds_namespace_and_64_bit_addresses() {
        let identify = NvmeCommand::identify_namespace(7, 0x1234_5678_9abc_def0);
        assert_eq!(identify.opcode(), OPCODE_IDENTIFY);
        assert_eq!(identify.cid(), 7);
        assert_eq!(identify.dwords[1], NAMESPACE_ID_ONE);
        assert_eq!(identify.dwords[6], 0x9abc_def0);
        assert_eq!(identify.dwords[7], 0x1234_5678);
        assert_eq!(identify.dwords[10], IDENTIFY_NAMESPACE);

        let read = NvmeCommand::transfer(OPCODE_READ, 9, 0x1122_3344_5566_7788, 0x1000);
        assert_eq!(read.dwords[10], 0x5566_7788);
        assert_eq!(read.dwords[11], 0x1122_3344);
        assert_eq!(read.dwords[12], 0);
    }

    #[test]
    fn queue_creation_uses_contiguous_depth_and_cq_one() {
        let completion = NvmeCommand::create_io_completion_queue(1, 0x8000, QUEUE_DEPTH).unwrap();
        assert_eq!(
            completion.dwords[10],
            u32::from(QUEUE_DEPTH - 1) | (1 << 16)
        );
        assert_eq!(completion.dwords[11], 1);
        let submission = NvmeCommand::create_io_submission_queue(2, 0x9000, QUEUE_DEPTH).unwrap();
        assert_eq!(
            submission.dwords[10],
            u32::from(QUEUE_DEPTH - 1) | (1 << 16)
        );
        assert_eq!(submission.dwords[11], 1 | (1 << 16));
        assert_eq!(
            NvmeCommand::create_io_submission_queue(1, 0x9000, 0),
            Err(NvmeError::InvalidQueueDepth)
        );
    }

    #[test]
    fn completion_status_decodes_phase_and_error() {
        let success = NvmeCompletion {
            dwords: [0, 0, 0, 11 | (1 << 16)],
        };
        assert_eq!(success.command_id(), 11);
        assert!(success.success(true));
        let failed = NvmeCompletion {
            dwords: [0, 0, 0, 11 | (1 << 17) | (7 << 17)],
        };
        assert_eq!(failed.status_code(), 7);
        assert!(!failed.success(true));
    }

    #[test]
    fn physical_regions_must_not_overlap() {
        #[repr(C, align(4096))]
        struct AlignedCommands([NvmeCommand; QUEUE_DEPTH as usize]);
        #[repr(C, align(4096))]
        struct AlignedCompletions([NvmeCompletion; QUEUE_DEPTH as usize]);
        #[repr(C, align(4096))]
        struct AlignedIdentify([u8; NAMESPACE_IDENTIFY_BYTES]);
        #[repr(C, align(4096))]
        struct AlignedSector([u8; SECTOR_BYTES]);

        let mut admin_sq = AlignedCommands([NvmeCommand::ZERO; QUEUE_DEPTH as usize]);
        let mut admin_cq = AlignedCompletions([NvmeCompletion::ZERO; QUEUE_DEPTH as usize]);
        let mut io_sq = AlignedCommands([NvmeCommand::ZERO; QUEUE_DEPTH as usize]);
        let mut io_cq = AlignedCompletions([NvmeCompletion::ZERO; QUEUE_DEPTH as usize]);
        let mut identify = AlignedIdentify([0_u8; NAMESPACE_IDENTIFY_BYTES]);
        let mut sector = AlignedSector([0_u8; SECTOR_BYTES]);
        let layout = NvmeDmaLayout {
            admin_submission: NonNull::from(&mut admin_sq.0[0]),
            admin_submission_physical: 0x1000,
            admin_completion: NonNull::from(&mut admin_cq.0[0]),
            admin_completion_physical: 0x2000,
            io_submission: NonNull::from(&mut io_sq.0[0]),
            io_submission_physical: 0x3000,
            io_completion: NonNull::from(&mut io_cq.0[0]),
            io_completion_physical: 0x4000,
            identify: NonNull::from(&mut identify.0[0]),
            identify_physical: 0x5000,
            sector: NonNull::from(&mut sector.0[0]),
            sector_physical: 0x6000,
        };
        assert!(layout.validate().is_ok());
        let unaligned = NvmeDmaLayout {
            admin_submission_physical: 0x1100,
            ..layout
        };
        assert_eq!(unaligned.validate(), Err(NvmeError::InvalidDmaLayout));
        let overlapping = NvmeDmaLayout {
            sector_physical: 0x5000,
            ..layout
        };
        assert_eq!(overlapping.validate(), Err(NvmeError::InvalidDmaLayout));
    }
}
