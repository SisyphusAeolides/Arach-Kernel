//! Source-defined WPR2 metadata and SEC2 Booter Load contract for TU117.
//!
//! Turing GSP-RM is not a host executable.  NVIDIA's 610.43.03 TU102/TU117
//! implementation places the GSP-RM ELF and the RISC-V boot binary in
//! DMA-visible system memory, then gives Booter Load the physical address of
//! a 256-byte WPR metadata record through SEC2 mailboxes 0 and 1.  Booter
//! creates and locks WPR2 in *GPU framebuffer* memory from that record.
//!
//! This module deliberately serializes and validates that boundary without
//! pretending that system RAM is framebuffer RAM.  A native executor must
//! obtain its framebuffer evidence from the real Turing memory manager and
//! must hold an active VT-d domain that maps every nonzero system address
//! named by the record before it may submit the mailbox request.

use super::hermes_gsp::HermesFault;

/// Source-defined Turing WPR metadata size.
pub const T1000_WPR_METADATA_BYTES: usize = 256;
/// WPR2's start and end use this hardware alignment.
pub const T1000_WPR_ALIGNMENT: u64 = 128 * 1024;
/// Heap and framebuffer accounting in the TU10x layout is MiB-granular.
pub const T1000_WPR_HEAP_ALIGNMENT: u64 = 1024 * 1024;
/// The TU102 family reserves this FRTS region for normal boot.
pub const T1000_FRTS_BYTES: u64 = 1024 * 1024;
/// The extracted GSP boot image's payload is exactly one page for the pinned
/// 610.43.03 TU117 bundle.  The `nvfw_bin_hdr` and descriptor are not copied
/// to the RISC-V boot-binary allocation.
pub const T1000_GSP_BOOT_BINARY_BYTES: u64 = 4096;

const WPR_METADATA_MAGIC: u64 = 0xdc3a_ae21_371a_60b3;
const WPR_METADATA_REVISION: u64 = 1;
const PAGE_BYTES: u64 = 4096;

/// Hardware-observed framebuffer placement inputs.  The executor obtains
/// these only after it has mapped the actual Turing control aperture and
/// confirmed the usable framebuffer and VBIOS-reserved boundary.  No PCI BAR
/// length can substitute for either observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TuringFramebufferEvidence {
    /// Usable local-framebuffer size, before the VBIOS-reserved tail.
    pub usable_bytes: u64,
    /// Beginning of the display/VBIOS workspace in framebuffer-offset space.
    /// NVIDIA records this separately from the actual WPR boundary.
    pub vga_workspace_offset: u64,
    /// Bytes occupied by the display/VBIOS workspace. On the TU10x normal
    /// path this extends from `vga_workspace_offset` through `usable_bytes`.
    pub vga_workspace_bytes: u64,
    /// The full MMU-lock observation. The WPR ceiling is derived internally
    /// as the minimum of this lock's lower bound and the VGA workspace.
    pub mmu_lock: TuringMmuLock,
    /// Optional recovery margin requested by a real retry policy.
    pub wpr_end_margin: u64,
    /// Calibrated GSP heap size in WPR2, supplied by the Turing allocator.
    pub wpr_heap_bytes: u64,
    /// Calibrated heap placed before WPR2, supplied by the Turing allocator.
    pub non_wpr_heap_bytes: u64,
}

/// Result of reading Turing's VBIOS-programmed MMU lock. The source-defined
/// WPR calculation only consumes the lower bound, but keeping the complete
/// interval makes an impossible or truncated hardware observation rejectable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TuringMmuLock {
    NotPresent,
    Present { start: u64, end: u64 },
}

/// DMA translations proven live in the GPU's isolated VT-d domain.  These
/// are device-visible IOVA/physical addresses, not CPU virtual addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TuringGspDmaInputs {
    /// Mapped system-memory address of the verified GSP-RM ELF.
    pub gsp_rm_address: u64,
    /// The GSP-RM ELF's exact measured byte count.
    pub gsp_rm_bytes: u64,
    /// Mapped system-memory address of the GSP RISC-V boot binary payload.
    pub gsp_boot_binary_address: u64,
    /// Mapped system-memory address of this serialized WPR metadata page.
    pub metadata_address: u64,
}

/// The subset of the versioned RISC-V descriptor that is consumed by Turing
/// WPR metadata.  The loader must derive these offsets from the verified
/// boot-binary descriptor; callers may not use guessed register values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TuringRiscvBootOffsets {
    pub monitor_code_offset: u64,
    pub monitor_data_offset: u64,
    pub manifest_offset: u64,
}

/// A validated GPU-framebuffer WPR2 geometry plus its exact 256-byte Booter
/// metadata record.  `metadata` begins unverified; only SEC2 Booter Load can
/// lock it in WPR2 and set its verified value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TuringWprPlan {
    pub wpr_start: u64,
    pub wpr_end: u64,
    pub gsp_rm_offset: u64,
    pub gsp_boot_binary_offset: u64,
    pub metadata: [u8; T1000_WPR_METADATA_BYTES],
}

/// The only mailbox payload accepted for the normal TU117 Booter Load path.
/// Mailbox zero carries the low address word; mailbox one carries the high
/// word.  Success is a zero value returned in mailbox zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TuringSec2BooterLoad {
    metadata_address: u64,
}

impl TuringSec2BooterLoad {
    /// Binds a page-aligned, nonzero metadata DMA address to the source-
    /// documented SEC2 mailbox format.
    pub fn new(metadata_address: u64) -> Result<Self, HermesFault> {
        if metadata_address == 0 || metadata_address % PAGE_BYTES != 0 {
            return Err(HermesFault::DmaAddressOverflow);
        }
        Ok(Self { metadata_address })
    }

    pub const fn mailbox_words(self) -> (u32, u32) {
        (
            self.metadata_address as u32,
            (self.metadata_address >> 32) as u32,
        )
    }

    /// Accepts completion only when Booter reported success and hardware has
    /// subsequently observed WPR2 as active.  The caller must stop all GSP
    /// register access on failure and begin the controlled recovery path.
    pub const fn complete(self, mailbox_zero: u32, wpr2_active: bool) -> Result<(), HermesFault> {
        if mailbox_zero == 0 && wpr2_active {
            Ok(())
        } else {
            Err(HermesFault::DeviceFault)
        }
    }
}

impl TuringWprPlan {
    /// Constructs the normal-boot TU117 WPR2 layout from hardware observations
    /// and VT-d-mapped system memory.  This never performs MMIO or DMA; the
    /// native executor submits the resulting record only after an active
    /// requester domain has been established.
    pub fn build(
        framebuffer: TuringFramebufferEvidence,
        dma: TuringGspDmaInputs,
        boot_offsets: TuringRiscvBootOffsets,
    ) -> Result<Self, HermesFault> {
        let reserved_top_offset = validate_framebuffer(framebuffer)?;
        validate_dma(dma)?;
        validate_boot_offsets(boot_offsets)?;

        let wpr_end = align_down(
            reserved_top_offset
                .checked_sub(framebuffer.wpr_end_margin)
                .ok_or(HermesFault::DmaAddressOverflow)?,
            T1000_WPR_ALIGNMENT,
        );
        let frts_offset = wpr_end
            .checked_sub(T1000_FRTS_BYTES)
            .ok_or(HermesFault::DmaAddressOverflow)?;
        let gsp_boot_binary_offset = align_down(
            frts_offset
                .checked_sub(T1000_GSP_BOOT_BINARY_BYTES)
                .ok_or(HermesFault::DmaAddressOverflow)?,
            PAGE_BYTES,
        );
        let gsp_rm_offset = align_down(
            gsp_boot_binary_offset
                .checked_sub(dma.gsp_rm_bytes)
                .ok_or(HermesFault::DmaAddressOverflow)?,
            64 * 1024,
        );
        let wpr_heap_offset = align_down(
            gsp_rm_offset
                .checked_sub(framebuffer.wpr_heap_bytes)
                .ok_or(HermesFault::DmaAddressOverflow)?,
            T1000_WPR_HEAP_ALIGNMENT,
        );
        let wpr_start = wpr_heap_offset
            .checked_sub(T1000_WPR_HEAP_ALIGNMENT)
            .ok_or(HermesFault::DmaAddressOverflow)?;
        let non_wpr_offset = wpr_start
            .checked_sub(framebuffer.non_wpr_heap_bytes)
            .ok_or(HermesFault::DmaAddressOverflow)?;

        if wpr_start % T1000_WPR_ALIGNMENT != 0
            || wpr_end % T1000_WPR_ALIGNMENT != 0
            || wpr_start >= wpr_end
            || wpr_end > reserved_top_offset
            || non_wpr_offset >= wpr_start
        {
            return Err(HermesFault::FirmwareRejected);
        }

        let mut metadata = [0_u8; T1000_WPR_METADATA_BYTES];
        write_u64(&mut metadata, 0, WPR_METADATA_MAGIC)?;
        write_u64(&mut metadata, 8, WPR_METADATA_REVISION)?;
        write_u64(&mut metadata, 16, dma.gsp_rm_address)?;
        write_u64(&mut metadata, 24, dma.gsp_rm_bytes)?;
        write_u64(&mut metadata, 32, dma.gsp_boot_binary_address)?;
        write_u64(&mut metadata, 40, T1000_GSP_BOOT_BINARY_BYTES)?;
        write_u64(&mut metadata, 48, boot_offsets.monitor_code_offset)?;
        write_u64(&mut metadata, 56, boot_offsets.monitor_data_offset)?;
        write_u64(&mut metadata, 64, boot_offsets.manifest_offset)?;
        // Signature address/length at 72/80 are deliberately zero: the
        // source-pinned TU117 bundle contains no independently staged
        // signature allocation.  Booter validates the vendor-sealed inputs.
        write_u64(&mut metadata, 88, non_wpr_offset)?;
        write_u64(&mut metadata, 96, non_wpr_offset)?;
        write_u64(&mut metadata, 104, framebuffer.non_wpr_heap_bytes)?;
        write_u64(&mut metadata, 112, wpr_start)?;
        write_u64(&mut metadata, 120, wpr_heap_offset)?;
        write_u64(
            &mut metadata,
            128,
            gsp_rm_offset
                .checked_sub(wpr_heap_offset)
                .ok_or(HermesFault::FirmwareRejected)?,
        )?;
        write_u64(&mut metadata, 136, gsp_rm_offset)?;
        write_u64(&mut metadata, 144, gsp_boot_binary_offset)?;
        write_u64(&mut metadata, 152, frts_offset)?;
        write_u64(&mut metadata, 160, T1000_FRTS_BYTES)?;
        write_u64(&mut metadata, 168, wpr_end)?;
        write_u64(&mut metadata, 176, framebuffer.usable_bytes)?;
        write_u64(&mut metadata, 184, framebuffer.vga_workspace_offset)?;
        write_u64(&mut metadata, 192, framebuffer.vga_workspace_bytes)?;
        // Boot count, partition data, flags, PMU reservation, and verified
        // state remain zero for the first normal boot.  SEC2 changes the last
        // field only after it has locked the record into WPR2.

        Ok(Self {
            wpr_start,
            wpr_end,
            gsp_rm_offset,
            gsp_boot_binary_offset,
            metadata,
        })
    }

    pub fn booter_load(&self, metadata_address: u64) -> Result<TuringSec2BooterLoad, HermesFault> {
        TuringSec2BooterLoad::new(metadata_address)
    }
}

fn validate_framebuffer(framebuffer: TuringFramebufferEvidence) -> Result<u64, HermesFault> {
    if framebuffer.usable_bytes == 0
        || framebuffer.usable_bytes % T1000_WPR_HEAP_ALIGNMENT != 0
        || framebuffer.vga_workspace_offset == 0
        || framebuffer.vga_workspace_offset >= framebuffer.usable_bytes
        || framebuffer.vga_workspace_bytes == 0
        || framebuffer
            .vga_workspace_offset
            .checked_add(framebuffer.vga_workspace_bytes)
            != Some(framebuffer.usable_bytes)
        || framebuffer.wpr_heap_bytes == 0
        || framebuffer.wpr_heap_bytes % T1000_WPR_HEAP_ALIGNMENT != 0
        || framebuffer.non_wpr_heap_bytes % T1000_WPR_HEAP_ALIGNMENT != 0
    {
        return Err(HermesFault::FirmwareRejected);
    }
    let reserved_top_offset = match framebuffer.mmu_lock {
        TuringMmuLock::NotPresent => framebuffer.vga_workspace_offset,
        TuringMmuLock::Present { start, end }
            if start != 0 && start < end && end <= framebuffer.usable_bytes =>
        {
            start.min(framebuffer.vga_workspace_offset)
        }
        TuringMmuLock::Present { .. } => return Err(HermesFault::FirmwareRejected),
    };
    if reserved_top_offset == 0 {
        return Err(HermesFault::FirmwareRejected);
    }
    Ok(reserved_top_offset)
}

fn validate_dma(dma: TuringGspDmaInputs) -> Result<(), HermesFault> {
    if dma.gsp_rm_address == 0
        || dma.gsp_rm_address % PAGE_BYTES != 0
        || dma.gsp_rm_bytes != 29_352_832
        || dma.gsp_boot_binary_address == 0
        || dma.gsp_boot_binary_address % PAGE_BYTES != 0
        || dma.metadata_address == 0
        || dma.metadata_address % PAGE_BYTES != 0
    {
        return Err(HermesFault::FirmwareRejected);
    }
    Ok(())
}

fn validate_boot_offsets(offsets: TuringRiscvBootOffsets) -> Result<(), HermesFault> {
    for offset in [
        offsets.monitor_code_offset,
        offsets.monitor_data_offset,
        offsets.manifest_offset,
    ] {
        if offset >= T1000_GSP_BOOT_BINARY_BYTES || offset % 4 != 0 {
            return Err(HermesFault::FirmwareRejected);
        }
    }
    Ok(())
}

fn align_down(value: u64, alignment: u64) -> u64 {
    value & !(alignment - 1)
}

fn write_u64(
    output: &mut [u8; T1000_WPR_METADATA_BYTES],
    offset: usize,
    value: u64,
) -> Result<(), HermesFault> {
    let end = offset.checked_add(8).ok_or(HermesFault::FirmwareRejected)?;
    let target = output
        .get_mut(offset..end)
        .ok_or(HermesFault::FirmwareRejected)?;
    target.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framebuffer() -> TuringFramebufferEvidence {
        TuringFramebufferEvidence {
            usable_bytes: 4 * 1024 * 1024 * 1024,
            vga_workspace_offset: 4 * 1024 * 1024 * 1024 - 2 * 1024 * 1024,
            vga_workspace_bytes: 2 * 1024 * 1024,
            mmu_lock: TuringMmuLock::NotPresent,
            wpr_end_margin: 0,
            wpr_heap_bytes: 64 * 1024 * 1024,
            non_wpr_heap_bytes: 8 * 1024 * 1024,
        }
    }

    fn dma() -> TuringGspDmaInputs {
        TuringGspDmaInputs {
            gsp_rm_address: 0x1_0000_0000,
            gsp_rm_bytes: 29_352_832,
            gsp_boot_binary_address: 0x1_0200_0000,
            metadata_address: 0x1_0300_0000,
        }
    }

    #[test]
    fn builds_the_256_byte_turing_wpr_metadata_record() {
        let plan = TuringWprPlan::build(
            framebuffer(),
            dma(),
            TuringRiscvBootOffsets {
                monitor_code_offset: 0,
                monitor_data_offset: 0,
                manifest_offset: 0,
            },
        )
        .unwrap();
        assert_eq!(plan.metadata.len(), T1000_WPR_METADATA_BYTES);
        assert_eq!(
            u64::from_le_bytes(plan.metadata[0..8].try_into().unwrap()),
            WPR_METADATA_MAGIC
        );
        assert_eq!(
            u64::from_le_bytes(plan.metadata[16..24].try_into().unwrap()),
            dma().gsp_rm_address
        );
        assert_eq!(
            u64::from_le_bytes(plan.metadata[24..32].try_into().unwrap()),
            dma().gsp_rm_bytes
        );
        assert_eq!(
            u64::from_le_bytes(plan.metadata[184..192].try_into().unwrap()),
            framebuffer().vga_workspace_offset
        );
        assert_eq!(
            u64::from_le_bytes(plan.metadata[192..200].try_into().unwrap()),
            framebuffer().vga_workspace_bytes
        );
        assert_eq!(
            u64::from_le_bytes(plan.metadata[248..256].try_into().unwrap()),
            0
        );
        assert_eq!(plan.wpr_start % T1000_WPR_ALIGNMENT, 0);
        assert_eq!(plan.wpr_end % T1000_WPR_ALIGNMENT, 0);
        assert!(plan.wpr_start < plan.wpr_end);
    }

    #[test]
    fn rejects_sysmem_that_is_not_mapped_at_page_alignment() {
        let mut inputs = dma();
        inputs.metadata_address += 1;
        assert_eq!(
            TuringWprPlan::build(
                framebuffer(),
                inputs,
                TuringRiscvBootOffsets {
                    monitor_code_offset: 0,
                    monitor_data_offset: 0,
                    manifest_offset: 0,
                },
            ),
            Err(HermesFault::FirmwareRejected)
        );
    }

    #[test]
    fn rejects_an_invalid_observed_mmu_lock() {
        let mut observed = framebuffer();
        observed.mmu_lock = TuringMmuLock::Present {
            start: observed.vga_workspace_offset,
            end: observed.vga_workspace_offset,
        };
        assert_eq!(
            TuringWprPlan::build(
                observed,
                dma(),
                TuringRiscvBootOffsets {
                    monitor_code_offset: 0,
                    monitor_data_offset: 0,
                    manifest_offset: 0,
                },
            ),
            Err(HermesFault::FirmwareRejected)
        );
    }

    #[test]
    fn uses_the_lower_valid_mmu_lock_as_the_wpr_ceiling() {
        let mut observed = framebuffer();
        let lock_start = observed.vga_workspace_offset - 64 * 1024 * 1024;
        observed.mmu_lock = TuringMmuLock::Present {
            start: lock_start,
            end: observed.vga_workspace_offset,
        };
        let plan = TuringWprPlan::build(
            observed,
            dma(),
            TuringRiscvBootOffsets {
                monitor_code_offset: 0,
                monitor_data_offset: 0,
                manifest_offset: 0,
            },
        )
        .unwrap();
        assert!(plan.wpr_end <= lock_start);
    }

    #[test]
    fn booter_load_requires_zero_mailbox_and_live_wpr2() {
        let request = TuringSec2BooterLoad::new(0x1_0300_0000).unwrap();
        assert_eq!(request.mailbox_words(), (0x0300_0000, 1));
        assert_eq!(request.complete(0, true), Ok(()));
        assert_eq!(request.complete(1, true), Err(HermesFault::DeviceFault));
        assert_eq!(request.complete(0, false), Err(HermesFault::DeviceFault));
    }
}
