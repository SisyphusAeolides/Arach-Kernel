//! Bounded block-device and GPT partition primitives.
//!
//! The Linux personality combines a bounded VFS with a read-only persistent
//! root broker. Device drivers implement [`BlockDevice`], while the partition
//! and filesystem layers consume the same checked sector interface. Storage is
//! not advertised until a driver supplies this contract and the filesystem
//! metadata passes its admission checks.

use crate::sync::SpinLock;

pub const SECTOR_BYTES: usize = 512;
pub const GPT_HEADER_LBA: u64 = 1;
pub const GPT_HEADER_BYTES: usize = 92;
pub const GPT_PARTITION_ENTRY_BYTES: usize = 128;
pub const MAXIMUM_GPT_PARTITIONS: usize = 128;
pub const MAXIMUM_GPT_PARTITION_NAME_UNITS: usize = 36;

const GPT_SIGNATURE: [u8; 8] = *b"EFI PART";
const GPT_REVISION_1_0: u32 = 0x0001_0000;

/// Errors that can be returned by a bounded block device or partition view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockError {
    InvalidSector,
    InvalidGeometry,
    ReadFailure,
    WriteFailure,
    FlushFailure,
    CorruptMetadata,
    UnsupportedMetadata,
    Capacity,
}

/// A synchronous, sector-addressed block device.
///
/// Implementations must not retain the caller's sector buffer after a method
/// returns.  A driver may serialize access internally; callers should treat a
/// device as exclusively borrowed for the duration of each operation.
pub trait BlockDevice {
    fn sector_count(&self) -> u64;

    fn read_sector(&mut self, lba: u64, sector: &mut [u8; SECTOR_BYTES]) -> Result<(), BlockError>;

    fn write_sector(&mut self, lba: u64, sector: &[u8; SECTOR_BYTES]) -> Result<(), BlockError>;

    fn flush(&mut self) -> Result<(), BlockError>;
}

/// A checked view over one contiguous partition.
pub struct PartitionView<'device, D: BlockDevice + ?Sized> {
    device: &'device mut D,
    start_lba: u64,
    sector_count: u64,
}

impl<'device, D: BlockDevice + ?Sized> PartitionView<'device, D> {
    pub fn new(
        device: &'device mut D,
        start_lba: u64,
        sector_count: u64,
    ) -> Result<Self, BlockError> {
        if sector_count == 0
            || start_lba
                .checked_add(sector_count)
                .is_none_or(|end| end > device.sector_count())
        {
            return Err(BlockError::InvalidGeometry);
        }
        Ok(Self {
            device,
            start_lba,
            sector_count,
        })
    }

    pub const fn start_lba(&self) -> u64 {
        self.start_lba
    }

    pub const fn sector_count(&self) -> u64 {
        self.sector_count
    }

    fn translate(&self, lba: u64) -> Result<u64, BlockError> {
        if lba >= self.sector_count {
            return Err(BlockError::InvalidSector);
        }
        self.start_lba
            .checked_add(lba)
            .ok_or(BlockError::InvalidSector)
    }

    pub fn read_sector(
        &mut self,
        lba: u64,
        sector: &mut [u8; SECTOR_BYTES],
    ) -> Result<(), BlockError> {
        self.device.read_sector(self.translate(lba)?, sector)
    }

    pub fn write_sector(
        &mut self,
        lba: u64,
        sector: &[u8; SECTOR_BYTES],
    ) -> Result<(), BlockError> {
        self.device.write_sector(self.translate(lba)?, sector)
    }

    pub fn flush(&mut self) -> Result<(), BlockError> {
        self.device.flush()
    }
}

impl<D: BlockDevice + ?Sized> BlockDevice for PartitionView<'_, D> {
    fn sector_count(&self) -> u64 {
        self.sector_count
    }

    fn read_sector(&mut self, lba: u64, sector: &mut [u8; SECTOR_BYTES]) -> Result<(), BlockError> {
        PartitionView::read_sector(self, lba, sector)
    }

    fn write_sector(&mut self, lba: u64, sector: &[u8; SECTOR_BYTES]) -> Result<(), BlockError> {
        PartitionView::write_sector(self, lba, sector)
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        PartitionView::flush(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GptPartition {
    pub index: u32,
    pub type_guid: [u8; 16],
    pub unique_guid: [u8; 16],
    pub first_lba: u64,
    pub last_lba: u64,
    pub attributes: u64,
    name: [u16; MAXIMUM_GPT_PARTITION_NAME_UNITS],
    name_len: u8,
}

impl GptPartition {
    const EMPTY: Self = Self {
        index: 0,
        type_guid: [0; 16],
        unique_guid: [0; 16],
        first_lba: 0,
        last_lba: 0,
        attributes: 0,
        name: [0; MAXIMUM_GPT_PARTITION_NAME_UNITS],
        name_len: 0,
    };

    pub fn name(&self) -> &[u16] {
        &self.name[..usize::from(self.name_len)]
    }

    pub const fn sector_count(&self) -> u64 {
        self.last_lba - self.first_lba + 1
    }

    pub fn open<'device, D: BlockDevice + ?Sized>(
        &self,
        device: &'device mut D,
    ) -> Result<PartitionView<'device, D>, BlockError> {
        PartitionView::new(device, self.first_lba, self.sector_count())
    }

    pub fn is_used(&self) -> bool {
        self.type_guid != [0; 16]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GptTable {
    pub disk_guid: [u8; 16],
    pub first_usable_lba: u64,
    pub last_usable_lba: u64,
    partitions: [GptPartition; MAXIMUM_GPT_PARTITIONS],
    partition_count: usize,
}

impl GptTable {
    pub fn parse<D: BlockDevice + ?Sized>(device: &mut D) -> Result<Self, BlockError> {
        if device.sector_count() < 3 {
            return Err(BlockError::InvalidGeometry);
        }

        let mut header = [0_u8; SECTOR_BYTES];
        device.read_sector(GPT_HEADER_LBA, &mut header)?;
        validate_header(&header, device.sector_count())?;

        let header_size = read_u32(&header, 12) as usize;
        let expected_header_crc = read_u32(&header, 16);
        let mut header_for_crc = header;
        header_for_crc[16..20].fill(0);
        if crc32(&header_for_crc[..header_size]) != expected_header_crc {
            return Err(BlockError::CorruptMetadata);
        }

        let entry_lba = read_u64(&header, 72);
        let entry_count = read_u32(&header, 80) as usize;
        let entry_size = read_u32(&header, 84) as usize;
        let entry_sectors = entry_count
            .checked_mul(entry_size)
            .and_then(|bytes| bytes.checked_add(SECTOR_BYTES - 1))
            .map(|bytes| bytes / SECTOR_BYTES)
            .ok_or(BlockError::Capacity)? as u64;
        if entry_count == 0
            || entry_count > MAXIMUM_GPT_PARTITIONS
            || entry_size != GPT_PARTITION_ENTRY_BYTES
            || entry_lba
                .checked_add(entry_sectors)
                .is_none_or(|end| end > device.sector_count())
        {
            return Err(BlockError::UnsupportedMetadata);
        }

        let first_usable_lba = read_u64(&header, 40);
        let last_usable_lba = read_u64(&header, 48);
        if entry_lba < 2
            || entry_lba
                .checked_add(entry_sectors)
                .is_none_or(|end| end > first_usable_lba)
        {
            return Err(BlockError::CorruptMetadata);
        }

        let expected_entries_crc = read_u32(&header, 88);
        let entry_bytes_total = entry_count * entry_size;
        let mut entries_crc = Crc32::new();
        let mut sector = [0_u8; SECTOR_BYTES];
        let mut entry_bytes = 0_usize;
        let mut lba = entry_lba;
        let mut partitions = [GptPartition::EMPTY; MAXIMUM_GPT_PARTITIONS];
        let mut partition_count = 0_usize;
        for _ in 0..entry_sectors {
            device.read_sector(lba, &mut sector)?;
            let remaining = entry_bytes_total - entry_bytes;
            let copied = remaining.min(SECTOR_BYTES);
            let entry_sector = &sector[..copied];
            entries_crc.update(entry_sector);
            // GPT entries are 128 bytes and therefore never straddle a
            // 512-byte sector. The final sector may contain unused trailing
            // bytes; those bytes are excluded from both the CRC and parsing.
            for (offset, raw) in entry_sector
                .chunks_exact(GPT_PARTITION_ENTRY_BYTES)
                .enumerate()
            {
                let index = (entry_bytes / GPT_PARTITION_ENTRY_BYTES) + offset;
                if raw[..16].iter().all(|byte| *byte == 0) {
                    continue;
                }
                let first_lba = read_u64(raw, 32);
                let last_lba = read_u64(raw, 40);
                if first_lba < first_usable_lba
                    || last_lba < first_lba
                    || last_lba > last_usable_lba
                {
                    return Err(BlockError::CorruptMetadata);
                }
                let mut partition = GptPartition::EMPTY;
                partition.index = index as u32;
                partition.type_guid.copy_from_slice(&raw[..16]);
                partition.unique_guid.copy_from_slice(&raw[16..32]);
                partition.first_lba = first_lba;
                partition.last_lba = last_lba;
                partition.attributes = read_u64(raw, 48);
                for unit in 0..MAXIMUM_GPT_PARTITION_NAME_UNITS {
                    let value = u16::from_le_bytes([raw[56 + unit * 2], raw[57 + unit * 2]]);
                    if value == 0 {
                        break;
                    }
                    partition.name[unit] = value;
                    partition.name_len = (unit + 1) as u8;
                }
                if partition_count == MAXIMUM_GPT_PARTITIONS {
                    return Err(BlockError::Capacity);
                }
                partitions[partition_count] = partition;
                partition_count += 1;
            }
            entry_bytes += copied;
            lba = lba.checked_add(1).ok_or(BlockError::InvalidSector)?;
        }
        if entries_crc.finish() != expected_entries_crc {
            return Err(BlockError::CorruptMetadata);
        }

        for left in 0..partition_count {
            for right in (left + 1)..partition_count {
                if partitions[left].first_lba <= partitions[right].last_lba
                    && partitions[right].first_lba <= partitions[left].last_lba
                {
                    return Err(BlockError::CorruptMetadata);
                }
            }
        }

        Ok(Self {
            disk_guid: read_array::<16>(&header, 56),
            first_usable_lba,
            last_usable_lba,
            partitions,
            partition_count,
        })
    }

    pub fn partitions(&self) -> &[GptPartition] {
        &self.partitions[..self.partition_count]
    }

    pub fn partition(&self, index: usize) -> Option<&GptPartition> {
        self.partitions().get(index)
    }
}

fn validate_header(header: &[u8; SECTOR_BYTES], sector_count: u64) -> Result<(), BlockError> {
    if header[..8] != GPT_SIGNATURE
        || read_u32(header, 8) != GPT_REVISION_1_0
        || !(GPT_HEADER_BYTES..=SECTOR_BYTES).contains(&(read_u32(header, 12) as usize))
        || read_u64(header, 0x18) != GPT_HEADER_LBA
        || read_u64(header, 0x20) >= sector_count
        || read_u64(header, 0x28) > read_u64(header, 0x30)
        || read_u64(header, 0x30) >= sector_count
    {
        return Err(BlockError::CorruptMetadata);
    }
    Ok(())
}

/// Errors returned by the bounded read-only ext4 reader.
///
/// The reader deliberately implements only the operations the early Arach
/// root needs: superblock validation, inode lookup, directory traversal, and
/// file reads.  It never writes metadata, replays a journal, or silently
/// treats an unsupported feature as a valid filesystem.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ext4Error {
    Io(BlockError),
    InvalidGeometry,
    CorruptMetadata,
    UnsupportedFeature,
    InvalidPath,
    NotFound,
    NotDirectory,
    NotFile,
    Capacity,
}

impl From<BlockError> for Ext4Error {
    fn from(error: BlockError) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Ext4NodeKind {
    File = 0,
    Directory = 1,
    Symlink = 2,
    Other = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ext4Metadata {
    pub inode: u32,
    pub size_bytes: u64,
    pub kind: Ext4NodeKind,
}

/// A sector reader retained by the kernel's persistent-root broker.
///
/// The callback is deliberately read-only.  The NVMe driver remains the
/// authority for hardware ownership while this storage layer supplies the
/// filesystem parser and path contract to Linux syscalls.
pub type RootSectorReader = fn(u64, &mut [u8; SECTOR_BYTES]) -> Result<(), BlockError>;

#[derive(Clone, Copy)]
struct PersistentRoot {
    filesystem: Ext4ReadOnly,
    sector_count: u64,
    reader: RootSectorReader,
}

static PERSISTENT_ROOT: SpinLock<Option<PersistentRoot>> = SpinLock::new(None);

/// Publish exactly one validated persistent root for the running kernel.
///
/// The filesystem has already been probed through the same callback-backed
/// device before this function is called.  Replacing a live root is refused;
/// a reboot or an explicit teardown must establish a new storage authority.
pub fn publish_persistent_root(
    filesystem: Ext4ReadOnly,
    sector_count: u64,
    reader: RootSectorReader,
) -> Result<(), Ext4Error> {
    if sector_count == 0 {
        return Err(Ext4Error::InvalidGeometry);
    }
    let mut root = PERSISTENT_ROOT.lock();
    if root.is_some() {
        return Err(Ext4Error::Capacity);
    }
    *root = Some(PersistentRoot {
        filesystem,
        sector_count,
        reader,
    });
    Ok(())
}

pub fn persistent_root_present() -> bool {
    PERSISTENT_ROOT.lock().is_some()
}

pub fn persistent_root_metadata(path: &[u8]) -> Result<Ext4Metadata, Ext4Error> {
    let root = PERSISTENT_ROOT
        .lock()
        .as_ref()
        .copied()
        .ok_or(Ext4Error::NotFound)?;
    let mut device = CallbackBlockDevice {
        sectors: root.sector_count,
        reader: root.reader,
    };
    root.filesystem.metadata(&mut device, path)
}

pub fn persistent_root_read(
    path: &[u8],
    offset: u64,
    output: &mut [u8],
) -> Result<usize, Ext4Error> {
    let root = PERSISTENT_ROOT
        .lock()
        .as_ref()
        .copied()
        .ok_or(Ext4Error::NotFound)?;
    let mut device = CallbackBlockDevice {
        sectors: root.sector_count,
        reader: root.reader,
    };
    root.filesystem.read_file(&mut device, path, offset, output)
}

struct CallbackBlockDevice {
    sectors: u64,
    reader: RootSectorReader,
}

impl BlockDevice for CallbackBlockDevice {
    fn sector_count(&self) -> u64 {
        self.sectors
    }

    fn read_sector(&mut self, lba: u64, sector: &mut [u8; SECTOR_BYTES]) -> Result<(), BlockError> {
        if lba >= self.sectors {
            return Err(BlockError::InvalidSector);
        }
        (self.reader)(lba, sector)
    }

    fn write_sector(&mut self, _lba: u64, _sector: &[u8; SECTOR_BYTES]) -> Result<(), BlockError> {
        Err(BlockError::WriteFailure)
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        Err(BlockError::FlushFailure)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Ext4Inode {
    number: u32,
    mode: u16,
    flags: u32,
    size_bytes: u64,
    block_map: [u8; 60],
}

impl Ext4Inode {
    fn kind(self) -> Ext4NodeKind {
        match self.mode & 0xf000 {
            0x4000 => Ext4NodeKind::Directory,
            0x8000 => Ext4NodeKind::File,
            0xa000 => Ext4NodeKind::Symlink,
            _ => Ext4NodeKind::Other,
        }
    }

    fn metadata(self) -> Ext4Metadata {
        Ext4Metadata {
            inode: self.number,
            size_bytes: self.size_bytes,
            kind: self.kind(),
        }
    }
}

/// A checked, read-only ext4 superblock view.
///
/// This type owns no device reference.  Callers may therefore retain the
/// validated geometry while serializing individual reads through a live NVMe
/// controller or a test block device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ext4ReadOnly {
    block_size: u32,
    blocks_count: u64,
    blocks_per_group: u32,
    inodes_count: u32,
    inodes_per_group: u32,
    inode_size: u16,
    group_count: u32,
    group_descriptor_size: u16,
    group_descriptor_start: u64,
    first_data_block: u32,
    feature_incompat: u32,
}

const EXT4_SUPERBLOCK_OFFSET: u64 = 1024;
const EXT4_SUPERBLOCK_BYTES: usize = 256;
const EXT4_MAGIC: u16 = 0xef53;
const EXT4_EXTENTS_FLAG: u32 = 0x0008_0000;
const EXT4_INCOMPAT_FILETYPE: u32 = 0x0002;
const EXT4_INCOMPAT_EXTENTS: u32 = 0x0040;
const EXT4_INCOMPAT_64BIT: u32 = 0x0080;
const EXT4_INCOMPAT_FLEX_BG: u32 = 0x0200;
const EXT4_INCOMPAT_RESERVED: u32 =
    EXT4_INCOMPAT_FILETYPE | EXT4_INCOMPAT_EXTENTS | EXT4_INCOMPAT_64BIT | EXT4_INCOMPAT_FLEX_BG;
const EXT4_RO_COMPAT_GDT_CSUM: u32 = 0x0010;
const EXT4_RO_COMPAT_METADATA_CSUM: u32 = 0x0400;
const EXT4_RO_COMPAT_BIGALLOC: u32 = 0x0200;
const EXT4_RO_COMPAT_QUOTA: u32 = 0x0100;
const EXT4_RO_COMPAT_SHARED_BLOCKS: u32 = 0x4000;
const EXT4_RO_COMPAT_VERITY: u32 = 0x8000;
const EXT4_RO_COMPAT_ORPHAN_PRESENT: u32 = 0x1_0000;
const EXT4_EXTENT_HEADER_MAGIC: u16 = 0xf30a;
const EXT4_EXTENT_UNWRITTEN: u16 = 0x8000;
const EXT4_EXTENT_ENTRY_BYTES: usize = 12;
const EXT4_MAXIMUM_BLOCK_SIZE: usize = 4096;
const EXT4_MAXIMUM_EXTENT_DEPTH: u16 = 5;
const EXT4_ROOT_INODE: u32 = 2;
const EXT4_MAXIMUM_PATH_BYTES: usize = 4096;
const EXT4_MAXIMUM_SYMLINK_DEPTH: usize = 8;
const EXT4_SCRATCH_BLOCKS: usize = EXT4_MAXIMUM_EXTENT_DEPTH as usize + 3;

struct Ext4Scratch {
    blocks: [[u8; EXT4_MAXIMUM_BLOCK_SIZE]; EXT4_SCRATCH_BLOCKS],
}

impl Ext4Scratch {
    const EMPTY: Self = Self {
        blocks: [[0; EXT4_MAXIMUM_BLOCK_SIZE]; EXT4_SCRATCH_BLOCKS],
    };

    fn block(&mut self, index: usize) -> Result<&mut [u8; EXT4_MAXIMUM_BLOCK_SIZE], Ext4Error> {
        self.blocks.get_mut(index).ok_or(Ext4Error::Capacity)
    }
}

static EXT4_SCRATCH: SpinLock<Ext4Scratch> = SpinLock::new(Ext4Scratch::EMPTY);

impl Ext4ReadOnly {
    /// Validate an ext4 superblock and its bounded geometry without mutating
    /// the device or trusting any unchecked on-disk offset.
    pub fn probe<D: BlockDevice + ?Sized>(device: &mut D) -> Result<Self, Ext4Error> {
        let mut superblock = [0_u8; EXT4_SUPERBLOCK_BYTES];
        read_bytes(device, EXT4_SUPERBLOCK_OFFSET, &mut superblock)?;
        if read_u16(&superblock, 0x38) != EXT4_MAGIC {
            return Err(Ext4Error::CorruptMetadata);
        }

        let log_block_size = read_u32(&superblock, 0x18);
        if log_block_size > 2 {
            return Err(Ext4Error::UnsupportedFeature);
        }
        let block_size = 1024_u32
            .checked_shl(log_block_size)
            .ok_or(Ext4Error::InvalidGeometry)?;
        if !(SECTOR_BYTES as u32..=EXT4_MAXIMUM_BLOCK_SIZE as u32).contains(&block_size)
            || block_size % SECTOR_BYTES as u32 != 0
        {
            return Err(Ext4Error::UnsupportedFeature);
        }

        let feature_incompat = read_u32(&superblock, 0x60);
        if feature_incompat & !EXT4_INCOMPAT_RESERVED != 0 {
            return Err(Ext4Error::UnsupportedFeature);
        }
        // The checksum and journal-recovery paths are intentionally not
        // guessed at.  Arach will admit a filesystem only after its metadata
        // is independently verifiable, never merely because ext4 recognizes
        // the feature bits.
        let feature_ro_compat = read_u32(&superblock, 0x64);
        if feature_ro_compat
            & (EXT4_RO_COMPAT_GDT_CSUM
                | EXT4_RO_COMPAT_METADATA_CSUM
                | EXT4_RO_COMPAT_BIGALLOC
                | EXT4_RO_COMPAT_QUOTA
                | EXT4_RO_COMPAT_SHARED_BLOCKS
                | EXT4_RO_COMPAT_VERITY
                | EXT4_RO_COMPAT_ORPHAN_PRESENT)
            != 0
        {
            return Err(Ext4Error::UnsupportedFeature);
        }

        let blocks_lo = u64::from(read_u32(&superblock, 0x04));
        let blocks_hi = if feature_incompat & EXT4_INCOMPAT_64BIT != 0 {
            u64::from(read_u32(&superblock, 0x150))
        } else {
            0
        };
        let blocks_count = blocks_lo | (blocks_hi << 32);
        let first_data_block = read_u32(&superblock, 0x14);
        let blocks_per_group = read_u32(&superblock, 0x20);
        let inodes_count = read_u32(&superblock, 0x00);
        let inodes_per_group = read_u32(&superblock, 0x28);
        let inode_size = read_u16(&superblock, 0x58);
        if blocks_count == 0
            || inodes_count < EXT4_ROOT_INODE
            || blocks_per_group == 0
            || inodes_per_group == 0
            || !inode_size.is_power_of_two()
            || !(128..=256).contains(&inode_size)
        {
            return Err(Ext4Error::InvalidGeometry);
        }
        let group_count = blocks_count
            .checked_sub(u64::from(first_data_block))
            .ok_or(Ext4Error::InvalidGeometry)?
            .checked_add(u64::from(blocks_per_group) - 1)
            .ok_or(Ext4Error::Capacity)?
            / u64::from(blocks_per_group);
        let group_count = u32::try_from(group_count).map_err(|_| Ext4Error::Capacity)?;
        if group_count == 0 {
            return Err(Ext4Error::InvalidGeometry);
        }
        let group_descriptor_size = match read_u16(&superblock, 0xfe) {
            0 => 32,
            value if (32..=64).contains(&value) && value.is_power_of_two() => value,
            _ => return Err(Ext4Error::UnsupportedFeature),
        };
        if feature_incompat & EXT4_INCOMPAT_64BIT != 0 && group_descriptor_size < 64 {
            return Err(Ext4Error::CorruptMetadata);
        }
        let group_descriptor_start = if block_size == 1024 { 2 } else { 1 };
        let total_bytes = device
            .sector_count()
            .checked_mul(SECTOR_BYTES as u64)
            .ok_or(Ext4Error::Capacity)?;
        let filesystem_bytes = blocks_count
            .checked_mul(u64::from(block_size))
            .ok_or(Ext4Error::Capacity)?;
        if filesystem_bytes > total_bytes
            || u64::from(first_data_block) >= blocks_count
            || u64::from(group_descriptor_start) >= blocks_count
        {
            return Err(Ext4Error::InvalidGeometry);
        }
        let filesystem = Self {
            block_size,
            blocks_count,
            blocks_per_group,
            inodes_count,
            inodes_per_group,
            inode_size,
            group_count,
            group_descriptor_size,
            group_descriptor_start,
            first_data_block,
            feature_incompat,
        };
        // The root inode is part of the mount contract.  Reject a volume that
        // advertises ext4 but cannot provide a valid root directory now.
        let mut scratch = EXT4_SCRATCH.lock();
        let root = filesystem.read_inode(device, EXT4_ROOT_INODE, &mut scratch)?;
        if root.kind() != Ext4NodeKind::Directory {
            return Err(Ext4Error::CorruptMetadata);
        }
        Ok(filesystem)
    }

    pub const fn block_size(&self) -> u32 {
        self.block_size
    }

    pub const fn blocks_count(&self) -> u64 {
        self.blocks_count
    }

    pub const fn feature_incompat(&self) -> u32 {
        self.feature_incompat
    }

    /// Resolve a normalized absolute path to ext4 metadata.
    pub fn metadata<D: BlockDevice + ?Sized>(
        &self,
        device: &mut D,
        path: &[u8],
    ) -> Result<Ext4Metadata, Ext4Error> {
        let mut scratch = EXT4_SCRATCH.lock();
        Ok(self.lookup(device, path, &mut scratch)?.metadata())
    }

    /// Read a regular file at an explicit byte offset.  Sparse extents are
    /// returned as zeroes; unwritten extents are never exposed as data.
    pub fn read_file<D: BlockDevice + ?Sized>(
        &self,
        device: &mut D,
        path: &[u8],
        offset: u64,
        output: &mut [u8],
    ) -> Result<usize, Ext4Error> {
        let mut scratch = EXT4_SCRATCH.lock();
        let inode = self.lookup(device, path, &mut scratch)?;
        self.read_inode_contents(device, inode, offset, output, &mut scratch)
    }

    fn read_inode_contents<D: BlockDevice + ?Sized>(
        &self,
        device: &mut D,
        inode: Ext4Inode,
        offset: u64,
        output: &mut [u8],
        scratch: &mut Ext4Scratch,
    ) -> Result<usize, Ext4Error> {
        if inode.kind() != Ext4NodeKind::File && inode.kind() != Ext4NodeKind::Symlink {
            return Err(Ext4Error::NotFile);
        }
        if offset >= inode.size_bytes || output.is_empty() {
            return Ok(0);
        }
        // ext4 stores short symlinks directly in the inode's 60-byte block
        // map. Avoid interpreting those bytes as block numbers.
        if inode.kind() == Ext4NodeKind::Symlink && inode.size_bytes <= 60 {
            let start = usize::try_from(offset).map_err(|_| Ext4Error::Capacity)?;
            let requested = output
                .len()
                .min(usize::try_from(inode.size_bytes).unwrap_or(usize::MAX) - start);
            output[..requested].copy_from_slice(&inode.block_map[start..start + requested]);
            return Ok(requested);
        }
        let remaining = inode.size_bytes - offset;
        let requested = output
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let mut copied = 0_usize;
        let block_size = self.block_size as usize;
        while copied < requested {
            let absolute = offset
                .checked_add(copied as u64)
                .ok_or(Ext4Error::Capacity)?;
            let logical = absolute / u64::from(self.block_size);
            let within = (absolute % u64::from(self.block_size)) as usize;
            let take = (block_size - within).min(requested - copied);
            let physical = self.map_block(device, inode, logical, scratch, 1)?;
            let block = scratch.block(0)?;
            block[..block_size].fill(0);
            if let Some(physical) = physical {
                self.read_block(device, physical, block)?;
            }
            output[copied..copied + take].copy_from_slice(&block[within..within + take]);
            copied += take;
        }
        Ok(copied)
    }

    fn lookup<D: BlockDevice + ?Sized>(
        &self,
        device: &mut D,
        path: &[u8],
        scratch: &mut Ext4Scratch,
    ) -> Result<Ext4Inode, Ext4Error> {
        if path.is_empty() || path.len() > EXT4_MAXIMUM_PATH_BYTES || path[0] != b'/' {
            return Err(Ext4Error::InvalidPath);
        }
        let mut active = [0_u8; EXT4_MAXIMUM_PATH_BYTES];
        active[..path.len()].copy_from_slice(path);
        let mut active_len = path.len();
        for _ in 0..=EXT4_MAXIMUM_SYMLINK_DEPTH {
            let mut inode = self.read_inode(device, EXT4_ROOT_INODE, scratch)?;
            let mut cursor = 0_usize;
            loop {
                let before = cursor;
                let Some(component) = next_component(&active[..active_len], &mut cursor)? else {
                    return Ok(inode);
                };
                let component_start = before
                    + active[before..active_len]
                        .iter()
                        .take_while(|byte| **byte == b'/')
                        .count();
                if component == b"." {
                    continue;
                }
                if inode.kind() != Ext4NodeKind::Directory {
                    return Err(Ext4Error::NotDirectory);
                }
                let child = self.find_directory_entry(device, inode, component, scratch)?;
                inode = self.read_inode(device, child, scratch)?;
                if inode.kind() != Ext4NodeKind::Symlink {
                    continue;
                }

                let mut target = [0_u8; EXT4_MAXIMUM_PATH_BYTES];
                let target_len =
                    self.read_inode_contents(device, inode, 0, &mut target, scratch)?;
                if target_len == 0 {
                    return Err(Ext4Error::InvalidPath);
                }
                let parent_len = if component_start <= 1 {
                    1
                } else {
                    component_start - 1
                };
                let suffix = &active[cursor..active_len];
                let mut combined = [0_u8; EXT4_MAXIMUM_PATH_BYTES];
                let mut combined_len = 0_usize;
                if target[0] != b'/' {
                    combined[..parent_len].copy_from_slice(&active[..parent_len]);
                    combined_len = parent_len;
                    if combined_len > 1 && combined[combined_len - 1] != b'/' {
                        combined[combined_len] = b'/';
                        combined_len += 1;
                    }
                }
                let target_end = combined_len
                    .checked_add(target_len)
                    .ok_or(Ext4Error::Capacity)?;
                if target_end > combined.len() {
                    return Err(Ext4Error::Capacity);
                }
                combined[combined_len..target_end].copy_from_slice(&target[..target_len]);
                combined_len = target_end;
                let suffix_end = combined_len
                    .checked_add(suffix.len())
                    .ok_or(Ext4Error::Capacity)?;
                if suffix_end > combined.len() {
                    return Err(Ext4Error::Capacity);
                }
                combined[combined_len..suffix_end].copy_from_slice(suffix);
                let normalized_len = normalize_path(&combined[..suffix_end], &mut active)?;
                active_len = normalized_len;
                break;
            }
        }
        Err(Ext4Error::InvalidPath)
    }

    fn read_inode<D: BlockDevice + ?Sized>(
        &self,
        device: &mut D,
        inode_number: u32,
        scratch: &mut Ext4Scratch,
    ) -> Result<Ext4Inode, Ext4Error> {
        if inode_number == 0 || inode_number > self.inodes_count {
            return Err(Ext4Error::NotFound);
        }
        let zero_based = u64::from(inode_number - 1);
        let group = zero_based / u64::from(self.inodes_per_group);
        let index = zero_based % u64::from(self.inodes_per_group);
        if group >= u64::from(self.group_count) {
            return Err(Ext4Error::CorruptMetadata);
        }
        let descriptor = self.group_descriptor(device, group, scratch)?;
        let byte_offset = index
            .checked_mul(u64::from(self.inode_size))
            .ok_or(Ext4Error::Capacity)?;
        let block = descriptor
            .checked_add(byte_offset / u64::from(self.block_size))
            .ok_or(Ext4Error::Capacity)?;
        let offset = usize::try_from(byte_offset % u64::from(self.block_size))
            .map_err(|_| Ext4Error::Capacity)?;
        let bytes = scratch.block(0)?;
        self.read_block(device, block, bytes)?;
        let inode_size = usize::from(self.inode_size);
        if offset
            .checked_add(inode_size)
            .is_none_or(|end| end > self.block_size as usize)
        {
            return Err(Ext4Error::CorruptMetadata);
        }
        let raw = &bytes[offset..offset + inode_size];
        let mut block_map = [0_u8; 60];
        block_map.copy_from_slice(&raw[40..100]);
        let size_lo = u64::from(read_u32(raw, 4));
        let size_hi = if inode_size >= 112 {
            u64::from(read_u32(raw, 108))
        } else {
            0
        };
        Ok(Ext4Inode {
            number: inode_number,
            mode: read_u16(raw, 0),
            flags: read_u32(raw, 32),
            size_bytes: size_lo | (size_hi << 32),
            block_map,
        })
    }

    fn group_descriptor<D: BlockDevice + ?Sized>(
        &self,
        device: &mut D,
        group: u64,
        scratch: &mut Ext4Scratch,
    ) -> Result<u64, Ext4Error> {
        let descriptor_offset = group
            .checked_mul(u64::from(self.group_descriptor_size))
            .ok_or(Ext4Error::Capacity)?;
        let block = self
            .group_descriptor_start
            .checked_add(descriptor_offset / u64::from(self.block_size))
            .ok_or(Ext4Error::Capacity)?;
        let offset = usize::try_from(descriptor_offset % u64::from(self.block_size))
            .map_err(|_| Ext4Error::Capacity)?;
        let bytes = scratch.block(1)?;
        self.read_block(device, block, bytes)?;
        let descriptor_size = usize::from(self.group_descriptor_size);
        if offset
            .checked_add(descriptor_size)
            .is_none_or(|end| end > self.block_size as usize)
        {
            return Err(Ext4Error::CorruptMetadata);
        }
        let raw = &bytes[offset..offset + descriptor_size];
        let low = u64::from(read_u32(raw, 8));
        let high = if descriptor_size >= 64 {
            u64::from(read_u32(raw, 40))
        } else {
            0
        };
        let inode_table = low | (high << 32);
        if inode_table < u64::from(self.first_data_block) || inode_table >= self.blocks_count {
            return Err(Ext4Error::CorruptMetadata);
        }
        Ok(inode_table)
    }

    fn find_directory_entry<D: BlockDevice + ?Sized>(
        &self,
        device: &mut D,
        directory: Ext4Inode,
        wanted: &[u8],
        scratch: &mut Ext4Scratch,
    ) -> Result<u32, Ext4Error> {
        let mut block_number = 0_u64;
        while block_number
            .checked_mul(u64::from(self.block_size))
            .is_some_and(|offset| offset < directory.size_bytes)
        {
            let physical = self.map_block(device, directory, block_number, scratch, 2)?;
            let block = scratch.block(1)?;
            block[..self.block_size as usize].fill(0);
            if let Some(physical) = physical {
                self.read_block(device, physical, block)?;
            }
            let mut offset = 0_usize;
            let block_size = self.block_size as usize;
            while offset < block_size {
                if block_size - offset < 8 {
                    return Err(Ext4Error::CorruptMetadata);
                }
                let inode = read_u32(&block[..], offset);
                let record_length = usize::from(read_u16(&block[..], offset + 4));
                let name_length = usize::from(block[offset + 6]);
                if record_length < 8
                    || record_length % 4 != 0
                    || record_length > block_size - offset
                    || name_length > record_length - 8
                {
                    return Err(Ext4Error::CorruptMetadata);
                }
                if inode != 0
                    && name_length == wanted.len()
                    && &block[offset + 8..offset + 8 + name_length] == wanted
                {
                    return Ok(inode);
                }
                offset += record_length;
            }
            block_number += 1;
        }
        Err(Ext4Error::NotFound)
    }

    fn map_block<D: BlockDevice + ?Sized>(
        &self,
        device: &mut D,
        inode: Ext4Inode,
        logical: u64,
        scratch: &mut Ext4Scratch,
        scratch_slot: usize,
    ) -> Result<Option<u64>, Ext4Error> {
        if inode.flags & EXT4_EXTENTS_FLAG == 0 {
            if logical < 12 {
                let block = u64::from(read_u32(&inode.block_map, logical as usize * 4));
                return Ok((block != 0).then_some(block));
            }
            return Err(Ext4Error::UnsupportedFeature);
        }
        scratch.block(scratch_slot)?[..60].copy_from_slice(&inode.block_map);
        self.map_extent_node(device, logical, 0, scratch, scratch_slot)
    }

    fn map_extent_node<D: BlockDevice + ?Sized>(
        &self,
        device: &mut D,
        logical: u64,
        level: u16,
        scratch: &mut Ext4Scratch,
        scratch_slot: usize,
    ) -> Result<Option<u64>, Ext4Error> {
        let (entries, maximum, depth) = {
            let node = scratch.block(scratch_slot)?;
            if read_u16(node, 0) != EXT4_EXTENT_HEADER_MAGIC || level > EXT4_MAXIMUM_EXTENT_DEPTH {
                return Err(Ext4Error::CorruptMetadata);
            }
            (
                usize::from(read_u16(node, 2)),
                usize::from(read_u16(node, 4)),
                read_u16(node, 6),
            )
        };
        if entries == 0 || entries > maximum || entries > (EXT4_MAXIMUM_BLOCK_SIZE - 12) / 12 {
            return Err(Ext4Error::CorruptMetadata);
        }
        if depth == 0 {
            for index in 0..entries {
                let offset = 12 + index * EXT4_EXTENT_ENTRY_BYTES;
                let (first, raw_length, physical_high, physical_low) = {
                    let node = scratch.block(scratch_slot)?;
                    (
                        u64::from(read_u32(node, offset)),
                        read_u16(node, offset + 4),
                        read_u16(node, offset + 6),
                        read_u32(node, offset + 8),
                    )
                };
                let length = u64::from(raw_length & !EXT4_EXTENT_UNWRITTEN);
                if length == 0 {
                    return Err(Ext4Error::CorruptMetadata);
                }
                let end = first.checked_add(length).ok_or(Ext4Error::Capacity)?;
                if logical >= first && logical < end {
                    if raw_length & EXT4_EXTENT_UNWRITTEN != 0 {
                        return Ok(None);
                    }
                    let physical = (u64::from(physical_high) << 32) | u64::from(physical_low);
                    let physical = physical
                        .checked_add(logical - first)
                        .ok_or(Ext4Error::Capacity)?;
                    if physical >= self.blocks_count {
                        return Err(Ext4Error::CorruptMetadata);
                    }
                    return Ok(Some(physical));
                }
            }
            return Ok(None);
        }
        if depth != level + 1 {
            return Err(Ext4Error::CorruptMetadata);
        }
        let selected = {
            let node = scratch.block(scratch_slot)?;
            let mut selected = None;
            for index in 0..entries {
                let offset = 12 + index * EXT4_EXTENT_ENTRY_BYTES;
                let first = u64::from(read_u32(node, offset));
                if first <= logical {
                    selected = Some(offset);
                } else {
                    break;
                }
            }
            selected
        };
        let Some(offset) = selected else {
            return Ok(None);
        };
        let child_slot = scratch_slot.checked_add(1).ok_or(Ext4Error::Capacity)?;
        let child = {
            let node = scratch.block(scratch_slot)?;
            (u64::from(read_u16(node, offset + 8)) << 32) | u64::from(read_u32(node, offset + 4))
        };
        {
            let child_node = scratch.block(child_slot)?;
            self.read_block(device, child, child_node)?;
        }
        self.map_extent_node(device, logical, level + 1, scratch, child_slot)
    }

    fn read_block<D: BlockDevice + ?Sized>(
        &self,
        device: &mut D,
        block: u64,
        output: &mut [u8; EXT4_MAXIMUM_BLOCK_SIZE],
    ) -> Result<(), Ext4Error> {
        if block >= self.blocks_count {
            return Err(Ext4Error::CorruptMetadata);
        }
        let offset = block
            .checked_mul(u64::from(self.block_size))
            .ok_or(Ext4Error::Capacity)?;
        output[..self.block_size as usize].fill(0);
        read_bytes(device, offset, &mut output[..self.block_size as usize])
    }
}

fn next_component<'path>(
    path: &'path [u8],
    cursor: &mut usize,
) -> Result<Option<&'path [u8]>, Ext4Error> {
    while *cursor < path.len() && path[*cursor] == b'/' {
        *cursor += 1;
    }
    if *cursor == path.len() {
        return Ok(None);
    }
    let begin = *cursor;
    while *cursor < path.len() && path[*cursor] != b'/' {
        *cursor += 1;
    }
    let component = &path[begin..*cursor];
    if component.is_empty() || component.len() > 255 {
        return Err(Ext4Error::InvalidPath);
    }
    Ok(Some(component))
}

fn normalize_path(
    path: &[u8],
    output: &mut [u8; EXT4_MAXIMUM_PATH_BYTES],
) -> Result<usize, Ext4Error> {
    if path.is_empty() || path[0] != b'/' {
        return Err(Ext4Error::InvalidPath);
    }
    output[0] = b'/';
    let mut output_len = 1_usize;
    let mut cursor = 0_usize;
    while let Some(component) = next_component(path, &mut cursor)? {
        if component == b"." {
            continue;
        }
        if component == b".." {
            if output_len > 1 {
                output_len -= 1;
                while output_len > 1 && output[output_len - 1] != b'/' {
                    output_len -= 1;
                }
            }
            continue;
        }
        let separator = usize::from(output_len > 1);
        let end = output_len
            .checked_add(separator)
            .and_then(|value| value.checked_add(component.len()))
            .ok_or(Ext4Error::Capacity)?;
        if end > output.len() {
            return Err(Ext4Error::Capacity);
        }
        if separator != 0 {
            output[output_len] = b'/';
            output_len += 1;
        }
        output[output_len..end].copy_from_slice(component);
        output_len = end;
    }
    Ok(output_len)
}

fn read_bytes<D: BlockDevice + ?Sized>(
    device: &mut D,
    offset: u64,
    output: &mut [u8],
) -> Result<(), Ext4Error> {
    let device_bytes = device
        .sector_count()
        .checked_mul(SECTOR_BYTES as u64)
        .ok_or(Ext4Error::Capacity)?;
    let output_len = u64::try_from(output.len()).map_err(|_| Ext4Error::Capacity)?;
    if offset > device_bytes || output_len > device_bytes - offset {
        return Err(Ext4Error::InvalidGeometry);
    }
    let mut copied = 0_usize;
    let mut sector = [0_u8; SECTOR_BYTES];
    while copied < output.len() {
        let absolute = offset
            .checked_add(copied as u64)
            .ok_or(Ext4Error::Capacity)?;
        let lba = absolute / SECTOR_BYTES as u64;
        let within = (absolute % SECTOR_BYTES as u64) as usize;
        device.read_sector(lba, &mut sector)?;
        let take = (SECTOR_BYTES - within).min(output.len() - copied);
        output[copied..copied + take].copy_from_slice(&sector[within..within + take]);
        copied += take;
    }
    Ok(())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    bytes[offset..offset + N].try_into().unwrap()
}

struct Crc32 {
    value: u32,
}

impl Crc32 {
    const fn new() -> Self {
        Self { value: u32::MAX }
    }

    fn update(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.value ^= u32::from(*byte);
            for _ in 0..8 {
                let mask = 0_u32.wrapping_sub(self.value & 1);
                self.value = (self.value >> 1) ^ (0xedb8_8320 & mask);
            }
        }
    }

    const fn finish(self) -> u32 {
        !self.value
    }
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = Crc32::new();
    crc.update(bytes);
    crc.finish()
}

/// Fixed-size block storage used by host tests and driver bring-up.
#[cfg(test)]
pub struct MemoryBlockDevice<const SECTORS: usize> {
    sectors: [[u8; SECTOR_BYTES]; SECTORS],
}

#[cfg(test)]
impl<const SECTORS: usize> MemoryBlockDevice<SECTORS> {
    pub const fn new() -> Self {
        Self {
            sectors: [[0; SECTOR_BYTES]; SECTORS],
        }
    }

    pub fn sector_mut(&mut self, lba: usize) -> Option<&mut [u8; SECTOR_BYTES]> {
        self.sectors.get_mut(lba)
    }
}

#[cfg(test)]
impl<const SECTORS: usize> BlockDevice for MemoryBlockDevice<SECTORS> {
    fn sector_count(&self) -> u64 {
        SECTORS as u64
    }

    fn read_sector(&mut self, lba: u64, sector: &mut [u8; SECTOR_BYTES]) -> Result<(), BlockError> {
        let source = self
            .sectors
            .get(lba as usize)
            .ok_or(BlockError::InvalidSector)?;
        *sector = *source;
        Ok(())
    }

    fn write_sector(&mut self, lba: u64, sector: &[u8; SECTOR_BYTES]) -> Result<(), BlockError> {
        let target = self
            .sectors
            .get_mut(lba as usize)
            .ok_or(BlockError::InvalidSector)?;
        *target = *sector;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TYPE_GUID: [u8; 16] = [1; 16];
    const UNIQUE_GUID: [u8; 16] = [2; 16];

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn ext4_disk() -> MemoryBlockDevice<128> {
        let mut disk = MemoryBlockDevice::new();
        // A small, deliberately ordinary ext4 geometry: 4 KiB blocks, one
        // group, a 128-byte inode, and extent-backed root/file inodes.
        let superblock = disk.sector_mut(2).unwrap();
        put_u32(superblock, 0x00, 8);
        put_u32(superblock, 0x04, 16);
        put_u32(superblock, 0x14, 0);
        put_u32(superblock, 0x18, 2);
        put_u32(superblock, 0x20, 16);
        put_u32(superblock, 0x28, 8);
        put_u16(superblock, 0x38, EXT4_MAGIC);
        put_u16(superblock, 0x58, 128);
        put_u32(
            superblock,
            0x60,
            EXT4_INCOMPAT_FILETYPE | EXT4_INCOMPAT_EXTENTS,
        );
        put_u16(superblock, 0xfe, 32);

        // Block group descriptor table, block 1: inode table starts at block 2.
        let descriptor = disk.sector_mut(8).unwrap();
        put_u32(descriptor, 8, 2);

        fn put_extent(inode: &mut [u8], physical_block: u32) {
            put_u16(inode, 0, 0x41ed); // directory mode is overwritten below for files
            put_u32(inode, 32, EXT4_EXTENTS_FLAG);
            put_u16(inode, 40, EXT4_EXTENT_HEADER_MAGIC);
            put_u16(inode, 42, 1);
            put_u16(inode, 44, 4);
            put_u16(inode, 46, 0);
            put_u32(inode, 52, 0);
            put_u16(inode, 56, 1);
            put_u16(inode, 58, 0);
            put_u32(inode, 60, physical_block);
        }

        // Inode 2 (root directory) and inode 3 (/hello), in block 2.
        let inode_table = disk.sector_mut(16).unwrap();
        let root = &mut inode_table[128..256];
        put_extent(root, 3);
        put_u32(root, 4, 4096);
        let file = &mut inode_table[256..384];
        put_extent(file, 4);
        put_u16(file, 0, 0x81a4);
        put_u32(file, 4, 22);

        // Root directory entries: '.', '..', and 'hello'.
        let directory = disk.sector_mut(24).unwrap();
        put_u32(directory, 0, 2);
        put_u16(directory, 4, 12);
        directory[6] = 1;
        directory[7] = 2;
        directory[8] = b'.';
        put_u32(directory, 12, 2);
        put_u16(directory, 16, 12);
        directory[18] = 2;
        directory[19] = 2;
        directory[20..22].copy_from_slice(b"..");
        put_u32(directory, 24, 3);
        put_u16(directory, 28, 4072);
        directory[30] = 5;
        directory[31] = 1;
        directory[32..37].copy_from_slice(b"hello");

        disk.sector_mut(32).unwrap()[..22].copy_from_slice(b"Arach persistent root\n");
        disk
    }

    fn valid_disk() -> MemoryBlockDevice<64> {
        let mut disk = MemoryBlockDevice::new();
        let entries_crc = {
            let entries = disk.sector_mut(2).unwrap();
            entries[..16].copy_from_slice(&TYPE_GUID);
            entries[16..32].copy_from_slice(&UNIQUE_GUID);
            put_u64(entries, 32, 34);
            put_u64(entries, 40, 47);
            entries[56..58].copy_from_slice(&(b'A' as u16).to_le_bytes());
            entries[58..60].copy_from_slice(&(b'r' as u16).to_le_bytes());
            entries[60..62].copy_from_slice(&(b'a' as u16).to_le_bytes());
            entries[62..64].copy_from_slice(&(b'c' as u16).to_le_bytes());
            entries[64..66].copy_from_slice(&(b'h' as u16).to_le_bytes());
            entries[66..68].copy_from_slice(&(b'O' as u16).to_le_bytes());
            entries[68..70].copy_from_slice(&(b'S' as u16).to_le_bytes());
            let mut crc = Crc32::new();
            crc.update(entries);
            // Eight entries occupy two sectors. The second sector is all
            // zeroes, exercising the streaming parser's final-sector path.
            crc.update(&[0; SECTOR_BYTES]);
            crc.finish()
        };

        let mut header = [0_u8; SECTOR_BYTES];
        header[..8].copy_from_slice(&GPT_SIGNATURE);
        put_u32(&mut header, 8, GPT_REVISION_1_0);
        put_u32(&mut header, 12, GPT_HEADER_BYTES as u32);
        put_u64(&mut header, 0x18, GPT_HEADER_LBA);
        put_u64(&mut header, 0x20, 63);
        put_u64(&mut header, 0x28, 34);
        put_u64(&mut header, 0x30, 62);
        header[56..72].copy_from_slice(&[3; 16]);
        put_u64(&mut header, 72, 2);
        put_u32(&mut header, 80, 8);
        put_u32(&mut header, 84, GPT_PARTITION_ENTRY_BYTES as u32);
        put_u32(&mut header, 88, entries_crc);
        let header_crc = {
            let mut for_crc = header;
            for_crc[16..20].fill(0);
            crc32(&for_crc[..GPT_HEADER_BYTES])
        };
        put_u32(&mut header, 16, header_crc);
        *disk.sector_mut(1).unwrap() = header;
        disk
    }

    #[test]
    fn parses_checked_gpt_partition() {
        let mut disk = valid_disk();
        let table = GptTable::parse(&mut disk).unwrap();
        assert_eq!(table.disk_guid, [3; 16]);
        assert_eq!(table.partitions().len(), 1);
        let partition = table.partition(0).unwrap();
        assert_eq!(partition.index, 0);
        assert_eq!(partition.first_lba, 34);
        assert_eq!(partition.last_lba, 47);
        assert_eq!(partition.sector_count(), 14);
        assert_eq!(
            partition.name(),
            &[
                b'A' as u16,
                b'r' as u16,
                b'a' as u16,
                b'c' as u16,
                b'h' as u16,
                b'O' as u16,
                b'S' as u16
            ]
        );
    }

    #[test]
    fn rejects_header_crc_corruption() {
        let mut disk = valid_disk();
        disk.sector_mut(1).unwrap()[32] ^= 1;
        assert_eq!(GptTable::parse(&mut disk), Err(BlockError::CorruptMetadata));
    }

    #[test]
    fn rejects_partition_crc_corruption() {
        let mut disk = valid_disk();
        disk.sector_mut(2).unwrap()[0] ^= 1;
        assert_eq!(GptTable::parse(&mut disk), Err(BlockError::CorruptMetadata));
    }

    #[test]
    fn partition_view_translates_and_bounds_io() {
        let mut disk = MemoryBlockDevice::<8>::new();
        let mut view = PartitionView::new(&mut disk, 2, 3).unwrap();
        let mut sector = [0_u8; SECTOR_BYTES];
        sector[0] = 0x5a;
        view.write_sector(1, &sector).unwrap();
        sector.fill(0);
        view.read_sector(1, &mut sector).unwrap();
        assert_eq!(sector[0], 0x5a);
        assert_eq!(
            view.read_sector(3, &mut sector),
            Err(BlockError::InvalidSector)
        );
        assert!(matches!(
            PartitionView::new(&mut disk, 7, 2),
            Err(BlockError::InvalidGeometry)
        ));
    }

    #[test]
    fn device_rejects_out_of_range_sector() {
        let mut disk = MemoryBlockDevice::<2>::new();
        let sector = [0_u8; SECTOR_BYTES];
        assert_eq!(
            disk.write_sector(2, &sector),
            Err(BlockError::InvalidSector)
        );
    }

    #[test]
    fn probes_ext4_and_reads_a_persistent_file() {
        let mut disk = ext4_disk();
        let filesystem = Ext4ReadOnly::probe(&mut disk).unwrap();
        assert_eq!(filesystem.block_size(), 4096);
        assert_eq!(filesystem.blocks_count(), 16);
        let metadata = filesystem.metadata(&mut disk, b"/hello").unwrap();
        assert_eq!(metadata.inode, 3);
        assert_eq!(metadata.kind, Ext4NodeKind::File);
        assert_eq!(metadata.size_bytes, 22);
        let mut contents = [0_u8; 22];
        assert_eq!(
            filesystem
                .read_file(&mut disk, b"/hello", 0, &mut contents)
                .unwrap(),
            22
        );
        assert_eq!(&contents, b"Arach persistent root\n");
    }

    #[test]
    fn rejects_an_unsupported_ext4_incompatibility() {
        let mut disk = ext4_disk();
        put_u32(disk.sector_mut(2).unwrap(), 0x60, 0x8000);
        assert_eq!(
            Ext4ReadOnly::probe(&mut disk),
            Err(Ext4Error::UnsupportedFeature)
        );
    }
}
