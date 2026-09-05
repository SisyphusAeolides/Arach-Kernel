//! Bounded block-device and GPT partition primitives.
//!
//! The Linux personality currently exposes an in-memory VFS.  This module is
//! the first persistent-storage boundary: device drivers implement
//! [`BlockDevice`], while the partition and filesystem layers can consume the
//! same checked sector interface.  No driver is assumed here, and no storage
//! is advertised as available until a driver supplies this contract.

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

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
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

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
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
}
