//! Bounded anonymous Linux memory-file descriptions.
//!
//! Metadata and generation-safe descriptor ownership live here. Physical
//! pages are owned by the process runtime so every `MAP_SHARED` alias resolves
//! to the same frames even after the last public descriptor closes.

use crate::linux_eventfd::{READY_IN, READY_OUT};
use crate::process::lifecycle::ProcessHandle;
use crate::sync::SpinLock;

pub const MFD_CLOEXEC: u32 = 0x0001;
pub const MFD_ALLOW_SEALING: u32 = 0x0002;
pub const MFD_ALLOWED_FLAGS: u32 = MFD_CLOEXEC | MFD_ALLOW_SEALING;
pub const MAXIMUM_MEMFD_NAME_BYTES: usize = 249;
pub const MAXIMUM_MEMFD_BYTES: usize = 1024 * 1024;

const MAXIMUM_MEMFDS: usize = 32;
const INDEX_BITS: u32 = 6;
const INDEX_MASK: u32 = (1 << INDEX_BITS) - 1;
const MAXIMUM_GENERATION: u32 = u32::MAX >> INDEX_BITS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemfdError {
    InvalidArgument,
    BadFileDescriptor,
    Capacity,
    PermissionDenied,
    OperationNotSupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemfdSnapshot {
    pub identity: u32,
    pub size_bytes: usize,
    pub flags: u32,
    pub name_length: u8,
    pub name: [u8; MAXIMUM_MEMFD_NAME_BYTES],
}

#[derive(Clone, Copy)]
struct MemfdSlot {
    occupied: bool,
    generation: u32,
    owner: ProcessHandle,
    flags: u32,
    name_length: u8,
    name: [u8; MAXIMUM_MEMFD_NAME_BYTES],
    size_bytes: usize,
    offset: usize,
}

impl MemfdSlot {
    const EMPTY: Self = Self {
        occupied: false,
        generation: 0,
        owner: ProcessHandle {
            pid: 0,
            generation: 0,
        },
        flags: 0,
        name_length: 0,
        name: [0; MAXIMUM_MEMFD_NAME_BYTES],
        size_bytes: 0,
        offset: 0,
    };
}

static MEMFDS: SpinLock<[MemfdSlot; MAXIMUM_MEMFDS]> =
    SpinLock::new([MemfdSlot::EMPTY; MAXIMUM_MEMFDS]);

fn valid_owner(owner: ProcessHandle) -> bool {
    owner.pid != 0 && owner.generation != 0
}

fn encode(index: usize, generation: u32) -> Option<u32> {
    if index >= MAXIMUM_MEMFDS || generation == 0 || generation > MAXIMUM_GENERATION {
        return None;
    }
    Some((generation << INDEX_BITS) | (index as u32 + 1))
}

fn decode(handle: u32) -> Option<(usize, u32)> {
    let encoded_index = handle & INDEX_MASK;
    let generation = handle >> INDEX_BITS;
    if encoded_index == 0 || generation == 0 {
        return None;
    }
    let index = (encoded_index - 1) as usize;
    (index < MAXIMUM_MEMFDS).then_some((index, generation))
}

fn resolve(
    slots: &[MemfdSlot; MAXIMUM_MEMFDS],
    owner: ProcessHandle,
    handle: u32,
) -> Result<(usize, MemfdSlot), MemfdError> {
    let (index, generation) = decode(handle).ok_or(MemfdError::BadFileDescriptor)?;
    let slot = slots[index];
    if !slot.occupied || slot.generation != generation || slot.owner != owner {
        return Err(MemfdError::BadFileDescriptor);
    }
    Ok((index, slot))
}

pub fn create(owner: ProcessHandle, name: &[u8], flags: u32) -> Result<u32, MemfdError> {
    if !valid_owner(owner)
        || name.len() > MAXIMUM_MEMFD_NAME_BYTES
        || name.contains(&0)
        || flags & !MFD_ALLOWED_FLAGS != 0
    {
        return Err(MemfdError::InvalidArgument);
    }
    let (index, handle) = {
        let mut slots = MEMFDS.lock();
        let index = slots
            .iter()
            .position(|slot| !slot.occupied)
            .ok_or(MemfdError::Capacity)?;
        let generation = slots[index]
            .generation
            .checked_add(1)
            .filter(|generation| *generation <= MAXIMUM_GENERATION)
            .ok_or(MemfdError::Capacity)?;
        let handle = encode(index, generation).ok_or(MemfdError::Capacity)?;
        let mut slot = MemfdSlot {
            occupied: true,
            generation,
            owner,
            flags,
            name_length: name.len() as u8,
            ..MemfdSlot::EMPTY
        };
        slot.name[..name.len()].copy_from_slice(name);
        slots[index] = slot;
        (index, handle)
    };
    #[cfg(target_os = "none")]
    if crate::process::runtime::linux_shared_memory_create(handle).is_err() {
        let mut slots = MEMFDS.lock();
        let generation = slots[index].generation;
        slots[index] = MemfdSlot {
            generation,
            ..MemfdSlot::EMPTY
        };
        return Err(MemfdError::Capacity);
    }
    #[cfg(not(target_os = "none"))]
    let _ = index;
    Ok(handle)
}

pub fn truncate(owner: ProcessHandle, handle: u32, size_bytes: usize) -> Result<(), MemfdError> {
    if size_bytes > MAXIMUM_MEMFD_BYTES {
        return Err(MemfdError::InvalidArgument);
    }
    let (index, current) = {
        let slots = MEMFDS.lock();
        resolve(&slots, owner, handle)?
    };
    #[cfg(target_os = "none")]
    crate::process::runtime::linux_shared_memory_resize(handle, current.size_bytes, size_bytes)
        .map_err(|_| MemfdError::OperationNotSupported)?;
    let mut slots = MEMFDS.lock();
    let (_, observed) = resolve(&slots, owner, handle)?;
    if observed.size_bytes != current.size_bytes {
        return Err(MemfdError::PermissionDenied);
    }
    slots[index].size_bytes = size_bytes;
    slots[index].offset = slots[index].offset.min(size_bytes);
    Ok(())
}

pub fn seek(
    owner: ProcessHandle,
    handle: u32,
    offset: i64,
    whence: u32,
) -> Result<u64, MemfdError> {
    let mut slots = MEMFDS.lock();
    let (index, slot) = resolve(&slots, owner, handle)?;
    let base = match whence {
        0 => 0_i128,
        1 => slot.offset as i128,
        2 => slot.size_bytes as i128,
        _ => return Err(MemfdError::InvalidArgument),
    };
    let next = base
        .checked_add(i128::from(offset))
        .filter(|value| *value >= 0 && *value <= usize::MAX as i128)
        .ok_or(MemfdError::InvalidArgument)? as usize;
    slots[index].offset = next;
    Ok(next as u64)
}

pub fn snapshot(owner: ProcessHandle, handle: u32) -> Result<MemfdSnapshot, MemfdError> {
    let slots = MEMFDS.lock();
    let (_, slot) = resolve(&slots, owner, handle)?;
    Ok(MemfdSnapshot {
        identity: handle,
        size_bytes: slot.size_bytes,
        flags: slot.flags,
        name_length: slot.name_length,
        name: slot.name,
    })
}

pub fn readiness(owner: ProcessHandle, handle: u32) -> Result<u32, MemfdError> {
    let slots = MEMFDS.lock();
    resolve(&slots, owner, handle)?;
    Ok(READY_IN | READY_OUT)
}

pub fn close(owner: ProcessHandle, handle: u32) -> Result<(), MemfdError> {
    let index = {
        let slots = MEMFDS.lock();
        resolve(&slots, owner, handle)?.0
    };
    #[cfg(target_os = "none")]
    crate::process::runtime::linux_shared_memory_close(handle)
        .map_err(|_| MemfdError::PermissionDenied)?;
    let mut slots = MEMFDS.lock();
    let (_, slot) = resolve(&slots, owner, handle)?;
    slots[index] = MemfdSlot {
        generation: slot.generation,
        ..MemfdSlot::EMPTY
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: ProcessHandle = ProcessHandle {
        pid: 0x5401,
        generation: 5,
    };

    #[test]
    fn generation_bound_memfd_resizes_and_seeks_without_allocating_payload_bytes() {
        let handle = create(OWNER, b"wayland-buffer", MFD_CLOEXEC).unwrap();
        truncate(OWNER, handle, 64 * 1024).unwrap();
        assert_eq!(snapshot(OWNER, handle).unwrap().size_bytes, 64 * 1024);
        assert_eq!(seek(OWNER, handle, -4096, 2), Ok(60 * 1024));
        assert_eq!(readiness(OWNER, handle), Ok(READY_IN | READY_OUT));
        close(OWNER, handle).unwrap();
        assert_eq!(snapshot(OWNER, handle), Err(MemfdError::BadFileDescriptor));
    }

    #[test]
    fn memfd_rejects_oversized_backings_and_stale_owners() {
        let handle = create(OWNER, b"bounded", 0).unwrap();
        assert_eq!(
            truncate(OWNER, handle, MAXIMUM_MEMFD_BYTES + 1),
            Err(MemfdError::InvalidArgument)
        );
        assert_eq!(
            snapshot(
                ProcessHandle {
                    generation: OWNER.generation + 1,
                    ..OWNER
                },
                handle,
            ),
            Err(MemfdError::BadFileDescriptor)
        );
        close(OWNER, handle).unwrap();
    }
}
