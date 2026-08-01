//! Bounded Linux regular-file descriptors backed by Akashic VFS.
//!
//! Linux descriptor numbers are deliberately separate from Akashic capability
//! tokens. Each descriptor is bound to one exact PID generation, while the
//! underlying VFS continues to enforce the process-owned capability. The table
//! is fixed-capacity and allocation-free.

use crate::akashic_vfs::{self, NodeKind, Stat, VfsError};
use crate::linux_eventfd::{READY_IN, READY_OUT};
use crate::process::lifecycle::ProcessHandle;
use crate::sync::SpinLock;

pub const O_ACCMODE: u32 = 0x3;
pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 0x1;
pub const O_RDWR: u32 = 0x2;
pub const O_CREAT: u32 = 0x40;
pub const O_EXCL: u32 = 0x80;
pub const O_TRUNC: u32 = 0x200;
pub const O_APPEND: u32 = 0x400;
pub const O_NONBLOCK: u32 = 0x800;
pub const O_LARGEFILE: u32 = 0x8000;
pub const O_DIRECTORY: u32 = 0x1_0000;
pub const O_CLOEXEC: u32 = 0x8_0000;

const ALLOWED_OPEN_FLAGS: u32 = O_ACCMODE
    | O_CREAT
    | O_EXCL
    | O_TRUNC
    | O_APPEND
    | O_NONBLOCK
    | O_LARGEFILE
    | O_DIRECTORY
    | O_CLOEXEC;

pub const MAXIMUM_FILE_DESCRIPTORS: usize = 128;
const FILE_DESCRIPTOR_BASE: u32 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileError {
    InvalidArgument,
    BadFileDescriptor,
    Capacity,
    Vfs(VfsError),
}

impl From<VfsError> for FileError {
    fn from(error: VfsError) -> Self {
        Self::Vfs(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileSlot {
    owner: ProcessHandle,
    capability: u64,
    linux_flags: u32,
}

impl FileSlot {
    const EMPTY: Self = Self {
        owner: ProcessHandle {
            pid: 0,
            generation: 0,
        },
        capability: 0,
        linux_flags: 0,
    };

    const fn occupied(self) -> bool {
        self.owner.pid != 0 && self.owner.generation != 0 && self.capability != 0
    }
}

static FILES: SpinLock<[FileSlot; MAXIMUM_FILE_DESCRIPTORS]> =
    SpinLock::new([FileSlot::EMPTY; MAXIMUM_FILE_DESCRIPTORS]);

const fn index_for_fd(fd: u32) -> Option<usize> {
    if fd < FILE_DESCRIPTOR_BASE {
        return None;
    }
    let index = (fd - FILE_DESCRIPTOR_BASE) as usize;
    if index < MAXIMUM_FILE_DESCRIPTORS {
        Some(index)
    } else {
        None
    }
}

const fn fd_for_index(index: usize) -> u32 {
    FILE_DESCRIPTOR_BASE + index as u32
}

fn mapped_open_flags(flags: u32) -> Result<(u32, bool), FileError> {
    if flags & !ALLOWED_OPEN_FLAGS != 0
        || flags & O_EXCL != 0 && flags & O_CREAT == 0
        || flags & O_DIRECTORY != 0 && flags & O_CREAT != 0
    {
        return Err(FileError::InvalidArgument);
    }

    let mut mapped = match flags & O_ACCMODE {
        O_RDONLY => akashic_vfs::flags::READ_INTENT,
        O_WRONLY => akashic_vfs::flags::WRITE_INTENT,
        O_RDWR => akashic_vfs::flags::READ_INTENT | akashic_vfs::flags::WRITE_INTENT,
        _ => return Err(FileError::InvalidArgument),
    };
    let writable = mapped & akashic_vfs::flags::WRITE_INTENT != 0;
    if flags & (O_TRUNC | O_APPEND) != 0 && !writable {
        return Err(FileError::InvalidArgument);
    }
    if flags & O_CREAT != 0 {
        mapped |= akashic_vfs::flags::CREATE_INTENT;
    }
    if flags & O_EXCL != 0 {
        mapped |= akashic_vfs::flags::EXCLUSIVE;
    }
    if flags & O_TRUNC != 0 {
        mapped |= akashic_vfs::flags::TRUNCATE;
    }
    if flags & O_APPEND != 0 {
        mapped |= akashic_vfs::flags::APPEND_ONLY;
    }
    Ok((mapped, flags & O_DIRECTORY != 0))
}

fn slot_for(owner: ProcessHandle, fd: u32) -> Result<FileSlot, FileError> {
    let index = index_for_fd(fd).ok_or(FileError::BadFileDescriptor)?;
    let table = FILES.lock();
    let slot = table[index];
    if !slot.occupied() || slot.owner != owner {
        return Err(FileError::BadFileDescriptor);
    }
    Ok(slot)
}

pub fn open(owner: ProcessHandle, path: &[u8], flags: u32, now: u64) -> Result<u32, FileError> {
    if owner.pid == 0 || owner.generation == 0 {
        return Err(FileError::InvalidArgument);
    }
    let (mapped, require_directory) = mapped_open_flags(flags)?;
    let mut table = FILES.lock();
    let Some((index, slot)) = table
        .iter_mut()
        .enumerate()
        .find(|(_, slot)| !slot.occupied())
    else {
        return Err(FileError::Capacity);
    };

    let capability = akashic_vfs::open(owner, path, mapped, now)?;
    if require_directory {
        match akashic_vfs::stat_handle(owner, capability) {
            Ok(stat) if stat.kind == NodeKind::Directory => {}
            Ok(_) => {
                let _ = akashic_vfs::close(owner, capability);
                return Err(FileError::Vfs(VfsError::NotDirectory));
            }
            Err(error) => {
                let _ = akashic_vfs::close(owner, capability);
                return Err(FileError::Vfs(error));
            }
        }
    }

    *slot = FileSlot {
        owner,
        capability,
        linux_flags: flags,
    };
    Ok(fd_for_index(index))
}

pub fn is_open(owner: ProcessHandle, fd: u32) -> bool {
    slot_for(owner, fd).is_ok()
}

pub fn read(owner: ProcessHandle, fd: u32, output: &mut [u8]) -> Result<usize, FileError> {
    let slot = slot_for(owner, fd)?;
    akashic_vfs::read(owner, slot.capability, output).map_err(FileError::from)
}

pub fn write(owner: ProcessHandle, fd: u32, input: &[u8], now: u64) -> Result<usize, FileError> {
    let slot = slot_for(owner, fd)?;
    akashic_vfs::write(owner, slot.capability, input, now).map_err(FileError::from)
}

pub fn seek(owner: ProcessHandle, fd: u32, offset: i64, whence: u32) -> Result<u64, FileError> {
    let slot = slot_for(owner, fd)?;
    akashic_vfs::seek(owner, slot.capability, offset, whence).map_err(FileError::from)
}

pub fn fstat(owner: ProcessHandle, fd: u32) -> Result<Stat, FileError> {
    let slot = slot_for(owner, fd)?;
    akashic_vfs::stat_handle(owner, slot.capability).map_err(FileError::from)
}

pub fn stat(path: &[u8]) -> Result<Stat, FileError> {
    akashic_vfs::stat(path).map_err(FileError::from)
}

pub fn unlink(path: &[u8]) -> Result<(), FileError> {
    akashic_vfs::unlink(path).map_err(FileError::from)
}

pub fn readiness(owner: ProcessHandle, fd: u32) -> Result<u32, FileError> {
    let slot = slot_for(owner, fd)?;
    let mut ready = READY_IN;
    if slot.linux_flags & O_ACCMODE != O_RDONLY {
        ready |= READY_OUT;
    }
    Ok(ready)
}

pub fn close(owner: ProcessHandle, fd: u32) -> Result<(), FileError> {
    let index = index_for_fd(fd).ok_or(FileError::BadFileDescriptor)?;
    let mut table = FILES.lock();
    let slot = table[index];
    if !slot.occupied() || slot.owner != owner {
        return Err(FileError::BadFileDescriptor);
    }
    akashic_vfs::close(owner, slot.capability)?;
    table[index] = FileSlot::EMPTY;
    Ok(())
}

pub fn close_all(owner: ProcessHandle) -> usize {
    if owner.pid == 0 || owner.generation == 0 {
        return 0;
    }
    let mut table = FILES.lock();
    let mut closed = 0;
    for slot in table.iter_mut() {
        if slot.occupied() && slot.owner == owner {
            let _ = akashic_vfs::close(owner, slot.capability);
            *slot = FileSlot::EMPTY;
            closed += 1;
        }
    }
    closed
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUND_TRIP_OWNER: ProcessHandle = ProcessHandle {
        pid: 0x4101,
        generation: 7,
    };
    const GENERATION_OWNER: ProcessHandle = ProcessHandle {
        pid: 0x4102,
        generation: 7,
    };
    const DIRECTORY_OWNER: ProcessHandle = ProcessHandle {
        pid: 0x4103,
        generation: 7,
    };
    const CLOSE_ALL_OWNER: ProcessHandle = ProcessHandle {
        pid: 0x4104,
        generation: 7,
    };

    #[test]
    fn regular_file_round_trip_uses_linux_descriptors() {
        let path = b"/linux-file-round-trip";
        let fd = open(ROUND_TRIP_OWNER, path, O_CREAT | O_EXCL | O_RDWR, 1).unwrap();
        assert!((3..3 + MAXIMUM_FILE_DESCRIPTORS as u32).contains(&fd));
        assert_eq!(write(ROUND_TRIP_OWNER, fd, b"arach", 2), Ok(5));
        assert_eq!(
            seek(ROUND_TRIP_OWNER, fd, 0, akashic_vfs::seek::FROM_START),
            Ok(0)
        );
        let mut output = [0_u8; 8];
        assert_eq!(read(ROUND_TRIP_OWNER, fd, &mut output), Ok(5));
        assert_eq!(&output[..5], b"arach");
        assert_eq!(fstat(ROUND_TRIP_OWNER, fd).unwrap().size_bytes, 5);
        close(ROUND_TRIP_OWNER, fd).unwrap();
        unlink(path).unwrap();
    }

    #[test]
    fn descriptor_ownership_includes_pid_generation() {
        let path = b"/linux-file-generation";
        let fd = open(GENERATION_OWNER, path, O_CREAT | O_EXCL | O_RDWR, 1).unwrap();
        let recycled = ProcessHandle {
            pid: GENERATION_OWNER.pid,
            generation: GENERATION_OWNER.generation + 1,
        };
        assert_eq!(
            read(recycled, fd, &mut [0_u8; 1]),
            Err(FileError::BadFileDescriptor)
        );
        assert_eq!(close(recycled, fd), Err(FileError::BadFileDescriptor));
        close(GENERATION_OWNER, fd).unwrap();
        unlink(path).unwrap();
    }

    #[test]
    fn directory_flag_and_open_flag_validation_fail_closed() {
        let root_fd = open(DIRECTORY_OWNER, b"/", O_RDONLY | O_DIRECTORY, 1).unwrap();
        assert!((3..3 + MAXIMUM_FILE_DESCRIPTORS as u32).contains(&root_fd));
        close(DIRECTORY_OWNER, root_fd).unwrap();
        assert_eq!(
            open(DIRECTORY_OWNER, b"/invalid", O_EXCL | O_RDWR, 1),
            Err(FileError::InvalidArgument)
        );
        assert_eq!(
            open(DIRECTORY_OWNER, b"/invalid", O_RDONLY | O_TRUNC, 1),
            Err(FileError::InvalidArgument)
        );
    }
    #[test]
    fn close_all_reclaims_exact_owner_descriptors() {
        let first_path = b"/linux-file-close-all-a";
        let second_path = b"/linux-file-close-all-b";
        let first = open(CLOSE_ALL_OWNER, first_path, O_CREAT | O_EXCL | O_RDWR, 1).unwrap();
        let second = open(CLOSE_ALL_OWNER, second_path, O_CREAT | O_EXCL | O_RDWR, 1).unwrap();
        assert_eq!(close_all(CLOSE_ALL_OWNER), 2);
        assert_eq!(
            close(CLOSE_ALL_OWNER, first),
            Err(FileError::BadFileDescriptor)
        );
        assert_eq!(
            close(CLOSE_ALL_OWNER, second),
            Err(FileError::BadFileDescriptor)
        );
        unlink(first_path).unwrap();
        unlink(second_path).unwrap();
    }
}
