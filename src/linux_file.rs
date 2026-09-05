//! Bounded Linux regular-file open objects backed by Akashic VFS.
//!
//! `linux_fd` assigns the public descriptor number. This module's private
//! backend handle remains separate from the Akashic capability token and bound
//! to one exact PID generation. The table is fixed-capacity and
//! allocation-free.

use crate::akashic_vfs::{self, FileRangeSnapshot, NodeKind, Stat, VfsError};
use crate::linux_eventfd::{READY_IN, READY_OUT};
use crate::process::lifecycle::ProcessHandle;
use crate::storage::{self, Ext4Error, Ext4NodeKind};
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
/// Paths below these directories are eligible for the installed-root reader.
/// Device, process, runtime, and temporary namespaces remain owned by their
/// dedicated kernel backends; probing the disk for those paths would add
/// needless I/O to every early-manager lookup.
fn persistent_path_candidate(path: &[u8]) -> bool {
    path == b"/bin"
        || path.starts_with(b"/bin/")
        || path == b"/etc"
        || path.starts_with(b"/etc/")
        || path == b"/home"
        || path.starts_with(b"/home/")
        || path == b"/lib"
        || path.starts_with(b"/lib/")
        || path == b"/opt"
        || path.starts_with(b"/opt/")
        || path == b"/root"
        || path.starts_with(b"/root/")
        || path == b"/sbin"
        || path.starts_with(b"/sbin/")
        || path == b"/usr"
        || path.starts_with(b"/usr/")
        || path == b"/var"
        || path.starts_with(b"/var/")
}

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

fn persistent_error(error: Ext4Error) -> FileError {
    let vfs = match error {
        Ext4Error::NotDirectory => VfsError::NotDirectory,
        Ext4Error::NotFile => VfsError::NotFile,
        Ext4Error::NotFound => VfsError::NotFound,
        Ext4Error::InvalidPath => VfsError::InvalidPath,
        Ext4Error::Capacity => VfsError::Capacity,
        Ext4Error::UnsupportedFeature
        | Ext4Error::CorruptMetadata
        | Ext4Error::InvalidGeometry
        | Ext4Error::Io(_) => VfsError::Unsupported,
    };
    FileError::Vfs(vfs)
}

fn ensure_persistent_parents(path: &[u8], now: u64) -> Result<(), FileError> {
    for (index, byte) in path.iter().enumerate().skip(1) {
        if *byte != b'/' {
            continue;
        }
        let parent = &path[..index];
        match akashic_vfs::mkdir(parent, now) {
            Ok(()) | Err(VfsError::AlreadyExists) => {}
            Err(error) => return Err(FileError::Vfs(error)),
        }
    }
    Ok(())
}

/// Copy one small persistent-root file into the bounded VFS namespace.  This
/// bridge is intentionally capped: larger executables must use the future
/// direct block-backed file backend rather than being truncated or accepted
/// as complete.
fn materialize_persistent_path(
    owner: ProcessHandle,
    path: &[u8],
    metadata: storage::Ext4Metadata,
    now: u64,
) -> Result<(), FileError> {
    ensure_persistent_parents(path, now)?;
    if metadata.kind == Ext4NodeKind::Directory {
        return match akashic_vfs::mkdir(path, now) {
            Ok(()) | Err(VfsError::AlreadyExists) => Ok(()),
            Err(error) => Err(FileError::Vfs(error)),
        };
    }
    if metadata.kind != Ext4NodeKind::File
        || metadata.size_bytes > akashic_vfs::MAXIMUM_FILE_BYTES as u64
    {
        return Err(FileError::Vfs(VfsError::FileTooLarge));
    }
    let seed_flags = akashic_vfs::flags::READ_INTENT
        | akashic_vfs::flags::WRITE_INTENT
        | akashic_vfs::flags::CREATE_INTENT
        | akashic_vfs::flags::EXCLUSIVE;
    let token = akashic_vfs::open(owner, path, seed_flags, now)?;
    let mut result = Ok(());
    let mut offset = 0_u64;
    let mut chunk = [0_u8; 4096];
    while offset < metadata.size_bytes {
        let requested = core::cmp::min(chunk.len() as u64, metadata.size_bytes - offset) as usize;
        match storage::persistent_root_read(path, offset, &mut chunk[..requested]) {
            Ok(0) => {
                result = Err(FileError::Vfs(VfsError::Unsupported));
                break;
            }
            Ok(bytes) => match akashic_vfs::write(owner, token, &chunk[..bytes], now) {
                Ok(written) if written == bytes => offset += bytes as u64,
                Ok(_) => {
                    result = Err(FileError::Vfs(VfsError::Unsupported));
                    break;
                }
                Err(error) => {
                    result = Err(FileError::Vfs(error));
                    break;
                }
            },
            Err(error) => {
                result = Err(persistent_error(error));
                break;
            }
        }
    }
    let close_result = akashic_vfs::close(owner, token);
    if result.is_ok() {
        close_result.map_err(FileError::from)
    } else {
        let _ = close_result;
        result
    }
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

    let capability = match akashic_vfs::open(owner, path, mapped, now) {
        Ok(capability) => capability,
        Err(VfsError::NotFound) => {
            if persistent_path_candidate(path)
                && let Ok(metadata) = storage::persistent_root_metadata(path)
            {
                if flags & O_ACCMODE != O_RDONLY || flags & (O_TRUNC | O_APPEND) != 0 {
                    return Err(FileError::Vfs(VfsError::PermissionDenied));
                }
                if flags & O_EXCL != 0 {
                    return Err(FileError::Vfs(VfsError::AlreadyExists));
                }
                materialize_persistent_path(owner, path, metadata, now)?;
                akashic_vfs::open(owner, path, mapped, now)?
            } else {
                let Some(contents) = crate::linux_mount::default_file_contents(path) else {
                    return Err(FileError::Vfs(VfsError::NotFound));
                };
                // Seed a read-only-opened pseudo-file through a temporary
                // read/write capability, then reopen it with the caller's exact
                // flags so its cursor starts at byte zero.
                let seed_flags = akashic_vfs::flags::READ_INTENT
                    | akashic_vfs::flags::WRITE_INTENT
                    | akashic_vfs::flags::CREATE_INTENT
                    | akashic_vfs::flags::EXCLUSIVE;
                let seed = akashic_vfs::open(owner, path, seed_flags, now)?;
                if let Err(error) = akashic_vfs::write(owner, seed, contents, now)
                    .and_then(|_| akashic_vfs::close(owner, seed).map(|()| contents.len()))
                {
                    let _ = akashic_vfs::close(owner, seed);
                    return Err(FileError::Vfs(error));
                }
                akashic_vfs::open(owner, path, mapped, now)?
            }
        }
        Err(error) => return Err(FileError::Vfs(error)),
    };
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

/// Takes a position-independent file snapshot through a descriptor owned by
/// this exact process generation. The descriptor cursor is left unchanged.
pub fn snapshot_range(
    owner: ProcessHandle,
    fd: u32,
    offset: usize,
    output: &mut [u8],
) -> Result<FileRangeSnapshot, FileError> {
    let slot = slot_for(owner, fd)?;
    akashic_vfs::read_handle_range_snapshot(owner, slot.capability, offset, output)
        .map_err(FileError::from)
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
    match akashic_vfs::stat(path) {
        Ok(stat) => Ok(stat),
        Err(VfsError::NotFound) => {
            let Some(contents) = crate::linux_mount::default_file_contents(path) else {
                return Err(FileError::Vfs(VfsError::NotFound));
            };
            // Cgroup-v2 control files are materialized lazily on first open;
            // expose their file identity to metadata probes in the meantime.
            Ok(Stat {
                size_bytes: contents.len() as u64,
                created_ticks: 0,
                modified_ticks: 0,
                flags: 0,
                kind: NodeKind::File,
            })
        }
        Err(error) => Err(FileError::Vfs(error)),
    }
}

pub fn readdir(owner: ProcessHandle, fd: u32) -> Result<Option<akashic_vfs::Dirent>, FileError> {
    let slot = slot_for(owner, fd)?;
    akashic_vfs::readdir(owner, slot.capability).map_err(FileError::from)
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

pub fn close_on_exec(owner: ProcessHandle) -> usize {
    if owner.pid == 0 || owner.generation == 0 {
        return 0;
    }
    let mut table = FILES.lock();
    let mut closed = 0;
    for slot in table.iter_mut() {
        if slot.occupied() && slot.owner == owner && slot.linux_flags & O_CLOEXEC != 0 {
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
    const EXEC_OWNER: ProcessHandle = ProcessHandle {
        pid: 0x4105,
        generation: 7,
    };
    const SNAPSHOT_OWNER: ProcessHandle = ProcessHandle {
        pid: 0x4106,
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
    fn descriptor_snapshot_preserves_cursor_and_access_mode() {
        let path = b"/linux-file-snapshot";
        let fd = open(SNAPSHOT_OWNER, path, O_CREAT | O_EXCL | O_RDWR, 1).unwrap();
        assert_eq!(write(SNAPSHOT_OWNER, fd, b"mapped-bytes", 2), Ok(12));
        assert_eq!(
            seek(SNAPSHOT_OWNER, fd, 3, akashic_vfs::seek::FROM_START),
            Ok(3)
        );
        let mut snapshot = [0_u8; 6];
        let range = snapshot_range(SNAPSHOT_OWNER, fd, 1, &mut snapshot).unwrap();
        assert_ne!(range.inode_id, 0);
        assert_eq!(range.file_bytes, 12);
        assert_eq!(range.bytes, 6);
        assert_eq!(&snapshot, b"apped-");
        let mut current = [0_u8; 1];
        assert_eq!(read(SNAPSHOT_OWNER, fd, &mut current), Ok(1));
        assert_eq!(current, [b'p']);
        close(SNAPSHOT_OWNER, fd).unwrap();

        let write_only = open(SNAPSHOT_OWNER, path, O_WRONLY, 3).unwrap();
        assert_eq!(
            snapshot_range(SNAPSHOT_OWNER, write_only, 0, &mut snapshot),
            Err(FileError::Vfs(VfsError::PermissionDenied))
        );
        close(SNAPSHOT_OWNER, write_only).unwrap();
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

    #[test]
    fn exec_closes_only_flagged_regular_files() {
        let flagged_path = b"/linux-file-exec-flagged";
        let retained_path = b"/linux-file-exec-retained";
        let flagged = open(
            EXEC_OWNER,
            flagged_path,
            O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC,
            1,
        )
        .unwrap();
        let retained = open(EXEC_OWNER, retained_path, O_CREAT | O_EXCL | O_RDWR, 1).unwrap();
        assert_eq!(close_on_exec(EXEC_OWNER), 1);
        assert!(!is_open(EXEC_OWNER, flagged));
        assert!(is_open(EXEC_OWNER, retained));
        close(EXEC_OWNER, retained).unwrap();
        unlink(flagged_path).unwrap();
        unlink(retained_path).unwrap();
    }
}
