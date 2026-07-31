#!/usr/bin/env python3
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


def replace_region(text: str, start: str, end: str, body: str, label: str) -> str:
    first = text.find(start)
    if first < 0:
        raise SystemExit(f"{label}: start marker missing")
    second = text.find(end, first + len(start))
    if second < 0:
        raise SystemExit(f"{label}: end marker missing")
    if text.find(start, first + len(start)) >= 0:
        raise SystemExit(f"{label}: start marker is not unique")
    return text[:first] + body.rstrip() + "\n\n" + text[second:]


root = Path(__file__).resolve().parents[1]

lib_path = root / "src/lib.rs"
lib = lib_path.read_text(encoding="utf-8")
lib = replace_once(
    lib,
    "pub mod linux_epoll;\npub mod linux_eventfd;\npub mod linux_timerfd;",
    "pub mod linux_epoll;\npub mod linux_eventfd;\npub mod linux_file;\npub mod linux_timerfd;",
    "lib module declaration",
)
lib_path.write_text(lib, encoding="utf-8")

eventfd_path = root / "src/linux_eventfd.rs"
eventfd = eventfd_path.read_text(encoding="utf-8")
eventfd = replace_once(
    eventfd,
    "const EVENTFD_BASE: u32 = 3;",
    "const EVENTFD_BASE: u32 = 0x100;",
    "eventfd descriptor range",
)
eventfd_path.write_text(eventfd, encoding="utf-8")

vfs_path = root / "src/akashic_vfs.rs"
vfs = vfs_path.read_text(encoding="utf-8")
vfs = replace_once(
    vfs,
    "                if open_flags & flags::WRITE_INTENT == 0 {\n                    return Err(VfsError::PermissionDenied);\n                }\n                self.require_parent_directory(path)?;",
    "                self.require_parent_directory(path)?;",
    "read-only create semantics",
)
vfs = replace_once(
    vfs,
    "    pub fn stat(&mut self, path: &[u8]) -> Result<Stat, VfsError> {\n        self.ensure_initialized()?;\n        validate_path(path)?;\n        let index = self.find_node(path).ok_or(VfsError::NotFound)?;\n        Ok(self.nodes[index].stat())\n    }\n\n    pub fn mkdir",
    "    pub fn stat(&mut self, path: &[u8]) -> Result<Stat, VfsError> {\n        self.ensure_initialized()?;\n        validate_path(path)?;\n        let index = self.find_node(path).ok_or(VfsError::NotFound)?;\n        Ok(self.nodes[index].stat())\n    }\n\n    pub fn stat_handle(\n        &mut self,\n        owner: ProcessHandle,\n        token: u64,\n    ) -> Result<Stat, VfsError> {\n        self.ensure_initialized()?;\n        let handle_index = self.find_handle(owner, token)?;\n        let node_index = usize::from(self.handles[handle_index].node);\n        Ok(self.nodes[node_index].stat())\n    }\n\n    pub fn mkdir",
    "VFS handle stat method",
)
vfs = replace_once(
    vfs,
    "pub fn stat(path: &[u8]) -> Result<Stat, VfsError> {\n    KERNEL_VFS.lock().stat(path)\n}\n\npub fn mkdir",
    "pub fn stat(path: &[u8]) -> Result<Stat, VfsError> {\n    KERNEL_VFS.lock().stat(path)\n}\n\npub fn stat_handle(owner: ProcessHandle, token: u64) -> Result<Stat, VfsError> {\n    KERNEL_VFS.lock().stat_handle(owner, token)\n}\n\npub fn mkdir",
    "VFS handle stat wrapper",
)
vfs_path.write_text(vfs, encoding="utf-8")

linux_file_path = root / "src/linux_file.rs"
linux_file = linux_file_path.read_text(encoding="utf-8")
linux_file = replace_once(
    linux_file,
    "    fn directory_flag_and_open_flag_validation_fail_closed() {\n        assert_eq!(\n            open(OWNER, b\"/\", O_RDONLY | O_DIRECTORY, 1).map(|_| ()),\n            Ok(())\n        );\n        let root_fd = open(OWNER, b\"/\", O_RDONLY | O_DIRECTORY, 1).unwrap();",
    "    fn directory_flag_and_open_flag_validation_fail_closed() {\n        let root_fd = open(OWNER, b\"/\", O_RDONLY | O_DIRECTORY, 1).unwrap();",
    "directory test descriptor leak",
)
linux_file_path.write_text(linux_file, encoding="utf-8")

syscalls_path = root / "src/syscalls.rs"
syscalls = syscalls_path.read_text(encoding="utf-8")
syscalls = replace_once(
    syscalls,
    "const ERROR_NOT_IMPLEMENTED: isize = -38;",
    "const ERROR_NOT_IMPLEMENTED: isize = -38;\n#[cfg(target_os = \"none\")]\nconst ERROR_TOO_MANY_OPEN_FILES: isize = -24;\n#[cfg(target_os = \"none\")]\nconst ERROR_NAME_TOO_LONG: isize = -36;",
    "Linux file errno constants",
)
syscalls = replace_once(
    syscalls,
    "#[cfg(target_os = \"none\")]\nconst COM1: u16 = 0x3f8;",
    "#[cfg(target_os = \"none\")]\nconst LINUX_AT_FDCWD: i64 = -100;\n#[cfg(target_os = \"none\")]\nconst LINUX_AT_REMOVEDIR: u32 = 0x200;\n#[cfg(target_os = \"none\")]\nconst COM1: u16 = 0x3f8;",
    "Linux at constants",
)
linux_stat = '''#[cfg(any(target_os = "none", test))]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LinuxStat {
    st_dev: u64,
    st_ino: u64,
    st_nlink: u64,
    st_mode: u32,
    st_uid: u32,
    st_gid: u32,
    pad0: u32,
    st_rdev: u64,
    st_size: i64,
    st_blksize: i64,
    st_blocks: i64,
    st_atime: i64,
    st_atime_nsec: i64,
    st_mtime: i64,
    st_mtime_nsec: i64,
    st_ctime: i64,
    st_ctime_nsec: i64,
    unused: [i64; 3],
}

'''
syscalls = replace_once(
    syscalls,
    "static YIELD_HITS: AtomicUsize = AtomicUsize::new(0);",
    linux_stat + "static YIELD_HITS: AtomicUsize = AtomicUsize::new(0);",
    "Linux stat wire type",
)
syscalls = replace_once(
    syscalls,
    "    let _ = crate::akashic_vfs::close_all(exiting);",
    "    let _ = crate::linux_file::close_all(exiting);\n    let _ = crate::akashic_vfs::close_all(exiting);",
    "Linux file exit reclamation",
)
syscalls = replace_once(
    syscalls,
    "        Some(crate::process::abi::LinuxSyscall::Read) => linux_read(arguments),\n        Some(crate::process::abi::LinuxSyscall::Write) => linux_write(arguments),\n        Some(crate::process::abi::LinuxSyscall::Close) => linux_close(arguments),\n        Some(crate::process::abi::LinuxSyscall::Poll) => linux_poll(arguments),",
    "        Some(crate::process::abi::LinuxSyscall::Read) => linux_read(arguments),\n        Some(crate::process::abi::LinuxSyscall::Write) => linux_write(arguments),\n        Some(crate::process::abi::LinuxSyscall::Open) => linux_open(arguments),\n        Some(crate::process::abi::LinuxSyscall::Close) => linux_close(arguments),\n        Some(crate::process::abi::LinuxSyscall::Stat) => linux_stat(arguments),\n        Some(crate::process::abi::LinuxSyscall::Fstat) => linux_fstat(arguments),\n        Some(crate::process::abi::LinuxSyscall::Poll) => linux_poll(arguments),\n        Some(crate::process::abi::LinuxSyscall::Lseek) => linux_lseek(arguments),",
    "Linux file dispatch prefix",
)
syscalls = replace_once(
    syscalls,
    "        Some(crate::process::abi::LinuxSyscall::EpollCtl) => linux_epoll_ctl(arguments),\n        Some(_) => ERROR_NOT_IMPLEMENTED,",
    "        Some(crate::process::abi::LinuxSyscall::EpollCtl) => linux_epoll_ctl(arguments),\n        Some(crate::process::abi::LinuxSyscall::OpenAt) => linux_openat(arguments),\n        Some(crate::process::abi::LinuxSyscall::UnlinkAt) => linux_unlinkat(arguments),\n        Some(_) => ERROR_NOT_IMPLEMENTED,",
    "Linux file dispatch suffix",
)

read_body = r'''#[cfg(target_os = "none")]
fn linux_read(arguments: [u64; 6]) -> isize {
    let Ok(fd) = u32::try_from(arguments[0]) else {
        return ERROR_BAD_FILE_DESCRIPTOR;
    };
    let owner_handle = match current_akashic_owner() {
        Ok(owner) => owner,
        Err(error) => return error,
    };
    let length = core::cmp::min(arguments[2], MAXIMUM_AKASHIC_IO_BYTES as u64) as usize;
    {
        let mut staging = AKASHIC_IO_STAGING.lock();
        match crate::linux_file::read(owner_handle, fd, &mut staging[..length]) {
            Ok(copied) => {
                return if copy_to_user(arguments[1], &staging[..copied]).is_ok() {
                    copied as isize
                } else {
                    ERROR_BAD_ADDRESS
                };
            }
            Err(crate::linux_file::FileError::BadFileDescriptor) => {}
            Err(error) => return map_linux_file_error(error),
        }
    }

    if arguments[2] != core::mem::size_of::<u64>() as u64 {
        return ERROR_INVALID_ARGUMENT;
    }
    let owner = owner_handle.pid;
    match crate::linux_eventfd::read(owner, fd) {
        Ok(value) => {
            if copy_value_to_user(arguments[1], &value).is_err() {
                ERROR_BAD_ADDRESS
            } else {
                core::mem::size_of::<u64>() as isize
            }
        }
        Err(crate::linux_eventfd::EventFdError::WouldBlock) => ERROR_TRY_AGAIN,
        Err(crate::linux_eventfd::EventFdError::BadFileDescriptor) => {
            match crate::linux_timerfd::read(owner, fd, crate::interrupts::monotonic_nanoseconds()) {
                Ok(value) => {
                    if copy_value_to_user(arguments[1], &value).is_err() {
                        ERROR_BAD_ADDRESS
                    } else {
                        core::mem::size_of::<u64>() as isize
                    }
                }
                Err(crate::linux_timerfd::TimerFdError::WouldBlock) => ERROR_TRY_AGAIN,
                Err(crate::linux_timerfd::TimerFdError::BadFileDescriptor) => {
                    ERROR_BAD_FILE_DESCRIPTOR
                }
                Err(_) => ERROR_IO,
            }
        }
        Err(_) => ERROR_IO,
    }
}'''
syscalls = replace_region(
    syscalls,
    '#[cfg(target_os = "none")]\nfn linux_read(arguments: [u64; 6]) -> isize {',
    '#[cfg(target_os = "none")]\nfn linux_write(arguments: [u64; 6]) -> isize {',
    read_body,
    "Linux read implementation",
)

write_body = r'''#[cfg(target_os = "none")]
fn linux_write(arguments: [u64; 6]) -> isize {
    if arguments[0] == 1 || arguments[0] == 2 {
        return write_from_user(arguments);
    }
    let Ok(fd) = u32::try_from(arguments[0]) else {
        return ERROR_BAD_FILE_DESCRIPTOR;
    };
    let owner_handle = match current_akashic_owner() {
        Ok(owner) => owner,
        Err(error) => return error,
    };
    if crate::linux_file::is_open(owner_handle, fd) {
        let length = core::cmp::min(arguments[2], MAXIMUM_AKASHIC_IO_BYTES as u64) as usize;
        let mut staging = AKASHIC_IO_STAGING.lock();
        if copy_from_user(arguments[1], &mut staging[..length]).is_err() {
            return ERROR_BAD_ADDRESS;
        }
        return match crate::linux_file::write(
            owner_handle,
            fd,
            &staging[..length],
            crate::interrupts::monotonic_nanoseconds(),
        ) {
            Ok(written) => written as isize,
            Err(error) => map_linux_file_error(error),
        };
    }

    if arguments[2] != core::mem::size_of::<u64>() as u64 {
        return ERROR_INVALID_ARGUMENT;
    }
    let mut bytes = [0_u8; core::mem::size_of::<u64>()];
    if copy_from_user(arguments[1], &mut bytes).is_err() {
        return ERROR_BAD_ADDRESS;
    }
    let value = u64::from_ne_bytes(bytes);
    match crate::linux_eventfd::write(owner_handle.pid, fd, value) {
        Ok(()) => core::mem::size_of::<u64>() as isize,
        Err(crate::linux_eventfd::EventFdError::InvalidArgument) => ERROR_INVALID_ARGUMENT,
        Err(crate::linux_eventfd::EventFdError::Overflow) => ERROR_TRY_AGAIN,
        Err(crate::linux_eventfd::EventFdError::BadFileDescriptor) => ERROR_BAD_FILE_DESCRIPTOR,
        Err(_) => ERROR_IO,
    }
}'''
syscalls = replace_region(
    syscalls,
    '#[cfg(target_os = "none")]\nfn linux_write(arguments: [u64; 6]) -> isize {',
    '#[cfg(target_os = "none")]\nfn linux_close(arguments: [u64; 6]) -> isize {',
    write_body,
    "Linux write implementation",
)

close_and_files = r'''#[cfg(target_os = "none")]
fn linux_close(arguments: [u64; 6]) -> isize {
    let Ok(fd) = u32::try_from(arguments[0]) else {
        return ERROR_BAD_FILE_DESCRIPTOR;
    };
    let owner_handle = match current_akashic_owner() {
        Ok(owner) => owner,
        Err(error) => return error,
    };
    match crate::linux_file::close(owner_handle, fd) {
        Ok(()) => return 0,
        Err(crate::linux_file::FileError::BadFileDescriptor) => {}
        Err(error) => return map_linux_file_error(error),
    }

    let owner = owner_handle.pid;
    match crate::linux_eventfd::close(owner, fd) {
        Ok(()) => 0,
        Err(crate::linux_eventfd::EventFdError::BadFileDescriptor) => {
            match crate::linux_timerfd::close(owner, fd) {
                Ok(()) => 0,
                Err(crate::linux_timerfd::TimerFdError::BadFileDescriptor) => {
                    match crate::linux_epoll::close(owner, fd) {
                        Ok(()) => 0,
                        Err(crate::linux_epoll::EpollError::BadFileDescriptor) => {
                            ERROR_BAD_FILE_DESCRIPTOR
                        }
                        Err(_) => ERROR_IO,
                    }
                }
                Err(_) => ERROR_IO,
            }
        }
        Err(_) => ERROR_IO,
    }
}

#[cfg(target_os = "none")]
fn linux_open(arguments: [u64; 6]) -> isize {
    let Ok(flags) = u32::try_from(arguments[1]) else {
        return ERROR_INVALID_ARGUMENT;
    };
    linux_open_path(arguments[0], flags, None)
}

#[cfg(target_os = "none")]
fn linux_openat(arguments: [u64; 6]) -> isize {
    let Ok(flags) = u32::try_from(arguments[2]) else {
        return ERROR_INVALID_ARGUMENT;
    };
    linux_open_path(arguments[1], flags, Some(arguments[0] as i64))
}

#[cfg(target_os = "none")]
fn linux_open_path(pointer: u64, flags: u32, dirfd: Option<i64>) -> isize {
    let (path, length, was_absolute) = match copy_linux_path(pointer) {
        Ok(value) => value,
        Err(error) => return error,
    };
    if !was_absolute && dirfd.is_some_and(|fd| fd != LINUX_AT_FDCWD) {
        return ERROR_BAD_FILE_DESCRIPTOR;
    }
    let owner = match current_akashic_owner() {
        Ok(owner) => owner,
        Err(error) => return error,
    };
    match crate::linux_file::open(
        owner,
        &path[..length],
        flags,
        crate::interrupts::monotonic_nanoseconds(),
    ) {
        Ok(fd) => fd as isize,
        Err(error) => map_linux_file_error(error),
    }
}

#[cfg(target_os = "none")]
fn linux_stat(arguments: [u64; 6]) -> isize {
    let (path, length, _) = match copy_linux_path(arguments[0]) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let stat = match crate::linux_file::stat(&path[..length]) {
        Ok(stat) => stat,
        Err(error) => return map_linux_file_error(error),
    };
    write_linux_stat(arguments[1], stat, stable_linux_inode(&path[..length]))
}

#[cfg(target_os = "none")]
fn linux_fstat(arguments: [u64; 6]) -> isize {
    let Ok(fd) = u32::try_from(arguments[0]) else {
        return ERROR_BAD_FILE_DESCRIPTOR;
    };
    let owner = match current_akashic_owner() {
        Ok(owner) => owner,
        Err(error) => return error,
    };
    let stat = match crate::linux_file::fstat(owner, fd) {
        Ok(stat) => stat,
        Err(error) => return map_linux_file_error(error),
    };
    write_linux_stat(arguments[1], stat, u64::from(fd) + 1)
}

#[cfg(target_os = "none")]
fn linux_lseek(arguments: [u64; 6]) -> isize {
    let Ok(fd) = u32::try_from(arguments[0]) else {
        return ERROR_BAD_FILE_DESCRIPTOR;
    };
    let Ok(whence) = u32::try_from(arguments[2]) else {
        return ERROR_INVALID_ARGUMENT;
    };
    let owner = match current_akashic_owner() {
        Ok(owner) => owner,
        Err(error) => return error,
    };
    match crate::linux_file::seek(owner, fd, arguments[1] as i64, whence) {
        Ok(offset) => isize::try_from(offset).unwrap_or(isize::MAX),
        Err(error) => map_linux_file_error(error),
    }
}

#[cfg(target_os = "none")]
fn linux_unlinkat(arguments: [u64; 6]) -> isize {
    let Ok(flags) = u32::try_from(arguments[2]) else {
        return ERROR_INVALID_ARGUMENT;
    };
    if flags & !LINUX_AT_REMOVEDIR != 0 {
        return ERROR_INVALID_ARGUMENT;
    }
    let (path, length, was_absolute) = match copy_linux_path(arguments[1]) {
        Ok(value) => value,
        Err(error) => return error,
    };
    if !was_absolute && arguments[0] as i64 != LINUX_AT_FDCWD {
        return ERROR_BAD_FILE_DESCRIPTOR;
    }
    match crate::linux_file::unlink(&path[..length]) {
        Ok(()) => 0,
        Err(error) => map_linux_file_error(error),
    }
}

#[cfg(target_os = "none")]
fn copy_linux_path(
    pointer: u64,
) -> Result<([u8; crate::akashic_vfs::MAXIMUM_PATH_BYTES], usize, bool), isize> {
    if pointer == 0 {
        return Err(ERROR_BAD_ADDRESS);
    }
    let mut path = [0_u8; crate::akashic_vfs::MAXIMUM_PATH_BYTES];
    let mut length = 0_usize;
    loop {
        if length == path.len() {
            return Err(ERROR_NAME_TOO_LONG);
        }
        let address = pointer
            .checked_add(length as u64)
            .ok_or(ERROR_BAD_ADDRESS)?;
        let mut byte = [0_u8; 1];
        copy_from_user(address, &mut byte).map_err(|_| ERROR_BAD_ADDRESS)?;
        if byte[0] == 0 {
            break;
        }
        path[length] = byte[0];
        length += 1;
    }
    if length == 0 {
        return Err(ERROR_NO_ENTRY);
    }
    let was_absolute = path[0] == b'/';
    if !was_absolute {
        if length == path.len() {
            return Err(ERROR_NAME_TOO_LONG);
        }
        path.copy_within(0..length, 1);
        path[0] = b'/';
        length += 1;
    }
    Ok((path, length, was_absolute))
}

#[cfg(target_os = "none")]
fn write_linux_stat(
    destination: u64,
    stat: crate::akashic_vfs::Stat,
    inode: u64,
) -> isize {
    let (mode, links) = match stat.kind {
        crate::akashic_vfs::NodeKind::File => (0o100_644, 1),
        crate::akashic_vfs::NodeKind::Directory => (0o040_755, 2),
    };
    let seconds = core::cmp::min(stat.modified_ticks / 1_000_000_000, i64::MAX as u64) as i64;
    let nanoseconds = (stat.modified_ticks % 1_000_000_000) as i64;
    let size = core::cmp::min(stat.size_bytes, i64::MAX as u64) as i64;
    let encoded = LinuxStat {
        st_dev: 1,
        st_ino: inode.max(1),
        st_nlink: links,
        st_mode: mode,
        st_uid: 0,
        st_gid: 0,
        pad0: 0,
        st_rdev: 0,
        st_size: size,
        st_blksize: PAGE_SIZE as i64,
        st_blocks: size.saturating_add(511) / 512,
        st_atime: seconds,
        st_atime_nsec: nanoseconds,
        st_mtime: seconds,
        st_mtime_nsec: nanoseconds,
        st_ctime: seconds,
        st_ctime_nsec: nanoseconds,
        unused: [0; 3],
    };
    if copy_value_to_user(destination, &encoded).is_ok() {
        0
    } else {
        ERROR_BAD_ADDRESS
    }
}

#[cfg(target_os = "none")]
fn stable_linux_inode(path: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in path {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash.max(1)
}

#[cfg(target_os = "none")]
fn map_linux_file_error(error: crate::linux_file::FileError) -> isize {
    match error {
        crate::linux_file::FileError::InvalidArgument => ERROR_INVALID_ARGUMENT,
        crate::linux_file::FileError::BadFileDescriptor => ERROR_BAD_FILE_DESCRIPTOR,
        crate::linux_file::FileError::Capacity => ERROR_TOO_MANY_OPEN_FILES,
        crate::linux_file::FileError::Vfs(error) => map_akashic_error(error),
    }
}'''
syscalls = replace_region(
    syscalls,
    '#[cfg(target_os = "none")]\nfn linux_close(arguments: [u64; 6]) -> isize {',
    '#[cfg(target_os = "none")]\nfn linux_eventfd2(arguments: [u64; 6]) -> isize {',
    close_and_files,
    "Linux close and file operations",
)

syscalls = replace_once(
    syscalls,
    "        assert_eq!(core::mem::size_of::<LinuxUtsName>(), 390);\n        assert_eq!(core::mem::size_of::<LinuxTimespec>(), 16);",
    "        assert_eq!(core::mem::size_of::<LinuxUtsName>(), 390);\n        assert_eq!(core::mem::size_of::<LinuxTimespec>(), 16);\n        assert_eq!(core::mem::size_of::<LinuxStat>(), 144);",
    "Linux stat layout test",
)
syscalls_path.write_text(syscalls, encoding="utf-8")
