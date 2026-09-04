//! Bounded Linux API-filesystem mount namespace.
//!
//! Early Linux userspace mounts a small, fixed set of kernel-backed
//! filesystems before starting services.  Arach records those mounts with a
//! distinct device identity so path metadata observes an actual mount point.

use crate::akashic_vfs::{self, MAXIMUM_PATH_BYTES, NodeKind};
use crate::sync::SpinLock;

const MAXIMUM_MOUNTS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountError {
    AlreadyMounted,
    Capacity,
    InvalidPath,
    NotDirectory,
    NotFound,
    UnsupportedFilesystem,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Filesystem {
    Proc = 1,
    Sysfs = 2,
    Devtmpfs = 3,
    Devpts = 4,
    Tmpfs = 5,
    Cgroup2 = 6,
    Securityfs = 7,
}

impl Filesystem {
    pub fn parse(name: &[u8]) -> Result<Self, MountError> {
        match name {
            b"proc" => Ok(Self::Proc),
            b"sysfs" => Ok(Self::Sysfs),
            b"devtmpfs" => Ok(Self::Devtmpfs),
            b"devpts" => Ok(Self::Devpts),
            b"tmpfs" => Ok(Self::Tmpfs),
            b"cgroup2" => Ok(Self::Cgroup2),
            b"securityfs" => Ok(Self::Securityfs),
            _ => Err(MountError::UnsupportedFilesystem),
        }
    }
}

#[derive(Clone, Copy)]
struct Mount {
    used: bool,
    target: [u8; MAXIMUM_PATH_BYTES],
    target_len: u16,
    filesystem: Filesystem,
    device: u64,
}

impl Mount {
    const EMPTY: Self = Self {
        used: false,
        target: [0; MAXIMUM_PATH_BYTES],
        target_len: 0,
        filesystem: Filesystem::Tmpfs,
        device: 0,
    };

    fn target(&self) -> &[u8] {
        &self.target[..usize::from(self.target_len)]
    }
}

static MOUNTS: SpinLock<[Mount; MAXIMUM_MOUNTS]> = SpinLock::new([Mount::EMPTY; MAXIMUM_MOUNTS]);

pub fn mount(target: &[u8], filesystem: Filesystem) -> Result<u64, MountError> {
    if target.len() < 2 || target.len() > MAXIMUM_PATH_BYTES || target[0] != b'/' {
        return Err(MountError::InvalidPath);
    }
    match akashic_vfs::stat(target) {
        Ok(stat) if stat.kind == NodeKind::Directory => {}
        Ok(_) => return Err(MountError::NotDirectory),
        Err(akashic_vfs::VfsError::NotFound) => return Err(MountError::NotFound),
        Err(_) => return Err(MountError::InvalidPath),
    }

    let mut mounts = MOUNTS.lock();
    if mounts
        .iter()
        .any(|entry| entry.used && entry.target() == target)
    {
        return Err(MountError::AlreadyMounted);
    }
    let index = mounts
        .iter()
        .position(|entry| !entry.used)
        .ok_or(MountError::Capacity)?;
    let device = 2 + index as u64;
    let mut entry = Mount::EMPTY;
    entry.used = true;
    entry.target[..target.len()].copy_from_slice(target);
    entry.target_len = target.len() as u16;
    entry.filesystem = filesystem;
    entry.device = device;
    mounts[index] = entry;
    Ok(device)
}

pub fn device_for(path: &[u8]) -> u64 {
    let mounts = MOUNTS.lock();
    mounts
        .iter()
        .filter(|entry| entry.used && contains(entry.target(), path))
        .max_by_key(|entry| entry.target_len)
        .map_or(1, |entry| entry.device)
}

fn contains(target: &[u8], path: &[u8]) -> bool {
    path == target
        || path
            .strip_prefix(target)
            .is_some_and(|suffix| suffix.first() == Some(&b'/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_api_filesystems_are_explicit() {
        for name in [
            &b"proc"[..],
            &b"sysfs"[..],
            &b"devtmpfs"[..],
            &b"devpts"[..],
            &b"tmpfs"[..],
            &b"cgroup2"[..],
            &b"securityfs"[..],
        ] {
            assert!(Filesystem::parse(name).is_ok());
        }
        assert_eq!(
            Filesystem::parse(b"ext4"),
            Err(MountError::UnsupportedFilesystem)
        );
    }

    #[test]
    fn mount_membership_stops_at_path_boundaries() {
        assert!(contains(b"/proc", b"/proc"));
        assert!(contains(b"/proc", b"/proc/1/status"));
        assert!(!contains(b"/proc", b"/process"));
    }
}
