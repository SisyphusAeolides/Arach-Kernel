//! Bounded native Akashic VFS.
//!
//! The first production boundary is deliberately ephemeral: it provides the
//! complete process-owned path and handle semantics needed by native services
//! without pretending that a block-backed filesystem exists. Every object is
//! fixed-capacity, every handle is bound to one PID generation, and all path
//! mutations are serialized beneath one kernel lock.

use crate::process::lifecycle::ProcessHandle;
use crate::sync::SpinLock;

pub const MAXIMUM_PATH_BYTES: usize = 255;
pub const MAXIMUM_FILE_BYTES: usize = 64 * 1024;
pub const MAXIMUM_NODES: usize = 64;
pub const MAXIMUM_HANDLES: usize = 128;

pub mod flags {
    pub const READ_INTENT: u32 = 1 << 0;
    pub const WRITE_INTENT: u32 = 1 << 1;
    pub const CREATE_INTENT: u32 = 1 << 2;
    pub const EXCLUSIVE: u32 = 1 << 3;
    pub const TRUNCATE: u32 = 1 << 4;
    pub const APPEND_ONLY: u32 = 1 << 5;
    pub const EPHEMERAL: u32 = 1 << 6;
    pub const HOLOGRAM: u32 = 1 << 7;

    pub const KNOWN: u32 = READ_INTENT
        | WRITE_INTENT
        | CREATE_INTENT
        | EXCLUSIVE
        | TRUNCATE
        | APPEND_ONLY
        | EPHEMERAL
        | HOLOGRAM;
}

pub mod seek {
    pub const FROM_START: u32 = 0;
    pub const FROM_CURRENT: u32 = 1;
    pub const FROM_END: u32 = 2;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NodeKind {
    File = 0,
    Directory = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stat {
    pub size_bytes: u64,
    pub created_ticks: u64,
    pub modified_ticks: u64,
    pub flags: u32,
    pub kind: NodeKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileSnapshot {
    pub inode_id: u32,
    pub bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileRangeSnapshot {
    pub inode_id: u32,
    pub file_bytes: usize,
    pub bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilePairSnapshot {
    pub executable: FileSnapshot,
    pub interpreter: FileSnapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Dirent {
    pub name: [u8; MAXIMUM_PATH_BYTES],
    pub name_len: u8,
    pub kind: NodeKind,
}

impl Dirent {
    pub const EMPTY: Self = Self {
        name: [0; MAXIMUM_PATH_BYTES],
        name_len: 0,
        kind: NodeKind::File,
    };

    pub fn name(&self) -> &[u8] {
        &self.name[..usize::from(self.name_len)]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VfsError {
    NotFound,
    AlreadyExists,
    PermissionDenied,
    NotDirectory,
    NotFile,
    DirectoryNotEmpty,
    InvalidPath,
    InvalidHandle,
    Capacity,
    FileTooLarge,
    Busy,
    Unsupported,
    InvalidSeek,
}

#[derive(Clone, Copy)]
struct Node<const FILE_BYTES: usize> {
    used: bool,
    kind: NodeKind,
    path: [u8; MAXIMUM_PATH_BYTES],
    path_len: u16,
    content: [u8; FILE_BYTES],
    content_len: usize,
    flags: u32,
    created_ticks: u64,
    modified_ticks: u64,
    open_count: u16,
}

impl<const FILE_BYTES: usize> Node<FILE_BYTES> {
    const EMPTY: Self = Self {
        used: false,
        kind: NodeKind::File,
        path: [0; MAXIMUM_PATH_BYTES],
        path_len: 0,
        content: [0; FILE_BYTES],
        content_len: 0,
        flags: 0,
        created_ticks: 0,
        modified_ticks: 0,
        open_count: 0,
    };

    fn root() -> Self {
        let mut root = Self::EMPTY;
        root.used = true;
        root.kind = NodeKind::Directory;
        root.path[0] = b'/';
        root.path_len = 1;
        root.flags = flags::EPHEMERAL;
        root
    }

    fn path(&self) -> &[u8] {
        &self.path[..usize::from(self.path_len)]
    }

    fn set_path(&mut self, path: &[u8]) {
        self.path.fill(0);
        self.path[..path.len()].copy_from_slice(path);
        self.path_len = path.len() as u16;
    }

    fn stat(&self) -> Stat {
        Stat {
            size_bytes: self.content_len as u64,
            created_ticks: self.created_ticks,
            modified_ticks: self.modified_ticks,
            flags: self.flags,
            kind: self.kind,
        }
    }
}

#[derive(Clone, Copy)]
struct OpenHandle {
    used: bool,
    token: u64,
    owner: ProcessHandle,
    node: u16,
    cursor: usize,
    open_flags: u32,
}

impl OpenHandle {
    const EMPTY: Self = Self {
        used: false,
        token: 0,
        owner: ProcessHandle {
            pid: 0,
            generation: 0,
        },
        node: 0,
        cursor: 0,
        open_flags: 0,
    };
}

pub struct AkashicVfs<const NODES: usize, const HANDLES: usize, const FILE_BYTES: usize> {
    nodes: [Node<FILE_BYTES>; NODES],
    handles: [OpenHandle; HANDLES],
    initialized: bool,
    next_capability: u64,
}

impl<const NODES: usize, const HANDLES: usize, const FILE_BYTES: usize>
    AkashicVfs<NODES, HANDLES, FILE_BYTES>
{
    pub const fn new() -> Self {
        Self {
            nodes: [Node::EMPTY; NODES],
            handles: [OpenHandle::EMPTY; HANDLES],
            initialized: false,
            next_capability: 1,
        }
    }

    fn ensure_initialized(&mut self) -> Result<(), VfsError> {
        if self.initialized {
            return Ok(());
        }
        if NODES == 0 {
            return Err(VfsError::Capacity);
        }
        self.nodes[0] = Node::root();
        self.initialized = true;
        Ok(())
    }

    pub fn open(
        &mut self,
        owner: ProcessHandle,
        path: &[u8],
        open_flags: u32,
        now: u64,
    ) -> Result<u64, VfsError> {
        self.ensure_initialized()?;
        validate_owner(owner)?;
        validate_path(path)?;
        validate_open_flags(open_flags)?;

        let handle_slot = self
            .handles
            .iter()
            .position(|handle| !handle.used)
            .ok_or(VfsError::Capacity)?;

        let existing = self.find_node(path);
        let node_index = match existing {
            Some(index) => {
                let node = &self.nodes[index];
                if open_flags & flags::CREATE_INTENT != 0 && open_flags & flags::EXCLUSIVE != 0 {
                    return Err(VfsError::AlreadyExists);
                }
                match node.kind {
                    NodeKind::Directory => {
                        if open_flags
                            & (flags::WRITE_INTENT
                                | flags::CREATE_INTENT
                                | flags::TRUNCATE
                                | flags::APPEND_ONLY)
                            != 0
                        {
                            return Err(VfsError::NotFile);
                        }
                    }
                    NodeKind::File => {}
                }
                index
            }
            None => {
                if open_flags & flags::CREATE_INTENT == 0 {
                    return Err(VfsError::NotFound);
                }
                self.require_parent_directory(path)?;
                self.nodes
                    .iter()
                    .position(|node| !node.used)
                    .ok_or(VfsError::Capacity)?
            }
        };

        let token = self.allocate_capability(owner, node_index, now)?;
        if existing.is_none() {
            let node = &mut self.nodes[node_index];
            *node = Node::EMPTY;
            node.used = true;
            node.kind = NodeKind::File;
            node.set_path(path);
            node.flags = flags::EPHEMERAL;
            node.created_ticks = now;
            node.modified_ticks = now;
        } else if open_flags & flags::TRUNCATE != 0 {
            let node = &mut self.nodes[node_index];
            node.content[..node.content_len].fill(0);
            node.content_len = 0;
            node.modified_ticks = now;
        }

        let node = &mut self.nodes[node_index];
        node.open_count = node.open_count.checked_add(1).ok_or(VfsError::Capacity)?;
        let cursor = if open_flags & flags::APPEND_ONLY != 0 {
            node.content_len
        } else {
            0
        };
        self.handles[handle_slot] = OpenHandle {
            used: true,
            token,
            owner,
            node: node_index as u16,
            cursor,
            open_flags,
        };
        Ok(token)
    }

    pub fn close(&mut self, owner: ProcessHandle, token: u64) -> Result<(), VfsError> {
        self.ensure_initialized()?;
        let handle_index = self.find_handle(owner, token)?;
        self.close_index(handle_index);
        Ok(())
    }

    pub fn close_all(&mut self, owner: ProcessHandle) -> usize {
        if self.ensure_initialized().is_err() {
            return 0;
        }
        let mut closed = 0;
        for index in 0..HANDLES {
            if self.handles[index].used && self.handles[index].owner == owner {
                self.close_index(index);
                closed += 1;
            }
        }
        closed
    }

    pub fn read(
        &mut self,
        owner: ProcessHandle,
        token: u64,
        output: &mut [u8],
    ) -> Result<usize, VfsError> {
        self.ensure_initialized()?;
        let handle_index = self.find_handle(owner, token)?;
        let (node_index, cursor, open_flags) = {
            let handle = self.handles[handle_index];
            (usize::from(handle.node), handle.cursor, handle.open_flags)
        };
        if open_flags & flags::READ_INTENT == 0 {
            return Err(VfsError::PermissionDenied);
        }
        let copied = {
            let node = &self.nodes[node_index];
            if node.kind != NodeKind::File {
                return Err(VfsError::NotFile);
            }
            if cursor > node.content_len {
                return Err(VfsError::InvalidSeek);
            }
            let copied = core::cmp::min(output.len(), node.content_len - cursor);
            output[..copied].copy_from_slice(&node.content[cursor..cursor + copied]);
            copied
        };
        self.handles[handle_index].cursor = cursor + copied;
        Ok(copied)
    }

    /// Copies a regular-file range through an exact generation-owned handle
    /// without changing that handle's cursor. The file identity, complete
    /// length, and copied bytes all come from the same namespace lock hold.
    pub fn read_handle_range_snapshot(
        &mut self,
        owner: ProcessHandle,
        token: u64,
        offset: usize,
        output: &mut [u8],
    ) -> Result<FileRangeSnapshot, VfsError> {
        self.ensure_initialized()?;
        let handle_index = self.find_handle(owner, token)?;
        let handle = self.handles[handle_index];
        if handle.open_flags & flags::READ_INTENT == 0 {
            return Err(VfsError::PermissionDenied);
        }
        let node_index = usize::from(handle.node);
        let node = &self.nodes[node_index];
        if node.kind != NodeKind::File {
            return Err(VfsError::NotFile);
        }
        if offset > node.content_len {
            return Err(VfsError::InvalidSeek);
        }
        let inode_id = u32::try_from(node_index + 1).map_err(|_| VfsError::Capacity)?;
        let copied = core::cmp::min(output.len(), node.content_len - offset);
        output[..copied].copy_from_slice(&node.content[offset..offset + copied]);
        Ok(FileRangeSnapshot {
            inode_id,
            file_bytes: node.content_len,
            bytes: copied,
        })
    }

    pub fn write(
        &mut self,
        owner: ProcessHandle,
        token: u64,
        input: &[u8],
        now: u64,
    ) -> Result<usize, VfsError> {
        self.ensure_initialized()?;
        let handle_index = self.find_handle(owner, token)?;
        let (node_index, cursor, open_flags) = {
            let handle = self.handles[handle_index];
            (usize::from(handle.node), handle.cursor, handle.open_flags)
        };
        if open_flags & flags::WRITE_INTENT == 0 {
            return Err(VfsError::PermissionDenied);
        }

        let end = {
            let node = &mut self.nodes[node_index];
            if node.kind != NodeKind::File {
                return Err(VfsError::NotFile);
            }
            let offset = if open_flags & flags::APPEND_ONLY != 0 {
                node.content_len
            } else {
                cursor
            };
            let end = offset
                .checked_add(input.len())
                .ok_or(VfsError::FileTooLarge)?;
            if end > FILE_BYTES {
                return Err(VfsError::FileTooLarge);
            }
            if offset > node.content_len {
                node.content[node.content_len..offset].fill(0);
            }
            node.content[offset..end].copy_from_slice(input);
            node.content_len = core::cmp::max(node.content_len, end);
            node.modified_ticks = now;
            end
        };
        self.handles[handle_index].cursor = end;
        Ok(input.len())
    }

    pub fn seek(
        &mut self,
        owner: ProcessHandle,
        token: u64,
        offset: i64,
        whence: u32,
    ) -> Result<u64, VfsError> {
        self.ensure_initialized()?;
        let handle_index = self.find_handle(owner, token)?;
        let handle = self.handles[handle_index];
        let node = &self.nodes[usize::from(handle.node)];
        if node.kind != NodeKind::File {
            return Err(VfsError::NotFile);
        }
        let base = match whence {
            seek::FROM_START => 0_i128,
            seek::FROM_CURRENT => handle.cursor as i128,
            seek::FROM_END => node.content_len as i128,
            _ => return Err(VfsError::InvalidSeek),
        };
        let next = base + i128::from(offset);
        if next < 0 || next > FILE_BYTES as i128 {
            return Err(VfsError::InvalidSeek);
        }
        self.handles[handle_index].cursor = next as usize;
        Ok(next as u64)
    }

    pub fn stat(&mut self, path: &[u8]) -> Result<Stat, VfsError> {
        self.ensure_initialized()?;
        validate_path(path)?;
        let index = self.find_node(path).ok_or(VfsError::NotFound)?;
        Ok(self.nodes[index].stat())
    }

    /// Copies one regular file from a single locked namespace snapshot.
    pub fn read_file(&mut self, path: &[u8], output: &mut [u8]) -> Result<usize, VfsError> {
        self.read_file_snapshot(path, output)
            .map(|snapshot| snapshot.bytes)
    }

    /// Copies one complete regular file and returns its namespace identity
    /// from the same locked snapshot as the bytes.
    pub fn read_file_snapshot(
        &mut self,
        path: &[u8],
        output: &mut [u8],
    ) -> Result<FileSnapshot, VfsError> {
        self.ensure_initialized()?;
        validate_path(path)?;
        let index = self.find_node(path).ok_or(VfsError::NotFound)?;
        let node = &self.nodes[index];
        if node.kind != NodeKind::File {
            return Err(VfsError::NotFile);
        }
        if output.len() < node.content_len {
            return Err(VfsError::FileTooLarge);
        }
        output[..node.content_len].copy_from_slice(&node.content[..node.content_len]);
        Ok(FileSnapshot {
            inode_id: u32::try_from(index + 1).map_err(|_| VfsError::Capacity)?,
            bytes: node.content_len,
        })
    }

    /// Copies an executable and its interpreter while holding one namespace
    /// lock. All paths, kinds, and destination capacities are checked before
    /// either output is modified.
    pub fn read_file_pair_snapshot(
        &mut self,
        executable_path: &[u8],
        interpreter_path: &[u8],
        executable_output: &mut [u8],
        interpreter_output: &mut [u8],
    ) -> Result<FilePairSnapshot, VfsError> {
        self.ensure_initialized()?;
        validate_path(executable_path)?;
        validate_path(interpreter_path)?;
        let executable_index = self.find_node(executable_path).ok_or(VfsError::NotFound)?;
        let interpreter_index = self.find_node(interpreter_path).ok_or(VfsError::NotFound)?;
        let executable = &self.nodes[executable_index];
        let interpreter = &self.nodes[interpreter_index];
        if executable.kind != NodeKind::File || interpreter.kind != NodeKind::File {
            return Err(VfsError::NotFile);
        }
        if executable_output.len() < executable.content_len
            || interpreter_output.len() < interpreter.content_len
        {
            return Err(VfsError::FileTooLarge);
        }
        let executable_inode =
            u32::try_from(executable_index + 1).map_err(|_| VfsError::Capacity)?;
        let interpreter_inode =
            u32::try_from(interpreter_index + 1).map_err(|_| VfsError::Capacity)?;
        executable_output[..executable.content_len]
            .copy_from_slice(&executable.content[..executable.content_len]);
        interpreter_output[..interpreter.content_len]
            .copy_from_slice(&interpreter.content[..interpreter.content_len]);
        Ok(FilePairSnapshot {
            executable: FileSnapshot {
                inode_id: executable_inode,
                bytes: executable.content_len,
            },
            interpreter: FileSnapshot {
                inode_id: interpreter_inode,
                bytes: interpreter.content_len,
            },
        })
    }

    pub fn stat_handle(&mut self, owner: ProcessHandle, token: u64) -> Result<Stat, VfsError> {
        self.ensure_initialized()?;
        let handle_index = self.find_handle(owner, token)?;
        let node_index = usize::from(self.handles[handle_index].node);
        Ok(self.nodes[node_index].stat())
    }

    pub fn mkdir(&mut self, path: &[u8], now: u64) -> Result<(), VfsError> {
        self.ensure_initialized()?;
        validate_path(path)?;
        if path == b"/" || self.find_node(path).is_some() {
            return Err(VfsError::AlreadyExists);
        }
        self.require_parent_directory(path)?;
        let index = self
            .nodes
            .iter()
            .position(|node| !node.used)
            .ok_or(VfsError::Capacity)?;
        let node = &mut self.nodes[index];
        *node = Node::EMPTY;
        node.used = true;
        node.kind = NodeKind::Directory;
        node.set_path(path);
        node.flags = flags::EPHEMERAL;
        node.created_ticks = now;
        node.modified_ticks = now;
        Ok(())
    }

    pub fn unlink(&mut self, path: &[u8]) -> Result<(), VfsError> {
        self.ensure_initialized()?;
        validate_path(path)?;
        if path == b"/" {
            return Err(VfsError::PermissionDenied);
        }
        let index = self.find_node(path).ok_or(VfsError::NotFound)?;
        let node = self.nodes[index];
        if node.open_count != 0 {
            return Err(VfsError::Busy);
        }
        if node.kind == NodeKind::Directory
            && self
                .nodes
                .iter()
                .any(|candidate| candidate.used && is_descendant(path, candidate.path()))
        {
            return Err(VfsError::DirectoryNotEmpty);
        }
        self.nodes[index] = Node::EMPTY;
        Ok(())
    }

    pub fn rename(&mut self, from: &[u8], to: &[u8], now: u64) -> Result<(), VfsError> {
        self.ensure_initialized()?;
        validate_path(from)?;
        validate_path(to)?;
        if from == b"/" || to == b"/" {
            return Err(VfsError::PermissionDenied);
        }
        if from == to {
            return Ok(());
        }
        let source_index = self.find_node(from).ok_or(VfsError::NotFound)?;
        self.require_parent_directory(to)?;
        let source_kind = self.nodes[source_index].kind;
        if source_kind == NodeKind::Directory && is_descendant(from, to) {
            return Err(VfsError::InvalidPath);
        }

        let target_index = self.find_node(to);
        if let Some(index) = target_index {
            let target = self.nodes[index];
            if target.open_count != 0 {
                return Err(VfsError::Busy);
            }
            if target.kind != source_kind {
                return if target.kind == NodeKind::Directory {
                    Err(VfsError::NotFile)
                } else {
                    Err(VfsError::NotDirectory)
                };
            }
            if target.kind == NodeKind::Directory
                && self
                    .nodes
                    .iter()
                    .any(|candidate| candidate.used && is_descendant(to, candidate.path()))
            {
                return Err(VfsError::DirectoryNotEmpty);
            }
        }

        for index in 0..NODES {
            if !self.nodes[index].used
                || !(self.nodes[index].path() == from
                    || is_descendant(from, self.nodes[index].path()))
            {
                continue;
            }
            let mut candidate = [0_u8; MAXIMUM_PATH_BYTES];
            let candidate_len = renamed_path(from, to, self.nodes[index].path(), &mut candidate)?;
            for other in 0..NODES {
                if other == index
                    || Some(other) == target_index
                    || !self.nodes[other].used
                    || self.nodes[other].path() == from
                    || is_descendant(from, self.nodes[other].path())
                {
                    continue;
                }
                if self.nodes[other].path() == &candidate[..candidate_len] {
                    return Err(VfsError::AlreadyExists);
                }
            }
        }

        if let Some(index) = target_index {
            self.nodes[index] = Node::EMPTY;
        }
        for index in 0..NODES {
            if !self.nodes[index].used
                || !(self.nodes[index].path() == from
                    || is_descendant(from, self.nodes[index].path()))
            {
                continue;
            }
            let old_path = self.nodes[index].path();
            let mut candidate = [0_u8; MAXIMUM_PATH_BYTES];
            let candidate_len = renamed_path(from, to, old_path, &mut candidate)?;
            self.nodes[index].set_path(&candidate[..candidate_len]);
            self.nodes[index].modified_ticks = now;
        }
        Ok(())
    }

    pub fn readdir(
        &mut self,
        owner: ProcessHandle,
        token: u64,
    ) -> Result<Option<Dirent>, VfsError> {
        self.ensure_initialized()?;
        let handle_index = self.find_handle(owner, token)?;
        let handle = self.handles[handle_index];
        let directory = self.nodes[usize::from(handle.node)];
        if directory.kind != NodeKind::Directory {
            return Err(VfsError::NotDirectory);
        }
        let mut cursor = handle.cursor;
        while cursor < NODES {
            let candidate = self.nodes[cursor];
            cursor += 1;
            if !candidate.used {
                continue;
            }
            let Some(name) = direct_child_name(directory.path(), candidate.path()) else {
                continue;
            };
            let mut entry = Dirent::EMPTY;
            entry.name[..name.len()].copy_from_slice(name);
            entry.name_len = name.len() as u8;
            entry.kind = candidate.kind;
            self.handles[handle_index].cursor = cursor;
            return Ok(Some(entry));
        }
        self.handles[handle_index].cursor = NODES;
        Ok(None)
    }

    fn find_node(&self, path: &[u8]) -> Option<usize> {
        self.nodes
            .iter()
            .position(|node| node.used && node.path() == path)
    }

    fn require_parent_directory(&self, path: &[u8]) -> Result<usize, VfsError> {
        let parent = parent_path(path).ok_or(VfsError::InvalidPath)?;
        let index = self.find_node(parent).ok_or(VfsError::NotFound)?;
        if self.nodes[index].kind != NodeKind::Directory {
            return Err(VfsError::NotDirectory);
        }
        Ok(index)
    }

    fn find_handle(&self, owner: ProcessHandle, token: u64) -> Result<usize, VfsError> {
        validate_owner(owner)?;
        if token == 0 {
            return Err(VfsError::InvalidHandle);
        }
        self.handles
            .iter()
            .position(|handle| handle.used && handle.token == token && handle.owner == owner)
            .ok_or(VfsError::InvalidHandle)
    }

    fn allocate_capability(
        &mut self,
        owner: ProcessHandle,
        node: usize,
        now: u64,
    ) -> Result<u64, VfsError> {
        for _ in 0..=HANDLES {
            self.next_capability = self.next_capability.wrapping_add(1);
            if self.next_capability == 0 {
                self.next_capability = 1;
            }
            let owner_identity = u64::from(owner.pid) << 32 | u64::from(owner.generation);
            let token = mix64(
                self.next_capability
                    ^ owner_identity.rotate_left(17)
                    ^ now.rotate_left(31)
                    ^ (node as u64).rotate_left(47),
            ) & 0x7fff_ffff_ffff_ffff;
            if token != 0
                && self
                    .handles
                    .iter()
                    .all(|handle| !handle.used || handle.token != token)
            {
                return Ok(token);
            }
        }
        Err(VfsError::Capacity)
    }

    fn close_index(&mut self, handle_index: usize) {
        let handle = self.handles[handle_index];
        if handle.used {
            let node = &mut self.nodes[usize::from(handle.node)];
            node.open_count = node.open_count.saturating_sub(1);
            self.handles[handle_index] = OpenHandle::EMPTY;
        }
    }
}

impl<const NODES: usize, const HANDLES: usize, const FILE_BYTES: usize> Default
    for AkashicVfs<NODES, HANDLES, FILE_BYTES>
{
    fn default() -> Self {
        Self::new()
    }
}

type KernelVfs = AkashicVfs<MAXIMUM_NODES, MAXIMUM_HANDLES, MAXIMUM_FILE_BYTES>;

static KERNEL_VFS: SpinLock<KernelVfs> = SpinLock::new(KernelVfs::new());

pub fn open(owner: ProcessHandle, path: &[u8], open_flags: u32, now: u64) -> Result<u64, VfsError> {
    KERNEL_VFS.lock().open(owner, path, open_flags, now)
}

pub fn close(owner: ProcessHandle, token: u64) -> Result<(), VfsError> {
    KERNEL_VFS.lock().close(owner, token)
}

pub fn close_all(owner: ProcessHandle) -> usize {
    KERNEL_VFS.lock().close_all(owner)
}

pub fn read(owner: ProcessHandle, token: u64, output: &mut [u8]) -> Result<usize, VfsError> {
    KERNEL_VFS.lock().read(owner, token, output)
}

pub fn read_handle_range_snapshot(
    owner: ProcessHandle,
    token: u64,
    offset: usize,
    output: &mut [u8],
) -> Result<FileRangeSnapshot, VfsError> {
    KERNEL_VFS
        .lock()
        .read_handle_range_snapshot(owner, token, offset, output)
}

pub fn write(owner: ProcessHandle, token: u64, input: &[u8], now: u64) -> Result<usize, VfsError> {
    KERNEL_VFS.lock().write(owner, token, input, now)
}

pub fn seek(owner: ProcessHandle, token: u64, offset: i64, whence: u32) -> Result<u64, VfsError> {
    KERNEL_VFS.lock().seek(owner, token, offset, whence)
}

pub fn stat(path: &[u8]) -> Result<Stat, VfsError> {
    KERNEL_VFS.lock().stat(path)
}

pub fn read_file(path: &[u8], output: &mut [u8]) -> Result<usize, VfsError> {
    KERNEL_VFS.lock().read_file(path, output)
}

pub fn read_file_snapshot(path: &[u8], output: &mut [u8]) -> Result<FileSnapshot, VfsError> {
    KERNEL_VFS.lock().read_file_snapshot(path, output)
}

pub fn read_file_pair_snapshot(
    executable_path: &[u8],
    interpreter_path: &[u8],
    executable_output: &mut [u8],
    interpreter_output: &mut [u8],
) -> Result<FilePairSnapshot, VfsError> {
    KERNEL_VFS.lock().read_file_pair_snapshot(
        executable_path,
        interpreter_path,
        executable_output,
        interpreter_output,
    )
}

pub fn stat_handle(owner: ProcessHandle, token: u64) -> Result<Stat, VfsError> {
    KERNEL_VFS.lock().stat_handle(owner, token)
}

pub fn mkdir(path: &[u8], now: u64) -> Result<(), VfsError> {
    KERNEL_VFS.lock().mkdir(path, now)
}

pub fn unlink(path: &[u8]) -> Result<(), VfsError> {
    KERNEL_VFS.lock().unlink(path)
}

pub fn rename(from: &[u8], to: &[u8], now: u64) -> Result<(), VfsError> {
    KERNEL_VFS.lock().rename(from, to, now)
}

pub fn readdir(owner: ProcessHandle, token: u64) -> Result<Option<Dirent>, VfsError> {
    KERNEL_VFS.lock().readdir(owner, token)
}

fn validate_owner(owner: ProcessHandle) -> Result<(), VfsError> {
    if owner.pid == 0 || owner.generation == 0 {
        Err(VfsError::PermissionDenied)
    } else {
        Ok(())
    }
}

fn validate_open_flags(open_flags: u32) -> Result<(), VfsError> {
    if open_flags & !flags::KNOWN != 0
        || open_flags & (flags::READ_INTENT | flags::WRITE_INTENT) == 0
        || open_flags & flags::EXCLUSIVE != 0 && open_flags & flags::CREATE_INTENT == 0
        || open_flags & (flags::TRUNCATE | flags::APPEND_ONLY) != 0
            && open_flags & flags::WRITE_INTENT == 0
    {
        return Err(VfsError::PermissionDenied);
    }
    if open_flags & flags::HOLOGRAM != 0 {
        return Err(VfsError::Unsupported);
    }
    Ok(())
}

fn validate_path(path: &[u8]) -> Result<(), VfsError> {
    if path.is_empty()
        || path.len() > MAXIMUM_PATH_BYTES
        || path[0] != b'/'
        || path.contains(&0)
        || core::str::from_utf8(path).is_err()
    {
        return Err(VfsError::InvalidPath);
    }
    if path == b"/" {
        return Ok(());
    }
    if path.last() == Some(&b'/') {
        return Err(VfsError::InvalidPath);
    }
    for component in path[1..].split(|byte| *byte == b'/') {
        if component.is_empty() || component == b"." || component == b".." {
            return Err(VfsError::InvalidPath);
        }
    }
    Ok(())
}

fn parent_path(path: &[u8]) -> Option<&[u8]> {
    if path == b"/" {
        return None;
    }
    let slash = path.iter().rposition(|byte| *byte == b'/')?;
    if slash == 0 {
        Some(b"/")
    } else {
        Some(&path[..slash])
    }
}

fn is_descendant(parent: &[u8], candidate: &[u8]) -> bool {
    if parent == b"/" {
        return candidate.len() > 1 && candidate[0] == b'/';
    }
    candidate.len() > parent.len()
        && candidate.starts_with(parent)
        && candidate[parent.len()] == b'/'
}

fn direct_child_name<'a>(parent: &[u8], candidate: &'a [u8]) -> Option<&'a [u8]> {
    let remainder = if parent == b"/" {
        candidate.strip_prefix(b"/")?
    } else {
        candidate.strip_prefix(parent)?.strip_prefix(b"/")?
    };
    if remainder.is_empty() || remainder.contains(&b'/') {
        None
    } else {
        Some(remainder)
    }
}

fn renamed_path(
    from: &[u8],
    to: &[u8],
    current: &[u8],
    output: &mut [u8; MAXIMUM_PATH_BYTES],
) -> Result<usize, VfsError> {
    let suffix = current.strip_prefix(from).ok_or(VfsError::InvalidPath)?;
    let length = to
        .len()
        .checked_add(suffix.len())
        .ok_or(VfsError::InvalidPath)?;
    if length > MAXIMUM_PATH_BYTES {
        return Err(VfsError::InvalidPath);
    }
    output[..to.len()].copy_from_slice(to);
    output[to.len()..length].copy_from_slice(suffix);
    Ok(length)
}

fn mix64(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestVfs = AkashicVfs<16, 16, 128>;

    fn owner(pid: u32, generation: u32) -> ProcessHandle {
        ProcessHandle { pid, generation }
    }

    #[test]
    fn files_round_trip_and_zero_fill_sparse_writes() {
        let mut vfs = TestVfs::new();
        let owner = owner(7, 3);
        let handle = vfs
            .open(
                owner,
                b"/state",
                flags::READ_INTENT | flags::WRITE_INTENT | flags::CREATE_INTENT,
                10,
            )
            .unwrap();
        assert_eq!(vfs.write(owner, handle, b"abc", 11), Ok(3));
        assert_eq!(vfs.seek(owner, handle, 5, seek::FROM_START), Ok(5));
        assert_eq!(vfs.write(owner, handle, b"z", 12), Ok(1));
        assert_eq!(vfs.seek(owner, handle, 0, seek::FROM_START), Ok(0));
        let mut output = [0xff; 8];
        assert_eq!(vfs.read(owner, handle, &mut output), Ok(6));
        assert_eq!(&output[..6], b"abc\0\0z");
        let stat = vfs.stat(b"/state").unwrap();
        assert_eq!(stat.size_bytes, 6);
        assert_eq!(stat.modified_ticks, 12);
        assert_eq!(stat.flags, flags::EPHEMERAL);
        let mut snapshot = [0_u8; 8];
        assert_eq!(vfs.read_file(b"/state", &mut snapshot), Ok(6));
        assert_eq!(
            vfs.read_file_snapshot(b"/state", &mut snapshot),
            Ok(FileSnapshot {
                inode_id: 2,
                bytes: 6,
            })
        );
        assert_eq!(&snapshot[..6], b"abc\0\0z");
    }

    #[test]
    fn handle_range_snapshot_is_generation_bound_and_cursor_stable() {
        let mut vfs = TestVfs::new();
        let exact_owner = owner(12, 4);
        let handle = vfs
            .open(
                exact_owner,
                b"/mapped",
                flags::READ_INTENT | flags::WRITE_INTENT | flags::CREATE_INTENT,
                1,
            )
            .unwrap();
        vfs.write(exact_owner, handle, b"abcdef", 2).unwrap();
        vfs.seek(exact_owner, handle, 2, seek::FROM_START).unwrap();
        let mut range = [0_u8; 3];
        assert_eq!(
            vfs.read_handle_range_snapshot(exact_owner, handle, 1, &mut range),
            Ok(FileRangeSnapshot {
                inode_id: 2,
                file_bytes: 6,
                bytes: 3,
            })
        );
        assert_eq!(&range, b"bcd");
        let mut cursor_byte = [0_u8; 1];
        assert_eq!(vfs.read(exact_owner, handle, &mut cursor_byte), Ok(1));
        assert_eq!(cursor_byte, [b'c']);

        let recycled = owner(12, 5);
        assert_eq!(
            vfs.read_handle_range_snapshot(recycled, handle, 0, &mut range),
            Err(VfsError::InvalidHandle)
        );
        vfs.close(exact_owner, handle).unwrap();

        let write_only = vfs
            .open(exact_owner, b"/mapped", flags::WRITE_INTENT, 3)
            .unwrap();
        assert_eq!(
            vfs.read_handle_range_snapshot(exact_owner, write_only, 0, &mut range),
            Err(VfsError::PermissionDenied)
        );
        vfs.close(exact_owner, write_only).unwrap();
    }

    #[test]
    fn handles_are_owned_by_exact_pid_generation() {
        let mut vfs = TestVfs::new();
        let first = owner(2, 1);
        let recycled = owner(2, 2);
        let handle = vfs
            .open(
                first,
                b"/owned",
                flags::WRITE_INTENT | flags::CREATE_INTENT,
                1,
            )
            .unwrap();
        assert_eq!(
            vfs.write(recycled, handle, b"x", 2),
            Err(VfsError::InvalidHandle)
        );
        assert_eq!(vfs.close_all(first), 1);
        assert_eq!(vfs.close(first, handle), Err(VfsError::InvalidHandle));
    }

    #[test]
    fn directories_enforce_parentage_and_bounded_iteration() {
        let mut vfs = TestVfs::new();
        let owner = owner(3, 1);
        assert_eq!(vfs.mkdir(b"/var", 1), Ok(()));
        assert_eq!(vfs.mkdir(b"/var/lib", 2), Ok(()));
        let file = vfs
            .open(
                owner,
                b"/var/config",
                flags::WRITE_INTENT | flags::CREATE_INTENT,
                3,
            )
            .unwrap();
        vfs.close(owner, file).unwrap();
        let directory = vfs.open(owner, b"/var", flags::READ_INTENT, 4).unwrap();
        let mut names = [[0_u8; MAXIMUM_PATH_BYTES]; 2];
        let mut count = 0;
        while let Some(entry) = vfs.readdir(owner, directory).unwrap() {
            names[count][..entry.name().len()].copy_from_slice(entry.name());
            count += 1;
        }
        assert_eq!(count, 2);
        assert!(names.iter().any(|name| name.starts_with(b"lib")));
        assert!(names.iter().any(|name| name.starts_with(b"config")));
        assert_eq!(vfs.unlink(b"/var"), Err(VfsError::Busy));
        vfs.close(owner, directory).unwrap();
        assert_eq!(vfs.unlink(b"/var"), Err(VfsError::DirectoryNotEmpty));
    }

    #[test]
    fn rename_replaces_closed_files_and_moves_directory_subtrees() {
        let mut vfs = TestVfs::new();
        let owner = owner(4, 1);
        vfs.mkdir(b"/a", 1).unwrap();
        vfs.mkdir(b"/b", 1).unwrap();
        let source = vfs
            .open(
                owner,
                b"/a/source",
                flags::WRITE_INTENT | flags::CREATE_INTENT,
                2,
            )
            .unwrap();
        vfs.write(owner, source, b"new", 3).unwrap();
        vfs.close(owner, source).unwrap();
        let target = vfs
            .open(
                owner,
                b"/b/target",
                flags::WRITE_INTENT | flags::CREATE_INTENT,
                4,
            )
            .unwrap();
        vfs.close(owner, target).unwrap();
        assert_eq!(vfs.rename(b"/a/source", b"/b/target", 5), Ok(()));
        assert_eq!(vfs.stat(b"/a/source"), Err(VfsError::NotFound));
        assert_eq!(vfs.stat(b"/b/target").unwrap().size_bytes, 3);

        vfs.mkdir(b"/a/tree", 6).unwrap();
        vfs.mkdir(b"/a/tree/child", 7).unwrap();
        assert_eq!(vfs.rename(b"/a/tree", b"/b/tree", 8), Ok(()));
        assert_eq!(
            vfs.stat(b"/b/tree/child").unwrap().kind,
            NodeKind::Directory
        );
        assert_eq!(
            vfs.rename(b"/b/tree", b"/b/tree/child/loop", 9),
            Err(VfsError::InvalidPath)
        );
    }

    #[test]
    fn snapshots_an_executable_pair_without_partial_output() {
        let mut vfs = TestVfs::new();
        let owner = owner(8, 1);
        for (path, contents) in [
            (&b"/dynamic"[..], &b"main-image"[..]),
            (&b"/lib-ld"[..], &b"runtime-linker"[..]),
        ] {
            let handle = vfs
                .open(owner, path, flags::WRITE_INTENT | flags::CREATE_INTENT, 1)
                .unwrap();
            vfs.write(owner, handle, contents, 2).unwrap();
            vfs.close(owner, handle).unwrap();
        }
        let mut executable = [0_u8; 32];
        let mut interpreter = [0_u8; 32];
        assert_eq!(
            vfs.read_file_pair_snapshot(
                b"/dynamic",
                b"/lib-ld",
                &mut executable,
                &mut interpreter,
            ),
            Ok(FilePairSnapshot {
                executable: FileSnapshot {
                    inode_id: 2,
                    bytes: 10,
                },
                interpreter: FileSnapshot {
                    inode_id: 3,
                    bytes: 14,
                },
            })
        );
        assert_eq!(&executable[..10], b"main-image");
        assert_eq!(&interpreter[..14], b"runtime-linker");

        let mut untouched_executable = [0x5a_u8; 32];
        let mut undersized_interpreter = [0xa5_u8; 4];
        assert_eq!(
            vfs.read_file_pair_snapshot(
                b"/dynamic",
                b"/lib-ld",
                &mut untouched_executable,
                &mut undersized_interpreter,
            ),
            Err(VfsError::FileTooLarge)
        );
        assert_eq!(untouched_executable, [0x5a; 32]);
        assert_eq!(undersized_interpreter, [0xa5; 4]);
    }

    #[test]
    fn invalid_paths_flags_and_capacity_fail_closed() {
        let mut vfs = AkashicVfs::<3, 1, 4>::new();
        let owner = owner(5, 1);
        assert_eq!(vfs.mkdir(b"relative", 1), Err(VfsError::InvalidPath));
        assert_eq!(vfs.mkdir(b"/../escape", 1), Err(VfsError::InvalidPath));
        assert_eq!(
            vfs.open(owner, b"/x", flags::HOLOGRAM | flags::READ_INTENT, 1),
            Err(VfsError::Unsupported)
        );
        let handle = vfs
            .open(owner, b"/x", flags::WRITE_INTENT | flags::CREATE_INTENT, 2)
            .unwrap();
        assert_eq!(
            vfs.write(owner, handle, b"12345", 3),
            Err(VfsError::FileTooLarge)
        );
        assert_eq!(
            vfs.open(owner, b"/y", flags::WRITE_INTENT | flags::CREATE_INTENT, 4,),
            Err(VfsError::Capacity)
        );
    }
}
