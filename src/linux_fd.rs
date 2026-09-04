//! Unified Linux file-descriptor and open-object ownership.
//!
//! Every Linux process generation owns one bounded descriptor space. Small
//! descriptor numbers map to generation-tagged open objects, so distinct
//! backend families cannot collide and a recycled descriptor cannot revive an
//! epoll watch. Descriptor aliases, epoll references, and active operations
//! are counted separately: `dup` aliases one open object, close-on-exec is
//! descriptor local, and the last descriptor close detaches every watch
//! before that number can be reused.

use crate::akashic_vfs::{FileRangeSnapshot, NodeKind};
use crate::linux_eventfd::READY_OUT;
use crate::process::lifecycle::ProcessHandle;
use crate::sync::SpinLock;

pub const MAXIMUM_FILE_DESCRIPTORS: usize = 128;
pub const MAXIMUM_TRANSFER_DESCRIPTORS: usize = 8;
pub const FD_CLOEXEC: u32 = 1;

const MAXIMUM_DESCRIPTOR_SPACES: usize = crate::process::lifecycle::MAXIMUM_PROCESSES;
const MAXIMUM_OPEN_OBJECTS: usize = MAXIMUM_DESCRIPTOR_SPACES * MAXIMUM_FILE_DESCRIPTORS;
#[cfg(test)]
const STANDARD_OUTPUT: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorError {
    InvalidArgument,
    BadFileDescriptor,
    Capacity,
    WouldBlock,
    BrokenPipe,
    IllegalSeek,
    AlreadyExists,
    NotFound,
    AddressFamilyNotSupported,
    AddressInUse,
    ConnectionRefused,
    AlreadyConnected,
    NotConnected,
    NotSocket,
    OperationNotSupported,
    OperationNotPermitted,
    PermissionDenied,
    Io,
    File(crate::linux_file::FileError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteResult {
    Bytes(usize),
    Console,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DescriptorMetadata {
    pub mode: u32,
    pub size_bytes: u64,
    pub created_ticks: u64,
    pub modified_ticks: u64,
    pub inode: u64,
}

/// Stable identity of one open object within an exact process generation.
/// Epoll stores this key rather than a recyclable descriptor number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectKey {
    index: u16,
    generation: u32,
}

impl ObjectKey {
    pub const EMPTY: Self = Self {
        index: u16::MAX,
        generation: 0,
    };

    const fn new(index: usize, generation: u32) -> Self {
        Self {
            index: index as u16,
            generation,
        }
    }

    const fn index(self) -> Option<usize> {
        if self.generation == 0 || self.index == u16::MAX {
            None
        } else {
            Some(self.index as usize)
        }
    }

    pub const fn is_empty(self) -> bool {
        self.generation == 0 || self.index == u16::MAX
    }
}

/// One retained open description in transit through a kernel IPC queue.
/// Tokens are generation-bound and can only be created from a descriptor the
/// sending process currently owns. Installation consumes the token without
/// cloning backend state, preserving offsets and status flags across process
/// boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TransferToken {
    key: ObjectKey,
}

impl TransferToken {
    pub(crate) const EMPTY: Self = Self {
        key: ObjectKey::EMPTY,
    };

    pub(crate) const fn occupied(self) -> bool {
        !self.key.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenObjectKind {
    Empty,
    ConsoleInput,
    ConsoleOutput,
    ConsoleError,
    File(u32),
    MemFd(u32),
    EventFd(u32),
    TimerFd(u32),
    SignalFd(u32),
    Epoll(u32),
    PipeRead(u32),
    PipeWrite(u32),
    UnixSocket(u32),
    UnixDatagram(u32),
}

impl OpenObjectKind {
    const fn occupied(self) -> bool {
        !matches!(self, Self::Empty)
    }
}

#[derive(Clone, Copy)]
struct OpenObject {
    generation: u32,
    owner: ProcessHandle,
    references: u16,
    descriptor_references: u16,
    active_operations: u16,
    closing: bool,
    status_flags: u32,
    kind: OpenObjectKind,
}

impl OpenObject {
    const EMPTY: Self = Self {
        generation: 0,
        owner: ProcessHandle {
            pid: 0,
            generation: 0,
        },
        references: 0,
        descriptor_references: 0,
        active_operations: 0,
        closing: false,
        status_flags: 0,
        kind: OpenObjectKind::Empty,
    };

    fn take(&mut self) -> FinalObject {
        let pending = FinalObject {
            owner: self.owner,
            kind: self.kind,
        };
        let generation = self.generation;
        *self = Self::EMPTY;
        self.generation = generation;
        pending
    }
}

#[derive(Clone, Copy)]
struct FinalObject {
    owner: ProcessHandle,
    kind: OpenObjectKind,
}

impl FinalObject {
    const EMPTY: Self = Self {
        owner: ProcessHandle {
            pid: 0,
            generation: 0,
        },
        kind: OpenObjectKind::Empty,
    };
}

#[derive(Clone, Copy)]
struct DescriptorSlot {
    object: u16,
    flags: u8,
}

impl DescriptorSlot {
    const EMPTY: Self = Self {
        object: 0,
        flags: 0,
    };

    const fn occupied(self) -> bool {
        self.object != 0
    }

    const fn new(object_index: usize, flags: u8) -> Self {
        Self {
            object: object_index as u16 + 1,
            flags,
        }
    }

    const fn object_index(self) -> Option<usize> {
        if self.occupied() {
            Some(self.object as usize - 1)
        } else {
            None
        }
    }
}

struct DescriptorSpace {
    owner: ProcessHandle,
    descriptors: [DescriptorSlot; MAXIMUM_FILE_DESCRIPTORS],
}

impl DescriptorSpace {
    const EMPTY: Self = Self {
        owner: ProcessHandle {
            pid: 0,
            generation: 0,
        },
        descriptors: [DescriptorSlot::EMPTY; MAXIMUM_FILE_DESCRIPTORS],
    };

    const fn occupied(&self) -> bool {
        self.owner.pid != 0 && self.owner.generation != 0
    }
}

struct DescriptorRegistry {
    spaces: [DescriptorSpace; MAXIMUM_DESCRIPTOR_SPACES],
    objects: [OpenObject; MAXIMUM_OPEN_OBJECTS],
}

impl DescriptorRegistry {
    const EMPTY: Self = Self {
        spaces: [const { DescriptorSpace::EMPTY }; MAXIMUM_DESCRIPTOR_SPACES],
        objects: [OpenObject::EMPTY; MAXIMUM_OPEN_OBJECTS],
    };
}

static REGISTRY: SpinLock<DescriptorRegistry> = SpinLock::new(DescriptorRegistry::EMPTY);

#[derive(Clone, Copy)]
struct ObjectLease {
    key: ObjectKey,
    owner: ProcessHandle,
    kind: OpenObjectKind,
    status_flags: u32,
}

fn valid_owner(owner: ProcessHandle) -> bool {
    owner.pid != 0 && owner.generation != 0
}

fn find_space(
    spaces: &[DescriptorSpace; MAXIMUM_DESCRIPTOR_SPACES],
    owner: ProcessHandle,
) -> Option<usize> {
    spaces
        .iter()
        .position(|space| space.occupied() && space.owner == owner)
}

fn allocate_object(
    objects: &mut [OpenObject; MAXIMUM_OPEN_OBJECTS],
    owner: ProcessHandle,
    kind: OpenObjectKind,
    status_flags: u32,
) -> Result<usize, DescriptorError> {
    let index = objects
        .iter()
        .position(|object| !object.kind.occupied())
        .ok_or(DescriptorError::Capacity)?;
    let generation = objects[index]
        .generation
        .checked_add(1)
        .filter(|generation| *generation != 0)
        .ok_or(DescriptorError::Capacity)?;
    objects[index] = OpenObject {
        generation,
        owner,
        references: 0,
        descriptor_references: 0,
        active_operations: 0,
        closing: false,
        status_flags,
        kind,
    };
    Ok(index)
}

fn initialize_standard_descriptors(
    registry: &mut DescriptorRegistry,
    space_index: usize,
) -> Result<(), DescriptorError> {
    let owner = registry.spaces[space_index].owner;
    let standard = [
        (OpenObjectKind::ConsoleInput, crate::linux_file::O_RDONLY),
        (OpenObjectKind::ConsoleOutput, crate::linux_file::O_WRONLY),
        (OpenObjectKind::ConsoleError, crate::linux_file::O_WRONLY),
    ];
    for (fd, (kind, status_flags)) in standard.into_iter().enumerate() {
        let object_index = match allocate_object(&mut registry.objects, owner, kind, status_flags) {
            Ok(index) => index,
            Err(error) => {
                for descriptor in &mut registry.spaces[space_index].descriptors[..fd] {
                    let object_index = descriptor.object_index().unwrap();
                    *descriptor = DescriptorSlot::EMPTY;
                    registry.objects[object_index].take();
                }
                return Err(error);
            }
        };
        registry.objects[object_index].references = 1;
        registry.objects[object_index].descriptor_references = 1;
        registry.spaces[space_index].descriptors[fd] = DescriptorSlot::new(object_index, 0);
    }
    Ok(())
}

fn ensure_space(
    registry: &mut DescriptorRegistry,
    owner: ProcessHandle,
) -> Result<usize, DescriptorError> {
    if !valid_owner(owner) {
        return Err(DescriptorError::PermissionDenied);
    }
    if let Some(index) = find_space(&registry.spaces, owner) {
        return Ok(index);
    }
    let index = registry
        .spaces
        .iter()
        .position(|space| !space.occupied())
        .ok_or(DescriptorError::Capacity)?;
    registry.spaces[index].owner = owner;
    if initialize_standard_descriptors(registry, index).is_err() {
        registry.spaces[index].owner = DescriptorSpace::EMPTY.owner;
        return Err(DescriptorError::Capacity);
    }
    Ok(index)
}

fn install_object(
    owner: ProcessHandle,
    kind: OpenObjectKind,
    status_flags: u32,
    close_on_exec: bool,
) -> Result<u32, DescriptorError> {
    install_backend_object(owner, owner, kind, status_flags, close_on_exec)
}

fn install_backend_object(
    descriptor_owner: ProcessHandle,
    backend_owner: ProcessHandle,
    kind: OpenObjectKind,
    status_flags: u32,
    close_on_exec: bool,
) -> Result<u32, DescriptorError> {
    let mut registry = REGISTRY.lock();
    let space_index = ensure_space(&mut registry, descriptor_owner)?;
    let fd = registry.spaces[space_index]
        .descriptors
        .iter()
        .enumerate()
        .find(|(_, descriptor)| !descriptor.occupied())
        .map(|(index, _)| index)
        .ok_or(DescriptorError::Capacity)?;
    let object_index = allocate_object(&mut registry.objects, backend_owner, kind, status_flags)?;
    registry.objects[object_index].references = 1;
    registry.objects[object_index].descriptor_references = 1;
    registry.spaces[space_index].descriptors[fd] =
        DescriptorSlot::new(object_index, u8::from(close_on_exec));
    Ok(fd as u32)
}

fn install_object_pair(
    owner: ProcessHandle,
    first_kind: OpenObjectKind,
    first_status_flags: u32,
    second_kind: OpenObjectKind,
    second_status_flags: u32,
    close_on_exec: bool,
) -> Result<(u32, u32), DescriptorError> {
    let mut registry = REGISTRY.lock();
    let space_index = ensure_space(&mut registry, owner)?;
    let mut free_descriptors = registry.spaces[space_index]
        .descriptors
        .iter()
        .enumerate()
        .filter(|(_, descriptor)| !descriptor.occupied())
        .map(|(index, _)| index);
    let first_fd = free_descriptors.next().ok_or(DescriptorError::Capacity)?;
    let second_fd = free_descriptors.next().ok_or(DescriptorError::Capacity)?;
    let mut free_objects = registry
        .objects
        .iter()
        .enumerate()
        .filter(|(_, object)| !object.kind.occupied())
        .map(|(index, _)| index);
    let first_object = free_objects.next().ok_or(DescriptorError::Capacity)?;
    let second_object = free_objects.next().ok_or(DescriptorError::Capacity)?;
    let first_generation = registry.objects[first_object]
        .generation
        .checked_add(1)
        .filter(|generation| *generation != 0)
        .ok_or(DescriptorError::Capacity)?;
    let second_generation = registry.objects[second_object]
        .generation
        .checked_add(1)
        .filter(|generation| *generation != 0)
        .ok_or(DescriptorError::Capacity)?;

    registry.objects[first_object] = OpenObject {
        generation: first_generation,
        owner,
        references: 1,
        descriptor_references: 1,
        active_operations: 0,
        closing: false,
        status_flags: first_status_flags,
        kind: first_kind,
    };
    registry.objects[second_object] = OpenObject {
        generation: second_generation,
        owner,
        references: 1,
        descriptor_references: 1,
        active_operations: 0,
        closing: false,
        status_flags: second_status_flags,
        kind: second_kind,
    };
    let descriptor_flags = u8::from(close_on_exec);
    registry.spaces[space_index].descriptors[first_fd] =
        DescriptorSlot::new(first_object, descriptor_flags);
    registry.spaces[space_index].descriptors[second_fd] =
        DescriptorSlot::new(second_object, descriptor_flags);
    Ok((first_fd as u32, second_fd as u32))
}

fn acquire_descriptor(owner: ProcessHandle, fd: u32) -> Result<ObjectLease, DescriptorError> {
    let mut registry = REGISTRY.lock();
    let space_index = ensure_space(&mut registry, owner)?;
    let descriptor = *registry.spaces[space_index]
        .descriptors
        .get(fd as usize)
        .filter(|descriptor| descriptor.occupied())
        .ok_or(DescriptorError::BadFileDescriptor)?;
    let object_index = descriptor.object_index().unwrap();
    let object = registry
        .objects
        .get_mut(object_index)
        .filter(|object| object.kind.occupied() && !object.closing)
        .ok_or(DescriptorError::BadFileDescriptor)?;
    object.active_operations = object
        .active_operations
        .checked_add(1)
        .ok_or(DescriptorError::Capacity)?;
    Ok(ObjectLease {
        key: ObjectKey::new(object_index, object.generation),
        owner: object.owner,
        kind: object.kind,
        status_flags: object.status_flags,
    })
}

fn acquire_key(key: ObjectKey) -> Result<ObjectLease, DescriptorError> {
    let object_index = key.index().ok_or(DescriptorError::BadFileDescriptor)?;
    let mut registry = REGISTRY.lock();
    let object = registry
        .objects
        .get_mut(object_index)
        .filter(|object| {
            object.kind.occupied() && object.generation == key.generation && !object.closing
        })
        .ok_or(DescriptorError::BadFileDescriptor)?;
    object.active_operations = object
        .active_operations
        .checked_add(1)
        .ok_or(DescriptorError::Capacity)?;
    Ok(ObjectLease {
        key,
        owner: object.owner,
        kind: object.kind,
        status_flags: object.status_flags,
    })
}

fn maybe_take_closing(object: &mut OpenObject) -> Option<FinalObject> {
    if object.closing && object.references == 0 && object.active_operations == 0 {
        Some(object.take())
    } else {
        None
    }
}

fn release_lease(lease: ObjectLease) {
    let pending = {
        let mut registry = REGISTRY.lock();
        let Some(object_index) = lease.key.index() else {
            return;
        };
        let object = &mut registry.objects[object_index];
        if object.generation != lease.key.generation || object.active_operations == 0 {
            return;
        }
        object.active_operations -= 1;
        maybe_take_closing(object)
    };
    if let Some(pending) = pending {
        finalize_object(pending);
    }
}

fn retain_key(key: ObjectKey) -> Result<(), DescriptorError> {
    let object_index = key.index().ok_or(DescriptorError::BadFileDescriptor)?;
    let mut registry = REGISTRY.lock();
    let object = registry
        .objects
        .get_mut(object_index)
        .filter(|object| {
            object.kind.occupied()
                && object.generation == key.generation
                && object.descriptor_references != 0
                && !object.closing
        })
        .ok_or(DescriptorError::BadFileDescriptor)?;
    object.references = object
        .references
        .checked_add(1)
        .ok_or(DescriptorError::Capacity)?;
    Ok(())
}

fn drop_key_reference(key: ObjectKey) {
    let pending = {
        let mut registry = REGISTRY.lock();
        let Some(object_index) = key.index() else {
            return;
        };
        let object = &mut registry.objects[object_index];
        if object.generation != key.generation || object.references == 0 {
            return;
        }
        object.references -= 1;
        if object.references == 0 {
            object.closing = true;
        }
        maybe_take_closing(object)
    };
    if let Some(pending) = pending {
        finalize_object(pending);
    }
}

fn detach_epoll_watches(key: ObjectKey) {
    let detached = crate::linux_epoll::remove_target(key);
    for _ in 0..detached {
        drop_key_reference(key);
    }
}

fn finalize_object(pending: FinalObject) {
    let owner = pending.owner;
    match pending.kind {
        OpenObjectKind::Empty
        | OpenObjectKind::ConsoleInput
        | OpenObjectKind::ConsoleOutput
        | OpenObjectKind::ConsoleError => {}
        OpenObjectKind::File(fd) => {
            let _ = crate::linux_file::close(owner, fd);
        }
        OpenObjectKind::MemFd(fd) => {
            let _ = crate::linux_memfd::close(owner, fd);
        }
        OpenObjectKind::EventFd(fd) => {
            let _ = crate::linux_eventfd::close(owner.pid, fd);
        }
        OpenObjectKind::TimerFd(fd) => {
            let _ = crate::linux_timerfd::close(owner.pid, fd);
        }
        OpenObjectKind::SignalFd(fd) => {
            let _ = crate::linux_signalfd::close(owner, fd);
        }
        OpenObjectKind::PipeRead(handle) | OpenObjectKind::PipeWrite(handle) => {
            let _ = crate::linux_pipe::close(owner, handle);
        }
        OpenObjectKind::UnixSocket(handle) => {
            let _ = crate::linux_socket::close(owner, handle);
        }
        OpenObjectKind::UnixDatagram(handle) => {
            let _ = crate::linux_unix_dgram::close(owner, handle);
        }
        OpenObjectKind::Epoll(fd) => {
            let mut watched = [ObjectKey::EMPTY; crate::linux_epoll::MAXIMUM_EPOLL_WATCHES];
            if let Ok(count) = crate::linux_epoll::close(owner, fd, &mut watched) {
                for key in watched[..count].iter().copied() {
                    drop_key_reference(key);
                }
            }
        }
    }
}

pub fn open(
    owner: ProcessHandle,
    path: &[u8],
    flags: u32,
    now: u64,
) -> Result<u32, DescriptorError> {
    let backend = crate::linux_file::open(owner, path, flags, now).map_err(map_file_error)?;
    let status_flags = flags
        & (crate::linux_file::O_ACCMODE
            | crate::linux_file::O_APPEND
            | crate::linux_file::O_NONBLOCK
            | crate::linux_file::O_LARGEFILE
            | crate::linux_file::O_DIRECTORY);
    match install_object(
        owner,
        OpenObjectKind::File(backend),
        status_flags,
        flags & crate::linux_file::O_CLOEXEC != 0,
    ) {
        Ok(fd) => Ok(fd),
        Err(error) => {
            let _ = crate::linux_file::close(owner, backend);
            Err(error)
        }
    }
}

pub fn eventfd(owner: ProcessHandle, initial: u64, flags: u32) -> Result<u32, DescriptorError> {
    let backend =
        crate::linux_eventfd::create(owner.pid, initial, flags).map_err(|error| match error {
            crate::linux_eventfd::EventFdError::InvalidArgument => DescriptorError::InvalidArgument,
            crate::linux_eventfd::EventFdError::Capacity => DescriptorError::Capacity,
            _ => DescriptorError::Io,
        })?;
    let status_flags = crate::linux_file::O_RDWR | flags & crate::linux_eventfd::EFD_NONBLOCK;
    match install_object(
        owner,
        OpenObjectKind::EventFd(backend),
        status_flags,
        flags & crate::linux_eventfd::EFD_CLOEXEC != 0,
    ) {
        Ok(fd) => Ok(fd),
        Err(error) => {
            let _ = crate::linux_eventfd::close(owner.pid, backend);
            Err(error)
        }
    }
}

pub fn memfd_create(owner: ProcessHandle, name: &[u8], flags: u32) -> Result<u32, DescriptorError> {
    let backend = crate::linux_memfd::create(owner, name, flags).map_err(map_memfd_error)?;
    match install_object(
        owner,
        OpenObjectKind::MemFd(backend),
        crate::linux_file::O_RDWR,
        flags & crate::linux_memfd::MFD_CLOEXEC != 0,
    ) {
        Ok(fd) => Ok(fd),
        Err(error) => {
            let _ = crate::linux_memfd::close(owner, backend);
            Err(error)
        }
    }
}

pub fn timerfd_create(
    owner: ProcessHandle,
    clockid: u32,
    flags: u32,
) -> Result<u32, DescriptorError> {
    let backend =
        crate::linux_timerfd::create(owner.pid, clockid, flags).map_err(|error| match error {
            crate::linux_timerfd::TimerFdError::InvalidArgument => DescriptorError::InvalidArgument,
            crate::linux_timerfd::TimerFdError::Capacity => DescriptorError::Capacity,
            _ => DescriptorError::Io,
        })?;
    let status_flags = crate::linux_file::O_RDWR | flags & crate::linux_timerfd::TFD_NONBLOCK;
    match install_object(
        owner,
        OpenObjectKind::TimerFd(backend),
        status_flags,
        flags & crate::linux_timerfd::TFD_CLOEXEC != 0,
    ) {
        Ok(fd) => Ok(fd),
        Err(error) => {
            let _ = crate::linux_timerfd::close(owner.pid, backend);
            Err(error)
        }
    }
}

pub fn signalfd_create(
    owner: ProcessHandle,
    mask: u64,
    flags: u32,
) -> Result<u32, DescriptorError> {
    let backend = crate::linux_signalfd::create(owner, mask, flags).map_err(map_signalfd_error)?;
    let status_flags = crate::linux_file::O_RDWR | flags & crate::linux_signalfd::SFD_NONBLOCK;
    match install_object(
        owner,
        OpenObjectKind::SignalFd(backend),
        status_flags,
        flags & crate::linux_signalfd::SFD_CLOEXEC != 0,
    ) {
        Ok(fd) => Ok(fd),
        Err(error) => {
            let _ = crate::linux_signalfd::close(owner, backend);
            Err(error)
        }
    }
}

pub fn signalfd_update(owner: ProcessHandle, fd: u32, mask: u64) -> Result<(), DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::SignalFd(backend) => {
            crate::linux_signalfd::update(lease.owner, backend, mask).map_err(map_signalfd_error)
        }
        _ => Err(DescriptorError::InvalidArgument),
    };
    release_lease(lease);
    result
}

pub fn epoll_create(owner: ProcessHandle, flags: u32) -> Result<u32, DescriptorError> {
    let backend = crate::linux_epoll::create(owner, flags).map_err(map_epoll_error)?;
    match install_object(
        owner,
        OpenObjectKind::Epoll(backend),
        crate::linux_file::O_RDWR,
        flags & crate::linux_epoll::EPOLL_CLOEXEC != 0,
    ) {
        Ok(fd) => Ok(fd),
        Err(error) => {
            let mut ignored = [ObjectKey::EMPTY; crate::linux_epoll::MAXIMUM_EPOLL_WATCHES];
            let _ = crate::linux_epoll::close(owner, backend, &mut ignored);
            Err(error)
        }
    }
}

pub fn pipe(owner: ProcessHandle, flags: u32) -> Result<(u32, u32), DescriptorError> {
    const ALLOWED: u32 = crate::linux_file::O_NONBLOCK | crate::linux_file::O_CLOEXEC;
    if flags & !ALLOWED != 0 {
        return Err(DescriptorError::InvalidArgument);
    }
    let (reader, writer) = crate::linux_pipe::create(owner).map_err(map_pipe_error)?;
    match install_object_pair(
        owner,
        OpenObjectKind::PipeRead(reader),
        crate::linux_file::O_RDONLY | flags & crate::linux_file::O_NONBLOCK,
        OpenObjectKind::PipeWrite(writer),
        crate::linux_file::O_WRONLY | flags & crate::linux_file::O_NONBLOCK,
        flags & crate::linux_file::O_CLOEXEC != 0,
    ) {
        Ok(pair) => Ok(pair),
        Err(error) => {
            let _ = crate::linux_pipe::close(owner, reader);
            let _ = crate::linux_pipe::close(owner, writer);
            Err(error)
        }
    }
}

pub fn socket(
    owner: ProcessHandle,
    domain: u32,
    socket_type: u32,
    protocol: u32,
) -> Result<u32, DescriptorError> {
    if socket_type
        & !(crate::linux_socket::SOCKET_TYPE_MASK | crate::linux_socket::SOCKET_ALLOWED_FLAGS)
        != 0
    {
        return Err(DescriptorError::InvalidArgument);
    }
    let status_flags = crate::linux_file::O_RDWR
        | if socket_type & crate::linux_socket::SOCK_NONBLOCK != 0 {
            crate::linux_file::O_NONBLOCK
        } else {
            0
        };
    match socket_type & crate::linux_socket::SOCKET_TYPE_MASK {
        crate::linux_socket::SOCK_STREAM => {
            let backend = crate::linux_socket::create(owner, domain, socket_type, protocol)
                .map_err(map_socket_error)?;
            match install_object(
                owner,
                OpenObjectKind::UnixSocket(backend),
                status_flags,
                socket_type & crate::linux_socket::SOCK_CLOEXEC != 0,
            ) {
                Ok(fd) => Ok(fd),
                Err(error) => {
                    let _ = crate::linux_socket::close(owner, backend);
                    Err(error)
                }
            }
        }
        crate::linux_unix_dgram::SOCK_DGRAM => {
            if domain != crate::linux_socket::AF_UNIX || protocol != 0 {
                return Err(DescriptorError::OperationNotSupported);
            }
            let backend = crate::linux_unix_dgram::create(owner).map_err(map_datagram_error)?;
            match install_object(
                owner,
                OpenObjectKind::UnixDatagram(backend),
                status_flags,
                socket_type & crate::linux_socket::SOCK_CLOEXEC != 0,
            ) {
                Ok(fd) => Ok(fd),
                Err(error) => {
                    let _ = crate::linux_unix_dgram::close(owner, backend);
                    Err(error)
                }
            }
        }
        _ => Err(DescriptorError::OperationNotSupported),
    }
}

pub fn socket_pair(
    owner: ProcessHandle,
    domain: u32,
    socket_type: u32,
    protocol: u32,
) -> Result<(u32, u32), DescriptorError> {
    let (first, second) = crate::linux_socket::create_pair(owner, domain, socket_type, protocol)
        .map_err(map_socket_error)?;
    let status_flags = crate::linux_file::O_RDWR
        | if socket_type & crate::linux_socket::SOCK_NONBLOCK != 0 {
            crate::linux_file::O_NONBLOCK
        } else {
            0
        };
    match install_object_pair(
        owner,
        OpenObjectKind::UnixSocket(first),
        status_flags,
        OpenObjectKind::UnixSocket(second),
        status_flags,
        socket_type & crate::linux_socket::SOCK_CLOEXEC != 0,
    ) {
        Ok(pair) => Ok(pair),
        Err(error) => {
            let _ = crate::linux_socket::close(owner, first);
            let _ = crate::linux_socket::close(owner, second);
            Err(error)
        }
    }
}

pub fn bind_socket(
    owner: ProcessHandle,
    fd: u32,
    address: crate::linux_socket::UnixAddress,
) -> Result<(), DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::UnixSocket(backend) => {
            crate::linux_socket::bind(lease.owner, backend, address).map_err(map_socket_error)
        }
        OpenObjectKind::UnixDatagram(backend) => {
            crate::linux_unix_dgram::bind(lease.owner, backend, address).map_err(map_datagram_error)
        }
        _ => Err(DescriptorError::NotSocket),
    };
    release_lease(lease);
    result
}

pub fn listen_socket(owner: ProcessHandle, fd: u32, backlog: usize) -> Result<(), DescriptorError> {
    with_socket(owner, fd, |backend_owner, backend| {
        crate::linux_socket::listen(backend_owner, backend, backlog)
    })
}

pub fn connect_socket(
    owner: ProcessHandle,
    fd: u32,
    address: crate::linux_socket::UnixAddress,
) -> Result<(), DescriptorError> {
    with_socket(owner, fd, |backend_owner, backend| {
        crate::linux_socket::connect(backend_owner, backend, address)
    })
}

pub fn accept_socket(
    owner: ProcessHandle,
    fd: u32,
    flags: u32,
) -> Result<(u32, crate::linux_socket::UnixAddress), DescriptorError> {
    if flags & !(crate::linux_socket::SOCK_NONBLOCK | crate::linux_socket::SOCK_CLOEXEC) != 0 {
        return Err(DescriptorError::InvalidArgument);
    }
    let lease = acquire_descriptor(owner, fd)?;
    let backend_owner = lease.owner;
    let accepted = match lease.kind {
        OpenObjectKind::UnixSocket(backend) => {
            crate::linux_socket::accept(backend_owner, backend).map_err(map_socket_error)
        }
        _ => Err(DescriptorError::NotSocket),
    };
    release_lease(lease);
    let (backend, peer) = accepted?;
    let status_flags = crate::linux_file::O_RDWR
        | if flags & crate::linux_socket::SOCK_NONBLOCK != 0 {
            crate::linux_file::O_NONBLOCK
        } else {
            0
        };
    match install_backend_object(
        owner,
        backend_owner,
        OpenObjectKind::UnixSocket(backend),
        status_flags,
        flags & crate::linux_socket::SOCK_CLOEXEC != 0,
    ) {
        Ok(accepted_fd) => Ok((accepted_fd, peer)),
        Err(error) => {
            let _ = crate::linux_socket::close(backend_owner, backend);
            Err(error)
        }
    }
}

fn with_socket(
    owner: ProcessHandle,
    fd: u32,
    operation: impl FnOnce(ProcessHandle, u32) -> Result<(), crate::linux_socket::SocketError>,
) -> Result<(), DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::UnixSocket(backend) => {
            operation(lease.owner, backend).map_err(map_socket_error)
        }
        _ => Err(DescriptorError::NotSocket),
    };
    release_lease(lease);
    result
}

pub fn validate_socket(owner: ProcessHandle, fd: u32) -> Result<(), DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::UnixSocket(_) | OpenObjectKind::UnixDatagram(_) => Ok(()),
        _ => Err(DescriptorError::NotSocket),
    };
    release_lease(lease);
    result
}

pub fn is_datagram(owner: ProcessHandle, fd: u32) -> Result<bool, DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = matches!(lease.kind, OpenObjectKind::UnixDatagram(_));
    release_lease(lease);
    Ok(result)
}

pub fn socket_type(owner: ProcessHandle, fd: u32) -> Result<u32, DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::UnixSocket(_) => Ok(crate::linux_socket::SOCK_STREAM),
        OpenObjectKind::UnixDatagram(_) => Ok(crate::linux_socket::SOCK_DGRAM),
        _ => Err(DescriptorError::NotSocket),
    };
    release_lease(lease);
    result
}

pub fn shutdown_socket(owner: ProcessHandle, fd: u32, how: u32) -> Result<(), DescriptorError> {
    with_socket(owner, fd, |backend_owner, backend| {
        crate::linux_socket::shutdown(backend_owner, backend, how)
    })
}

pub fn socket_local_address(
    owner: ProcessHandle,
    fd: u32,
) -> Result<crate::linux_socket::UnixAddress, DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::UnixSocket(backend) => {
            crate::linux_socket::local_address(lease.owner, backend).map_err(map_socket_error)
        }
        OpenObjectKind::UnixDatagram(backend) => {
            crate::linux_unix_dgram::local_address(lease.owner, backend).map_err(map_datagram_error)
        }
        _ => Err(DescriptorError::NotSocket),
    };
    release_lease(lease);
    result
}

pub fn socket_peer_address(
    owner: ProcessHandle,
    fd: u32,
) -> Result<crate::linux_socket::UnixAddress, DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::UnixSocket(backend) => {
            crate::linux_socket::peer_address(lease.owner, backend).map_err(map_socket_error)
        }
        OpenObjectKind::UnixDatagram(backend) => {
            crate::linux_unix_dgram::peer_address(lease.owner, backend).map_err(map_datagram_error)
        }
        _ => Err(DescriptorError::NotSocket),
    };
    release_lease(lease);
    result
}

pub fn socket_peer_credentials(
    owner: ProcessHandle,
    fd: u32,
) -> Result<crate::linux_socket::PeerCredentials, DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::UnixSocket(backend) => {
            crate::linux_socket::peer_credentials(lease.owner, backend).map_err(map_socket_error)
        }
        _ => Err(DescriptorError::NotSocket),
    };
    release_lease(lease);
    result
}

pub fn socket_is_listener(owner: ProcessHandle, fd: u32) -> Result<bool, DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::UnixSocket(backend) => {
            crate::linux_socket::is_listener(lease.owner, backend).map_err(map_socket_error)
        }
        OpenObjectKind::UnixDatagram(_) => Ok(false),
        _ => Err(DescriptorError::NotSocket),
    };
    release_lease(lease);
    result
}

pub fn send_socket(
    owner: ProcessHandle,
    fd: u32,
    input: &[u8],
    flags: u32,
) -> Result<usize, DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::UnixSocket(backend) => {
            crate::linux_socket::send(lease.owner, backend, input, flags).map_err(map_socket_error)
        }
        _ => Err(DescriptorError::NotSocket),
    };
    release_lease(lease);
    result
}

pub fn send_datagram(
    owner: ProcessHandle,
    fd: u32,
    destination: crate::linux_socket::UnixAddress,
    input: &[u8],
    flags: u32,
) -> Result<usize, DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::UnixDatagram(backend) => {
            crate::linux_unix_dgram::send(lease.owner, backend, destination, input, flags)
                .map_err(map_datagram_error)
        }
        _ => Err(DescriptorError::NotSocket),
    };
    release_lease(lease);
    result
}

#[cfg_attr(not(target_os = "none"), allow(dead_code))]
pub(crate) fn send_socket_with_rights(
    owner: ProcessHandle,
    fd: u32,
    input: &[u8],
    flags: u32,
    descriptors: &[u32],
) -> Result<usize, DescriptorError> {
    let mut tokens = [TransferToken::EMPTY; MAXIMUM_TRANSFER_DESCRIPTORS];
    let count = capture_transfers(owner, descriptors, &mut tokens)?;
    let lease = match acquire_descriptor(owner, fd) {
        Ok(lease) => lease,
        Err(error) => {
            release_transfers(&mut tokens[..count]);
            return Err(error);
        }
    };
    let result = match lease.kind {
        OpenObjectKind::UnixSocket(backend) => crate::linux_socket::send_message(
            lease.owner,
            backend,
            input,
            flags,
            &mut tokens[..count],
        )
        .map_err(map_socket_error),
        _ => Err(DescriptorError::NotSocket),
    };
    release_lease(lease);
    release_transfers(&mut tokens[..count]);
    result
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
pub(crate) struct ReceivedSocketMessage {
    pub bytes: usize,
    pub descriptor_count: usize,
    pub control_truncated: bool,
}

#[cfg_attr(not(target_os = "none"), allow(dead_code))]
pub(crate) fn receive_socket_with_rights(
    owner: ProcessHandle,
    fd: u32,
    output: &mut [u8],
    flags: u32,
    close_on_exec: bool,
    descriptors: &mut [u32],
) -> Result<ReceivedSocketMessage, DescriptorError> {
    let mut tokens = [TransferToken::EMPTY; MAXIMUM_TRANSFER_DESCRIPTORS];
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::UnixSocket(backend) => {
            crate::linux_socket::receive_message(lease.owner, backend, output, flags, &mut tokens)
                .map_err(map_socket_error)
        }
        _ => Err(DescriptorError::NotSocket),
    };
    release_lease(lease);
    let (bytes, token_count) = result?;
    let install_count = token_count.min(descriptors.len());
    let installed = match install_transfers(
        owner,
        &mut tokens[..install_count],
        close_on_exec,
        descriptors,
    ) {
        Ok(installed) => installed,
        Err(error) => {
            release_transfers(&mut tokens[..token_count]);
            return Err(error);
        }
    };
    release_transfers(&mut tokens[install_count..token_count]);
    Ok(ReceivedSocketMessage {
        bytes,
        descriptor_count: installed,
        control_truncated: installed != token_count,
    })
}

pub fn receive_socket(
    owner: ProcessHandle,
    fd: u32,
    output: &mut [u8],
    flags: u32,
) -> Result<usize, DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::UnixSocket(backend) => {
            crate::linux_socket::receive(lease.owner, backend, output, flags)
                .map_err(map_socket_error)
        }
        OpenObjectKind::UnixDatagram(backend) => {
            crate::linux_unix_dgram::receive(lease.owner, backend, output, flags)
                .map(|received| received.bytes)
                .map_err(map_datagram_error)
        }
        _ => Err(DescriptorError::NotSocket),
    };
    release_lease(lease);
    result
}

pub fn receive_datagram(
    owner: ProcessHandle,
    fd: u32,
    output: &mut [u8],
    flags: u32,
) -> Result<crate::linux_unix_dgram::ReceivedDatagram, DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::UnixDatagram(backend) => {
            crate::linux_unix_dgram::receive(lease.owner, backend, output, flags)
                .map_err(map_datagram_error)
        }
        _ => Err(DescriptorError::NotSocket),
    };
    release_lease(lease);
    result
}

pub fn set_socket_passcred(
    owner: ProcessHandle,
    fd: u32,
    enabled: bool,
) -> Result<(), DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::UnixDatagram(backend) => {
            crate::linux_unix_dgram::set_passcred(lease.owner, backend, enabled)
                .map_err(map_datagram_error)
        }
        OpenObjectKind::UnixSocket(_) => Ok(()),
        _ => Err(DescriptorError::NotSocket),
    };
    release_lease(lease);
    result
}

pub fn socket_passcred(owner: ProcessHandle, fd: u32) -> Result<bool, DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::UnixDatagram(backend) => {
            crate::linux_unix_dgram::passcred(lease.owner, backend).map_err(map_datagram_error)
        }
        OpenObjectKind::UnixSocket(_) => Ok(false),
        _ => Err(DescriptorError::NotSocket),
    };
    release_lease(lease);
    result
}

pub fn read(
    owner: ProcessHandle,
    fd: u32,
    output: &mut [u8],
    now_ns: u64,
) -> Result<usize, DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::ConsoleInput => Err(DescriptorError::WouldBlock),
        OpenObjectKind::File(backend) => {
            crate::linux_file::read(lease.owner, backend, output).map_err(map_file_error)
        }
        OpenObjectKind::MemFd(_) => Err(DescriptorError::OperationNotSupported),
        OpenObjectKind::EventFd(backend) => {
            if output.len() != core::mem::size_of::<u64>() {
                Err(DescriptorError::InvalidArgument)
            } else {
                crate::linux_eventfd::read(lease.owner.pid, backend)
                    .map(|value| {
                        output.copy_from_slice(&value.to_ne_bytes());
                        output.len()
                    })
                    .map_err(map_eventfd_error)
            }
        }
        OpenObjectKind::TimerFd(backend) => {
            if output.len() != core::mem::size_of::<u64>() {
                Err(DescriptorError::InvalidArgument)
            } else {
                crate::linux_timerfd::read(lease.owner.pid, backend, now_ns)
                    .map(|value| {
                        output.copy_from_slice(&value.to_ne_bytes());
                        output.len()
                    })
                    .map_err(map_timerfd_error)
            }
        }
        OpenObjectKind::SignalFd(backend) => {
            crate::linux_signalfd::read(lease.owner, backend, output).map_err(map_signalfd_error)
        }
        OpenObjectKind::UnixDatagram(backend) => {
            crate::linux_unix_dgram::receive(lease.owner, backend, output, 0)
                .map(|received| received.bytes)
                .map_err(map_datagram_error)
        }
        OpenObjectKind::PipeRead(handle) => {
            crate::linux_pipe::read(lease.owner, handle, output).map_err(map_pipe_error)
        }
        OpenObjectKind::UnixSocket(handle) => {
            crate::linux_socket::read(lease.owner, handle, output).map_err(map_socket_error)
        }
        _ => Err(DescriptorError::BadFileDescriptor),
    };
    release_lease(lease);
    result
}

pub fn write(
    owner: ProcessHandle,
    fd: u32,
    input: &[u8],
    now: u64,
) -> Result<WriteResult, DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::ConsoleOutput | OpenObjectKind::ConsoleError => Ok(WriteResult::Console),
        OpenObjectKind::File(backend) => crate::linux_file::write(lease.owner, backend, input, now)
            .map(WriteResult::Bytes)
            .map_err(map_file_error),
        OpenObjectKind::MemFd(_) => Err(DescriptorError::OperationNotSupported),
        OpenObjectKind::EventFd(backend) => {
            if input.len() != core::mem::size_of::<u64>() {
                Err(DescriptorError::InvalidArgument)
            } else {
                let value = u64::from_ne_bytes(input.try_into().unwrap());
                crate::linux_eventfd::write(lease.owner.pid, backend, value)
                    .map(|()| WriteResult::Bytes(input.len()))
                    .map_err(map_eventfd_error)
            }
        }
        OpenObjectKind::PipeWrite(handle) => crate::linux_pipe::write(lease.owner, handle, input)
            .map(WriteResult::Bytes)
            .map_err(map_pipe_error),
        OpenObjectKind::UnixSocket(handle) => {
            crate::linux_socket::write(lease.owner, handle, input)
                .map(WriteResult::Bytes)
                .map_err(map_socket_error)
        }
        _ => Err(DescriptorError::BadFileDescriptor),
    };
    release_lease(lease);
    result
}

pub fn close(owner: ProcessHandle, fd: u32) -> Result<(), DescriptorError> {
    let (pending, detached) = {
        let mut registry = REGISTRY.lock();
        let space_index = ensure_space(&mut registry, owner)?;
        let descriptor = *registry.spaces[space_index]
            .descriptors
            .get(fd as usize)
            .filter(|descriptor| descriptor.occupied())
            .ok_or(DescriptorError::BadFileDescriptor)?;
        let object_index = descriptor.object_index().unwrap();
        if registry.objects[object_index].references == 0
            || registry.objects[object_index].descriptor_references == 0
        {
            return Err(DescriptorError::BadFileDescriptor);
        }
        registry.spaces[space_index].descriptors[fd as usize] = DescriptorSlot::EMPTY;
        let object = &mut registry.objects[object_index];
        object.references -= 1;
        object.descriptor_references -= 1;
        let detached = if object.descriptor_references == 0 {
            object.closing = true;
            Some(ObjectKey::new(object_index, object.generation))
        } else {
            None
        };
        (maybe_take_closing(object), detached)
    };
    if let Some(key) = detached {
        detach_epoll_watches(key);
    }
    if let Some(pending) = pending {
        finalize_object(pending);
    }
    Ok(())
}

pub fn duplicate(
    owner: ProcessHandle,
    old_fd: u32,
    minimum: u32,
    close_on_exec: bool,
) -> Result<u32, DescriptorError> {
    if minimum as usize >= MAXIMUM_FILE_DESCRIPTORS {
        return Err(DescriptorError::InvalidArgument);
    }
    let mut registry = REGISTRY.lock();
    let space_index = ensure_space(&mut registry, owner)?;
    let descriptor = *registry.spaces[space_index]
        .descriptors
        .get(old_fd as usize)
        .filter(|descriptor| descriptor.occupied())
        .ok_or(DescriptorError::BadFileDescriptor)?;
    let object_index = descriptor.object_index().unwrap();
    let generation = registry.objects[object_index].generation;
    let target = registry.spaces[space_index]
        .descriptors
        .iter()
        .enumerate()
        .skip(minimum as usize)
        .find(|(_, descriptor)| !descriptor.occupied())
        .map(|(index, _)| index)
        .ok_or(DescriptorError::Capacity)?;
    let object = &mut registry.objects[object_index];
    if !object.kind.occupied() || object.generation != generation || object.closing {
        return Err(DescriptorError::BadFileDescriptor);
    }
    let references = object
        .references
        .checked_add(1)
        .ok_or(DescriptorError::Capacity)?;
    let descriptor_references = object
        .descriptor_references
        .checked_add(1)
        .ok_or(DescriptorError::Capacity)?;
    object.references = references;
    object.descriptor_references = descriptor_references;
    registry.spaces[space_index].descriptors[target] =
        DescriptorSlot::new(object_index, u8::from(close_on_exec));
    Ok(target as u32)
}

pub fn duplicate_to(
    owner: ProcessHandle,
    old_fd: u32,
    new_fd: u32,
    close_on_exec: bool,
    reject_same: bool,
) -> Result<u32, DescriptorError> {
    if new_fd as usize >= MAXIMUM_FILE_DESCRIPTORS {
        return Err(DescriptorError::BadFileDescriptor);
    }
    if old_fd == new_fd {
        return if reject_same {
            Err(DescriptorError::InvalidArgument)
        } else {
            let lease = acquire_descriptor(owner, old_fd)?;
            release_lease(lease);
            Ok(new_fd)
        };
    }

    let (pending, detached) = {
        let mut registry = REGISTRY.lock();
        let space_index = ensure_space(&mut registry, owner)?;
        let source = *registry.spaces[space_index]
            .descriptors
            .get(old_fd as usize)
            .filter(|descriptor| descriptor.occupied())
            .ok_or(DescriptorError::BadFileDescriptor)?;
        let source_index = source.object_index().unwrap();
        if !registry.objects[source_index].kind.occupied() || registry.objects[source_index].closing
        {
            return Err(DescriptorError::BadFileDescriptor);
        }

        let existing = registry.spaces[space_index].descriptors[new_fd as usize];
        let mut pending = None;
        let mut detached = None;
        if existing.occupied() {
            let existing_index = existing.object_index().unwrap();
            if existing_index != source_index {
                let existing_object = &registry.objects[existing_index];
                if existing_object.references == 0 || existing_object.descriptor_references == 0 {
                    return Err(DescriptorError::BadFileDescriptor);
                }
                let source_references = registry.objects[source_index]
                    .references
                    .checked_add(1)
                    .ok_or(DescriptorError::Capacity)?;
                let source_descriptor_references = registry.objects[source_index]
                    .descriptor_references
                    .checked_add(1)
                    .ok_or(DescriptorError::Capacity)?;
                registry.objects[source_index].references = source_references;
                registry.objects[source_index].descriptor_references = source_descriptor_references;
                let object = &mut registry.objects[existing_index];
                object.references -= 1;
                object.descriptor_references -= 1;
                if object.descriptor_references == 0 {
                    object.closing = true;
                    detached = Some(ObjectKey::new(existing_index, object.generation));
                }
                pending = maybe_take_closing(object);
            }
        } else {
            let references = registry.objects[source_index]
                .references
                .checked_add(1)
                .ok_or(DescriptorError::Capacity)?;
            let descriptor_references = registry.objects[source_index]
                .descriptor_references
                .checked_add(1)
                .ok_or(DescriptorError::Capacity)?;
            registry.objects[source_index].references = references;
            registry.objects[source_index].descriptor_references = descriptor_references;
        }
        registry.spaces[space_index].descriptors[new_fd as usize] =
            DescriptorSlot::new(source_index, u8::from(close_on_exec));
        (pending, detached)
    };
    if let Some(key) = detached {
        detach_epoll_watches(key);
    }
    if let Some(pending) = pending {
        finalize_object(pending);
    }
    Ok(new_fd)
}

/// Retain exact open descriptions for one bounded ancillary transfer. The
/// reservation counts as a descriptor reference until it is either installed
/// in the receiver or explicitly released, so the sender may close its local
/// descriptor immediately after a successful send.
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
pub(crate) fn capture_transfers(
    owner: ProcessHandle,
    descriptors: &[u32],
    output: &mut [TransferToken],
) -> Result<usize, DescriptorError> {
    if descriptors.len() > MAXIMUM_TRANSFER_DESCRIPTORS || descriptors.len() > output.len() {
        return Err(DescriptorError::InvalidArgument);
    }
    let mut keys = [ObjectKey::EMPTY; MAXIMUM_TRANSFER_DESCRIPTORS];
    let mut registry = REGISTRY.lock();
    let space_index = ensure_space(&mut registry, owner)?;
    for (index, descriptor_number) in descriptors.iter().copied().enumerate() {
        let descriptor = *registry.spaces[space_index]
            .descriptors
            .get(descriptor_number as usize)
            .filter(|descriptor| descriptor.occupied())
            .ok_or(DescriptorError::BadFileDescriptor)?;
        let object_index = descriptor.object_index().unwrap();
        let object = &registry.objects[object_index];
        if !object.kind.occupied() || object.closing {
            return Err(DescriptorError::BadFileDescriptor);
        }
        if matches!(
            object.kind,
            OpenObjectKind::UnixSocket(_) | OpenObjectKind::Epoll(_)
        ) {
            return Err(DescriptorError::OperationNotSupported);
        }
        let key = ObjectKey::new(object_index, object.generation);
        let reservations = keys[..index]
            .iter()
            .filter(|existing| **existing == key)
            .count()
            + 1;
        let reservations = u16::try_from(reservations).map_err(|_| DescriptorError::Capacity)?;
        object
            .references
            .checked_add(reservations)
            .ok_or(DescriptorError::Capacity)?;
        object
            .descriptor_references
            .checked_add(reservations)
            .ok_or(DescriptorError::Capacity)?;
        keys[index] = key;
    }
    for key in keys[..descriptors.len()].iter().copied() {
        let object = &mut registry.objects[key.index().unwrap()];
        object.references += 1;
        object.descriptor_references += 1;
    }
    for (destination, key) in output.iter_mut().zip(keys).take(descriptors.len()) {
        *destination = TransferToken { key };
    }
    Ok(descriptors.len())
}

/// Install retained descriptions into one receiver's lowest available
/// descriptor numbers. The operation is atomic: capacity and every generation
/// are checked before any token or descriptor slot changes.
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
pub(crate) fn install_transfers(
    owner: ProcessHandle,
    tokens: &mut [TransferToken],
    close_on_exec: bool,
    output: &mut [u32],
) -> Result<usize, DescriptorError> {
    if tokens.len() > MAXIMUM_TRANSFER_DESCRIPTORS || tokens.len() > output.len() {
        return Err(DescriptorError::InvalidArgument);
    }
    let mut registry = REGISTRY.lock();
    let space_index = ensure_space(&mut registry, owner)?;
    let mut targets = [usize::MAX; MAXIMUM_TRANSFER_DESCRIPTORS];
    let mut target_count = 0;
    for (index, descriptor) in registry.spaces[space_index].descriptors.iter().enumerate() {
        if !descriptor.occupied() && target_count < tokens.len() {
            targets[target_count] = index;
            target_count += 1;
        }
    }
    if target_count != tokens.len() {
        return Err(DescriptorError::Capacity);
    }
    for token in tokens.iter().copied() {
        let object_index = token
            .key
            .index()
            .ok_or(DescriptorError::BadFileDescriptor)?;
        let object = &registry.objects[object_index];
        if !object.kind.occupied()
            || object.generation != token.key.generation
            || object.references == 0
            || object.descriptor_references == 0
            || object.closing
        {
            return Err(DescriptorError::BadFileDescriptor);
        }
    }
    for (index, token) in tokens.iter_mut().enumerate() {
        registry.spaces[space_index].descriptors[targets[index]] =
            DescriptorSlot::new(token.key.index().unwrap(), u8::from(close_on_exec));
        output[index] = targets[index] as u32;
        *token = TransferToken::EMPTY;
    }
    Ok(tokens.len())
}

pub(crate) fn release_transfers(tokens: &mut [TransferToken]) {
    for token in tokens {
        if !token.occupied() {
            continue;
        }
        let key = token.key;
        *token = TransferToken::EMPTY;
        let (pending, detached) = {
            let mut registry = REGISTRY.lock();
            let Some(object_index) = key.index() else {
                continue;
            };
            let object = &mut registry.objects[object_index];
            if object.generation != key.generation
                || object.references == 0
                || object.descriptor_references == 0
            {
                continue;
            }
            object.references -= 1;
            object.descriptor_references -= 1;
            let detached = if object.descriptor_references == 0 {
                object.closing = true;
                true
            } else {
                false
            };
            (maybe_take_closing(object), detached)
        };
        if detached {
            detach_epoll_watches(key);
        }
        if let Some(pending) = pending {
            finalize_object(pending);
        }
    }
}

pub fn descriptor_flags(owner: ProcessHandle, fd: u32) -> Result<u32, DescriptorError> {
    let mut registry = REGISTRY.lock();
    let space_index = ensure_space(&mut registry, owner)?;
    let descriptor = *registry.spaces[space_index]
        .descriptors
        .get(fd as usize)
        .filter(|descriptor| descriptor.occupied())
        .ok_or(DescriptorError::BadFileDescriptor)?;
    Ok(if descriptor.flags & 1 != 0 {
        FD_CLOEXEC
    } else {
        0
    })
}

pub fn set_descriptor_flags(
    owner: ProcessHandle,
    fd: u32,
    flags: u32,
) -> Result<(), DescriptorError> {
    if flags & !FD_CLOEXEC != 0 {
        return Err(DescriptorError::InvalidArgument);
    }
    let mut registry = REGISTRY.lock();
    let space_index = ensure_space(&mut registry, owner)?;
    let descriptor = registry.spaces[space_index]
        .descriptors
        .get_mut(fd as usize)
        .filter(|descriptor| descriptor.occupied())
        .ok_or(DescriptorError::BadFileDescriptor)?;
    descriptor.flags = u8::from(flags & FD_CLOEXEC != 0);
    Ok(())
}

pub fn status_flags(owner: ProcessHandle, fd: u32) -> Result<u32, DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let flags = lease.status_flags;
    release_lease(lease);
    Ok(flags)
}

pub fn set_status_flags(
    owner: ProcessHandle,
    fd: u32,
    requested: u32,
) -> Result<(), DescriptorError> {
    const MUTABLE: u32 = crate::linux_file::O_NONBLOCK;
    let mut registry = REGISTRY.lock();
    let space_index = ensure_space(&mut registry, owner)?;
    let descriptor = *registry.spaces[space_index]
        .descriptors
        .get(fd as usize)
        .filter(|descriptor| descriptor.occupied())
        .ok_or(DescriptorError::BadFileDescriptor)?;
    let object = &mut registry.objects[descriptor.object_index().unwrap()];
    object.status_flags = (object.status_flags & !MUTABLE) | (requested & MUTABLE);
    Ok(())
}

pub fn seek(
    owner: ProcessHandle,
    fd: u32,
    offset: i64,
    whence: u32,
) -> Result<u64, DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::File(backend) => {
            crate::linux_file::seek(lease.owner, backend, offset, whence).map_err(map_file_error)
        }
        OpenObjectKind::MemFd(backend) => {
            crate::linux_memfd::seek(lease.owner, backend, offset, whence).map_err(map_memfd_error)
        }
        _ => Err(DescriptorError::IllegalSeek),
    };
    release_lease(lease);
    result
}

pub fn metadata(owner: ProcessHandle, fd: u32) -> Result<DescriptorMetadata, DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let inode = object_inode(lease.owner, lease.key);
    let result = match lease.kind {
        OpenObjectKind::File(backend) => crate::linux_file::fstat(lease.owner, backend)
            .map(|stat| DescriptorMetadata {
                mode: match stat.kind {
                    NodeKind::File => 0o100_644,
                    NodeKind::Directory => 0o040_755,
                },
                size_bytes: stat.size_bytes,
                created_ticks: stat.created_ticks,
                modified_ticks: stat.modified_ticks,
                inode,
            })
            .map_err(map_file_error),
        OpenObjectKind::MemFd(backend) => crate::linux_memfd::snapshot(lease.owner, backend)
            .map(|snapshot| DescriptorMetadata {
                mode: 0o100_600,
                size_bytes: snapshot.size_bytes as u64,
                created_ticks: 0,
                modified_ticks: 0,
                inode,
            })
            .map_err(map_memfd_error),
        OpenObjectKind::PipeRead(_) | OpenObjectKind::PipeWrite(_) => Ok(DescriptorMetadata {
            mode: 0o010_600,
            size_bytes: 0,
            created_ticks: 0,
            modified_ticks: 0,
            inode,
        }),
        OpenObjectKind::UnixSocket(_) | OpenObjectKind::UnixDatagram(_) => Ok(DescriptorMetadata {
            mode: 0o140_600,
            size_bytes: 0,
            created_ticks: 0,
            modified_ticks: 0,
            inode,
        }),
        OpenObjectKind::ConsoleInput
        | OpenObjectKind::ConsoleOutput
        | OpenObjectKind::ConsoleError => Ok(DescriptorMetadata {
            mode: 0o020_620,
            size_bytes: 0,
            created_ticks: 0,
            modified_ticks: 0,
            inode,
        }),
        OpenObjectKind::EventFd(_)
        | OpenObjectKind::TimerFd(_)
        | OpenObjectKind::SignalFd(_)
        | OpenObjectKind::Epoll(_) => Ok(DescriptorMetadata {
            mode: 0o100_600,
            size_bytes: 0,
            created_ticks: 0,
            modified_ticks: 0,
            inode,
        }),
        OpenObjectKind::Empty => Err(DescriptorError::BadFileDescriptor),
    };
    release_lease(lease);
    result
}

fn object_inode(owner: ProcessHandle, key: ObjectKey) -> u64 {
    let index = key.index().unwrap_or(0) as u64 + 1;
    ((u64::from(owner.generation) << 32) ^ (u64::from(key.generation) << 8) ^ index).max(1)
}

pub fn truncate(owner: ProcessHandle, fd: u32, size_bytes: usize) -> Result<(), DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::MemFd(backend) => {
            crate::linux_memfd::truncate(lease.owner, backend, size_bytes).map_err(map_memfd_error)
        }
        _ => Err(DescriptorError::InvalidArgument),
    };
    release_lease(lease);
    result
}

pub fn shared_memory_snapshot(
    owner: ProcessHandle,
    fd: u32,
) -> Result<crate::linux_memfd::MemfdSnapshot, DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::MemFd(backend) => {
            crate::linux_memfd::snapshot(lease.owner, backend).map_err(map_memfd_error)
        }
        _ => Err(DescriptorError::OperationNotSupported),
    };
    release_lease(lease);
    result
}

pub fn snapshot_range(
    owner: ProcessHandle,
    fd: u32,
    offset: usize,
    output: &mut [u8],
) -> Result<FileRangeSnapshot, DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::File(backend) => {
            crate::linux_file::snapshot_range(lease.owner, backend, offset, output)
                .map_err(map_file_error)
        }
        OpenObjectKind::MemFd(_) => Err(DescriptorError::OperationNotSupported),
        _ => Err(DescriptorError::BadFileDescriptor),
    };
    release_lease(lease);
    result
}

fn readiness_for_lease(
    lease: ObjectLease,
    now_ns: u64,
    allow_epoll: bool,
) -> Result<(u32, u64), DescriptorError> {
    match lease.kind {
        OpenObjectKind::ConsoleInput => Ok((0, u64::from(lease.key.generation))),
        OpenObjectKind::ConsoleOutput | OpenObjectKind::ConsoleError => {
            Ok((READY_OUT, u64::from(lease.key.generation)))
        }
        OpenObjectKind::File(backend) => crate::linux_file::readiness(lease.owner, backend)
            .map(|ready| (ready, u64::from(lease.key.generation)))
            .map_err(map_file_error),
        OpenObjectKind::MemFd(backend) => crate::linux_memfd::readiness(lease.owner, backend)
            .map(|ready| (ready, u64::from(lease.key.generation)))
            .map_err(map_memfd_error),
        OpenObjectKind::EventFd(backend) => {
            let ready = crate::linux_eventfd::readiness(lease.owner.pid, backend)
                .map_err(map_eventfd_error)?;
            let generation = crate::linux_eventfd::readiness_generation(lease.owner.pid, backend)
                .map_err(map_eventfd_error)?;
            Ok((ready, generation))
        }
        OpenObjectKind::TimerFd(backend) => {
            let ready = crate::linux_timerfd::readiness(lease.owner.pid, backend, now_ns)
                .map_err(map_timerfd_error)?;
            let generation =
                crate::linux_timerfd::readiness_generation(lease.owner.pid, backend, now_ns)
                    .map_err(map_timerfd_error)?;
            Ok((ready, generation))
        }
        OpenObjectKind::SignalFd(backend) => {
            let ready = crate::linux_signalfd::readiness(lease.owner, backend)
                .map_err(map_signalfd_error)?;
            let generation = crate::linux_signalfd::readiness_generation(lease.owner, backend)
                .map_err(map_signalfd_error)?;
            Ok((ready, generation))
        }
        OpenObjectKind::PipeRead(handle) | OpenObjectKind::PipeWrite(handle) => {
            let ready =
                crate::linux_pipe::readiness(lease.owner, handle).map_err(map_pipe_error)?;
            let generation = crate::linux_pipe::readiness_generation(lease.owner, handle)
                .map_err(map_pipe_error)?;
            Ok((ready, generation))
        }
        OpenObjectKind::UnixSocket(handle) => {
            let ready =
                crate::linux_socket::readiness(lease.owner, handle).map_err(map_socket_error)?;
            let generation = crate::linux_socket::readiness_generation(lease.owner, handle)
                .map_err(map_socket_error)?;
            Ok((ready, generation))
        }
        OpenObjectKind::UnixDatagram(handle) => {
            let ready = crate::linux_unix_dgram::readiness(lease.owner, handle)
                .map_err(map_datagram_error)?;
            let generation = crate::linux_unix_dgram::readiness_generation(lease.owner, handle)
                .map_err(map_datagram_error)?;
            Ok((ready, generation))
        }
        OpenObjectKind::Epoll(backend) if allow_epoll => {
            crate::linux_epoll::readiness(lease.owner, backend)
                .map(|ready| (ready, u64::from(lease.key.generation)))
                .map_err(map_epoll_error)
        }
        _ => Err(DescriptorError::InvalidArgument),
    }
}

pub fn readiness(owner: ProcessHandle, fd: u32, now_ns: u64) -> Result<u32, DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = readiness_for_lease(lease, now_ns, true).map(|value| value.0);
    release_lease(lease);
    result
}

/// Readiness bridge used by epoll watches. Nested epoll objects are rejected,
/// preventing recursive watch graphs while the bounded first profile is in
/// force.
pub(crate) fn readiness_by_key(key: ObjectKey) -> Result<(u32, u64), DescriptorError> {
    let lease = acquire_key(key)?;
    let result = readiness_for_lease(lease, monotonic_now_ns(), false);
    release_lease(lease);
    result
}

#[inline]
fn monotonic_now_ns() -> u64 {
    #[cfg(target_os = "none")]
    {
        crate::interrupts::monotonic_nanoseconds()
    }
    #[cfg(not(target_os = "none"))]
    {
        0
    }
}

pub fn timerfd_settime(
    owner: ProcessHandle,
    fd: u32,
    flags: u32,
    value: crate::linux_timerfd::TimerSpec,
    now_ns: u64,
) -> Result<crate::linux_timerfd::TimerSpec, DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::TimerFd(backend) => {
            crate::linux_timerfd::settime(lease.owner.pid, backend, flags, value, now_ns)
                .map_err(map_timerfd_error)
        }
        _ => Err(DescriptorError::BadFileDescriptor),
    };
    release_lease(lease);
    result
}

pub fn timerfd_gettime(
    owner: ProcessHandle,
    fd: u32,
    now_ns: u64,
) -> Result<crate::linux_timerfd::TimerSpec, DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::TimerFd(backend) => {
            crate::linux_timerfd::gettime(lease.owner.pid, backend, now_ns)
                .map_err(map_timerfd_error)
        }
        _ => Err(DescriptorError::BadFileDescriptor),
    };
    release_lease(lease);
    result
}

pub fn epoll_ctl(
    owner: ProcessHandle,
    epfd: u32,
    operation: u32,
    target_fd: u32,
    events: u32,
    data: u64,
) -> Result<(), DescriptorError> {
    let epoll_lease = acquire_descriptor(owner, epfd)?;
    let target_lease = match acquire_descriptor(owner, target_fd) {
        Ok(lease) => lease,
        Err(error) => {
            release_lease(epoll_lease);
            return Err(error);
        }
    };
    let OpenObjectKind::Epoll(backend) = epoll_lease.kind else {
        release_lease(target_lease);
        release_lease(epoll_lease);
        return Err(DescriptorError::BadFileDescriptor);
    };
    if matches!(
        target_lease.kind,
        OpenObjectKind::File(_) | OpenObjectKind::MemFd(_)
    ) {
        release_lease(target_lease);
        release_lease(epoll_lease);
        return Err(DescriptorError::OperationNotPermitted);
    }
    if matches!(target_lease.kind, OpenObjectKind::Epoll(_)) || target_lease.key == epoll_lease.key
    {
        release_lease(target_lease);
        release_lease(epoll_lease);
        return Err(DescriptorError::InvalidArgument);
    }

    let result = crate::linux_epoll::ctl(
        epoll_lease.owner,
        backend,
        operation,
        target_lease.key,
        events,
        data,
    )
    .map_err(map_epoll_error);
    if result.is_ok() {
        match operation {
            crate::linux_epoll::EPOLL_CTL_ADD => {
                if retain_key(target_lease.key).is_err() {
                    let _ = crate::linux_epoll::ctl(
                        epoll_lease.owner,
                        backend,
                        crate::linux_epoll::EPOLL_CTL_DEL,
                        target_lease.key,
                        0,
                        0,
                    );
                    release_lease(target_lease);
                    release_lease(epoll_lease);
                    return Err(DescriptorError::Capacity);
                }
            }
            crate::linux_epoll::EPOLL_CTL_DEL => drop_key_reference(target_lease.key),
            _ => {}
        }
    }
    release_lease(target_lease);
    release_lease(epoll_lease);
    result
}

pub fn epoll_wait(
    owner: ProcessHandle,
    epfd: u32,
    output: &mut [crate::linux_epoll::ReadyEvent],
) -> Result<usize, DescriptorError> {
    let lease = acquire_descriptor(owner, epfd)?;
    let result = match lease.kind {
        OpenObjectKind::Epoll(backend) => {
            crate::linux_epoll::wait(lease.owner, backend, output).map_err(map_epoll_error)
        }
        _ => Err(DescriptorError::BadFileDescriptor),
    };
    release_lease(lease);
    result
}

pub fn close_on_exec(owner: ProcessHandle) -> usize {
    close_matching(owner, true)
}

pub fn close_all(owner: ProcessHandle) -> usize {
    close_matching(owner, false)
}

fn close_matching(owner: ProcessHandle, only_close_on_exec: bool) -> usize {
    let mut pending = [FinalObject::EMPTY; MAXIMUM_FILE_DESCRIPTORS];
    let mut detached = [ObjectKey::EMPTY; MAXIMUM_FILE_DESCRIPTORS];
    let (closed, pending_count, detached_count) = {
        let mut registry = REGISTRY.lock();
        let Some(space_index) = find_space(&registry.spaces, owner) else {
            return 0;
        };
        let DescriptorRegistry { spaces, objects } = &mut *registry;
        let space = &mut spaces[space_index];
        let mut closed = 0;
        let mut pending_count = 0;
        let mut detached_count = 0;
        for descriptor in &mut space.descriptors {
            if !descriptor.occupied()
                || only_close_on_exec && descriptor.flags & FD_CLOEXEC as u8 == 0
            {
                continue;
            }
            let object_index = descriptor.object_index().unwrap();
            *descriptor = DescriptorSlot::EMPTY;
            let object = &mut objects[object_index];
            object.references = object.references.saturating_sub(1);
            object.descriptor_references = object.descriptor_references.saturating_sub(1);
            if object.descriptor_references == 0 {
                object.closing = true;
                detached[detached_count] = ObjectKey::new(object_index, object.generation);
                detached_count += 1;
            }
            if let Some(final_object) = maybe_take_closing(object) {
                pending[pending_count] = final_object;
                pending_count += 1;
            }
            closed += 1;
        }
        if !only_close_on_exec {
            space.owner = DescriptorSpace::EMPTY.owner;
        }
        (closed, pending_count, detached_count)
    };
    for key in detached[..detached_count].iter().copied() {
        detach_epoll_watches(key);
    }
    for final_object in pending[..pending_count].iter().copied() {
        finalize_object(final_object);
    }
    closed
}

fn map_file_error(error: crate::linux_file::FileError) -> DescriptorError {
    DescriptorError::File(error)
}

fn map_memfd_error(error: crate::linux_memfd::MemfdError) -> DescriptorError {
    match error {
        crate::linux_memfd::MemfdError::InvalidArgument => DescriptorError::InvalidArgument,
        crate::linux_memfd::MemfdError::BadFileDescriptor => DescriptorError::BadFileDescriptor,
        crate::linux_memfd::MemfdError::Capacity => DescriptorError::Capacity,
        crate::linux_memfd::MemfdError::PermissionDenied => DescriptorError::PermissionDenied,
        crate::linux_memfd::MemfdError::OperationNotSupported => {
            DescriptorError::OperationNotSupported
        }
    }
}

fn map_eventfd_error(error: crate::linux_eventfd::EventFdError) -> DescriptorError {
    match error {
        crate::linux_eventfd::EventFdError::InvalidArgument => DescriptorError::InvalidArgument,
        crate::linux_eventfd::EventFdError::BadFileDescriptor => DescriptorError::BadFileDescriptor,
        crate::linux_eventfd::EventFdError::WouldBlock
        | crate::linux_eventfd::EventFdError::Overflow => DescriptorError::WouldBlock,
        crate::linux_eventfd::EventFdError::Capacity => DescriptorError::Capacity,
        crate::linux_eventfd::EventFdError::PermissionDenied => DescriptorError::PermissionDenied,
    }
}

fn map_timerfd_error(error: crate::linux_timerfd::TimerFdError) -> DescriptorError {
    match error {
        crate::linux_timerfd::TimerFdError::InvalidArgument => DescriptorError::InvalidArgument,
        crate::linux_timerfd::TimerFdError::BadFileDescriptor => DescriptorError::BadFileDescriptor,
        crate::linux_timerfd::TimerFdError::WouldBlock => DescriptorError::WouldBlock,
        crate::linux_timerfd::TimerFdError::Capacity => DescriptorError::Capacity,
    }
}

fn map_signalfd_error(error: crate::linux_signalfd::SignalFdError) -> DescriptorError {
    match error {
        crate::linux_signalfd::SignalFdError::InvalidArgument => DescriptorError::InvalidArgument,
        crate::linux_signalfd::SignalFdError::BadFileDescriptor => {
            DescriptorError::BadFileDescriptor
        }
        crate::linux_signalfd::SignalFdError::WouldBlock => DescriptorError::WouldBlock,
        crate::linux_signalfd::SignalFdError::Capacity => DescriptorError::Capacity,
    }
}

fn map_pipe_error(error: crate::linux_pipe::PipeError) -> DescriptorError {
    match error {
        crate::linux_pipe::PipeError::InvalidArgument => DescriptorError::InvalidArgument,
        crate::linux_pipe::PipeError::BadFileDescriptor => DescriptorError::BadFileDescriptor,
        crate::linux_pipe::PipeError::WouldBlock => DescriptorError::WouldBlock,
        crate::linux_pipe::PipeError::BrokenPipe => DescriptorError::BrokenPipe,
        crate::linux_pipe::PipeError::Capacity => DescriptorError::Capacity,
    }
}

fn map_socket_error(error: crate::linux_socket::SocketError) -> DescriptorError {
    match error {
        crate::linux_socket::SocketError::InvalidArgument => DescriptorError::InvalidArgument,
        crate::linux_socket::SocketError::BadFileDescriptor => DescriptorError::BadFileDescriptor,
        crate::linux_socket::SocketError::AddressFamilyNotSupported => {
            DescriptorError::AddressFamilyNotSupported
        }
        crate::linux_socket::SocketError::AddressInUse => DescriptorError::AddressInUse,
        crate::linux_socket::SocketError::ConnectionRefused => DescriptorError::ConnectionRefused,
        crate::linux_socket::SocketError::AlreadyConnected => DescriptorError::AlreadyConnected,
        crate::linux_socket::SocketError::NotConnected => DescriptorError::NotConnected,
        crate::linux_socket::SocketError::WouldBlock => DescriptorError::WouldBlock,
        crate::linux_socket::SocketError::BrokenPipe => DescriptorError::BrokenPipe,
        crate::linux_socket::SocketError::Capacity => DescriptorError::Capacity,
        crate::linux_socket::SocketError::OperationNotSupported => {
            DescriptorError::OperationNotSupported
        }
    }
}

fn map_datagram_error(error: crate::linux_unix_dgram::DatagramError) -> DescriptorError {
    match error {
        crate::linux_unix_dgram::DatagramError::InvalidArgument => DescriptorError::InvalidArgument,
        crate::linux_unix_dgram::DatagramError::BadFileDescriptor => {
            DescriptorError::BadFileDescriptor
        }
        crate::linux_unix_dgram::DatagramError::AddressInUse => DescriptorError::AddressInUse,
        crate::linux_unix_dgram::DatagramError::ConnectionRefused => {
            DescriptorError::ConnectionRefused
        }
        crate::linux_unix_dgram::DatagramError::WouldBlock => DescriptorError::WouldBlock,
        crate::linux_unix_dgram::DatagramError::Capacity => DescriptorError::Capacity,
        crate::linux_unix_dgram::DatagramError::NotConnected => DescriptorError::NotConnected,
        crate::linux_unix_dgram::DatagramError::OperationNotSupported => {
            DescriptorError::OperationNotSupported
        }
    }
}

fn map_epoll_error(error: crate::linux_epoll::EpollError) -> DescriptorError {
    match error {
        crate::linux_epoll::EpollError::InvalidArgument => DescriptorError::InvalidArgument,
        crate::linux_epoll::EpollError::BadFileDescriptor => DescriptorError::BadFileDescriptor,
        crate::linux_epoll::EpollError::Capacity => DescriptorError::Capacity,
        crate::linux_epoll::EpollError::AlreadyExists => DescriptorError::AlreadyExists,
        crate::linux_epoll::EpollError::NotFound => DescriptorError::NotFound,
    }
}

/// Returns the number of bytes immediately available to read on `fd`.
/// For object types that do not track precise byte counts the value is 1
/// when data is ready and 0 when not ready.
pub fn fionread(owner: ProcessHandle, fd: u32) -> Result<usize, DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let ready = readiness_for_lease(lease, monotonic_now_ns(), false).map(|value| value.0)?;
    Ok(if ready & crate::linux_eventfd::READY_IN != 0 {
        1
    } else {
        0
    })
}

/// Enable or disable `O_NONBLOCK` on the file description backing `fd`.
pub fn set_nonblock(owner: ProcessHandle, fd: u32, enable: bool) -> Result<(), DescriptorError> {
    let current = status_flags(owner, fd)?;
    let updated = if enable {
        current | crate::linux_file::O_NONBLOCK
    } else {
        current & !crate::linux_file::O_NONBLOCK
    };
    set_status_flags(owner, fd, updated)
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn owner(pid: u32) -> ProcessHandle {
        ProcessHandle { pid, generation: 9 }
    }

    fn cleanup(owner: ProcessHandle) {
        close_all(owner);
        let _ = crate::akashic_vfs::close_all(owner);
    }

    #[test]
    fn backend_families_share_one_dense_collision_free_namespace() {
        let owner = owner(0x5201);
        let file = open(
            owner,
            b"/unified-fd",
            crate::linux_file::O_CREAT | crate::linux_file::O_RDWR,
            1,
        )
        .unwrap();
        let event = eventfd(owner, 0, 0).unwrap();
        let timer = timerfd_create(owner, crate::linux_timerfd::CLOCK_MONOTONIC, 0).unwrap();
        let epoll = epoll_create(owner, 0).unwrap();
        let (reader, writer) = pipe(owner, crate::linux_file::O_NONBLOCK).unwrap();
        let (first_socket, second_socket) = socket_pair(
            owner,
            crate::linux_socket::AF_UNIX,
            crate::linux_socket::SOCK_STREAM,
            0,
        )
        .unwrap();
        assert_eq!(
            [
                file,
                event,
                timer,
                epoll,
                reader,
                writer,
                first_socket,
                second_socket,
            ],
            [3, 4, 5, 6, 7, 8, 9, 10]
        );
        cleanup(owner);
        let _ = crate::linux_file::unlink(b"/unified-fd");
    }

    #[test]
    fn dup_aliases_open_objects_and_cloexec_is_descriptor_local() {
        let owner = owner(0x5202);
        let (reader, writer) = pipe(owner, crate::linux_file::O_NONBLOCK).unwrap();
        let alias = duplicate(owner, writer, 0, false).unwrap();
        set_descriptor_flags(owner, writer, FD_CLOEXEC).unwrap();
        assert_eq!(close_on_exec(owner), 1);
        assert_eq!(
            descriptor_flags(owner, writer),
            Err(DescriptorError::BadFileDescriptor)
        );
        assert_eq!(write(owner, alias, b"shared", 0), Ok(WriteResult::Bytes(6)));
        let mut output = [0_u8; 6];
        assert_eq!(read(owner, reader, &mut output, 0), Ok(6));
        assert_eq!(&output, b"shared");
        cleanup(owner);
    }

    #[test]
    fn dup_to_can_atomically_replace_standard_output() {
        let owner = owner(0x5203);
        let (reader, writer) = pipe(owner, crate::linux_file::O_NONBLOCK).unwrap();
        assert_eq!(
            duplicate_to(owner, writer, STANDARD_OUTPUT, false, false),
            Ok(1)
        );
        assert_eq!(
            write(owner, 1, b"redirected", 0),
            Ok(WriteResult::Bytes(10))
        );
        let mut output = [0_u8; 10];
        assert_eq!(read(owner, reader, &mut output, 0), Ok(10));
        assert_eq!(&output, b"redirected");
        cleanup(owner);
    }

    #[test]
    fn duplicated_console_output_preserves_its_backend() {
        let owner = owner(0x5209);
        let alias = duplicate(owner, STANDARD_OUTPUT, 3, false).unwrap();
        assert_eq!(alias, 3);
        assert_eq!(
            write(owner, alias, b"console alias", 0),
            Ok(WriteResult::Console)
        );
        cleanup(owner);
    }

    #[test]
    fn last_descriptor_close_detaches_epoll_watch_before_reuse() {
        let owner = owner(0x5204);
        let event = eventfd(owner, 1, 0).unwrap();
        let epoll = epoll_create(owner, 0).unwrap();
        epoll_ctl(
            owner,
            epoll,
            crate::linux_epoll::EPOLL_CTL_ADD,
            event,
            crate::linux_epoll::EPOLLIN,
            0x55,
        )
        .unwrap();
        close(owner, event).unwrap();
        let replacement = eventfd(owner, 1, 0).unwrap();
        assert_eq!(replacement, event);
        let mut ready = [crate::linux_epoll::ReadyEvent { events: 0, data: 0 }; 1];
        assert_eq!(epoll_wait(owner, epoll, &mut ready), Ok(0));
        close(owner, epoll).unwrap();
        close(owner, replacement).unwrap();
        cleanup(owner);
    }

    #[test]
    fn epoll_watch_survives_while_a_descriptor_alias_remains() {
        let owner = owner(0x520a);
        let event = eventfd(owner, 1, 0).unwrap();
        let alias = duplicate(owner, event, 0, false).unwrap();
        let epoll = epoll_create(owner, 0).unwrap();
        epoll_ctl(
            owner,
            epoll,
            crate::linux_epoll::EPOLL_CTL_ADD,
            event,
            crate::linux_epoll::EPOLLIN,
            0x66,
        )
        .unwrap();
        close(owner, event).unwrap();
        let mut ready = [crate::linux_epoll::ReadyEvent { events: 0, data: 0 }; 1];
        assert_eq!(epoll_wait(owner, epoll, &mut ready), Ok(1));
        assert_eq!(ready[0].data, 0x66);
        close(owner, alias).unwrap();
        assert_eq!(epoll_wait(owner, epoll, &mut ready), Ok(0));
        cleanup(owner);
    }

    #[test]
    fn pipe_endpoint_lifetime_tracks_last_duplicate() {
        let owner = owner(0x5205);
        let (reader, writer) = pipe(owner, crate::linux_file::O_NONBLOCK).unwrap();
        let alias = duplicate(owner, writer, 0, false).unwrap();
        close(owner, writer).unwrap();
        assert_eq!(readiness(owner, reader, 0), Ok(0));
        close(owner, alias).unwrap();
        assert_eq!(
            readiness(owner, reader, 0),
            Ok(crate::linux_eventfd::READY_HUP)
        );
        assert_eq!(read(owner, reader, &mut [0_u8; 1], 0), Ok(0));
        cleanup(owner);
    }

    #[test]
    fn unix_socket_epoll_watch_and_peer_lifetime_track_last_duplicate() {
        let owner = owner(0x520c);
        let (first, second) = socket_pair(
            owner,
            crate::linux_socket::AF_UNIX,
            crate::linux_socket::SOCK_STREAM | crate::linux_socket::SOCK_NONBLOCK,
            0,
        )
        .unwrap();
        let alias = duplicate(owner, first, 0, false).unwrap();
        let epoll = epoll_create(owner, 0).unwrap();
        epoll_ctl(
            owner,
            epoll,
            crate::linux_epoll::EPOLL_CTL_ADD,
            first,
            crate::linux_epoll::EPOLLIN | crate::linux_epoll::EPOLLHUP,
            0x77,
        )
        .unwrap();
        close(owner, first).unwrap();
        assert_eq!(
            write(owner, second, b"socket", 0),
            Ok(WriteResult::Bytes(6))
        );
        let mut ready = [crate::linux_epoll::ReadyEvent { events: 0, data: 0 }; 1];
        assert_eq!(epoll_wait(owner, epoll, &mut ready), Ok(1));
        assert_eq!(ready[0].data, 0x77);
        let mut output = [0_u8; 6];
        assert_eq!(read(owner, alias, &mut output, 0), Ok(6));
        assert_eq!(&output, b"socket");
        close(owner, alias).unwrap();
        assert_eq!(epoll_wait(owner, epoll, &mut ready), Ok(0));
        assert_eq!(
            readiness(owner, second, 0),
            Ok(crate::linux_eventfd::READY_IN
                | crate::linux_eventfd::READY_ERR
                | crate::linux_eventfd::READY_HUP)
        );
        cleanup(owner);
    }

    #[test]
    fn named_unix_socket_crosses_descriptor_spaces_with_linux_metadata() {
        let server = owner(0x520d);
        let client = owner(0x520e);
        let address = crate::linux_socket::UnixAddress::new(b"\0arach-fd-cross-process").unwrap();
        let listener = socket(
            server,
            crate::linux_socket::AF_UNIX,
            crate::linux_socket::SOCK_STREAM,
            0,
        )
        .unwrap();
        bind_socket(server, listener, address).unwrap();
        listen_socket(server, listener, 4).unwrap();
        let client_socket = socket(
            client,
            crate::linux_socket::AF_UNIX,
            crate::linux_socket::SOCK_STREAM,
            0,
        )
        .unwrap();
        connect_socket(client, client_socket, address).unwrap();
        let (accepted, peer) = accept_socket(
            server,
            listener,
            crate::linux_socket::SOCK_NONBLOCK | crate::linux_socket::SOCK_CLOEXEC,
        )
        .unwrap();
        assert!(peer.is_unnamed());
        assert_eq!(socket_peer_address(client, client_socket), Ok(address));
        assert_eq!(
            socket_peer_credentials(server, accepted).unwrap().pid,
            client.pid
        );
        assert_eq!(
            socket_peer_credentials(client, client_socket).unwrap().pid,
            server.pid
        );
        assert_eq!(descriptor_flags(server, accepted), Ok(FD_CLOEXEC));
        assert_eq!(
            status_flags(server, accepted),
            Ok(crate::linux_file::O_RDWR | crate::linux_file::O_NONBLOCK)
        );
        assert_eq!(
            metadata(server, accepted).unwrap().mode & 0o170_000,
            0o140_000
        );
        assert_eq!(send_socket(client, client_socket, b"request", 0), Ok(7));
        let mut request = [0_u8; 7];
        assert_eq!(receive_socket(server, accepted, &mut request, 0), Ok(7));
        assert_eq!(&request, b"request");
        cleanup(client);
        cleanup(server);
    }

    #[test]
    fn exact_owner_generation_is_part_of_every_lookup() {
        let owner = owner(0x5206);
        let event = eventfd(owner, 1, 0).unwrap();
        let recycled = ProcessHandle {
            pid: owner.pid,
            generation: owner.generation + 1,
        };
        assert_eq!(
            readiness(recycled, event, 0),
            Err(DescriptorError::BadFileDescriptor)
        );
        cleanup(owner);
        cleanup(recycled);
    }

    #[test]
    fn fcntl_flags_and_pipe_metadata_follow_open_object_rules() {
        let owner = owner(0x5207);
        let file = open(
            owner,
            b"/fcntl-status",
            crate::linux_file::O_CREAT | crate::linux_file::O_RDWR | crate::linux_file::O_CLOEXEC,
            1,
        )
        .unwrap();
        assert_eq!(descriptor_flags(owner, file), Ok(FD_CLOEXEC));
        assert_eq!(status_flags(owner, file), Ok(crate::linux_file::O_RDWR));
        let (reader, writer) = pipe(owner, crate::linux_file::O_NONBLOCK).unwrap();
        let alias = duplicate(owner, reader, 20, true).unwrap();
        assert_eq!(alias, 20);
        assert_eq!(descriptor_flags(owner, reader), Ok(0));
        assert_eq!(descriptor_flags(owner, alias), Ok(FD_CLOEXEC));
        assert_eq!(
            status_flags(owner, reader),
            Ok(crate::linux_file::O_NONBLOCK)
        );
        set_status_flags(owner, reader, 0).unwrap();
        assert_eq!(status_flags(owner, alias), Ok(crate::linux_file::O_RDONLY));
        let original = metadata(owner, reader).unwrap();
        let duplicate = metadata(owner, alias).unwrap();
        assert_eq!(original.inode, duplicate.inode);
        assert_eq!(original.mode & 0o170_000, 0o010_000);
        close(owner, writer).unwrap();
        cleanup(owner);
        let _ = crate::linux_file::unlink(b"/fcntl-status");
    }

    #[test]
    fn closed_standard_streams_stay_closed_until_process_retirement() {
        let owner = owner(0x5208);
        assert_eq!(descriptor_flags(owner, 1), Ok(0));
        close(owner, 0).unwrap();
        close(owner, 1).unwrap();
        close(owner, 2).unwrap();
        assert_eq!(
            descriptor_flags(owner, 1),
            Err(DescriptorError::BadFileDescriptor)
        );
        close_all(owner);
        let registry = REGISTRY.lock();
        assert!(find_space(&registry.spaces, owner).is_none());
    }

    #[test]
    fn closed_standard_descriptor_numbers_return_to_the_dense_namespace() {
        let owner = owner(0x520b);
        close(owner, 0).unwrap();
        let event = eventfd(owner, 0, 0).unwrap();
        assert_eq!(event, 0);
        close(owner, event).unwrap();
        cleanup(owner);
    }

    #[test]
    fn unix_rights_preserve_cross_process_open_descriptions_after_sender_close() {
        let sender = owner(0x5210);
        let receiver = owner(0x5211);
        let address = crate::linux_socket::UnixAddress::new(b"\0fd-rights-a").unwrap();
        let listener = socket(
            receiver,
            crate::linux_socket::AF_UNIX,
            crate::linux_socket::SOCK_STREAM,
            0,
        )
        .unwrap();
        bind_socket(receiver, listener, address).unwrap();
        listen_socket(receiver, listener, 1).unwrap();
        let client = socket(
            sender,
            crate::linux_socket::AF_UNIX,
            crate::linux_socket::SOCK_STREAM,
            0,
        )
        .unwrap();
        connect_socket(sender, client, address).unwrap();
        let (server, _) = accept_socket(receiver, listener, 0).unwrap();

        let event = eventfd(sender, 7, 0).unwrap();
        let file = open(
            sender,
            b"/rights-file-a",
            crate::linux_file::O_CREAT | crate::linux_file::O_RDWR,
            1,
        )
        .unwrap();
        assert_eq!(write(sender, file, b"abcdef", 2), Ok(WriteResult::Bytes(6)));
        assert_eq!(seek(sender, file, 1, 0), Ok(1));
        let memory =
            memfd_create(sender, b"rights-memory", crate::linux_memfd::MFD_CLOEXEC).unwrap();
        truncate(sender, memory, 128 * 1024).unwrap();
        assert_eq!(
            send_socket_with_rights(sender, client, b"R", 0, &[event, file, memory]),
            Ok(1)
        );
        close(sender, event).unwrap();
        close(sender, file).unwrap();
        close(sender, memory).unwrap();

        let mut byte = [0_u8; 1];
        let mut received = [0_u32; MAXIMUM_TRANSFER_DESCRIPTORS];
        let message =
            receive_socket_with_rights(receiver, server, &mut byte, 0, true, &mut received)
                .unwrap();
        assert_eq!(byte, *b"R");
        assert_eq!(message.descriptor_count, 3);
        assert!(!message.control_truncated);
        assert_eq!(descriptor_flags(receiver, received[0]), Ok(FD_CLOEXEC));
        assert_eq!(descriptor_flags(receiver, received[1]), Ok(FD_CLOEXEC));
        assert_eq!(descriptor_flags(receiver, received[2]), Ok(FD_CLOEXEC));
        let mut event_value = [0_u8; 8];
        assert_eq!(read(receiver, received[0], &mut event_value, 0), Ok(8));
        assert_eq!(u64::from_ne_bytes(event_value), 7);
        let mut file_bytes = [0_u8; 3];
        assert_eq!(read(receiver, received[1], &mut file_bytes, 0), Ok(3));
        assert_eq!(&file_bytes, b"bcd");
        assert_eq!(
            metadata(receiver, received[2]).unwrap().size_bytes,
            128 * 1024
        );
        truncate(receiver, received[2], 96 * 1024).unwrap();
        assert_eq!(
            metadata(receiver, received[2]).unwrap().size_bytes,
            96 * 1024
        );

        cleanup(sender);
        cleanup(receiver);
        let _ = crate::linux_file::unlink(b"/rights-file-a");
    }

    #[test]
    fn truncated_unix_rights_close_uninstalled_descriptions() {
        let sender = owner(0x5212);
        let receiver = owner(0x5213);
        let address = crate::linux_socket::UnixAddress::new(b"\0fd-rights-b").unwrap();
        let listener = socket(
            receiver,
            crate::linux_socket::AF_UNIX,
            crate::linux_socket::SOCK_STREAM,
            0,
        )
        .unwrap();
        bind_socket(receiver, listener, address).unwrap();
        listen_socket(receiver, listener, 1).unwrap();
        let client = socket(
            sender,
            crate::linux_socket::AF_UNIX,
            crate::linux_socket::SOCK_STREAM,
            0,
        )
        .unwrap();
        connect_socket(sender, client, address).unwrap();
        let (server, _) = accept_socket(receiver, listener, 0).unwrap();
        let first = eventfd(sender, 3, 0).unwrap();
        let second = eventfd(sender, 5, 0).unwrap();
        let second_lease = acquire_descriptor(sender, second).unwrap();
        let OpenObjectKind::EventFd(second_backend) = second_lease.kind else {
            panic!("expected event descriptor");
        };
        release_lease(second_lease);
        assert_eq!(
            send_socket_with_rights(sender, client, b"T", 0, &[first, second]),
            Ok(1)
        );
        close(sender, first).unwrap();
        close(sender, second).unwrap();

        let mut byte = [0_u8; 1];
        let mut received = [0_u32; 1];
        let message =
            receive_socket_with_rights(receiver, server, &mut byte, 0, false, &mut received)
                .unwrap();
        assert_eq!(message.descriptor_count, 1);
        assert!(message.control_truncated);
        assert_eq!(
            crate::linux_eventfd::read(sender.pid, second_backend),
            Err(crate::linux_eventfd::EventFdError::BadFileDescriptor)
        );

        cleanup(sender);
        cleanup(receiver);
    }
}
