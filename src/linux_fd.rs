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
pub const FD_CLOEXEC: u32 = 1;

const MAXIMUM_DESCRIPTOR_SPACES: usize = crate::process::lifecycle::MAXIMUM_PROCESSES;
const MAXIMUM_OPEN_OBJECTS: usize = MAXIMUM_FILE_DESCRIPTORS;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenObjectKind {
    Empty,
    ConsoleInput,
    ConsoleOutput,
    ConsoleError,
    File(u32),
    EventFd(u32),
    TimerFd(u32),
    Epoll(u32),
    PipeRead(u32),
    PipeWrite(u32),
    UnixSocket(u32),
}

impl OpenObjectKind {
    const fn occupied(self) -> bool {
        !matches!(self, Self::Empty)
    }
}

#[derive(Clone, Copy)]
struct OpenObject {
    generation: u32,
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
        references: 0,
        descriptor_references: 0,
        active_operations: 0,
        closing: false,
        status_flags: 0,
        kind: OpenObjectKind::Empty,
    };

    fn take_kind(&mut self) -> OpenObjectKind {
        let kind = self.kind;
        self.references = 0;
        self.descriptor_references = 0;
        self.active_operations = 0;
        self.closing = false;
        self.status_flags = 0;
        self.kind = OpenObjectKind::Empty;
        kind
    }
}

#[derive(Clone, Copy)]
struct DescriptorSlot {
    object: u16,
    flags: u8,
}

impl DescriptorSlot {
    const EMPTY: Self = Self {
        object: u16::MAX,
        flags: 0,
    };

    const fn occupied(self) -> bool {
        self.object != u16::MAX
    }
}

#[derive(Clone, Copy)]
struct DescriptorSpace {
    owner: ProcessHandle,
    retiring: bool,
    descriptors: [DescriptorSlot; MAXIMUM_FILE_DESCRIPTORS],
    objects: [OpenObject; MAXIMUM_OPEN_OBJECTS],
}

impl DescriptorSpace {
    const EMPTY: Self = Self {
        owner: ProcessHandle {
            pid: 0,
            generation: 0,
        },
        retiring: false,
        descriptors: [DescriptorSlot::EMPTY; MAXIMUM_FILE_DESCRIPTORS],
        objects: [OpenObject::EMPTY; MAXIMUM_OPEN_OBJECTS],
    };

    const fn occupied(&self) -> bool {
        self.owner.pid != 0 && self.owner.generation != 0
    }

    fn object_for_descriptor(&self, fd: u32) -> Option<(usize, &OpenObject)> {
        let descriptor = *self.descriptors.get(fd as usize)?;
        if !descriptor.occupied() {
            return None;
        }
        let index = descriptor.object as usize;
        let object = self.objects.get(index)?;
        object.kind.occupied().then_some((index, object))
    }

    fn is_reclaimable(&self) -> bool {
        self.descriptors.iter().all(|slot| !slot.occupied())
            && self.objects.iter().all(|object| !object.kind.occupied())
    }
}

static SPACES: SpinLock<[DescriptorSpace; MAXIMUM_DESCRIPTOR_SPACES]> =
    SpinLock::new([DescriptorSpace::EMPTY; MAXIMUM_DESCRIPTOR_SPACES]);

#[derive(Clone, Copy)]
struct ObjectLease {
    key: ObjectKey,
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
    space: &mut DescriptorSpace,
    kind: OpenObjectKind,
    status_flags: u32,
) -> Result<usize, DescriptorError> {
    let index = space
        .objects
        .iter()
        .position(|object| !object.kind.occupied())
        .ok_or(DescriptorError::Capacity)?;
    let generation = space.objects[index]
        .generation
        .checked_add(1)
        .filter(|generation| *generation != 0)
        .ok_or(DescriptorError::Capacity)?;
    space.objects[index] = OpenObject {
        generation,
        references: 0,
        descriptor_references: 0,
        active_operations: 0,
        closing: false,
        status_flags,
        kind,
    };
    Ok(index)
}

fn initialize_standard_descriptors(space: &mut DescriptorSpace) -> Result<(), DescriptorError> {
    let standard = [
        (OpenObjectKind::ConsoleInput, crate::linux_file::O_RDONLY),
        (OpenObjectKind::ConsoleOutput, crate::linux_file::O_WRONLY),
        (OpenObjectKind::ConsoleError, crate::linux_file::O_WRONLY),
    ];
    for (fd, (kind, status_flags)) in standard.into_iter().enumerate() {
        let object_index = match allocate_object(space, kind, status_flags) {
            Ok(index) => index,
            Err(error) => {
                for descriptor in &mut space.descriptors[..fd] {
                    let object_index = descriptor.object as usize;
                    *descriptor = DescriptorSlot::EMPTY;
                    space.objects[object_index].take_kind();
                }
                return Err(error);
            }
        };
        space.objects[object_index].references = 1;
        space.objects[object_index].descriptor_references = 1;
        space.descriptors[fd] = DescriptorSlot {
            object: object_index as u16,
            flags: 0,
        };
    }
    Ok(())
}

fn ensure_space(
    spaces: &mut [DescriptorSpace; MAXIMUM_DESCRIPTOR_SPACES],
    owner: ProcessHandle,
) -> Result<usize, DescriptorError> {
    if !valid_owner(owner) {
        return Err(DescriptorError::PermissionDenied);
    }
    if let Some(index) = find_space(spaces, owner) {
        return Ok(index);
    }
    let index = spaces
        .iter()
        .position(|space| !space.occupied())
        .ok_or(DescriptorError::Capacity)?;
    spaces[index].owner = owner;
    spaces[index].retiring = false;
    if initialize_standard_descriptors(&mut spaces[index]).is_err() {
        spaces[index].owner = DescriptorSpace::EMPTY.owner;
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
    let mut spaces = SPACES.lock();
    let space_index = ensure_space(&mut spaces, owner)?;
    let space = &mut spaces[space_index];
    let fd = space
        .descriptors
        .iter()
        .enumerate()
        .find(|(_, descriptor)| !descriptor.occupied())
        .map(|(index, _)| index)
        .ok_or(DescriptorError::Capacity)?;
    let object_index = allocate_object(space, kind, status_flags)?;
    space.objects[object_index].references = 1;
    space.objects[object_index].descriptor_references = 1;
    space.descriptors[fd] = DescriptorSlot {
        object: object_index as u16,
        flags: u8::from(close_on_exec),
    };
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
    let mut spaces = SPACES.lock();
    let space_index = ensure_space(&mut spaces, owner)?;
    let space = &mut spaces[space_index];
    let mut free_descriptors = space
        .descriptors
        .iter()
        .enumerate()
        .filter(|(_, descriptor)| !descriptor.occupied())
        .map(|(index, _)| index);
    let first_fd = free_descriptors.next().ok_or(DescriptorError::Capacity)?;
    let second_fd = free_descriptors.next().ok_or(DescriptorError::Capacity)?;
    let mut free_objects = space
        .objects
        .iter()
        .enumerate()
        .filter(|(_, object)| !object.kind.occupied())
        .map(|(index, _)| index);
    let first_object = free_objects.next().ok_or(DescriptorError::Capacity)?;
    let second_object = free_objects.next().ok_or(DescriptorError::Capacity)?;
    let first_generation = space.objects[first_object]
        .generation
        .checked_add(1)
        .filter(|generation| *generation != 0)
        .ok_or(DescriptorError::Capacity)?;
    let second_generation = space.objects[second_object]
        .generation
        .checked_add(1)
        .filter(|generation| *generation != 0)
        .ok_or(DescriptorError::Capacity)?;

    space.objects[first_object] = OpenObject {
        generation: first_generation,
        references: 1,
        descriptor_references: 1,
        active_operations: 0,
        closing: false,
        status_flags: first_status_flags,
        kind: first_kind,
    };
    space.objects[second_object] = OpenObject {
        generation: second_generation,
        references: 1,
        descriptor_references: 1,
        active_operations: 0,
        closing: false,
        status_flags: second_status_flags,
        kind: second_kind,
    };
    let descriptor_flags = u8::from(close_on_exec);
    space.descriptors[first_fd] = DescriptorSlot {
        object: first_object as u16,
        flags: descriptor_flags,
    };
    space.descriptors[second_fd] = DescriptorSlot {
        object: second_object as u16,
        flags: descriptor_flags,
    };
    Ok((first_fd as u32, second_fd as u32))
}

fn acquire_descriptor(owner: ProcessHandle, fd: u32) -> Result<ObjectLease, DescriptorError> {
    let mut spaces = SPACES.lock();
    let space_index = ensure_space(&mut spaces, owner)?;
    let space = &mut spaces[space_index];
    let descriptor = *space
        .descriptors
        .get(fd as usize)
        .filter(|descriptor| descriptor.occupied())
        .ok_or(DescriptorError::BadFileDescriptor)?;
    let object_index = descriptor.object as usize;
    let object = space
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
        kind: object.kind,
        status_flags: object.status_flags,
    })
}

fn acquire_key(owner: ProcessHandle, key: ObjectKey) -> Result<ObjectLease, DescriptorError> {
    let object_index = key.index().ok_or(DescriptorError::BadFileDescriptor)?;
    let mut spaces = SPACES.lock();
    let space_index = find_space(&spaces, owner).ok_or(DescriptorError::BadFileDescriptor)?;
    let object = spaces[space_index]
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
        kind: object.kind,
        status_flags: object.status_flags,
    })
}

fn maybe_take_closing(object: &mut OpenObject) -> Option<OpenObjectKind> {
    if object.closing && object.references == 0 && object.active_operations == 0 {
        Some(object.take_kind())
    } else {
        None
    }
}

fn release_lease(owner: ProcessHandle, lease: ObjectLease) {
    let pending = {
        let mut spaces = SPACES.lock();
        let Some(space_index) = find_space(&spaces, owner) else {
            return;
        };
        let Some(object_index) = lease.key.index() else {
            return;
        };
        let object = &mut spaces[space_index].objects[object_index];
        if object.generation != lease.key.generation || object.active_operations == 0 {
            return;
        }
        object.active_operations -= 1;
        let pending = maybe_take_closing(object);
        if spaces[space_index].retiring && spaces[space_index].is_reclaimable() {
            spaces[space_index].owner = DescriptorSpace::EMPTY.owner;
            spaces[space_index].retiring = false;
        }
        pending
    };
    if let Some(kind) = pending {
        finalize_object(owner, kind);
    }
}

fn retain_key(owner: ProcessHandle, key: ObjectKey) -> Result<(), DescriptorError> {
    let object_index = key.index().ok_or(DescriptorError::BadFileDescriptor)?;
    let mut spaces = SPACES.lock();
    let space_index = find_space(&spaces, owner).ok_or(DescriptorError::BadFileDescriptor)?;
    let object = spaces[space_index]
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

fn drop_key_reference(owner: ProcessHandle, key: ObjectKey) {
    let pending = {
        let mut spaces = SPACES.lock();
        let Some(space_index) = find_space(&spaces, owner) else {
            return;
        };
        let Some(object_index) = key.index() else {
            return;
        };
        let object = &mut spaces[space_index].objects[object_index];
        if object.generation != key.generation || object.references == 0 {
            return;
        }
        object.references -= 1;
        if object.references == 0 {
            object.closing = true;
        }
        let pending = maybe_take_closing(object);
        if spaces[space_index].retiring && spaces[space_index].is_reclaimable() {
            spaces[space_index].owner = DescriptorSpace::EMPTY.owner;
            spaces[space_index].retiring = false;
        }
        pending
    };
    if let Some(kind) = pending {
        finalize_object(owner, kind);
    }
}

fn detach_epoll_watches(owner: ProcessHandle, key: ObjectKey) {
    let detached = crate::linux_epoll::remove_target(owner, key);
    for _ in 0..detached {
        drop_key_reference(owner, key);
    }
}

fn finalize_object(owner: ProcessHandle, kind: OpenObjectKind) {
    match kind {
        OpenObjectKind::Empty
        | OpenObjectKind::ConsoleInput
        | OpenObjectKind::ConsoleOutput
        | OpenObjectKind::ConsoleError => {}
        OpenObjectKind::File(fd) => {
            let _ = crate::linux_file::close(owner, fd);
        }
        OpenObjectKind::EventFd(fd) => {
            let _ = crate::linux_eventfd::close(owner.pid, fd);
        }
        OpenObjectKind::TimerFd(fd) => {
            let _ = crate::linux_timerfd::close(owner.pid, fd);
        }
        OpenObjectKind::PipeRead(handle) | OpenObjectKind::PipeWrite(handle) => {
            let _ = crate::linux_pipe::close(owner, handle);
        }
        OpenObjectKind::UnixSocket(handle) => {
            let _ = crate::linux_socket::close(owner, handle);
        }
        OpenObjectKind::Epoll(fd) => {
            let mut watched = [ObjectKey::EMPTY; crate::linux_epoll::MAXIMUM_EPOLL_WATCHES];
            if let Ok(count) = crate::linux_epoll::close(owner, fd, &mut watched) {
                for key in watched[..count].iter().copied() {
                    drop_key_reference(owner, key);
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
    let backend = crate::linux_socket::create(owner, domain, socket_type, protocol)
        .map_err(map_socket_error)?;
    let status_flags = crate::linux_file::O_RDWR
        | if socket_type & crate::linux_socket::SOCK_NONBLOCK != 0 {
            crate::linux_file::O_NONBLOCK
        } else {
            0
        };
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
    with_socket(owner, fd, |backend| {
        crate::linux_socket::bind(owner, backend, address)
    })
}

pub fn listen_socket(owner: ProcessHandle, fd: u32, backlog: usize) -> Result<(), DescriptorError> {
    with_socket(owner, fd, |backend| {
        crate::linux_socket::listen(owner, backend, backlog)
    })
}

pub fn connect_socket(
    owner: ProcessHandle,
    fd: u32,
    address: crate::linux_socket::UnixAddress,
) -> Result<(), DescriptorError> {
    with_socket(owner, fd, |backend| {
        crate::linux_socket::connect(owner, backend, address)
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
    let accepted = match lease.kind {
        OpenObjectKind::UnixSocket(backend) => {
            crate::linux_socket::accept(owner, backend).map_err(map_socket_error)
        }
        _ => Err(DescriptorError::NotSocket),
    };
    release_lease(owner, lease);
    let (backend, peer) = accepted?;
    let status_flags = crate::linux_file::O_RDWR
        | if flags & crate::linux_socket::SOCK_NONBLOCK != 0 {
            crate::linux_file::O_NONBLOCK
        } else {
            0
        };
    match install_object(
        owner,
        OpenObjectKind::UnixSocket(backend),
        status_flags,
        flags & crate::linux_socket::SOCK_CLOEXEC != 0,
    ) {
        Ok(accepted_fd) => Ok((accepted_fd, peer)),
        Err(error) => {
            let _ = crate::linux_socket::close(owner, backend);
            Err(error)
        }
    }
}

fn with_socket(
    owner: ProcessHandle,
    fd: u32,
    operation: impl FnOnce(u32) -> Result<(), crate::linux_socket::SocketError>,
) -> Result<(), DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::UnixSocket(backend) => operation(backend).map_err(map_socket_error),
        _ => Err(DescriptorError::NotSocket),
    };
    release_lease(owner, lease);
    result
}

pub fn validate_socket(owner: ProcessHandle, fd: u32) -> Result<(), DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::UnixSocket(_) => Ok(()),
        _ => Err(DescriptorError::NotSocket),
    };
    release_lease(owner, lease);
    result
}

pub fn shutdown_socket(owner: ProcessHandle, fd: u32, how: u32) -> Result<(), DescriptorError> {
    with_socket(owner, fd, |backend| {
        crate::linux_socket::shutdown(owner, backend, how)
    })
}

pub fn socket_local_address(
    owner: ProcessHandle,
    fd: u32,
) -> Result<crate::linux_socket::UnixAddress, DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::UnixSocket(backend) => {
            crate::linux_socket::local_address(owner, backend).map_err(map_socket_error)
        }
        _ => Err(DescriptorError::NotSocket),
    };
    release_lease(owner, lease);
    result
}

pub fn socket_peer_address(
    owner: ProcessHandle,
    fd: u32,
) -> Result<crate::linux_socket::UnixAddress, DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::UnixSocket(backend) => {
            crate::linux_socket::peer_address(owner, backend).map_err(map_socket_error)
        }
        _ => Err(DescriptorError::NotSocket),
    };
    release_lease(owner, lease);
    result
}

pub fn socket_peer_credentials(
    owner: ProcessHandle,
    fd: u32,
) -> Result<crate::linux_socket::PeerCredentials, DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::UnixSocket(backend) => {
            crate::linux_socket::peer_credentials(owner, backend).map_err(map_socket_error)
        }
        _ => Err(DescriptorError::NotSocket),
    };
    release_lease(owner, lease);
    result
}

pub fn socket_is_listener(owner: ProcessHandle, fd: u32) -> Result<bool, DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = match lease.kind {
        OpenObjectKind::UnixSocket(backend) => {
            crate::linux_socket::is_listener(owner, backend).map_err(map_socket_error)
        }
        _ => Err(DescriptorError::NotSocket),
    };
    release_lease(owner, lease);
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
            crate::linux_socket::send(owner, backend, input, flags).map_err(map_socket_error)
        }
        _ => Err(DescriptorError::NotSocket),
    };
    release_lease(owner, lease);
    result
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
            crate::linux_socket::receive(owner, backend, output, flags).map_err(map_socket_error)
        }
        _ => Err(DescriptorError::NotSocket),
    };
    release_lease(owner, lease);
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
            crate::linux_file::read(owner, backend, output).map_err(map_file_error)
        }
        OpenObjectKind::EventFd(backend) => {
            if output.len() != core::mem::size_of::<u64>() {
                Err(DescriptorError::InvalidArgument)
            } else {
                crate::linux_eventfd::read(owner.pid, backend)
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
                crate::linux_timerfd::read(owner.pid, backend, now_ns)
                    .map(|value| {
                        output.copy_from_slice(&value.to_ne_bytes());
                        output.len()
                    })
                    .map_err(map_timerfd_error)
            }
        }
        OpenObjectKind::PipeRead(handle) => {
            crate::linux_pipe::read(owner, handle, output).map_err(map_pipe_error)
        }
        OpenObjectKind::UnixSocket(handle) => {
            crate::linux_socket::read(owner, handle, output).map_err(map_socket_error)
        }
        _ => Err(DescriptorError::BadFileDescriptor),
    };
    release_lease(owner, lease);
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
        OpenObjectKind::File(backend) => crate::linux_file::write(owner, backend, input, now)
            .map(WriteResult::Bytes)
            .map_err(map_file_error),
        OpenObjectKind::EventFd(backend) => {
            if input.len() != core::mem::size_of::<u64>() {
                Err(DescriptorError::InvalidArgument)
            } else {
                let value = u64::from_ne_bytes(input.try_into().unwrap());
                crate::linux_eventfd::write(owner.pid, backend, value)
                    .map(|()| WriteResult::Bytes(input.len()))
                    .map_err(map_eventfd_error)
            }
        }
        OpenObjectKind::PipeWrite(handle) => crate::linux_pipe::write(owner, handle, input)
            .map(WriteResult::Bytes)
            .map_err(map_pipe_error),
        OpenObjectKind::UnixSocket(handle) => crate::linux_socket::write(owner, handle, input)
            .map(WriteResult::Bytes)
            .map_err(map_socket_error),
        _ => Err(DescriptorError::BadFileDescriptor),
    };
    release_lease(owner, lease);
    result
}

pub fn close(owner: ProcessHandle, fd: u32) -> Result<(), DescriptorError> {
    let (pending, detached) = {
        let mut spaces = SPACES.lock();
        let space_index = ensure_space(&mut spaces, owner)?;
        let space = &mut spaces[space_index];
        let descriptor = *space
            .descriptors
            .get(fd as usize)
            .filter(|descriptor| descriptor.occupied())
            .ok_or(DescriptorError::BadFileDescriptor)?;
        let object_index = descriptor.object as usize;
        if space.objects[object_index].references == 0
            || space.objects[object_index].descriptor_references == 0
        {
            return Err(DescriptorError::BadFileDescriptor);
        }
        space.descriptors[fd as usize] = DescriptorSlot::EMPTY;
        let object = &mut space.objects[object_index];
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
        detach_epoll_watches(owner, key);
    }
    if let Some(kind) = pending {
        finalize_object(owner, kind);
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
    let mut spaces = SPACES.lock();
    let space_index = ensure_space(&mut spaces, owner)?;
    let space = &mut spaces[space_index];
    let (object_index, object) = space
        .object_for_descriptor(old_fd)
        .ok_or(DescriptorError::BadFileDescriptor)?;
    let generation = object.generation;
    let target = space
        .descriptors
        .iter()
        .enumerate()
        .skip(minimum as usize)
        .find(|(_, descriptor)| !descriptor.occupied())
        .map(|(index, _)| index)
        .ok_or(DescriptorError::Capacity)?;
    let object = &mut space.objects[object_index];
    if object.generation != generation || object.closing {
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
    space.descriptors[target] = DescriptorSlot {
        object: object_index as u16,
        flags: u8::from(close_on_exec),
    };
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
            release_lease(owner, lease);
            Ok(new_fd)
        };
    }

    let (pending, detached) = {
        let mut spaces = SPACES.lock();
        let space_index = ensure_space(&mut spaces, owner)?;
        let space = &mut spaces[space_index];
        let source = *space
            .descriptors
            .get(old_fd as usize)
            .filter(|descriptor| descriptor.occupied())
            .ok_or(DescriptorError::BadFileDescriptor)?;
        let source_index = source.object as usize;
        if !space.objects[source_index].kind.occupied() || space.objects[source_index].closing {
            return Err(DescriptorError::BadFileDescriptor);
        }

        let existing = space.descriptors[new_fd as usize];
        let mut pending = None;
        let mut detached = None;
        if existing.occupied() {
            let existing_index = existing.object as usize;
            if existing_index != source_index {
                let existing_object = &space.objects[existing_index];
                if existing_object.references == 0 || existing_object.descriptor_references == 0 {
                    return Err(DescriptorError::BadFileDescriptor);
                }
                let source_references = space.objects[source_index]
                    .references
                    .checked_add(1)
                    .ok_or(DescriptorError::Capacity)?;
                let source_descriptor_references = space.objects[source_index]
                    .descriptor_references
                    .checked_add(1)
                    .ok_or(DescriptorError::Capacity)?;
                space.objects[source_index].references = source_references;
                space.objects[source_index].descriptor_references = source_descriptor_references;
                let object = &mut space.objects[existing_index];
                object.references -= 1;
                object.descriptor_references -= 1;
                if object.descriptor_references == 0 {
                    object.closing = true;
                    detached = Some(ObjectKey::new(existing_index, object.generation));
                }
                pending = maybe_take_closing(object);
            }
        } else {
            let references = space.objects[source_index]
                .references
                .checked_add(1)
                .ok_or(DescriptorError::Capacity)?;
            let descriptor_references = space.objects[source_index]
                .descriptor_references
                .checked_add(1)
                .ok_or(DescriptorError::Capacity)?;
            space.objects[source_index].references = references;
            space.objects[source_index].descriptor_references = descriptor_references;
        }
        space.descriptors[new_fd as usize] = DescriptorSlot {
            object: source_index as u16,
            flags: u8::from(close_on_exec),
        };
        (pending, detached)
    };
    if let Some(key) = detached {
        detach_epoll_watches(owner, key);
    }
    if let Some(kind) = pending {
        finalize_object(owner, kind);
    }
    Ok(new_fd)
}

pub fn descriptor_flags(owner: ProcessHandle, fd: u32) -> Result<u32, DescriptorError> {
    let mut spaces = SPACES.lock();
    let space_index = ensure_space(&mut spaces, owner)?;
    let descriptor = *spaces[space_index]
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
    let mut spaces = SPACES.lock();
    let space_index = ensure_space(&mut spaces, owner)?;
    let descriptor = spaces[space_index]
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
    release_lease(owner, lease);
    Ok(flags)
}

pub fn set_status_flags(
    owner: ProcessHandle,
    fd: u32,
    requested: u32,
) -> Result<(), DescriptorError> {
    const MUTABLE: u32 = crate::linux_file::O_NONBLOCK;
    let mut spaces = SPACES.lock();
    let space_index = ensure_space(&mut spaces, owner)?;
    let descriptor = *spaces[space_index]
        .descriptors
        .get(fd as usize)
        .filter(|descriptor| descriptor.occupied())
        .ok_or(DescriptorError::BadFileDescriptor)?;
    let object = &mut spaces[space_index].objects[descriptor.object as usize];
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
            crate::linux_file::seek(owner, backend, offset, whence).map_err(map_file_error)
        }
        _ => Err(DescriptorError::IllegalSeek),
    };
    release_lease(owner, lease);
    result
}

pub fn metadata(owner: ProcessHandle, fd: u32) -> Result<DescriptorMetadata, DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let inode = object_inode(owner, lease.key);
    let result = match lease.kind {
        OpenObjectKind::File(backend) => crate::linux_file::fstat(owner, backend)
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
        OpenObjectKind::PipeRead(_) | OpenObjectKind::PipeWrite(_) => Ok(DescriptorMetadata {
            mode: 0o010_600,
            size_bytes: 0,
            created_ticks: 0,
            modified_ticks: 0,
            inode,
        }),
        OpenObjectKind::UnixSocket(_) => Ok(DescriptorMetadata {
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
        OpenObjectKind::EventFd(_) | OpenObjectKind::TimerFd(_) | OpenObjectKind::Epoll(_) => {
            Ok(DescriptorMetadata {
                mode: 0o100_600,
                size_bytes: 0,
                created_ticks: 0,
                modified_ticks: 0,
                inode,
            })
        }
        OpenObjectKind::Empty => Err(DescriptorError::BadFileDescriptor),
    };
    release_lease(owner, lease);
    result
}

fn object_inode(owner: ProcessHandle, key: ObjectKey) -> u64 {
    let index = key.index().unwrap_or(0) as u64 + 1;
    ((u64::from(owner.generation) << 32) ^ (u64::from(key.generation) << 8) ^ index).max(1)
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
            crate::linux_file::snapshot_range(owner, backend, offset, output)
                .map_err(map_file_error)
        }
        _ => Err(DescriptorError::BadFileDescriptor),
    };
    release_lease(owner, lease);
    result
}

fn readiness_for_lease(
    owner: ProcessHandle,
    lease: ObjectLease,
    now_ns: u64,
    allow_epoll: bool,
) -> Result<(u32, u64), DescriptorError> {
    match lease.kind {
        OpenObjectKind::ConsoleInput => Ok((0, u64::from(lease.key.generation))),
        OpenObjectKind::ConsoleOutput | OpenObjectKind::ConsoleError => {
            Ok((READY_OUT, u64::from(lease.key.generation)))
        }
        OpenObjectKind::File(backend) => crate::linux_file::readiness(owner, backend)
            .map(|ready| (ready, u64::from(lease.key.generation)))
            .map_err(map_file_error),
        OpenObjectKind::EventFd(backend) => {
            let ready =
                crate::linux_eventfd::readiness(owner.pid, backend).map_err(map_eventfd_error)?;
            let generation = crate::linux_eventfd::readiness_generation(owner.pid, backend)
                .map_err(map_eventfd_error)?;
            Ok((ready, generation))
        }
        OpenObjectKind::TimerFd(backend) => {
            let ready = crate::linux_timerfd::readiness(owner.pid, backend, now_ns)
                .map_err(map_timerfd_error)?;
            let generation = crate::linux_timerfd::readiness_generation(owner.pid, backend, now_ns)
                .map_err(map_timerfd_error)?;
            Ok((ready, generation))
        }
        OpenObjectKind::PipeRead(handle) | OpenObjectKind::PipeWrite(handle) => {
            let ready = crate::linux_pipe::readiness(owner, handle).map_err(map_pipe_error)?;
            let generation =
                crate::linux_pipe::readiness_generation(owner, handle).map_err(map_pipe_error)?;
            Ok((ready, generation))
        }
        OpenObjectKind::UnixSocket(handle) => {
            let ready = crate::linux_socket::readiness(owner, handle).map_err(map_socket_error)?;
            let generation = crate::linux_socket::readiness_generation(owner, handle)
                .map_err(map_socket_error)?;
            Ok((ready, generation))
        }
        OpenObjectKind::Epoll(backend) if allow_epoll => {
            crate::linux_epoll::readiness(owner, backend)
                .map(|ready| (ready, u64::from(lease.key.generation)))
                .map_err(map_epoll_error)
        }
        _ => Err(DescriptorError::InvalidArgument),
    }
}

pub fn readiness(owner: ProcessHandle, fd: u32, now_ns: u64) -> Result<u32, DescriptorError> {
    let lease = acquire_descriptor(owner, fd)?;
    let result = readiness_for_lease(owner, lease, now_ns, true).map(|value| value.0);
    release_lease(owner, lease);
    result
}

/// Readiness bridge used by epoll watches. Nested epoll objects are rejected,
/// preventing recursive watch graphs while the bounded first profile is in
/// force.
pub(crate) fn readiness_by_key(
    owner: ProcessHandle,
    key: ObjectKey,
) -> Result<(u32, u64), DescriptorError> {
    let lease = acquire_key(owner, key)?;
    let result = readiness_for_lease(owner, lease, monotonic_now_ns(), false);
    release_lease(owner, lease);
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
            crate::linux_timerfd::settime(owner.pid, backend, flags, value, now_ns)
                .map_err(map_timerfd_error)
        }
        _ => Err(DescriptorError::BadFileDescriptor),
    };
    release_lease(owner, lease);
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
            crate::linux_timerfd::gettime(owner.pid, backend, now_ns).map_err(map_timerfd_error)
        }
        _ => Err(DescriptorError::BadFileDescriptor),
    };
    release_lease(owner, lease);
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
            release_lease(owner, epoll_lease);
            return Err(error);
        }
    };
    let OpenObjectKind::Epoll(backend) = epoll_lease.kind else {
        release_lease(owner, target_lease);
        release_lease(owner, epoll_lease);
        return Err(DescriptorError::BadFileDescriptor);
    };
    if matches!(target_lease.kind, OpenObjectKind::File(_)) {
        release_lease(owner, target_lease);
        release_lease(owner, epoll_lease);
        return Err(DescriptorError::OperationNotPermitted);
    }
    if matches!(target_lease.kind, OpenObjectKind::Epoll(_)) || target_lease.key == epoll_lease.key
    {
        release_lease(owner, target_lease);
        release_lease(owner, epoll_lease);
        return Err(DescriptorError::InvalidArgument);
    }

    let result = crate::linux_epoll::ctl(owner, backend, operation, target_lease.key, events, data)
        .map_err(map_epoll_error);
    if result.is_ok() {
        match operation {
            crate::linux_epoll::EPOLL_CTL_ADD => {
                if retain_key(owner, target_lease.key).is_err() {
                    let _ = crate::linux_epoll::ctl(
                        owner,
                        backend,
                        crate::linux_epoll::EPOLL_CTL_DEL,
                        target_lease.key,
                        0,
                        0,
                    );
                    release_lease(owner, target_lease);
                    release_lease(owner, epoll_lease);
                    return Err(DescriptorError::Capacity);
                }
            }
            crate::linux_epoll::EPOLL_CTL_DEL => drop_key_reference(owner, target_lease.key),
            _ => {}
        }
    }
    release_lease(owner, target_lease);
    release_lease(owner, epoll_lease);
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
            crate::linux_epoll::wait(owner, backend, output).map_err(map_epoll_error)
        }
        _ => Err(DescriptorError::BadFileDescriptor),
    };
    release_lease(owner, lease);
    result
}

pub fn close_on_exec(owner: ProcessHandle) -> usize {
    close_matching(owner, true)
}

pub fn close_all(owner: ProcessHandle) -> usize {
    close_matching(owner, false)
}

fn close_matching(owner: ProcessHandle, only_close_on_exec: bool) -> usize {
    let mut pending = [OpenObjectKind::Empty; MAXIMUM_OPEN_OBJECTS];
    let mut detached = [ObjectKey::EMPTY; MAXIMUM_OPEN_OBJECTS];
    let (closed, pending_count, detached_count) = {
        let mut spaces = SPACES.lock();
        let Some(space_index) = find_space(&spaces, owner) else {
            return 0;
        };
        let space = &mut spaces[space_index];
        if !only_close_on_exec {
            space.retiring = true;
        }
        let mut closed = 0;
        let mut pending_count = 0;
        let mut detached_count = 0;
        for descriptor in &mut space.descriptors {
            if !descriptor.occupied()
                || only_close_on_exec && descriptor.flags & FD_CLOEXEC as u8 == 0
            {
                continue;
            }
            let object_index = descriptor.object as usize;
            *descriptor = DescriptorSlot::EMPTY;
            let object = &mut space.objects[object_index];
            object.references = object.references.saturating_sub(1);
            object.descriptor_references = object.descriptor_references.saturating_sub(1);
            if object.descriptor_references == 0 {
                object.closing = true;
                detached[detached_count] = ObjectKey::new(object_index, object.generation);
                detached_count += 1;
            }
            if let Some(kind) = maybe_take_closing(object) {
                pending[pending_count] = kind;
                pending_count += 1;
            }
            closed += 1;
        }
        if space.retiring && space.is_reclaimable() {
            space.owner = DescriptorSpace::EMPTY.owner;
            space.retiring = false;
        }
        (closed, pending_count, detached_count)
    };
    for key in detached[..detached_count].iter().copied() {
        detach_epoll_watches(owner, key);
    }
    for kind in pending[..pending_count].iter().copied() {
        finalize_object(owner, kind);
    }
    closed
}

fn map_file_error(error: crate::linux_file::FileError) -> DescriptorError {
    DescriptorError::File(error)
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

fn map_epoll_error(error: crate::linux_epoll::EpollError) -> DescriptorError {
    match error {
        crate::linux_epoll::EpollError::InvalidArgument => DescriptorError::InvalidArgument,
        crate::linux_epoll::EpollError::BadFileDescriptor => DescriptorError::BadFileDescriptor,
        crate::linux_epoll::EpollError::Capacity => DescriptorError::Capacity,
        crate::linux_epoll::EpollError::AlreadyExists => DescriptorError::AlreadyExists,
        crate::linux_epoll::EpollError::NotFound => DescriptorError::NotFound,
    }
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
        let spaces = SPACES.lock();
        assert!(find_space(&spaces, owner).is_none());
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
}
