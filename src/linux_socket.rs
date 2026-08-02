//! Bounded Linux Unix-domain stream sockets.
//!
//! Public descriptors remain owned by `linux_fd`. This module owns a global
//! local-socket namespace, generation-bound endpoint handles, bounded listen
//! queues, and fixed full-duplex byte streams. Named listeners may connect
//! different process generations without granting either side access to the
//! other's descriptor table. Operations that would sleep return `EAGAIN`
//! until scheduler-backed descriptor wait queues are qualified.
//!
//! Pathname and abstract names currently live in this private namespace;
//! pathname sockets do not yet materialize Akashic VFS inodes. Datagram and
//! sequenced-packet modes, explicit credential messages, and scheduler-backed
//! blocking waits remain explicit later contracts.

use crate::linux_eventfd::{READY_ERR, READY_HUP, READY_IN, READY_OUT};
use crate::process::lifecycle::ProcessHandle;
use crate::sync::SpinLock;

pub const AF_UNIX: u32 = 1;
pub const SOCK_STREAM: u32 = 1;
pub const SOCK_NONBLOCK: u32 = 0x800;
pub const SOCK_CLOEXEC: u32 = 0x80000;
pub const SOCKET_TYPE_MASK: u32 = 0xf;
pub const SOCKET_ALLOWED_FLAGS: u32 = SOCK_NONBLOCK | SOCK_CLOEXEC;

pub const SHUT_RD: u32 = 0;
pub const SHUT_WR: u32 = 1;
pub const SHUT_RDWR: u32 = 2;

pub const MSG_PEEK: u32 = 0x2;
pub const MSG_DONTWAIT: u32 = 0x40;
pub const MSG_NOSIGNAL: u32 = 0x4000;
pub const SEND_FLAGS: u32 = MSG_DONTWAIT | MSG_NOSIGNAL;
pub const RECEIVE_FLAGS: u32 = MSG_PEEK | MSG_DONTWAIT;

pub const UNIX_PATH_BYTES: usize = 108;
pub const SOCKET_BUFFER_BYTES: usize = 4096;
pub const MAXIMUM_LISTEN_BACKLOG: usize = 8;
pub const MAXIMUM_RIGHTS_RECORDS: usize = 8;
const MAXIMUM_ENDPOINTS: usize = 64;
const MAXIMUM_CONNECTIONS: usize = 32;
const ENDPOINT_INDEX_BITS: u32 = 8;
const ENDPOINT_INDEX_MASK: u32 = (1 << ENDPOINT_INDEX_BITS) - 1;
const MAXIMUM_ENDPOINT_GENERATION: u32 = u32::MAX >> ENDPOINT_INDEX_BITS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketError {
    InvalidArgument,
    BadFileDescriptor,
    AddressFamilyNotSupported,
    AddressInUse,
    ConnectionRefused,
    AlreadyConnected,
    NotConnected,
    WouldBlock,
    BrokenPipe,
    Capacity,
    OperationNotSupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnixAddress {
    bytes: [u8; UNIX_PATH_BYTES],
    length: u8,
}

impl UnixAddress {
    pub const UNNAMED: Self = Self {
        bytes: [0; UNIX_PATH_BYTES],
        length: 0,
    };

    pub fn new(path: &[u8]) -> Result<Self, SocketError> {
        if path.is_empty() || path.len() > UNIX_PATH_BYTES {
            return Err(SocketError::InvalidArgument);
        }
        let mut address = Self::UNNAMED;
        address.bytes[..path.len()].copy_from_slice(path);
        address.length = path.len() as u8;
        Ok(address)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.length)]
    }

    pub const fn is_unnamed(self) -> bool {
        self.length == 0
    }

    pub fn is_abstract(self) -> bool {
        self.length != 0 && self.bytes[0] == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCredentials {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum EndpointState {
    Unbound = 0,
    Bound = 1,
    Listening = 2,
    Connected = 3,
}

#[derive(Clone, Copy)]
struct EndpointSlot {
    occupied: bool,
    generation: u32,
    owner: ProcessHandle,
    state: EndpointState,
    address: UnixAddress,
    connection_index: u8,
    connection_generation: u32,
    side: u8,
    backlog: u8,
    pending_head: u8,
    pending_length: u8,
    pending: [u32; MAXIMUM_LISTEN_BACKLOG],
    readiness_generation: u64,
}

impl EndpointSlot {
    const EMPTY: Self = Self {
        occupied: false,
        generation: 0,
        owner: ProcessHandle {
            pid: 0,
            generation: 0,
        },
        state: EndpointState::Unbound,
        address: UnixAddress::UNNAMED,
        connection_index: u8::MAX,
        connection_generation: 0,
        side: 0,
        backlog: 0,
        pending_head: 0,
        pending_length: 0,
        pending: [0; MAXIMUM_LISTEN_BACKLOG],
        readiness_generation: 0,
    };
}

struct ByteQueue {
    head: usize,
    length: usize,
    sequence: u64,
    bytes: [u8; SOCKET_BUFFER_BYTES],
}

impl ByteQueue {
    const EMPTY: Self = Self {
        head: 0,
        length: 0,
        sequence: 0,
        bytes: [0; SOCKET_BUFFER_BYTES],
    };

    fn clear(&mut self) {
        self.sequence = self.sequence.wrapping_add(self.length as u64);
        self.head = 0;
        self.length = 0;
        self.bytes.fill(0);
    }

    fn reset(&mut self) {
        self.head = 0;
        self.length = 0;
        self.sequence = 0;
        self.bytes.fill(0);
    }

    fn tail_sequence(&self) -> Option<u64> {
        self.sequence.checked_add(self.length as u64)
    }
}

#[derive(Clone, Copy)]
struct RightsRecord {
    sequence: u64,
    count: u8,
    tokens: [crate::linux_fd::TransferToken; crate::linux_fd::MAXIMUM_TRANSFER_DESCRIPTORS],
}

impl RightsRecord {
    const EMPTY: Self = Self {
        sequence: 0,
        count: 0,
        tokens: [crate::linux_fd::TransferToken::EMPTY;
            crate::linux_fd::MAXIMUM_TRANSFER_DESCRIPTORS],
    };
}

#[derive(Clone, Copy)]
struct RightsQueue {
    head: u8,
    length: u8,
    records: [RightsRecord; MAXIMUM_RIGHTS_RECORDS],
}

impl RightsQueue {
    const EMPTY: Self = Self {
        head: 0,
        length: 0,
        records: [RightsRecord::EMPTY; MAXIMUM_RIGHTS_RECORDS],
    };

    fn push(
        &mut self,
        sequence: u64,
        tokens: &mut [crate::linux_fd::TransferToken],
    ) -> Result<(), SocketError> {
        if tokens.is_empty()
            || tokens.len() > crate::linux_fd::MAXIMUM_TRANSFER_DESCRIPTORS
            || usize::from(self.length) >= MAXIMUM_RIGHTS_RECORDS
            || tokens.iter().any(|token| !token.occupied())
        {
            return Err(SocketError::Capacity);
        }
        let index = (usize::from(self.head) + usize::from(self.length)) % MAXIMUM_RIGHTS_RECORDS;
        let mut record = RightsRecord {
            sequence,
            count: tokens.len() as u8,
            ..RightsRecord::EMPTY
        };
        for (destination, source) in record.tokens.iter_mut().zip(tokens.iter_mut()) {
            *destination = *source;
            *source = crate::linux_fd::TransferToken::EMPTY;
        }
        self.records[index] = record;
        self.length += 1;
        Ok(())
    }

    fn record(&self, offset: usize) -> Option<RightsRecord> {
        if offset >= usize::from(self.length) {
            return None;
        }
        Some(self.records[(usize::from(self.head) + offset) % MAXIMUM_RIGHTS_RECORDS])
    }

    fn pop(&mut self, output: &mut [crate::linux_fd::TransferToken]) -> usize {
        if self.length == 0 {
            return 0;
        }
        let index = usize::from(self.head);
        let mut record = self.records[index];
        let count = usize::from(record.count).min(output.len());
        for (destination, source) in output.iter_mut().zip(record.tokens.iter_mut()).take(count) {
            *destination = *source;
            *source = crate::linux_fd::TransferToken::EMPTY;
        }
        self.records[index] = RightsRecord::EMPTY;
        self.head = ((index + 1) % MAXIMUM_RIGHTS_RECORDS) as u8;
        self.length -= 1;
        count
    }

    fn drain(&mut self, output: &mut [crate::linux_fd::TransferToken]) -> usize {
        let mut count = 0;
        while self.length != 0 {
            count += self.pop(&mut output[count..]);
        }
        self.head = 0;
        count
    }

    fn reset_empty(&mut self) {
        debug_assert_eq!(self.length, 0);
        self.head = 0;
        self.length = 0;
        for record in &mut self.records {
            debug_assert_eq!(record.count, 0);
            record.sequence = 0;
            record.count = 0;
            record.tokens.fill(crate::linux_fd::TransferToken::EMPTY);
        }
    }
}

struct ConnectionSlot {
    occupied: bool,
    generation: u32,
    endpoint_handles: [u32; 2],
    owners: [ProcessHandle; 2],
    addresses: [UnixAddress; 2],
    endpoint_open: [bool; 2],
    read_open: [bool; 2],
    write_open: [bool; 2],
    outgoing: [ByteQueue; 2],
    outgoing_rights: [RightsQueue; 2],
    readiness_generation: u64,
}

impl ConnectionSlot {
    const EMPTY: Self = Self {
        occupied: false,
        generation: 0,
        endpoint_handles: [0; 2],
        owners: [
            ProcessHandle {
                pid: 0,
                generation: 0,
            },
            ProcessHandle {
                pid: 0,
                generation: 0,
            },
        ],
        addresses: [UnixAddress::UNNAMED; 2],
        endpoint_open: [false; 2],
        read_open: [false; 2],
        write_open: [false; 2],
        outgoing: [const { ByteQueue::EMPTY }; 2],
        outgoing_rights: [RightsQueue::EMPTY; 2],
        readiness_generation: 0,
    };

    fn initialize(
        &mut self,
        generation: u32,
        first_handle: u32,
        second_handle: u32,
        first_owner: ProcessHandle,
        second_owner: ProcessHandle,
        first_address: UnixAddress,
        second_address: UnixAddress,
    ) {
        debug_assert!(!self.occupied);
        self.occupied = true;
        self.generation = generation;
        self.endpoint_handles[0] = first_handle;
        self.endpoint_handles[1] = second_handle;
        self.owners[0] = first_owner;
        self.owners[1] = second_owner;
        self.addresses[0] = first_address;
        self.addresses[1] = second_address;
        for side in 0..2 {
            self.endpoint_open[side] = true;
            self.read_open[side] = true;
            self.write_open[side] = true;
            self.outgoing[side].reset();
            self.outgoing_rights[side].reset_empty();
        }
        self.readiness_generation = 1;
    }

    fn reset_preserving_generation(&mut self) {
        self.occupied = false;
        for side in 0..2 {
            self.endpoint_handles[side] = 0;
            self.owners[side] = ProcessHandle {
                pid: 0,
                generation: 0,
            };
            self.addresses[side] = UnixAddress::UNNAMED;
            self.endpoint_open[side] = false;
            self.read_open[side] = false;
            self.write_open[side] = false;
            self.outgoing[side].reset();
            self.outgoing_rights[side].reset_empty();
        }
        self.readiness_generation = 0;
    }
}

struct SocketRegistry {
    endpoints: [EndpointSlot; MAXIMUM_ENDPOINTS],
    connections: [ConnectionSlot; MAXIMUM_CONNECTIONS],
}

impl SocketRegistry {
    const fn new() -> Self {
        Self {
            endpoints: [EndpointSlot::EMPTY; MAXIMUM_ENDPOINTS],
            connections: [const { ConnectionSlot::EMPTY }; MAXIMUM_CONNECTIONS],
        }
    }
}

static REGISTRY: SpinLock<SocketRegistry> = SpinLock::new(SocketRegistry::new());

fn valid_owner(owner: ProcessHandle) -> bool {
    owner.pid != 0 && owner.generation != 0
}

fn next_endpoint_generation(current: u32) -> Option<u32> {
    current
        .checked_add(1)
        .filter(|generation| *generation <= MAXIMUM_ENDPOINT_GENERATION)
}

fn next_connection_generation(current: u32) -> Option<u32> {
    current.checked_add(1).filter(|generation| *generation != 0)
}

fn encode_endpoint(index: usize, generation: u32) -> Option<u32> {
    if index >= MAXIMUM_ENDPOINTS || generation == 0 || generation > MAXIMUM_ENDPOINT_GENERATION {
        return None;
    }
    Some((generation << ENDPOINT_INDEX_BITS) | (index as u32 + 1))
}

fn decode_endpoint(handle: u32) -> Option<(usize, u32)> {
    let encoded_index = handle & ENDPOINT_INDEX_MASK;
    let generation = handle >> ENDPOINT_INDEX_BITS;
    if encoded_index == 0 || generation == 0 {
        return None;
    }
    let index = (encoded_index - 1) as usize;
    (index < MAXIMUM_ENDPOINTS).then_some((index, generation))
}

fn resolved_endpoint(
    registry: &SocketRegistry,
    owner: ProcessHandle,
    handle: u32,
) -> Result<(usize, EndpointSlot), SocketError> {
    let (index, generation) = decode_endpoint(handle).ok_or(SocketError::BadFileDescriptor)?;
    let endpoint = registry.endpoints[index];
    if !endpoint.occupied || endpoint.generation != generation || endpoint.owner != owner {
        return Err(SocketError::BadFileDescriptor);
    }
    Ok((index, endpoint))
}

fn resolved_connection(
    registry: &SocketRegistry,
    endpoint: EndpointSlot,
    handle: u32,
) -> Result<(usize, usize), SocketError> {
    if endpoint.state != EndpointState::Connected {
        return Err(SocketError::NotConnected);
    }
    let connection_index = usize::from(endpoint.connection_index);
    let side = usize::from(endpoint.side);
    let connection = registry
        .connections
        .get(connection_index)
        .filter(|connection| {
            connection.occupied
                && connection.generation == endpoint.connection_generation
                && side < 2
                && connection.endpoint_handles[side] == handle
                && connection.owners[side] == endpoint.owner
        })
        .ok_or(SocketError::BadFileDescriptor)?;
    let _ = connection;
    Ok((connection_index, side))
}

fn advance_generation(generation: &mut u64) {
    *generation = generation.wrapping_add(1);
    if *generation == 0 {
        *generation = 1;
    }
}

fn retire_endpoint(endpoint: &mut EndpointSlot) {
    let generation = endpoint.generation;
    *endpoint = EndpointSlot {
        generation,
        ..EndpointSlot::EMPTY
    };
}

fn retire_connection(
    connection: &mut ConnectionSlot,
    discarded: &mut [crate::linux_fd::TransferToken],
) -> usize {
    let first = connection.outgoing_rights[0].drain(discarded);
    let second = connection.outgoing_rights[1].drain(&mut discarded[first..]);
    connection.reset_preserving_generation();
    first + second
}

fn initialize_endpoint(
    registry: &mut SocketRegistry,
    index: usize,
    owner: ProcessHandle,
) -> Result<u32, SocketError> {
    let generation = next_endpoint_generation(registry.endpoints[index].generation)
        .ok_or(SocketError::Capacity)?;
    let handle = encode_endpoint(index, generation).ok_or(SocketError::Capacity)?;
    registry.endpoints[index] = EndpointSlot {
        occupied: true,
        generation,
        owner,
        readiness_generation: 1,
        ..EndpointSlot::EMPTY
    };
    Ok(handle)
}

fn initialize_connected_endpoint(
    registry: &mut SocketRegistry,
    index: usize,
    owner: ProcessHandle,
    connection_index: usize,
    connection_generation: u32,
    side: usize,
) -> Result<u32, SocketError> {
    let handle = initialize_endpoint(registry, index, owner)?;
    let endpoint = &mut registry.endpoints[index];
    endpoint.state = EndpointState::Connected;
    endpoint.connection_index = connection_index as u8;
    endpoint.connection_generation = connection_generation;
    endpoint.side = side as u8;
    Ok(handle)
}

fn validate_create(domain: u32, socket_type: u32, protocol: u32) -> Result<(), SocketError> {
    if domain != AF_UNIX {
        return Err(SocketError::AddressFamilyNotSupported);
    }
    if socket_type & !(SOCKET_TYPE_MASK | SOCKET_ALLOWED_FLAGS) != 0 {
        return Err(SocketError::InvalidArgument);
    }
    if socket_type & SOCKET_TYPE_MASK != SOCK_STREAM || protocol != 0 {
        return Err(SocketError::OperationNotSupported);
    }
    Ok(())
}

pub fn create(
    owner: ProcessHandle,
    domain: u32,
    socket_type: u32,
    protocol: u32,
) -> Result<u32, SocketError> {
    if !valid_owner(owner) {
        return Err(SocketError::InvalidArgument);
    }
    validate_create(domain, socket_type, protocol)?;
    let mut registry = REGISTRY.lock();
    let index = registry
        .endpoints
        .iter()
        .position(|endpoint| !endpoint.occupied)
        .ok_or(SocketError::Capacity)?;
    initialize_endpoint(&mut registry, index, owner)
}

pub fn create_pair(
    owner: ProcessHandle,
    domain: u32,
    socket_type: u32,
    protocol: u32,
) -> Result<(u32, u32), SocketError> {
    if !valid_owner(owner) {
        return Err(SocketError::InvalidArgument);
    }
    validate_create(domain, socket_type, protocol)?;
    let mut registry = REGISTRY.lock();
    let mut free_endpoints = registry
        .endpoints
        .iter()
        .enumerate()
        .filter(|(_, endpoint)| !endpoint.occupied)
        .map(|(index, _)| index);
    let first_index = free_endpoints.next().ok_or(SocketError::Capacity)?;
    let second_index = free_endpoints.next().ok_or(SocketError::Capacity)?;
    let connection_index = registry
        .connections
        .iter()
        .position(|connection| !connection.occupied)
        .ok_or(SocketError::Capacity)?;
    let connection_generation =
        next_connection_generation(registry.connections[connection_index].generation)
            .ok_or(SocketError::Capacity)?;

    let first = initialize_connected_endpoint(
        &mut registry,
        first_index,
        owner,
        connection_index,
        connection_generation,
        0,
    )?;
    let second = match initialize_connected_endpoint(
        &mut registry,
        second_index,
        owner,
        connection_index,
        connection_generation,
        1,
    ) {
        Ok(handle) => handle,
        Err(error) => {
            retire_endpoint(&mut registry.endpoints[first_index]);
            return Err(error);
        }
    };
    registry.connections[connection_index].initialize(
        connection_generation,
        first,
        second,
        owner,
        owner,
        UnixAddress::UNNAMED,
        UnixAddress::UNNAMED,
    );
    Ok((first, second))
}

pub fn bind(owner: ProcessHandle, handle: u32, address: UnixAddress) -> Result<(), SocketError> {
    if address.is_unnamed() {
        return Err(SocketError::InvalidArgument);
    }
    let mut registry = REGISTRY.lock();
    let (index, endpoint) = resolved_endpoint(&registry, owner, handle)?;
    if endpoint.state != EndpointState::Unbound {
        return Err(SocketError::InvalidArgument);
    }
    if registry
        .endpoints
        .iter()
        .enumerate()
        .any(|(other_index, other)| {
            other_index != index
                && other.occupied
                && !other.address.is_unnamed()
                && other.address == address
        })
    {
        return Err(SocketError::AddressInUse);
    }
    let endpoint = &mut registry.endpoints[index];
    endpoint.state = EndpointState::Bound;
    endpoint.address = address;
    advance_generation(&mut endpoint.readiness_generation);
    Ok(())
}

pub fn listen(owner: ProcessHandle, handle: u32, backlog: usize) -> Result<(), SocketError> {
    let mut registry = REGISTRY.lock();
    let (index, endpoint) = resolved_endpoint(&registry, owner, handle)?;
    if !matches!(
        endpoint.state,
        EndpointState::Bound | EndpointState::Listening
    ) {
        return Err(SocketError::InvalidArgument);
    }
    let endpoint = &mut registry.endpoints[index];
    endpoint.state = EndpointState::Listening;
    endpoint.backlog = backlog.clamp(1, MAXIMUM_LISTEN_BACKLOG) as u8;
    advance_generation(&mut endpoint.readiness_generation);
    Ok(())
}

pub fn connect(owner: ProcessHandle, handle: u32, address: UnixAddress) -> Result<(), SocketError> {
    if address.is_unnamed() {
        return Err(SocketError::InvalidArgument);
    }
    let mut registry = REGISTRY.lock();
    let (client_index, client) = resolved_endpoint(&registry, owner, handle)?;
    match client.state {
        EndpointState::Connected => return Err(SocketError::AlreadyConnected),
        EndpointState::Listening => return Err(SocketError::InvalidArgument),
        EndpointState::Unbound | EndpointState::Bound => {}
    }
    let listener_index = registry
        .endpoints
        .iter()
        .position(|endpoint| {
            endpoint.occupied
                && endpoint.state == EndpointState::Listening
                && endpoint.address == address
        })
        .ok_or(SocketError::ConnectionRefused)?;
    let listener = registry.endpoints[listener_index];
    if usize::from(listener.pending_length) >= usize::from(listener.backlog) {
        return Err(SocketError::WouldBlock);
    }
    let server_index = registry
        .endpoints
        .iter()
        .position(|endpoint| !endpoint.occupied)
        .ok_or(SocketError::Capacity)?;
    let connection_index = registry
        .connections
        .iter()
        .position(|connection| !connection.occupied)
        .ok_or(SocketError::Capacity)?;
    let connection_generation =
        next_connection_generation(registry.connections[connection_index].generation)
            .ok_or(SocketError::Capacity)?;
    let server_handle = initialize_connected_endpoint(
        &mut registry,
        server_index,
        listener.owner,
        connection_index,
        connection_generation,
        1,
    )?;

    let client_endpoint = &mut registry.endpoints[client_index];
    client_endpoint.state = EndpointState::Connected;
    client_endpoint.connection_index = connection_index as u8;
    client_endpoint.connection_generation = connection_generation;
    client_endpoint.side = 0;
    advance_generation(&mut client_endpoint.readiness_generation);

    registry.connections[connection_index].initialize(
        connection_generation,
        handle,
        server_handle,
        owner,
        listener.owner,
        client.address,
        listener.address,
    );

    let listener = &mut registry.endpoints[listener_index];
    let tail = (usize::from(listener.pending_head) + usize::from(listener.pending_length))
        % MAXIMUM_LISTEN_BACKLOG;
    listener.pending[tail] = server_handle;
    listener.pending_length += 1;
    advance_generation(&mut listener.readiness_generation);
    Ok(())
}

pub fn accept(owner: ProcessHandle, handle: u32) -> Result<(u32, UnixAddress), SocketError> {
    let mut registry = REGISTRY.lock();
    let (listener_index, listener) = resolved_endpoint(&registry, owner, handle)?;
    if listener.state != EndpointState::Listening {
        return Err(SocketError::InvalidArgument);
    }
    if listener.pending_length == 0 {
        return Err(SocketError::WouldBlock);
    }
    let head = usize::from(listener.pending_head);
    let accepted = listener.pending[head];
    let (_, endpoint) = resolved_endpoint(&registry, owner, accepted)?;
    let (connection_index, side) = resolved_connection(&registry, endpoint, accepted)?;
    let peer = registry.connections[connection_index].addresses[1 - side];

    let listener = &mut registry.endpoints[listener_index];
    listener.pending[head] = 0;
    listener.pending_head = ((head + 1) % MAXIMUM_LISTEN_BACKLOG) as u8;
    listener.pending_length -= 1;
    advance_generation(&mut listener.readiness_generation);
    Ok((accepted, peer))
}

pub fn read(owner: ProcessHandle, handle: u32, output: &mut [u8]) -> Result<usize, SocketError> {
    receive(owner, handle, output, 0)
}

pub fn receive(
    owner: ProcessHandle,
    handle: u32,
    output: &mut [u8],
    flags: u32,
) -> Result<usize, SocketError> {
    let mut discarded =
        [crate::linux_fd::TransferToken::EMPTY; crate::linux_fd::MAXIMUM_TRANSFER_DESCRIPTORS];
    let (copied, discarded_count) = receive_message(owner, handle, output, flags, &mut discarded)?;
    crate::linux_fd::release_transfers(&mut discarded[..discarded_count]);
    Ok(copied)
}

pub(crate) fn receive_message(
    owner: ProcessHandle,
    handle: u32,
    output: &mut [u8],
    flags: u32,
    rights_output: &mut [crate::linux_fd::TransferToken],
) -> Result<(usize, usize), SocketError> {
    if flags & !RECEIVE_FLAGS != 0 {
        return Err(SocketError::OperationNotSupported);
    }
    let mut registry = REGISTRY.lock();
    let (_, endpoint) = resolved_endpoint(&registry, owner, handle)?;
    let (connection_index, side) = resolved_connection(&registry, endpoint, handle)?;
    let connection = &mut registry.connections[connection_index];
    if !connection.read_open[side] {
        return Ok((0, 0));
    }
    if output.is_empty() {
        return Ok((0, 0));
    }
    let incoming = 1 - side;
    let queue = &mut connection.outgoing[incoming];
    if queue.length == 0 {
        return if connection.write_open[incoming] {
            Err(SocketError::WouldBlock)
        } else {
            Ok((0, 0))
        };
    }
    let mut copied = output.len().min(queue.length);
    let head_sequence = queue.sequence;
    let mut deliver_rights = false;
    if let Some(first) = connection.outgoing_rights[incoming].record(0) {
        let initial_end = head_sequence
            .checked_add(copied as u64)
            .ok_or(SocketError::Capacity)?;
        if first.sequence < head_sequence
            || first.sequence >= queue.tail_sequence().ok_or(SocketError::Capacity)?
        {
            return Err(SocketError::BadFileDescriptor);
        }
        deliver_rights = first.sequence < initial_end && flags & MSG_PEEK == 0;
        if deliver_rights {
            if usize::from(first.count) > rights_output.len() {
                return Err(SocketError::Capacity);
            }
            if let Some(second) = connection.outgoing_rights[incoming].record(1)
                && second.sequence < initial_end
            {
                copied = usize::try_from(second.sequence - head_sequence)
                    .map_err(|_| SocketError::Capacity)?;
            }
        }
    }
    if flags & MSG_PEEK != 0 {
        for (offset, destination) in output[..copied].iter_mut().enumerate() {
            *destination = queue.bytes[(queue.head + offset) % SOCKET_BUFFER_BYTES];
        }
        return Ok((copied, 0));
    }
    for destination in &mut output[..copied] {
        *destination = queue.bytes[queue.head];
        queue.head = (queue.head + 1) % SOCKET_BUFFER_BYTES;
    }
    queue.length -= copied;
    queue.sequence = queue
        .sequence
        .checked_add(copied as u64)
        .ok_or(SocketError::Capacity)?;
    let rights_count = if deliver_rights {
        connection.outgoing_rights[incoming].pop(rights_output)
    } else {
        0
    };
    advance_generation(&mut connection.readiness_generation);
    Ok((copied, rights_count))
}

pub fn write(owner: ProcessHandle, handle: u32, input: &[u8]) -> Result<usize, SocketError> {
    send(owner, handle, input, 0)
}

pub fn send(
    owner: ProcessHandle,
    handle: u32,
    input: &[u8],
    flags: u32,
) -> Result<usize, SocketError> {
    send_message(owner, handle, input, flags, &mut [])
}

pub(crate) fn send_message(
    owner: ProcessHandle,
    handle: u32,
    input: &[u8],
    flags: u32,
    rights: &mut [crate::linux_fd::TransferToken],
) -> Result<usize, SocketError> {
    if flags & !SEND_FLAGS != 0 {
        return Err(SocketError::OperationNotSupported);
    }
    let mut registry = REGISTRY.lock();
    let (_, endpoint) = resolved_endpoint(&registry, owner, handle)?;
    let (connection_index, side) = resolved_connection(&registry, endpoint, handle)?;
    let connection = &mut registry.connections[connection_index];
    let peer = 1 - side;
    if !connection.write_open[side] || !connection.read_open[peer] {
        return Err(SocketError::BrokenPipe);
    }
    if input.is_empty() {
        return if rights.is_empty() {
            Ok(0)
        } else {
            Err(SocketError::InvalidArgument)
        };
    }
    let queue = &connection.outgoing[side];
    let available = SOCKET_BUFFER_BYTES - queue.length;
    if available == 0 {
        return Err(SocketError::WouldBlock);
    }
    let copied = input.len().min(available);
    let rights_sequence = queue.tail_sequence().ok_or(SocketError::Capacity)?;
    if !rights.is_empty() {
        connection.outgoing_rights[side].push(rights_sequence, rights)?;
    }
    let queue = &mut connection.outgoing[side];
    for byte in &input[..copied] {
        let tail = (queue.head + queue.length) % SOCKET_BUFFER_BYTES;
        queue.bytes[tail] = *byte;
        queue.length += 1;
    }
    advance_generation(&mut connection.readiness_generation);
    Ok(copied)
}

pub fn shutdown(owner: ProcessHandle, handle: u32, how: u32) -> Result<(), SocketError> {
    if how > SHUT_RDWR {
        return Err(SocketError::InvalidArgument);
    }
    let mut discarded = [crate::linux_fd::TransferToken::EMPTY;
        MAXIMUM_RIGHTS_RECORDS * crate::linux_fd::MAXIMUM_TRANSFER_DESCRIPTORS];
    let discarded_count = {
        let mut registry = REGISTRY.lock();
        let (_, endpoint) = resolved_endpoint(&registry, owner, handle)?;
        let (connection_index, side) = resolved_connection(&registry, endpoint, handle)?;
        let connection = &mut registry.connections[connection_index];
        let mut discarded_count = 0;
        if matches!(how, SHUT_RD | SHUT_RDWR) {
            let incoming = 1 - side;
            connection.read_open[side] = false;
            connection.outgoing[incoming].clear();
            discarded_count = connection.outgoing_rights[incoming].drain(&mut discarded);
        }
        if matches!(how, SHUT_WR | SHUT_RDWR) {
            connection.write_open[side] = false;
        }
        advance_generation(&mut connection.readiness_generation);
        discarded_count
    };
    crate::linux_fd::release_transfers(&mut discarded[..discarded_count]);
    Ok(())
}

pub fn readiness(owner: ProcessHandle, handle: u32) -> Result<u32, SocketError> {
    let registry = REGISTRY.lock();
    let (_, endpoint) = resolved_endpoint(&registry, owner, handle)?;
    if endpoint.state == EndpointState::Listening {
        return Ok(if endpoint.pending_length == 0 {
            0
        } else {
            READY_IN
        });
    }
    let (connection_index, side) = resolved_connection(&registry, endpoint, handle)?;
    let connection = &registry.connections[connection_index];
    let peer = 1 - side;
    let mut ready = 0;
    if connection.outgoing[peer].length != 0 || !connection.write_open[peer] {
        ready |= READY_IN;
    }
    if connection.write_open[side]
        && connection.read_open[peer]
        && connection.outgoing[side].length < SOCKET_BUFFER_BYTES
    {
        ready |= READY_OUT;
    }
    if !connection.read_open[peer] {
        ready |= READY_ERR;
    }
    if !connection.write_open[peer] {
        ready |= READY_HUP;
    }
    Ok(ready)
}

pub fn readiness_generation(owner: ProcessHandle, handle: u32) -> Result<u64, SocketError> {
    let registry = REGISTRY.lock();
    let (_, endpoint) = resolved_endpoint(&registry, owner, handle)?;
    if endpoint.state == EndpointState::Listening {
        return Ok(endpoint.readiness_generation);
    }
    let (connection_index, _) = resolved_connection(&registry, endpoint, handle)?;
    Ok(registry.connections[connection_index].readiness_generation)
}

pub fn local_address(owner: ProcessHandle, handle: u32) -> Result<UnixAddress, SocketError> {
    let registry = REGISTRY.lock();
    let (_, endpoint) = resolved_endpoint(&registry, owner, handle)?;
    if endpoint.state == EndpointState::Connected {
        let (connection_index, side) = resolved_connection(&registry, endpoint, handle)?;
        Ok(registry.connections[connection_index].addresses[side])
    } else {
        Ok(endpoint.address)
    }
}

pub fn peer_address(owner: ProcessHandle, handle: u32) -> Result<UnixAddress, SocketError> {
    let registry = REGISTRY.lock();
    let (_, endpoint) = resolved_endpoint(&registry, owner, handle)?;
    let (connection_index, side) = resolved_connection(&registry, endpoint, handle)?;
    Ok(registry.connections[connection_index].addresses[1 - side])
}

pub fn peer_credentials(owner: ProcessHandle, handle: u32) -> Result<PeerCredentials, SocketError> {
    let registry = REGISTRY.lock();
    let (_, endpoint) = resolved_endpoint(&registry, owner, handle)?;
    let (connection_index, side) = resolved_connection(&registry, endpoint, handle)?;
    Ok(PeerCredentials {
        pid: registry.connections[connection_index].owners[1 - side].pid,
        uid: 0,
        gid: 0,
    })
}

pub fn is_listener(owner: ProcessHandle, handle: u32) -> Result<bool, SocketError> {
    let registry = REGISTRY.lock();
    let (_, endpoint) = resolved_endpoint(&registry, owner, handle)?;
    Ok(endpoint.state == EndpointState::Listening)
}

fn close_connected_endpoint(
    registry: &mut SocketRegistry,
    index: usize,
    discarded: &mut [crate::linux_fd::TransferToken],
) -> usize {
    let endpoint = registry.endpoints[index];
    let mut discarded_count = 0;
    if endpoint.state == EndpointState::Connected {
        let connection_index = usize::from(endpoint.connection_index);
        let side = usize::from(endpoint.side);
        if let Some(connection) = registry
            .connections
            .get_mut(connection_index)
            .filter(|entry| {
                entry.occupied
                    && entry.generation == endpoint.connection_generation
                    && side < 2
                    && entry.endpoint_handles[side]
                        == encode_endpoint(index, endpoint.generation).unwrap_or(0)
            })
        {
            connection.endpoint_open[side] = false;
            connection.read_open[side] = false;
            connection.write_open[side] = false;
            let incoming = 1 - side;
            connection.outgoing[incoming].clear();
            discarded_count += connection.outgoing_rights[incoming].drain(discarded);
            advance_generation(&mut connection.readiness_generation);
            if !connection.endpoint_open[0] && !connection.endpoint_open[1] {
                discarded_count += retire_connection(connection, &mut discarded[discarded_count..]);
            }
        }
    }
    retire_endpoint(&mut registry.endpoints[index]);
    discarded_count
}

pub fn close(owner: ProcessHandle, handle: u32) -> Result<(), SocketError> {
    const MAXIMUM_CLOSE_DISCARDS: usize = MAXIMUM_LISTEN_BACKLOG
        * MAXIMUM_RIGHTS_RECORDS
        * crate::linux_fd::MAXIMUM_TRANSFER_DESCRIPTORS;
    let mut discarded = [crate::linux_fd::TransferToken::EMPTY; MAXIMUM_CLOSE_DISCARDS];
    let discarded_count = {
        let mut registry = REGISTRY.lock();
        let (index, endpoint) = resolved_endpoint(&registry, owner, handle)?;
        let mut discarded_count = 0;
        if endpoint.state == EndpointState::Listening {
            let mut pending = [0_u32; MAXIMUM_LISTEN_BACKLOG];
            let pending_count = usize::from(endpoint.pending_length);
            for (offset, destination) in pending[..pending_count].iter_mut().enumerate() {
                *destination = endpoint.pending
                    [(usize::from(endpoint.pending_head) + offset) % MAXIMUM_LISTEN_BACKLOG];
            }
            retire_endpoint(&mut registry.endpoints[index]);
            for pending_handle in pending[..pending_count].iter().copied() {
                if let Some((pending_index, generation)) = decode_endpoint(pending_handle) {
                    let queued = registry.endpoints[pending_index];
                    if queued.occupied
                        && queued.generation == generation
                        && queued.owner == owner
                        && queued.state == EndpointState::Connected
                    {
                        discarded_count += close_connected_endpoint(
                            &mut registry,
                            pending_index,
                            &mut discarded[discarded_count..],
                        );
                    }
                }
            }
        } else {
            discarded_count = close_connected_endpoint(&mut registry, index, &mut discarded);
        }
        discarded_count
    };
    crate::linux_fd::release_transfers(&mut discarded[..discarded_count]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER: ProcessHandle = ProcessHandle {
        pid: 0x5301,
        generation: 4,
    };
    const CLIENT: ProcessHandle = ProcessHandle {
        pid: 0x5302,
        generation: 7,
    };

    #[test]
    fn socketpair_is_full_duplex_and_generation_bound() {
        let (first, second) = create_pair(SERVER, AF_UNIX, SOCK_STREAM, 0).unwrap();
        assert_eq!(readiness(SERVER, first), Ok(READY_OUT));
        assert_eq!(write(SERVER, first, b"first"), Ok(5));
        assert_eq!(write(SERVER, second, b"second"), Ok(6));
        let mut first_output = [0_u8; 6];
        let mut second_output = [0_u8; 5];
        assert_eq!(read(SERVER, first, &mut first_output), Ok(6));
        assert_eq!(read(SERVER, second, &mut second_output), Ok(5));
        assert_eq!(&first_output, b"second");
        assert_eq!(&second_output, b"first");
        close(SERVER, first).unwrap();
        assert_eq!(
            readiness(SERVER, second),
            Ok(READY_IN | READY_ERR | READY_HUP)
        );
        close(SERVER, second).unwrap();
        assert_eq!(
            read(SERVER, first, &mut [0_u8; 1]),
            Err(SocketError::BadFileDescriptor)
        );
    }

    #[test]
    fn named_listener_connects_distinct_process_generations() {
        let address = UnixAddress::new(b"/run/arach/socket-test-a").unwrap();
        let listener = create(SERVER, AF_UNIX, SOCK_STREAM, 0).unwrap();
        bind(SERVER, listener, address).unwrap();
        listen(SERVER, listener, 3).unwrap();
        let client = create(CLIENT, AF_UNIX, SOCK_STREAM, 0).unwrap();
        connect(CLIENT, client, address).unwrap();
        assert_eq!(readiness(SERVER, listener), Ok(READY_IN));
        let (server, peer) = accept(SERVER, listener).unwrap();
        assert!(peer.is_unnamed());
        assert_eq!(peer_address(CLIENT, client), Ok(address));
        assert_eq!(peer_credentials(SERVER, server).unwrap().pid, CLIENT.pid);
        assert_eq!(peer_credentials(CLIENT, client).unwrap().pid, SERVER.pid);
        assert_eq!(write(CLIENT, client, b"request"), Ok(7));
        let mut request = [0_u8; 7];
        assert_eq!(read(SERVER, server, &mut request), Ok(7));
        assert_eq!(&request, b"request");
        assert_eq!(write(SERVER, server, b"reply"), Ok(5));
        let mut reply = [0_u8; 5];
        assert_eq!(read(CLIENT, client, &mut reply), Ok(5));
        assert_eq!(&reply, b"reply");
        close(CLIENT, client).unwrap();
        close(SERVER, server).unwrap();
        close(SERVER, listener).unwrap();
    }

    #[test]
    fn shutdown_and_listener_close_publish_peer_hangup() {
        let (first, second) = create_pair(SERVER, AF_UNIX, SOCK_STREAM, 0).unwrap();
        shutdown(SERVER, first, SHUT_WR).unwrap();
        assert_eq!(
            readiness(SERVER, second),
            Ok(READY_IN | READY_OUT | READY_HUP)
        );
        assert_eq!(read(SERVER, second, &mut [0_u8; 1]), Ok(0));
        assert_eq!(write(SERVER, first, b"x"), Err(SocketError::BrokenPipe));
        close(SERVER, first).unwrap();
        close(SERVER, second).unwrap();

        let address = UnixAddress::new(b"/run/arach/socket-test-b").unwrap();
        let listener = create(SERVER, AF_UNIX, SOCK_STREAM, 0).unwrap();
        bind(SERVER, listener, address).unwrap();
        listen(SERVER, listener, 1).unwrap();
        let client = create(CLIENT, AF_UNIX, SOCK_STREAM, 0).unwrap();
        connect(CLIENT, client, address).unwrap();
        close(SERVER, listener).unwrap();
        assert_eq!(
            readiness(CLIENT, client),
            Ok(READY_IN | READY_ERR | READY_HUP)
        );
        close(CLIENT, client).unwrap();
    }

    #[test]
    fn stream_buffers_are_bounded_and_peek_does_not_consume() {
        let (first, second) = create_pair(SERVER, AF_UNIX, SOCK_STREAM, 0).unwrap();
        let payload = [0x5a_u8; SOCKET_BUFFER_BYTES];
        assert_eq!(
            send(SERVER, first, &payload, MSG_DONTWAIT),
            Ok(payload.len())
        );
        assert_eq!(send(SERVER, first, b"x", 0), Err(SocketError::WouldBlock));
        let mut peeked = [0_u8; 8];
        assert_eq!(receive(SERVER, second, &mut peeked, MSG_PEEK), Ok(8));
        assert_eq!(peeked, [0x5a; 8]);
        let mut consumed = [0_u8; 8];
        assert_eq!(receive(SERVER, second, &mut consumed, 0), Ok(8));
        assert_eq!(consumed, peeked);
        assert_eq!(send(SERVER, first, b"refilled", 0), Ok(8));
        assert_eq!(
            send(SERVER, first, b"unsupported", MSG_PEEK),
            Err(SocketError::OperationNotSupported)
        );
        close(SERVER, first).unwrap();
        close(SERVER, second).unwrap();
    }

    #[test]
    fn namespace_and_listen_backlog_are_bounded() {
        let address = UnixAddress::new(b"\0arach-backlog-c").unwrap();
        let listener = create(SERVER, AF_UNIX, SOCK_STREAM, 0).unwrap();
        bind(SERVER, listener, address).unwrap();
        listen(SERVER, listener, 1).unwrap();
        let duplicate = create(CLIENT, AF_UNIX, SOCK_STREAM, 0).unwrap();
        assert_eq!(
            bind(CLIENT, duplicate, address),
            Err(SocketError::AddressInUse)
        );
        let first = create(CLIENT, AF_UNIX, SOCK_STREAM, 0).unwrap();
        let second_owner = ProcessHandle {
            pid: CLIENT.pid + 1,
            generation: CLIENT.generation,
        };
        let second = create(second_owner, AF_UNIX, SOCK_STREAM, 0).unwrap();
        connect(CLIENT, first, address).unwrap();
        assert_eq!(
            connect(second_owner, second, address),
            Err(SocketError::WouldBlock)
        );
        let (accepted, _) = accept(SERVER, listener).unwrap();
        connect(second_owner, second, address).unwrap();
        close(SERVER, accepted).unwrap();
        let (second_accepted, _) = accept(SERVER, listener).unwrap();
        close(CLIENT, first).unwrap();
        close(second_owner, second).unwrap();
        close(SERVER, second_accepted).unwrap();
        close(CLIENT, duplicate).unwrap();
        close(SERVER, listener).unwrap();

        let replacement = create(SERVER, AF_UNIX, SOCK_STREAM, 0).unwrap();
        bind(SERVER, replacement, address).unwrap();
        close(SERVER, replacement).unwrap();
    }
}
