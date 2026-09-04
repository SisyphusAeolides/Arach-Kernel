//! Bounded AF_UNIX datagram sockets.
//!
//! Datagram endpoints are intentionally small and local: one fixed queue per
//! bound endpoint, one bounded payload per queued message, and generation-
//! checked handles. This is enough for the service-manager notification and
//! journal sockets while keeping allocation and copy sizes explicit.

use crate::linux_eventfd::{READY_IN, READY_OUT};
use crate::linux_socket::{SOCKET_BUFFER_BYTES, UnixAddress};
use crate::process::lifecycle::ProcessHandle;
use crate::sync::SpinLock;

pub const SOCK_DGRAM: u32 = 2;
pub const MSG_PEEK: u32 = 0x2;
pub const MSG_DONTWAIT: u32 = 0x40;
pub const MSG_NOSIGNAL: u32 = 0x4000;
pub const SEND_FLAGS: u32 = MSG_DONTWAIT | MSG_NOSIGNAL;
pub const RECEIVE_FLAGS: u32 = MSG_PEEK | MSG_DONTWAIT;
pub const MAXIMUM_DATAGRAM_BYTES: usize = SOCKET_BUFFER_BYTES;

const MAXIMUM_ENDPOINTS: usize = 32;
const MAXIMUM_QUEUE_LENGTH: usize = 32;
const ENDPOINT_INDEX_BITS: u32 = 8;
const ENDPOINT_INDEX_MASK: u32 = (1 << ENDPOINT_INDEX_BITS) - 1;
const MAXIMUM_ENDPOINT_GENERATION: u32 = u32::MAX >> ENDPOINT_INDEX_BITS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatagramError {
    InvalidArgument,
    BadFileDescriptor,
    AddressInUse,
    ConnectionRefused,
    NotConnected,
    WouldBlock,
    Capacity,
    OperationNotSupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedDatagram {
    pub bytes: usize,
    pub sender: ProcessHandle,
    pub sender_address: UnixAddress,
    pub truncated: bool,
}

#[derive(Clone, Copy)]
struct Datagram {
    sender: ProcessHandle,
    sender_address: UnixAddress,
    length: u16,
    bytes: [u8; MAXIMUM_DATAGRAM_BYTES],
}

impl Datagram {
    const EMPTY: Self = Self {
        sender: ProcessHandle {
            pid: 0,
            generation: 0,
        },
        sender_address: UnixAddress::UNNAMED,
        length: 0,
        bytes: [0; MAXIMUM_DATAGRAM_BYTES],
    };
}

#[derive(Clone, Copy)]
struct Endpoint {
    owner: ProcessHandle,
    generation: u32,
    address: UnixAddress,
    bound: bool,
    passcred: bool,
    queue_head: u8,
    queue_length: u8,
    queue: [Datagram; MAXIMUM_QUEUE_LENGTH],
    readiness_generation: u64,
}

impl Endpoint {
    const EMPTY: Self = Self {
        owner: ProcessHandle {
            pid: 0,
            generation: 0,
        },
        generation: 0,
        address: UnixAddress::UNNAMED,
        bound: false,
        passcred: false,
        queue_head: 0,
        queue_length: 0,
        queue: [Datagram::EMPTY; MAXIMUM_QUEUE_LENGTH],
        readiness_generation: 0,
    };

    const fn occupied(self) -> bool {
        self.owner.pid != 0 && self.owner.generation != 0
    }

    fn clear_queue(&mut self) {
        self.queue_head = 0;
        self.queue_length = 0;
        for item in &mut self.queue {
            *item = Datagram::EMPTY;
        }
    }
}

static ENDPOINTS: SpinLock<[Endpoint; MAXIMUM_ENDPOINTS]> =
    SpinLock::new([Endpoint::EMPTY; MAXIMUM_ENDPOINTS]);

fn next_generation(current: u32) -> Option<u32> {
    current
        .checked_add(1)
        .filter(|generation| *generation <= MAXIMUM_ENDPOINT_GENERATION)
}

fn encode(index: usize, generation: u32) -> Option<u32> {
    if index >= MAXIMUM_ENDPOINTS || generation == 0 || generation > MAXIMUM_ENDPOINT_GENERATION {
        return None;
    }
    Some((generation << ENDPOINT_INDEX_BITS) | (index as u32 + 1))
}

fn decode(handle: u32) -> Option<(usize, u32)> {
    let encoded_index = handle & ENDPOINT_INDEX_MASK;
    let generation = handle >> ENDPOINT_INDEX_BITS;
    if encoded_index == 0 || generation == 0 {
        return None;
    }
    let index = (encoded_index - 1) as usize;
    (index < MAXIMUM_ENDPOINTS).then_some((index, generation))
}

fn endpoint<'a>(
    table: &'a mut [Endpoint; MAXIMUM_ENDPOINTS],
    owner: ProcessHandle,
    handle: u32,
) -> Result<&'a mut Endpoint, DatagramError> {
    let (index, generation) = decode(handle).ok_or(DatagramError::BadFileDescriptor)?;
    let slot = &mut table[index];
    if !slot.occupied() || slot.generation != generation || slot.owner != owner {
        return Err(DatagramError::BadFileDescriptor);
    }
    Ok(slot)
}

pub fn create(owner: ProcessHandle) -> Result<u32, DatagramError> {
    if owner.pid == 0 || owner.generation == 0 {
        return Err(DatagramError::InvalidArgument);
    }
    let mut table = ENDPOINTS.lock();
    let (index, slot) = table
        .iter_mut()
        .enumerate()
        .find(|(_, slot)| !slot.occupied())
        .ok_or(DatagramError::Capacity)?;
    let generation = next_generation(slot.generation).ok_or(DatagramError::Capacity)?;
    *slot = Endpoint {
        owner,
        generation,
        ..Endpoint::EMPTY
    };
    encode(index, generation).ok_or(DatagramError::Capacity)
}

pub fn bind(owner: ProcessHandle, handle: u32, address: UnixAddress) -> Result<(), DatagramError> {
    if address.is_unnamed() {
        return Err(DatagramError::InvalidArgument);
    }
    let mut table = ENDPOINTS.lock();
    let (index, generation) = decode(handle).ok_or(DatagramError::BadFileDescriptor)?;
    {
        let slot = &table[index];
        if !slot.occupied() || slot.generation != generation || slot.owner != owner {
            return Err(DatagramError::BadFileDescriptor);
        }
        if slot.bound {
            return Err(DatagramError::InvalidArgument);
        }
    }
    if table
        .iter()
        .any(|slot| slot.occupied() && slot.bound && slot.address == address)
    {
        return Err(DatagramError::AddressInUse);
    }
    let slot = &mut table[index];
    slot.address = address;
    slot.bound = true;
    Ok(())
}

pub fn set_passcred(owner: ProcessHandle, handle: u32, enabled: bool) -> Result<(), DatagramError> {
    let mut table = ENDPOINTS.lock();
    endpoint(&mut table, owner, handle)?.passcred = enabled;
    Ok(())
}

pub fn passcred(owner: ProcessHandle, handle: u32) -> Result<bool, DatagramError> {
    let mut table = ENDPOINTS.lock();
    Ok(endpoint(&mut table, owner, handle)?.passcred)
}

pub fn send(
    owner: ProcessHandle,
    handle: u32,
    destination: UnixAddress,
    input: &[u8],
    flags: u32,
) -> Result<usize, DatagramError> {
    if flags & !SEND_FLAGS != 0 || input.len() > MAXIMUM_DATAGRAM_BYTES {
        return Err(DatagramError::InvalidArgument);
    }
    let mut table = ENDPOINTS.lock();
    let sender = endpoint(&mut table, owner, handle)?;
    if sender.bound && destination == sender.address {
        return Err(DatagramError::ConnectionRefused);
    }
    let sender_address = if sender.bound {
        sender.address
    } else {
        UnixAddress::UNNAMED
    };
    let destination_index = table
        .iter()
        .position(|slot| slot.occupied() && slot.bound && slot.address == destination)
        .ok_or(DatagramError::ConnectionRefused)?;
    let target = &mut table[destination_index];
    if usize::from(target.queue_length) >= MAXIMUM_QUEUE_LENGTH {
        return Err(DatagramError::WouldBlock);
    }
    let queue_index =
        (usize::from(target.queue_head) + usize::from(target.queue_length)) % MAXIMUM_QUEUE_LENGTH;
    let mut datagram = Datagram {
        sender: owner,
        sender_address,
        length: input.len() as u16,
        ..Datagram::EMPTY
    };
    datagram.bytes[..input.len()].copy_from_slice(input);
    target.queue[queue_index] = datagram;
    if target.queue_length == 0 {
        target.readiness_generation = target.readiness_generation.wrapping_add(1);
    }
    target.queue_length += 1;
    Ok(input.len())
}

pub fn receive(
    owner: ProcessHandle,
    handle: u32,
    output: &mut [u8],
    flags: u32,
) -> Result<ReceivedDatagram, DatagramError> {
    if flags & !RECEIVE_FLAGS != 0 {
        return Err(DatagramError::InvalidArgument);
    }
    let mut table = ENDPOINTS.lock();
    let slot = endpoint(&mut table, owner, handle)?;
    if slot.queue_length == 0 {
        return Err(DatagramError::WouldBlock);
    }
    let queue_index = usize::from(slot.queue_head);
    let datagram = slot.queue[queue_index];
    let requested = usize::from(datagram.length);
    let copied = requested.min(output.len());
    output[..copied].copy_from_slice(&datagram.bytes[..copied]);
    let truncated = copied < requested;
    if flags & MSG_PEEK == 0 {
        slot.queue[queue_index] = Datagram::EMPTY;
        slot.queue_head = ((queue_index + 1) % MAXIMUM_QUEUE_LENGTH) as u8;
        slot.queue_length -= 1;
        if slot.queue_length == 0 {
            slot.readiness_generation = slot.readiness_generation.wrapping_add(1);
        }
    }
    Ok(ReceivedDatagram {
        bytes: copied,
        sender: datagram.sender,
        sender_address: datagram.sender_address,
        truncated,
    })
}

pub fn readiness(owner: ProcessHandle, handle: u32) -> Result<u32, DatagramError> {
    let mut table = ENDPOINTS.lock();
    let slot = endpoint(&mut table, owner, handle)?;
    Ok(READY_OUT | if slot.queue_length != 0 { READY_IN } else { 0 })
}

pub fn readiness_generation(owner: ProcessHandle, handle: u32) -> Result<u64, DatagramError> {
    let mut table = ENDPOINTS.lock();
    Ok(endpoint(&mut table, owner, handle)?.readiness_generation)
}

pub fn local_address(owner: ProcessHandle, handle: u32) -> Result<UnixAddress, DatagramError> {
    let mut table = ENDPOINTS.lock();
    Ok(endpoint(&mut table, owner, handle)?.address)
}

pub fn bound(address: UnixAddress) -> bool {
    let table = ENDPOINTS.lock();
    table
        .iter()
        .any(|slot| slot.occupied() && slot.bound && slot.address == address)
}

pub fn peer_address(owner: ProcessHandle, handle: u32) -> Result<UnixAddress, DatagramError> {
    let mut table = ENDPOINTS.lock();
    let slot = endpoint(&mut table, owner, handle)?;
    if slot.bound {
        Ok(UnixAddress::UNNAMED)
    } else {
        Err(DatagramError::NotConnected)
    }
}

pub fn close(owner: ProcessHandle, handle: u32) -> Result<(), DatagramError> {
    let mut table = ENDPOINTS.lock();
    let (index, generation) = decode(handle).ok_or(DatagramError::BadFileDescriptor)?;
    let slot = &mut table[index];
    if !slot.occupied() || slot.generation != generation || slot.owner != owner {
        return Err(DatagramError::BadFileDescriptor);
    }
    let previous_generation = slot.generation;
    slot.clear_queue();
    *slot = Endpoint {
        generation: previous_generation,
        ..Endpoint::EMPTY
    };
    Ok(())
}

pub fn close_all(owner: ProcessHandle) -> usize {
    if owner.pid == 0 || owner.generation == 0 {
        return 0;
    }
    let mut table = ENDPOINTS.lock();
    let mut closed = 0;
    for slot in table.iter_mut() {
        if slot.owner == owner {
            let generation = slot.generation;
            slot.clear_queue();
            *slot = Endpoint {
                generation,
                ..Endpoint::EMPTY
            };
            closed += 1;
        }
    }
    closed
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECEIVER: ProcessHandle = ProcessHandle {
        pid: 0x6301,
        generation: 2,
    };
    const SENDER: ProcessHandle = ProcessHandle {
        pid: 0x6302,
        generation: 2,
    };

    #[test]
    fn bound_datagram_round_trip_preserves_sender() {
        let receiver = create(RECEIVER).unwrap();
        let sender = create(SENDER).unwrap();
        let address = UnixAddress::new(b"/run/test-dgram").unwrap();
        bind(RECEIVER, receiver, address).unwrap();
        assert_eq!(send(SENDER, sender, address, b"hello", 0), Ok(5));
        let mut output = [0_u8; 16];
        let received = receive(RECEIVER, receiver, &mut output, 0).unwrap();
        assert_eq!(received.bytes, 5);
        assert_eq!(&output[..5], b"hello");
        assert_eq!(received.sender, SENDER);
        close(RECEIVER, receiver).unwrap();
        close(SENDER, sender).unwrap();
    }
}
