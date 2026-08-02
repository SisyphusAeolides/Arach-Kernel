//! Bounded Linux anonymous pipes.
//!
//! Pipe storage and endpoint handles are generation-bound. Public Linux file
//! descriptors are assigned by `linux_fd`; this module owns only the shared
//! byte stream and opaque endpoint handles. Reads and writes never allocate,
//! writes no larger than `PIPE_BUF` are atomic, and readiness transitions are
//! observable by poll and epoll.

use crate::linux_eventfd::{READY_ERR, READY_HUP, READY_IN, READY_OUT};
use crate::process::lifecycle::ProcessHandle;
use crate::sync::SpinLock;

pub const PIPE_BUF: usize = 4096;
const MAXIMUM_PIPES: usize = 32;
const MAXIMUM_ENDPOINTS: usize = MAXIMUM_PIPES * 2;
const ENDPOINT_INDEX_BITS: u32 = 8;
const ENDPOINT_INDEX_MASK: u32 = (1 << ENDPOINT_INDEX_BITS) - 1;
const MAXIMUM_ENDPOINT_GENERATION: u32 = u32::MAX >> ENDPOINT_INDEX_BITS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PipeError {
    InvalidArgument,
    BadFileDescriptor,
    WouldBlock,
    BrokenPipe,
    Capacity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum Direction {
    Read = 0,
    Write = 1,
}

#[derive(Clone, Copy)]
struct EndpointSlot {
    occupied: bool,
    generation: u32,
    owner: ProcessHandle,
    pipe_index: u8,
    pipe_generation: u32,
    direction: Direction,
}

impl EndpointSlot {
    const EMPTY: Self = Self {
        occupied: false,
        generation: 0,
        owner: ProcessHandle {
            pid: 0,
            generation: 0,
        },
        pipe_index: 0,
        pipe_generation: 0,
        direction: Direction::Read,
    };
}

#[derive(Clone, Copy)]
struct PipeSlot {
    occupied: bool,
    generation: u32,
    owner: ProcessHandle,
    read_open: bool,
    write_open: bool,
    head: usize,
    length: usize,
    bytes: [u8; PIPE_BUF],
    readiness_generation: u64,
}

impl PipeSlot {
    const EMPTY: Self = Self {
        occupied: false,
        generation: 0,
        owner: ProcessHandle {
            pid: 0,
            generation: 0,
        },
        read_open: false,
        write_open: false,
        head: 0,
        length: 0,
        bytes: [0; PIPE_BUF],
        readiness_generation: 0,
    };
}

struct PipeRegistry {
    pipes: [PipeSlot; MAXIMUM_PIPES],
    endpoints: [EndpointSlot; MAXIMUM_ENDPOINTS],
}

impl PipeRegistry {
    const fn new() -> Self {
        Self {
            pipes: [PipeSlot::EMPTY; MAXIMUM_PIPES],
            endpoints: [EndpointSlot::EMPTY; MAXIMUM_ENDPOINTS],
        }
    }
}

static REGISTRY: SpinLock<PipeRegistry> = SpinLock::new(PipeRegistry::new());

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

fn next_generation(current: u32) -> Option<u32> {
    current
        .checked_add(1)
        .filter(|generation| *generation <= MAXIMUM_ENDPOINT_GENERATION)
}

fn resolved_endpoint(
    registry: &PipeRegistry,
    owner: ProcessHandle,
    handle: u32,
) -> Result<(usize, EndpointSlot), PipeError> {
    let (endpoint_index, generation) =
        decode_endpoint(handle).ok_or(PipeError::BadFileDescriptor)?;
    let endpoint = registry.endpoints[endpoint_index];
    if !endpoint.occupied || endpoint.generation != generation || endpoint.owner != owner {
        return Err(PipeError::BadFileDescriptor);
    }
    let pipe_index = usize::from(endpoint.pipe_index);
    let pipe = registry.pipes[pipe_index];
    if !pipe.occupied || pipe.generation != endpoint.pipe_generation || pipe.owner != owner {
        return Err(PipeError::BadFileDescriptor);
    }
    Ok((pipe_index, endpoint))
}

/// Create one read endpoint and one write endpoint for an exact process
/// generation. Endpoint handles remain private to the unified descriptor
/// layer.
pub fn create(owner: ProcessHandle) -> Result<(u32, u32), PipeError> {
    if owner.pid == 0 || owner.generation == 0 {
        return Err(PipeError::InvalidArgument);
    }
    let mut registry = REGISTRY.lock();
    let pipe_index = registry
        .pipes
        .iter()
        .position(|pipe| !pipe.occupied)
        .ok_or(PipeError::Capacity)?;
    let mut free_endpoints = registry
        .endpoints
        .iter()
        .enumerate()
        .filter(|(_, endpoint)| !endpoint.occupied)
        .map(|(index, _)| index);
    let read_index = free_endpoints.next().ok_or(PipeError::Capacity)?;
    let write_index = free_endpoints.next().ok_or(PipeError::Capacity)?;

    let pipe_generation = registry.pipes[pipe_index]
        .generation
        .checked_add(1)
        .ok_or(PipeError::Capacity)?;
    let read_generation =
        next_generation(registry.endpoints[read_index].generation).ok_or(PipeError::Capacity)?;
    let write_generation =
        next_generation(registry.endpoints[write_index].generation).ok_or(PipeError::Capacity)?;
    let read_handle = encode_endpoint(read_index, read_generation).ok_or(PipeError::Capacity)?;
    let write_handle = encode_endpoint(write_index, write_generation).ok_or(PipeError::Capacity)?;

    registry.pipes[pipe_index] = PipeSlot {
        occupied: true,
        generation: pipe_generation,
        owner,
        read_open: true,
        write_open: true,
        head: 0,
        length: 0,
        bytes: [0; PIPE_BUF],
        readiness_generation: 1,
    };
    registry.endpoints[read_index] = EndpointSlot {
        occupied: true,
        generation: read_generation,
        owner,
        pipe_index: pipe_index as u8,
        pipe_generation,
        direction: Direction::Read,
    };
    registry.endpoints[write_index] = EndpointSlot {
        occupied: true,
        generation: write_generation,
        owner,
        pipe_index: pipe_index as u8,
        pipe_generation,
        direction: Direction::Write,
    };
    Ok((read_handle, write_handle))
}

pub fn read(owner: ProcessHandle, handle: u32, output: &mut [u8]) -> Result<usize, PipeError> {
    if output.is_empty() {
        return Ok(0);
    }
    let mut registry = REGISTRY.lock();
    let (pipe_index, endpoint) = resolved_endpoint(&registry, owner, handle)?;
    if endpoint.direction != Direction::Read {
        return Err(PipeError::BadFileDescriptor);
    }
    let pipe = &mut registry.pipes[pipe_index];
    if pipe.length == 0 {
        return if pipe.write_open {
            Err(PipeError::WouldBlock)
        } else {
            Ok(0)
        };
    }

    let copied = output.len().min(pipe.length);
    for destination in &mut output[..copied] {
        *destination = pipe.bytes[pipe.head];
        pipe.head = (pipe.head + 1) % PIPE_BUF;
    }
    pipe.length -= copied;
    pipe.readiness_generation = pipe.readiness_generation.wrapping_add(1);
    Ok(copied)
}

pub fn write(owner: ProcessHandle, handle: u32, input: &[u8]) -> Result<usize, PipeError> {
    if input.is_empty() {
        return Ok(0);
    }
    if input.len() > PIPE_BUF {
        return Err(PipeError::InvalidArgument);
    }
    let mut registry = REGISTRY.lock();
    let (pipe_index, endpoint) = resolved_endpoint(&registry, owner, handle)?;
    if endpoint.direction != Direction::Write {
        return Err(PipeError::BadFileDescriptor);
    }
    let pipe = &mut registry.pipes[pipe_index];
    if !pipe.read_open {
        return Err(PipeError::BrokenPipe);
    }
    let available = PIPE_BUF - pipe.length;
    if input.len() > available {
        return Err(PipeError::WouldBlock);
    }
    for byte in input {
        let tail = (pipe.head + pipe.length) % PIPE_BUF;
        pipe.bytes[tail] = *byte;
        pipe.length += 1;
    }
    pipe.readiness_generation = pipe.readiness_generation.wrapping_add(1);
    Ok(input.len())
}

pub fn readiness(owner: ProcessHandle, handle: u32) -> Result<u32, PipeError> {
    let registry = REGISTRY.lock();
    let (pipe_index, endpoint) = resolved_endpoint(&registry, owner, handle)?;
    let pipe = &registry.pipes[pipe_index];
    match endpoint.direction {
        Direction::Read => {
            let mut ready = 0;
            if pipe.length != 0 {
                ready |= READY_IN;
            }
            if !pipe.write_open {
                ready |= READY_HUP;
            }
            Ok(ready)
        }
        Direction::Write => {
            if !pipe.read_open {
                Ok(READY_ERR)
            } else if pipe.length < PIPE_BUF {
                Ok(READY_OUT)
            } else {
                Ok(0)
            }
        }
    }
}

pub fn readiness_generation(owner: ProcessHandle, handle: u32) -> Result<u64, PipeError> {
    let registry = REGISTRY.lock();
    let (pipe_index, _) = resolved_endpoint(&registry, owner, handle)?;
    Ok(registry.pipes[pipe_index].readiness_generation)
}

pub fn close(owner: ProcessHandle, handle: u32) -> Result<(), PipeError> {
    let mut registry = REGISTRY.lock();
    let (pipe_index, endpoint) = resolved_endpoint(&registry, owner, handle)?;
    let (endpoint_index, _) = decode_endpoint(handle).ok_or(PipeError::BadFileDescriptor)?;
    registry.endpoints[endpoint_index].occupied = false;
    let pipe = &mut registry.pipes[pipe_index];
    match endpoint.direction {
        Direction::Read => pipe.read_open = false,
        Direction::Write => pipe.write_open = false,
    }
    pipe.readiness_generation = pipe.readiness_generation.wrapping_add(1);
    if !pipe.read_open && !pipe.write_open {
        pipe.occupied = false;
        pipe.owner = ProcessHandle {
            pid: 0,
            generation: 0,
        };
        pipe.head = 0;
        pipe.length = 0;
        pipe.bytes.fill(0);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: ProcessHandle = ProcessHandle {
        pid: 0x5101,
        generation: 4,
    };

    #[test]
    fn pipe_round_trip_and_readiness_are_bounded() {
        let (reader, writer) = create(OWNER).unwrap();
        assert_eq!(readiness(OWNER, reader), Ok(0));
        assert_eq!(readiness(OWNER, writer), Ok(READY_OUT));
        assert_eq!(write(OWNER, writer, b"arach"), Ok(5));
        assert_eq!(readiness(OWNER, reader), Ok(READY_IN));
        let mut output = [0_u8; 8];
        assert_eq!(read(OWNER, reader, &mut output), Ok(5));
        assert_eq!(&output[..5], b"arach");
        assert_eq!(read(OWNER, reader, &mut output), Err(PipeError::WouldBlock));
        close(OWNER, reader).unwrap();
        close(OWNER, writer).unwrap();
    }

    #[test]
    fn endpoint_lifetime_drives_eof_hup_and_broken_pipe() {
        let (reader, writer) = create(OWNER).unwrap();
        close(OWNER, writer).unwrap();
        assert_eq!(readiness(OWNER, reader), Ok(READY_HUP));
        assert_eq!(read(OWNER, reader, &mut [0_u8; 1]), Ok(0));
        close(OWNER, reader).unwrap();

        let (reader, writer) = create(OWNER).unwrap();
        close(OWNER, reader).unwrap();
        assert_eq!(readiness(OWNER, writer), Ok(READY_ERR));
        assert_eq!(write(OWNER, writer, b"x"), Err(PipeError::BrokenPipe));
        close(OWNER, writer).unwrap();
    }

    #[test]
    fn stale_handles_and_pid_generations_never_alias() {
        let (reader, writer) = create(OWNER).unwrap();
        close(OWNER, reader).unwrap();
        close(OWNER, writer).unwrap();
        let (replacement, replacement_writer) = create(OWNER).unwrap();
        assert_ne!(reader, replacement);
        assert_eq!(
            read(OWNER, reader, &mut [0_u8; 1]),
            Err(PipeError::BadFileDescriptor)
        );
        let recycled = ProcessHandle {
            pid: OWNER.pid,
            generation: OWNER.generation + 1,
        };
        assert_eq!(
            read(recycled, replacement, &mut [0_u8; 1]),
            Err(PipeError::BadFileDescriptor)
        );
        close(OWNER, replacement).unwrap();
        close(OWNER, replacement_writer).unwrap();
    }

    #[test]
    fn pipe_buf_writes_are_atomic_when_capacity_is_exhausted() {
        let (reader, writer) = create(OWNER).unwrap();
        let full = [0x5a_u8; PIPE_BUF];
        assert_eq!(write(OWNER, writer, &full), Ok(PIPE_BUF));
        assert_eq!(write(OWNER, writer, b"x"), Err(PipeError::WouldBlock));
        let mut first = [0_u8; 17];
        assert_eq!(read(OWNER, reader, &mut first), Ok(first.len()));
        assert_eq!(write(OWNER, writer, b"replacement"), Ok(11));
        close(OWNER, reader).unwrap();
        close(OWNER, writer).unwrap();
    }
}
