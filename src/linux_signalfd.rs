//! Bounded Linux `signalfd(2)` objects.
//!
//! Signal delivery in the Linux personality is represented by the fixed
//! pending-bit table in `linux_signal`. A signalfd owns a mask selecting which
//! pending bits it consumes and exposes the selected signals as fixed-size
//! `signalfd_siginfo` records. Reads remain non-sleeping while the scheduler
//! wait queues are still being brought up.

use crate::linux_eventfd::READY_IN;
use crate::process::lifecycle::ProcessHandle;
use crate::sync::SpinLock;

pub const SFD_NONBLOCK: u32 = 0x800;
pub const SFD_CLOEXEC: u32 = 0x80000;
pub const SIGNALFD_ALLOWED_FLAGS: u32 = SFD_NONBLOCK | SFD_CLOEXEC;
pub const SIGNALFD_INFO_BYTES: usize = 128;

const MAXIMUM_SIGNALFDS: usize = 32;
const SIGNALFD_BASE: u32 = 0x4000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalFdError {
    InvalidArgument,
    BadFileDescriptor,
    WouldBlock,
    Capacity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SignalFdSlot {
    owner: ProcessHandle,
    mask: u64,
    flags: u32,
}

impl SignalFdSlot {
    const EMPTY: Self = Self {
        owner: ProcessHandle {
            pid: 0,
            generation: 0,
        },
        mask: 0,
        flags: 0,
    };

    const fn occupied(self) -> bool {
        self.owner.pid != 0 && self.owner.generation != 0
    }
}

static SIGNALFDS: SpinLock<[SignalFdSlot; MAXIMUM_SIGNALFDS]> =
    SpinLock::new([SignalFdSlot::EMPTY; MAXIMUM_SIGNALFDS]);

const fn index_for_fd(fd: u32) -> Option<usize> {
    if fd < SIGNALFD_BASE {
        return None;
    }
    let index = (fd - SIGNALFD_BASE) as usize;
    if index < MAXIMUM_SIGNALFDS {
        Some(index)
    } else {
        None
    }
}

const fn fd_for_index(index: usize) -> u32 {
    SIGNALFD_BASE + index as u32
}

/// Allocate a signalfd owned by `owner`.
pub fn create(owner: ProcessHandle, mask: u64, flags: u32) -> Result<u32, SignalFdError> {
    if owner.pid == 0 || owner.generation == 0 || flags & !SIGNALFD_ALLOWED_FLAGS != 0 {
        return Err(SignalFdError::InvalidArgument);
    }
    let mut table = SIGNALFDS.lock();
    let Some((index, slot)) = table
        .iter_mut()
        .enumerate()
        .find(|(_, slot)| !slot.occupied())
    else {
        return Err(SignalFdError::Capacity);
    };
    *slot = SignalFdSlot { owner, mask, flags };
    Ok(fd_for_index(index))
}

/// Replace the signal mask for an existing signalfd.
pub fn update(owner: ProcessHandle, fd: u32, mask: u64) -> Result<(), SignalFdError> {
    let index = index_for_fd(fd).ok_or(SignalFdError::BadFileDescriptor)?;
    let mut table = SIGNALFDS.lock();
    let slot = &mut table[index];
    if !slot.occupied() || slot.owner != owner {
        return Err(SignalFdError::BadFileDescriptor);
    }
    slot.mask = mask;
    Ok(())
}

/// Read one `signalfd_siginfo` record. The first four bytes contain `ssi_signo`;
/// the remaining fields are reserved for the signal metadata not yet modeled
/// by the bounded process personality.
pub fn read(owner: ProcessHandle, fd: u32, output: &mut [u8]) -> Result<usize, SignalFdError> {
    if output.len() < SIGNALFD_INFO_BYTES || output.len() % SIGNALFD_INFO_BYTES != 0 {
        return Err(SignalFdError::InvalidArgument);
    }
    let index = index_for_fd(fd).ok_or(SignalFdError::BadFileDescriptor)?;
    let (mask, slot_owner) = {
        let table = SIGNALFDS.lock();
        let slot = table[index];
        if !slot.occupied() || slot.owner != owner {
            return Err(SignalFdError::BadFileDescriptor);
        }
        (slot.mask, slot.owner)
    };
    let Some(signal) = crate::linux_signal::dequeue_for_signalfd(slot_owner, mask) else {
        return Err(SignalFdError::WouldBlock);
    };
    output[..SIGNALFD_INFO_BYTES].fill(0);
    output[..4].copy_from_slice(&signal.to_ne_bytes());
    Ok(SIGNALFD_INFO_BYTES)
}

/// Return readable readiness without consuming a pending signal.
pub fn readiness(owner: ProcessHandle, fd: u32) -> Result<u32, SignalFdError> {
    let index = index_for_fd(fd).ok_or(SignalFdError::BadFileDescriptor)?;
    let table = SIGNALFDS.lock();
    let slot = table[index];
    if !slot.occupied() || slot.owner != owner {
        return Err(SignalFdError::BadFileDescriptor);
    }
    Ok(
        if crate::linux_signal::pending_for_signalfd(owner, slot.mask) {
            READY_IN
        } else {
            0
        },
    )
}

/// Return a transition value for edge-triggered epoll watches.
pub fn readiness_generation(owner: ProcessHandle, fd: u32) -> Result<u64, SignalFdError> {
    let index = index_for_fd(fd).ok_or(SignalFdError::BadFileDescriptor)?;
    let table = SIGNALFDS.lock();
    let slot = table[index];
    if !slot.occupied() || slot.owner != owner {
        return Err(SignalFdError::BadFileDescriptor);
    }
    Ok(crate::linux_signal::pending_mask(owner) & slot.mask)
}

pub fn close(owner: ProcessHandle, fd: u32) -> Result<(), SignalFdError> {
    let index = index_for_fd(fd).ok_or(SignalFdError::BadFileDescriptor)?;
    let mut table = SIGNALFDS.lock();
    let slot = &mut table[index];
    if !slot.occupied() || slot.owner != owner {
        return Err(SignalFdError::BadFileDescriptor);
    }
    *slot = SignalFdSlot::EMPTY;
    Ok(())
}

pub fn close_all(owner: ProcessHandle) -> usize {
    if owner.pid == 0 || owner.generation == 0 {
        return 0;
    }
    let mut table = SIGNALFDS.lock();
    let mut closed = 0;
    for slot in table.iter_mut() {
        if slot.owner == owner {
            *slot = SignalFdSlot::EMPTY;
            closed += 1;
        }
    }
    closed
}

pub fn close_on_exec(owner: ProcessHandle) -> usize {
    if owner.pid == 0 || owner.generation == 0 {
        return 0;
    }
    let mut table = SIGNALFDS.lock();
    let mut closed = 0;
    for slot in table.iter_mut() {
        if slot.owner == owner && slot.flags & SFD_CLOEXEC != 0 {
            *slot = SignalFdSlot::EMPTY;
            closed += 1;
        }
    }
    closed
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: ProcessHandle = ProcessHandle {
        pid: 0x6201,
        generation: 7,
    };

    #[test]
    fn pending_signal_is_read_as_one_fixed_record() {
        let fd = create(OWNER, 1 << 14, SFD_NONBLOCK).unwrap();
        crate::linux_signal::queue(OWNER, 15).unwrap();
        assert_eq!(readiness(OWNER, fd), Ok(READY_IN));
        let mut output = [0_u8; SIGNALFD_INFO_BYTES];
        assert_eq!(read(OWNER, fd, &mut output), Ok(SIGNALFD_INFO_BYTES));
        assert_eq!(u32::from_ne_bytes(output[..4].try_into().unwrap()), 15);
        assert_eq!(read(OWNER, fd, &mut output), Err(SignalFdError::WouldBlock));
        close(OWNER, fd).unwrap();
        crate::linux_signal::clear_thread(OWNER, None);
    }
}
