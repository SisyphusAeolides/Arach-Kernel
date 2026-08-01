//! Bounded Linux `eventfd2(2)` objects.
//!
//! The first Linux userspace services need one reliable wake primitive before
//! epoll, timerfd, and device file descriptors can be layered on top.  This
//! module deliberately owns only eventfd state: it does not pretend to be a
//! general file descriptor table.  Descriptors are process-owned, have a
//! stable bounded lifetime, and return `EAGAIN` instead of sleeping when an
//! operation would block.  The latter is an explicit kernel contract while
//! scheduler wait queues are still being brought up.

use crate::sync::SpinLock;

pub const EFD_SEMAPHORE: u32 = 0x1;
pub const EFD_NONBLOCK: u32 = 0x800;
pub const EFD_CLOEXEC: u32 = 0x80000;
pub const EVENTFD_ALLOWED_FLAGS: u32 = EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC;

/// Linux readiness bits shared by `poll(2)` and `epoll(7)`.
pub const READY_IN: u32 = 0x001;
pub const READY_OUT: u32 = 0x004;
pub const READY_ERR: u32 = 0x008;
pub const READY_HUP: u32 = 0x010;

const MAXIMUM_EVENTFDS: usize = 64;
const EVENTFD_BASE: u32 = 0x100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventFdError {
    InvalidArgument,
    BadFileDescriptor,
    WouldBlock,
    Overflow,
    Capacity,
    PermissionDenied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EventFdSlot {
    owner: u32,
    counter: u64,
    flags: u32,
    /// Monotonic readiness transition generation used by edge-triggered
    /// epoll watches.  It advances whenever the counter crosses between
    /// empty and readable (or the reserved full and writable states).
    readiness_generation: u64,
}

impl EventFdSlot {
    const EMPTY: Self = Self {
        owner: 0,
        counter: 0,
        flags: 0,
        readiness_generation: 0,
    };

    const fn occupied(self) -> bool {
        self.owner != 0
    }
}

static EVENTFDS: SpinLock<[EventFdSlot; MAXIMUM_EVENTFDS]> =
    SpinLock::new([EventFdSlot::EMPTY; MAXIMUM_EVENTFDS]);

const fn index_for_fd(fd: u32) -> Option<usize> {
    if fd < EVENTFD_BASE {
        return None;
    }
    let index = (fd - EVENTFD_BASE) as usize;
    if index < MAXIMUM_EVENTFDS {
        Some(index)
    } else {
        None
    }
}

const fn fd_for_index(index: usize) -> u32 {
    EVENTFD_BASE + index as u32
}

/// Allocate an eventfd owned by `owner`.
pub fn create(owner: u32, initial: u64, flags: u32) -> Result<u32, EventFdError> {
    if owner == 0 || flags & !EVENTFD_ALLOWED_FLAGS != 0 {
        return Err(EventFdError::InvalidArgument);
    }

    let mut table = EVENTFDS.lock();
    let Some((index, slot)) = table
        .iter_mut()
        .enumerate()
        .find(|(_, slot)| !slot.occupied())
    else {
        return Err(EventFdError::Capacity);
    };
    *slot = EventFdSlot {
        owner,
        counter: initial,
        flags,
        readiness_generation: u64::from(initial != 0),
    };
    Ok(fd_for_index(index))
}

/// Read one eventfd value.  A semaphore returns one unit; a normal eventfd
/// drains the complete counter.  Empty counters are never allowed to sleep.
pub fn read(owner: u32, fd: u32) -> Result<u64, EventFdError> {
    let index = index_for_fd(fd).ok_or(EventFdError::BadFileDescriptor)?;
    let mut table = EVENTFDS.lock();
    let slot = &mut table[index];
    if !slot.occupied() || slot.owner != owner {
        return Err(EventFdError::BadFileDescriptor);
    }
    if slot.counter == 0 {
        return Err(EventFdError::WouldBlock);
    }

    let previous = slot.counter;
    if slot.flags & EFD_SEMAPHORE != 0 {
        slot.counter -= 1;
        if slot.counter == 0 {
            slot.readiness_generation = slot.readiness_generation.wrapping_add(1);
        }
        Ok(1)
    } else {
        let value = slot.counter;
        slot.counter = 0;
        if previous != 0 {
            slot.readiness_generation = slot.readiness_generation.wrapping_add(1);
        }
        Ok(value)
    }
}

/// Add one eventfd value.  Linux reserves `u64::MAX`; an overflowing write
/// is reported as would-block rather than wrapping kernel-owned state.
pub fn write(owner: u32, fd: u32, value: u64) -> Result<(), EventFdError> {
    let index = index_for_fd(fd).ok_or(EventFdError::BadFileDescriptor)?;
    if value == u64::MAX {
        return Err(EventFdError::InvalidArgument);
    }

    let mut table = EVENTFDS.lock();
    let slot = &mut table[index];
    if !slot.occupied() || slot.owner != owner {
        return Err(EventFdError::BadFileDescriptor);
    }
    let previous = slot.counter;
    slot.counter = slot
        .counter
        .checked_add(value)
        .ok_or(EventFdError::Overflow)?;
    if previous == 0 && slot.counter != 0 {
        slot.readiness_generation = slot.readiness_generation.wrapping_add(1);
    }
    Ok(())
}

/// Return the currently observable readiness bits without consuming state.
/// Eventfds are readable when their counter is non-zero and writable until
/// their counter reaches the reserved all-ones value.
pub fn readiness(owner: u32, fd: u32) -> Result<u32, EventFdError> {
    let index = index_for_fd(fd).ok_or(EventFdError::BadFileDescriptor)?;
    let table = EVENTFDS.lock();
    let slot = &table[index];
    if !slot.occupied() || slot.owner != owner {
        return Err(EventFdError::BadFileDescriptor);
    }
    let mut ready = READY_OUT;
    if slot.counter != 0 {
        ready |= READY_IN;
    }
    if slot.counter == u64::MAX {
        ready &= !READY_OUT;
    }
    Ok(ready)
}

/// Return the readiness transition generation without consuming the counter.
pub fn readiness_generation(owner: u32, fd: u32) -> Result<u64, EventFdError> {
    let index = index_for_fd(fd).ok_or(EventFdError::BadFileDescriptor)?;
    let table = EVENTFDS.lock();
    let slot = &table[index];
    if !slot.occupied() || slot.owner != owner {
        return Err(EventFdError::BadFileDescriptor);
    }
    Ok(slot.readiness_generation)
}

/// Close an eventfd owned by `owner`.
pub fn close(owner: u32, fd: u32) -> Result<(), EventFdError> {
    let index = index_for_fd(fd).ok_or(EventFdError::BadFileDescriptor)?;
    let mut table = EVENTFDS.lock();
    let slot = &mut table[index];
    if !slot.occupied() || slot.owner != owner {
        return Err(EventFdError::BadFileDescriptor);
    }
    *slot = EventFdSlot::EMPTY;
    Ok(())
}

/// Reclaim every descriptor owned by an exiting process.  The lifecycle layer
/// calls this before publishing the zombie transition so an eventfd can never
/// outlive its process and consume one of the fixed descriptor slots forever.
pub fn close_all(owner: u32) -> usize {
    if owner == 0 {
        return 0;
    }
    let mut table = EVENTFDS.lock();
    let mut closed = 0;
    for slot in table.iter_mut() {
        if slot.owner == owner {
            *slot = EventFdSlot::EMPTY;
            closed += 1;
        }
    }
    closed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_eventfd_accumulates_and_drains() {
        let owner = 0x1001;
        let fd = create(owner, 4, 0).unwrap();
        write(owner, fd, 3).unwrap();
        assert_eq!(read(owner, fd), Ok(7));
        assert_eq!(read(owner, fd), Err(EventFdError::WouldBlock));
        close(owner, fd).unwrap();
    }

    #[test]
    fn semaphore_returns_one_and_preserves_remaining_units() {
        let owner = 0x1002;
        let fd = create(owner, 2, EFD_SEMAPHORE).unwrap();
        assert_eq!(read(owner, fd), Ok(1));
        assert_eq!(read(owner, fd), Ok(1));
        assert_eq!(read(owner, fd), Err(EventFdError::WouldBlock));
        close(owner, fd).unwrap();
    }

    #[test]
    fn ownership_and_close_are_enforced() {
        let owner = 0x1003;
        let other = 0x1004;
        let fd = create(owner, 0, EFD_NONBLOCK).unwrap();
        assert_eq!(read(other, fd), Err(EventFdError::BadFileDescriptor));
        assert_eq!(write(other, fd, 1), Err(EventFdError::BadFileDescriptor));
        assert_eq!(close(other, fd), Err(EventFdError::BadFileDescriptor));
        close(owner, fd).unwrap();
        assert_eq!(read(owner, fd), Err(EventFdError::BadFileDescriptor));
    }

    #[test]
    fn process_exit_reclaims_all_owned_descriptors() {
        let owner = 0x1006;
        let first = create(owner, 1, 0).unwrap();
        let second = create(owner, 2, 0).unwrap();
        assert_eq!(close_all(owner), 2);
        assert_eq!(close(owner, first), Err(EventFdError::BadFileDescriptor));
        assert_eq!(close(owner, second), Err(EventFdError::BadFileDescriptor));
    }

    #[test]
    fn readiness_tracks_counter_without_consuming_it() {
        let owner = 0x1007;
        let fd = create(owner, 0, 0).unwrap();
        assert_eq!(readiness(owner, fd), Ok(READY_OUT));
        write(owner, fd, 1).unwrap();
        assert_eq!(readiness(owner, fd), Ok(READY_IN | READY_OUT));
        assert_eq!(read(owner, fd), Ok(1));
        assert_eq!(readiness(owner, fd), Ok(READY_OUT));
        close(owner, fd).unwrap();
    }

    #[test]
    fn reserved_values_and_unknown_flags_fail_closed() {
        let owner = 0x1005;
        assert_eq!(
            create(owner, 0, 1 << 31),
            Err(EventFdError::InvalidArgument)
        );
        let fd = create(owner, 0, 0).unwrap();
        assert_eq!(
            write(owner, fd, u64::MAX),
            Err(EventFdError::InvalidArgument)
        );
        close(owner, fd).unwrap();
    }
}
