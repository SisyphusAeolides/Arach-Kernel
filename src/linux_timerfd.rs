//! Bounded Linux `timerfd(2)` objects.
//!
//! Timerfds are the first time-based descriptor in the Linux personality. The
//! backend table is intentionally fixed-capacity and process-owned, while
//! `linux_fd` assigns public descriptors. Expiry is evaluated lazily from the
//! monotonic clock: a
//! timer never needs an interrupt-time allocation, while `read`, `poll`, and
//! `epoll` all observe the same expiration count and transition generation.

use crate::linux_eventfd::READY_IN;
use crate::sync::SpinLock;

pub const CLOCK_MONOTONIC: u32 = 1;
pub const TFD_TIMER_ABSTIME: u32 = 1;
pub const TFD_NONBLOCK: u32 = 0x800;
pub const TFD_CLOEXEC: u32 = 0x80000;
pub const TIMERFD_CREATE_ALLOWED_FLAGS: u32 = TFD_NONBLOCK | TFD_CLOEXEC;
pub const TIMERFD_SETTIME_ALLOWED_FLAGS: u32 = TFD_TIMER_ABSTIME;

const MAXIMUM_TIMERFDS: usize = 64;
const TIMERFD_BASE: u32 = 0x2000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerSpec {
    /// Relative or absolute expiration in nanoseconds, depending on the
    /// operation. Zero disarms the timer.
    pub value_ns: u64,
    /// Repeating interval in nanoseconds. Zero means one-shot.
    pub interval_ns: u64,
}

impl TimerSpec {
    pub const DISARMED: Self = Self {
        value_ns: 0,
        interval_ns: 0,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimerFdError {
    InvalidArgument,
    BadFileDescriptor,
    WouldBlock,
    Capacity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TimerFdSlot {
    owner: u32,
    flags: u32,
    interval_ns: u64,
    next_expiration_ns: u64,
    expirations: u64,
    /// Monotonic transition generation used by edge-triggered epoll.
    readiness_generation: u64,
}

impl TimerFdSlot {
    const EMPTY: Self = Self {
        owner: 0,
        flags: 0,
        interval_ns: 0,
        next_expiration_ns: 0,
        expirations: 0,
        readiness_generation: 0,
    };

    const fn occupied(self) -> bool {
        self.owner != 0
    }
}

static TIMERFDS: SpinLock<[TimerFdSlot; MAXIMUM_TIMERFDS]> =
    SpinLock::new([TimerFdSlot::EMPTY; MAXIMUM_TIMERFDS]);

const fn index_for_fd(fd: u32) -> Option<usize> {
    if fd < TIMERFD_BASE {
        return None;
    }
    let index = (fd - TIMERFD_BASE) as usize;
    if index < MAXIMUM_TIMERFDS {
        Some(index)
    } else {
        None
    }
}

const fn fd_for_index(index: usize) -> u32 {
    TIMERFD_BASE + index as u32
}

fn checked_deadline(now_ns: u64, value_ns: u64) -> Option<u64> {
    now_ns.checked_add(value_ns)
}

/// Allocate a monotonic timerfd owned by `owner`.
pub fn create(owner: u32, clockid: u32, flags: u32) -> Result<u32, TimerFdError> {
    if owner == 0 || clockid != CLOCK_MONOTONIC || flags & !TIMERFD_CREATE_ALLOWED_FLAGS != 0 {
        return Err(TimerFdError::InvalidArgument);
    }
    let mut table = TIMERFDS.lock();
    let Some((index, slot)) = table
        .iter_mut()
        .enumerate()
        .find(|(_, slot)| !slot.occupied())
    else {
        return Err(TimerFdError::Capacity);
    };
    *slot = TimerFdSlot {
        owner,
        flags,
        ..TimerFdSlot::EMPTY
    };
    Ok(fd_for_index(index))
}

fn remaining(slot: &TimerFdSlot, now_ns: u64) -> TimerSpec {
    TimerSpec {
        value_ns: slot.next_expiration_ns.checked_sub(now_ns).unwrap_or(0),
        interval_ns: slot.interval_ns,
    }
}

/// Apply a new timer value and optionally return the previous remaining value.
/// `now_ns` is supplied by the syscall boundary so tests can advance time
/// deterministically without depending on a host clock.
pub fn settime(
    owner: u32,
    fd: u32,
    flags: u32,
    new_value: TimerSpec,
    now_ns: u64,
) -> Result<TimerSpec, TimerFdError> {
    if flags & !TIMERFD_SETTIME_ALLOWED_FLAGS != 0 {
        return Err(TimerFdError::InvalidArgument);
    }
    let index = index_for_fd(fd).ok_or(TimerFdError::BadFileDescriptor)?;
    let mut table = TIMERFDS.lock();
    let slot = &mut table[index];
    if !slot.occupied() || slot.owner != owner {
        return Err(TimerFdError::BadFileDescriptor);
    }
    refresh(slot, now_ns);
    let old = remaining(slot, now_ns);
    if new_value.value_ns == 0 {
        slot.interval_ns = 0;
        slot.next_expiration_ns = 0;
        slot.expirations = 0;
        return Ok(old);
    }
    let deadline = if flags & TFD_TIMER_ABSTIME != 0 {
        new_value.value_ns
    } else {
        checked_deadline(now_ns, new_value.value_ns).ok_or(TimerFdError::InvalidArgument)?
    };
    if deadline == 0 {
        return Err(TimerFdError::InvalidArgument);
    }
    slot.interval_ns = new_value.interval_ns;
    slot.next_expiration_ns = deadline;
    slot.expirations = 0;
    Ok(old)
}

/// Return the current remaining value without consuming expirations.
pub fn gettime(owner: u32, fd: u32, now_ns: u64) -> Result<TimerSpec, TimerFdError> {
    let index = index_for_fd(fd).ok_or(TimerFdError::BadFileDescriptor)?;
    let mut table = TIMERFDS.lock();
    let slot = &mut table[index];
    if !slot.occupied() || slot.owner != owner {
        return Err(TimerFdError::BadFileDescriptor);
    }
    refresh(slot, now_ns);
    Ok(remaining(slot, now_ns))
}

/// Read and consume the accumulated expiration count.
pub fn read(owner: u32, fd: u32, now_ns: u64) -> Result<u64, TimerFdError> {
    let index = index_for_fd(fd).ok_or(TimerFdError::BadFileDescriptor)?;
    let mut table = TIMERFDS.lock();
    let slot = &mut table[index];
    if !slot.occupied() || slot.owner != owner {
        return Err(TimerFdError::BadFileDescriptor);
    }
    refresh(slot, now_ns);
    if slot.expirations == 0 {
        return Err(TimerFdError::WouldBlock);
    }
    let value = slot.expirations;
    slot.expirations = 0;
    slot.readiness_generation = slot.readiness_generation.wrapping_add(1);
    Ok(value)
}

/// Return readiness without consuming expiration state.
pub fn readiness(owner: u32, fd: u32, now_ns: u64) -> Result<u32, TimerFdError> {
    let index = index_for_fd(fd).ok_or(TimerFdError::BadFileDescriptor)?;
    let mut table = TIMERFDS.lock();
    let slot = &mut table[index];
    if !slot.occupied() || slot.owner != owner {
        return Err(TimerFdError::BadFileDescriptor);
    }
    refresh(slot, now_ns);
    // A timerfd is readable once one or more expirations have accumulated. It
    // is not a writable stream; reporting only input avoids false POLLOUT
    // wakeups in event loops that use readiness as a progress guarantee.
    if slot.expirations != 0 {
        Ok(READY_IN)
    } else {
        Ok(0)
    }
}

pub fn readiness_generation(owner: u32, fd: u32, now_ns: u64) -> Result<u64, TimerFdError> {
    let index = index_for_fd(fd).ok_or(TimerFdError::BadFileDescriptor)?;
    let mut table = TIMERFDS.lock();
    let slot = &mut table[index];
    if !slot.occupied() || slot.owner != owner {
        return Err(TimerFdError::BadFileDescriptor);
    }
    refresh(slot, now_ns);
    Ok(slot.readiness_generation)
}

pub fn close(owner: u32, fd: u32) -> Result<(), TimerFdError> {
    let index = index_for_fd(fd).ok_or(TimerFdError::BadFileDescriptor)?;
    let mut table = TIMERFDS.lock();
    let slot = &mut table[index];
    if !slot.occupied() || slot.owner != owner {
        return Err(TimerFdError::BadFileDescriptor);
    }
    *slot = TimerFdSlot::EMPTY;
    Ok(())
}

pub fn close_all(owner: u32) -> usize {
    if owner == 0 {
        return 0;
    }
    let mut table = TIMERFDS.lock();
    let mut closed = 0;
    for slot in table.iter_mut() {
        if slot.owner == owner {
            *slot = TimerFdSlot::EMPTY;
            closed += 1;
        }
    }
    closed
}

pub fn close_on_exec(owner: u32) -> usize {
    if owner == 0 {
        return 0;
    }
    let mut table = TIMERFDS.lock();
    let mut closed = 0;
    for slot in table.iter_mut() {
        if slot.owner == owner && slot.flags & TFD_CLOEXEC != 0 {
            *slot = TimerFdSlot::EMPTY;
            closed += 1;
        }
    }
    closed
}

/// Advance a timer to `now_ns`, recording every elapsed interval. This is
/// deliberately called while the table lock is held by all public readers.
fn refresh(slot: &mut TimerFdSlot, now_ns: u64) {
    if slot.next_expiration_ns == 0 || now_ns < slot.next_expiration_ns {
        return;
    }
    let elapsed = now_ns - slot.next_expiration_ns;
    let count = if slot.interval_ns == 0 {
        1
    } else {
        elapsed
            .checked_div(slot.interval_ns)
            .unwrap_or(0)
            .saturating_add(1)
    };
    let was_empty = slot.expirations == 0;
    slot.expirations = slot.expirations.saturating_add(count);
    if was_empty {
        slot.readiness_generation = slot.readiness_generation.wrapping_add(1);
    }
    if slot.interval_ns == 0 {
        slot.next_expiration_ns = 0;
    } else {
        let advance = slot.interval_ns.saturating_mul(count);
        slot.next_expiration_ns = slot.next_expiration_ns.saturating_add(advance);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_shot_expires_once_and_reports_readability() {
        let owner = 0x3001;
        let fd = create(owner, CLOCK_MONOTONIC, TFD_NONBLOCK).unwrap();
        assert_eq!(
            settime(
                owner,
                fd,
                0,
                TimerSpec {
                    value_ns: 10,
                    interval_ns: 0,
                },
                100,
            ),
            Ok(TimerSpec::DISARMED)
        );
        assert_eq!(readiness(owner, fd, 109), Ok(0));
        assert_eq!(readiness(owner, fd, 110), Ok(READY_IN));
        assert_eq!(read(owner, fd, 110), Ok(1));
        assert_eq!(read(owner, fd, 111), Err(TimerFdError::WouldBlock));
        close(owner, fd).unwrap();
    }

    #[test]
    fn periodic_timer_accumulates_missed_intervals() {
        let owner = 0x3002;
        let fd = create(owner, CLOCK_MONOTONIC, 0).unwrap();
        settime(
            owner,
            fd,
            0,
            TimerSpec {
                value_ns: 10,
                interval_ns: 10,
            },
            0,
        )
        .unwrap();
        assert_eq!(read(owner, fd, 35), Ok(3));
        assert_eq!(gettime(owner, fd, 35).unwrap().value_ns, 5);
        close(owner, fd).unwrap();
    }

    #[test]
    fn absolute_timer_and_old_value_are_monotonic() {
        let owner = 0x3003;
        let fd = create(owner, CLOCK_MONOTONIC, 0).unwrap();
        settime(
            owner,
            fd,
            TFD_TIMER_ABSTIME,
            TimerSpec {
                value_ns: 500,
                interval_ns: 0,
            },
            100,
        )
        .unwrap();
        let old = settime(
            owner,
            fd,
            TFD_TIMER_ABSTIME,
            TimerSpec {
                value_ns: 800,
                interval_ns: 0,
            },
            300,
        )
        .unwrap();
        assert_eq!(old.value_ns, 200);
        close(owner, fd).unwrap();
    }

    #[test]
    fn ownership_flags_and_overflow_fail_closed() {
        let owner = 0x3004;
        let other = 0x3005;
        assert_eq!(
            create(owner, 0, 1 << 31),
            Err(TimerFdError::InvalidArgument)
        );
        let fd = create(owner, CLOCK_MONOTONIC, 0).unwrap();
        assert_eq!(read(other, fd, 0), Err(TimerFdError::BadFileDescriptor));
        assert_eq!(
            settime(
                owner,
                fd,
                0,
                TimerSpec {
                    value_ns: u64::MAX,
                    interval_ns: 0,
                },
                1,
            ),
            Err(TimerFdError::InvalidArgument)
        );
        close(owner, fd).unwrap();
    }

    #[test]
    fn process_exit_reclaims_timerfds() {
        let owner = 0x3006;
        let first = create(owner, CLOCK_MONOTONIC, 0).unwrap();
        let second = create(owner, CLOCK_MONOTONIC, 0).unwrap();
        assert_eq!(close_all(owner), 2);
        assert_eq!(close(owner, first), Err(TimerFdError::BadFileDescriptor));
        assert_eq!(close(owner, second), Err(TimerFdError::BadFileDescriptor));
    }

    #[test]
    fn exec_closes_only_flagged_timerfds() {
        let owner = 0x3007;
        let flagged = create(owner, CLOCK_MONOTONIC, TFD_CLOEXEC).unwrap();
        let retained = create(owner, CLOCK_MONOTONIC, 0).unwrap();
        assert_eq!(close_on_exec(owner), 1);
        assert_eq!(
            gettime(owner, flagged, 0),
            Err(TimerFdError::BadFileDescriptor)
        );
        assert_eq!(gettime(owner, retained, 0), Ok(TimerSpec::DISARMED));
        close(owner, retained).unwrap();
    }
}
