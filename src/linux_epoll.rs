//! Bounded Linux `epoll(7)` readiness for the kernel-owned wake descriptors.
//!
//! This is intentionally a narrow first descriptor bridge.  It implements
//! the userspace-visible epoll control/event ABI for eventfds and timerfds,
//! with level and edge-triggered watches, while refusing to masquerade as a
//! general file or device descriptor backend. The fixed tables keep every
//! allocation and readiness scan bounded until the full descriptor layer
//! exists.

use crate::linux_eventfd;
use crate::sync::SpinLock;

pub const EPOLL_CLOEXEC: u32 = 0x80000;
pub const EPOLL_ALLOWED_FLAGS: u32 = EPOLL_CLOEXEC;

pub const EPOLL_CTL_ADD: u32 = 1;
pub const EPOLL_CTL_DEL: u32 = 2;
pub const EPOLL_CTL_MOD: u32 = 3;

pub const EPOLLIN: u32 = linux_eventfd::READY_IN;
pub const EPOLLOUT: u32 = linux_eventfd::READY_OUT;
pub const EPOLLERR: u32 = linux_eventfd::READY_ERR;
pub const EPOLLHUP: u32 = linux_eventfd::READY_HUP;
pub const EPOLLET: u32 = 1 << 31;
const EPOLL_INTEREST_MASK: u32 = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLET;

const MAXIMUM_EPOLL_OBJECTS: usize = 16;
const MAXIMUM_EPOLL_WATCHES: usize = 32;
const EPOLL_BASE: u32 = 0x1000;

pub const MAXIMUM_READY_EVENTS: usize = MAXIMUM_EPOLL_WATCHES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EpollError {
    InvalidArgument,
    BadFileDescriptor,
    AlreadyExists,
    NotFound,
    Capacity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadyEvent {
    pub events: u32,
    pub data: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Watch {
    fd: u32,
    events: u32,
    data: u64,
    last_ready: u32,
    last_generation: u64,
    edge_seen: bool,
}

impl Watch {
    const EMPTY: Self = Self {
        fd: 0,
        events: 0,
        data: 0,
        last_ready: 0,
        last_generation: 0,
        edge_seen: false,
    };

    const fn occupied(self) -> bool {
        self.fd != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EpollSlot {
    owner: u32,
    flags: u32,
    watches: [Watch; MAXIMUM_EPOLL_WATCHES],
}

impl EpollSlot {
    const EMPTY: Self = Self {
        owner: 0,
        flags: 0,
        watches: [Watch::EMPTY; MAXIMUM_EPOLL_WATCHES],
    };

    const fn occupied(self) -> bool {
        self.owner != 0
    }
}

static EPOLLS: SpinLock<[EpollSlot; MAXIMUM_EPOLL_OBJECTS]> =
    SpinLock::new([EpollSlot::EMPTY; MAXIMUM_EPOLL_OBJECTS]);

const fn index_for_fd(fd: u32) -> Option<usize> {
    if fd < EPOLL_BASE {
        return None;
    }
    let index = (fd - EPOLL_BASE) as usize;
    if index < MAXIMUM_EPOLL_OBJECTS {
        Some(index)
    } else {
        None
    }
}

const fn fd_for_index(index: usize) -> u32 {
    EPOLL_BASE + index as u32
}

#[inline]
fn monotonic_now_ns() -> u64 {
    #[cfg(target_os = "none")]
    {
        crate::interrupts::monotonic_nanoseconds()
    }
    #[cfg(not(target_os = "none"))]
    {
        // Host-side epoll tests use eventfds, whose readiness is independent
        // of time. Timerfd tests exercise explicit timestamps directly in
        // `linux_timerfd`; keeping the host wrapper deterministic avoids a
        // std dependency in this no_std module.
        0
    }
}

fn target_readiness(owner: u32, fd: u32) -> Option<(u32, u64)> {
    if let Ok(ready) = linux_eventfd::readiness(owner, fd) {
        let generation = linux_eventfd::readiness_generation(owner, fd).unwrap_or(0);
        return Some((ready, generation));
    }
    let now = monotonic_now_ns();
    if let Ok(ready) = crate::linux_timerfd::readiness(owner, fd, now) {
        let generation = crate::linux_timerfd::readiness_generation(owner, fd, now).unwrap_or(0);
        return Some((ready, generation));
    }
    None
}

/// Allocate an epoll instance owned by `owner`.
pub fn create(owner: u32, flags: u32) -> Result<u32, EpollError> {
    if owner == 0 || flags & !EPOLL_ALLOWED_FLAGS != 0 {
        return Err(EpollError::InvalidArgument);
    }
    let mut table = EPOLLS.lock();
    let Some((index, slot)) = table
        .iter_mut()
        .enumerate()
        .find(|(_, slot)| !slot.occupied())
    else {
        return Err(EpollError::Capacity);
    };
    *slot = EpollSlot {
        owner,
        flags,
        watches: [Watch::EMPTY; MAXIMUM_EPOLL_WATCHES],
    };
    Ok(fd_for_index(index))
}

/// Add, modify, or remove one supported wake-descriptor watch. Validating the target before
/// taking the epoll table lock keeps the lock order independent of eventfd
/// operations and prevents a close/readiness race from becoming a deadlock.
pub fn ctl(
    owner: u32,
    epfd: u32,
    operation: u32,
    fd: u32,
    events: u32,
    data: u64,
) -> Result<(), EpollError> {
    let target_is_valid = target_readiness(owner, fd).is_some();
    if !target_is_valid || fd == epfd || events & !EPOLL_INTEREST_MASK != 0 {
        return Err(EpollError::InvalidArgument);
    }
    let index = index_for_fd(epfd).ok_or(EpollError::BadFileDescriptor)?;
    let mut table = EPOLLS.lock();
    let slot = &mut table[index];
    if !slot.occupied() || slot.owner != owner {
        return Err(EpollError::BadFileDescriptor);
    }
    let existing = slot.watches.iter().position(|watch| watch.fd == fd);
    match operation {
        EPOLL_CTL_ADD => {
            if existing.is_some() {
                return Err(EpollError::AlreadyExists);
            }
            let Some(watch) = slot.watches.iter_mut().find(|watch| !watch.occupied()) else {
                return Err(EpollError::Capacity);
            };
            *watch = Watch {
                fd,
                events,
                data,
                last_ready: 0,
                last_generation: 0,
                edge_seen: false,
            };
            Ok(())
        }
        EPOLL_CTL_MOD => {
            let Some(position) = existing else {
                return Err(EpollError::NotFound);
            };
            slot.watches[position] = Watch {
                fd,
                events,
                data,
                last_ready: 0,
                last_generation: 0,
                edge_seen: false,
            };
            Ok(())
        }
        EPOLL_CTL_DEL => {
            let Some(position) = existing else {
                return Err(EpollError::NotFound);
            };
            slot.watches[position] = Watch::EMPTY;
            Ok(())
        }
        _ => Err(EpollError::InvalidArgument),
    }
}

/// Collect ready events without sleeping.  A positive timeout is accepted
/// but treated as a bounded probe; scheduler wait queues will own sleeping
/// once ordinary file descriptors are implemented.  Level-triggered watches
/// repeat while ready; edge-triggered watches report only a 0→ready change.
pub fn wait(owner: u32, epfd: u32, output: &mut [ReadyEvent]) -> Result<usize, EpollError> {
    if output.is_empty() {
        return Err(EpollError::InvalidArgument);
    }
    let index = index_for_fd(epfd).ok_or(EpollError::BadFileDescriptor)?;
    // Snapshot before querying targets. `ctl` validates a target before
    // taking this table's lock, so holding both locks in the opposite order
    // would permit a cross-CPU deadlock.
    let mut watches = {
        let table = EPOLLS.lock();
        let slot = &table[index];
        if !slot.occupied() || slot.owner != owner {
            return Err(EpollError::BadFileDescriptor);
        }
        slot.watches
    };

    let mut count = 0;
    for watch in &mut watches {
        if !watch.occupied() {
            continue;
        }
        let (ready, generation, invalid) = match target_readiness(owner, watch.fd) {
            Some((ready, generation)) => (ready, generation, false),
            None => (EPOLLERR | EPOLLHUP, 0, true),
        };
        let interested = ready & (watch.events & !EPOLLET);
        let edge = watch.events & EPOLLET != 0;
        let should_report = if invalid {
            true
        } else if edge {
            interested != 0 && (!watch.edge_seen || watch.last_generation != generation)
        } else {
            interested != 0
        };
        if should_report && count < output.len() {
            let mut event_bits = interested;
            if invalid {
                event_bits |= EPOLLERR | EPOLLHUP;
            }
            output[count] = ReadyEvent {
                events: event_bits,
                data: watch.data,
            };
            count += 1;
        }
        watch.last_ready = interested;
        if edge && (should_report || interested == 0) {
            watch.edge_seen = should_report || watch.edge_seen;
            watch.last_generation = generation;
        }
    }

    let mut table = EPOLLS.lock();
    let slot = &mut table[index];
    if !slot.occupied() || slot.owner != owner {
        return Err(EpollError::BadFileDescriptor);
    }
    for watch in &watches {
        if let Some(current) = slot
            .watches
            .iter_mut()
            .find(|current| current.fd == watch.fd)
        {
            current.last_ready = watch.last_ready;
            current.last_generation = watch.last_generation;
            current.edge_seen = watch.edge_seen;
        }
    }
    Ok(count)
}

/// Return readiness for `poll(2)` when the descriptor is an epoll object.
pub fn readiness(owner: u32, epfd: u32) -> Result<u32, EpollError> {
    let index = index_for_fd(epfd).ok_or(EpollError::BadFileDescriptor)?;
    let watches = {
        let table = EPOLLS.lock();
        let slot = &table[index];
        if !slot.occupied() || slot.owner != owner {
            return Err(EpollError::BadFileDescriptor);
        }
        slot.watches
    };
    for watch in &watches {
        if watch.occupied() {
            let (ready, generation) =
                target_readiness(owner, watch.fd).unwrap_or((EPOLLERR | EPOLLHUP, 0));
            let edge = watch.events & EPOLLET != 0;
            let edge_pending = !edge || !watch.edge_seen || watch.last_generation != generation;
            if ready & (watch.events & !EPOLLET) != 0 && edge_pending {
                return Ok(EPOLLIN);
            }
        }
    }
    Ok(EPOLLOUT)
}

/// Close one epoll instance owned by `owner`.
pub fn close(owner: u32, epfd: u32) -> Result<(), EpollError> {
    let index = index_for_fd(epfd).ok_or(EpollError::BadFileDescriptor)?;
    let mut table = EPOLLS.lock();
    let slot = &mut table[index];
    if !slot.occupied() || slot.owner != owner {
        return Err(EpollError::BadFileDescriptor);
    }
    *slot = EpollSlot::EMPTY;
    Ok(())
}

/// Reclaim epoll instances owned by an exiting process.
pub fn close_all(owner: u32) -> usize {
    if owner == 0 {
        return 0;
    }
    let mut table = EPOLLS.lock();
    let mut closed = 0;
    for slot in table.iter_mut() {
        if slot.owner == owner {
            *slot = EpollSlot::EMPTY;
            closed += 1;
        }
    }
    closed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_watch_reports_eventfd_readiness_until_consumed() {
        let owner = 0x2001;
        let eventfd = linux_eventfd::create(owner, 1, 0).unwrap();
        let epfd = create(owner, 0).unwrap();
        ctl(owner, epfd, EPOLL_CTL_ADD, eventfd, EPOLLIN, 0x55).unwrap();
        let mut output = [ReadyEvent { events: 0, data: 0 }; 1];
        assert_eq!(wait(owner, epfd, &mut output), Ok(1));
        assert_eq!(
            output[0],
            ReadyEvent {
                events: EPOLLIN,
                data: 0x55
            }
        );
        assert_eq!(wait(owner, epfd, &mut output), Ok(1));
        linux_eventfd::read(owner, eventfd).unwrap();
        assert_eq!(wait(owner, epfd, &mut output), Ok(0));
        close_all(owner);
        linux_eventfd::close(owner, eventfd).unwrap();
    }

    #[test]
    fn edge_watch_reports_only_a_new_ready_transition() {
        let owner = 0x2002;
        let eventfd = linux_eventfd::create(owner, 0, 0).unwrap();
        let epfd = create(owner, 0).unwrap();
        ctl(owner, epfd, EPOLL_CTL_ADD, eventfd, EPOLLIN | EPOLLET, 7).unwrap();
        let mut output = [ReadyEvent { events: 0, data: 0 }; 1];
        assert_eq!(wait(owner, epfd, &mut output), Ok(0));
        linux_eventfd::write(owner, eventfd, 1).unwrap();
        assert_eq!(wait(owner, epfd, &mut output), Ok(1));
        assert_eq!(wait(owner, epfd, &mut output), Ok(0));
        linux_eventfd::read(owner, eventfd).unwrap();
        linux_eventfd::write(owner, eventfd, 1).unwrap();
        assert_eq!(wait(owner, epfd, &mut output), Ok(1));
        close_all(owner);
        linux_eventfd::close(owner, eventfd).unwrap();
    }

    #[test]
    fn ctl_rejects_duplicate_and_cross_owner_targets() {
        let owner = 0x2003;
        let other = 0x2004;
        let eventfd = linux_eventfd::create(owner, 0, 0).unwrap();
        let epfd = create(owner, 0).unwrap();
        assert_eq!(
            ctl(other, epfd, EPOLL_CTL_ADD, eventfd, EPOLLIN, 0),
            Err(EpollError::InvalidArgument)
        );
        ctl(owner, epfd, EPOLL_CTL_ADD, eventfd, EPOLLIN, 0).unwrap();
        assert_eq!(
            ctl(owner, epfd, EPOLL_CTL_ADD, eventfd, EPOLLIN, 0),
            Err(EpollError::AlreadyExists)
        );
        close_all(owner);
        linux_eventfd::close(owner, eventfd).unwrap();
    }
}
