//! Bounded Linux `epoll(7)` readiness for the kernel-owned wake descriptors.
//!
//! Watches retain generation-tagged unified open objects rather than public
//! descriptor numbers. A watch follows the open description while any
//! descriptor alias remains and is removed on the last descriptor close, so
//! descriptor reuse cannot retarget it. Every allocation and readiness scan
//! remains bounded.

use crate::linux_eventfd;
use crate::linux_fd::ObjectKey;
use crate::process::lifecycle::ProcessHandle;
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
pub const MAXIMUM_EPOLL_WATCHES: usize = 32;
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
    target: ObjectKey,
    registration: u64,
    events: u32,
    data: u64,
    last_ready: u32,
    last_generation: u64,
    edge_seen: bool,
}

impl Watch {
    const EMPTY: Self = Self {
        target: ObjectKey::EMPTY,
        registration: 0,
        events: 0,
        data: 0,
        last_ready: 0,
        last_generation: 0,
        edge_seen: false,
    };

    const fn occupied(self) -> bool {
        !self.target.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EpollSlot {
    owner: ProcessHandle,
    flags: u32,
    next_registration: u64,
    watches: [Watch; MAXIMUM_EPOLL_WATCHES],
}

impl EpollSlot {
    const EMPTY: Self = Self {
        owner: ProcessHandle {
            pid: 0,
            generation: 0,
        },
        flags: 0,
        next_registration: 0,
        watches: [Watch::EMPTY; MAXIMUM_EPOLL_WATCHES],
    };

    const fn occupied(self) -> bool {
        self.owner.pid != 0 && self.owner.generation != 0
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

fn target_readiness(target: ObjectKey) -> Option<(u32, u64)> {
    crate::linux_fd::readiness_by_key(target).ok()
}

/// Allocate an epoll instance owned by `owner`.
pub fn create(owner: ProcessHandle, flags: u32) -> Result<u32, EpollError> {
    if owner.pid == 0 || owner.generation == 0 || flags & !EPOLL_ALLOWED_FLAGS != 0 {
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
        next_registration: 0,
        watches: [Watch::EMPTY; MAXIMUM_EPOLL_WATCHES],
    };
    Ok(fd_for_index(index))
}

/// Add, modify, or remove one supported wake-descriptor watch. Add and modify
/// validate the target before taking the epoll table lock, keeping lock order
/// independent of backend operations. Delete accepts the exact stored key so
/// an add/last-close race can roll back a just-published watch.
pub fn ctl(
    owner: ProcessHandle,
    epfd: u32,
    operation: u32,
    target: ObjectKey,
    events: u32,
    data: u64,
) -> Result<(), EpollError> {
    if events & !EPOLL_INTEREST_MASK != 0
        || operation != EPOLL_CTL_DEL && target_readiness(target).is_none()
    {
        return Err(EpollError::InvalidArgument);
    }
    let index = index_for_fd(epfd).ok_or(EpollError::BadFileDescriptor)?;
    let mut table = EPOLLS.lock();
    let slot = &mut table[index];
    if !slot.occupied() || slot.owner != owner {
        return Err(EpollError::BadFileDescriptor);
    }
    let existing = slot.watches.iter().position(|watch| watch.target == target);
    match operation {
        EPOLL_CTL_ADD => {
            if existing.is_some() {
                return Err(EpollError::AlreadyExists);
            }
            let Some(position) = slot.watches.iter().position(|watch| !watch.occupied()) else {
                return Err(EpollError::Capacity);
            };
            let registration = slot
                .next_registration
                .checked_add(1)
                .filter(|registration| *registration != 0)
                .ok_or(EpollError::Capacity)?;
            slot.next_registration = registration;
            slot.watches[position] = Watch {
                target,
                registration,
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
            let registration = slot
                .next_registration
                .checked_add(1)
                .filter(|registration| *registration != 0)
                .ok_or(EpollError::Capacity)?;
            slot.next_registration = registration;
            slot.watches[position] = Watch {
                target,
                registration,
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
pub fn wait(
    owner: ProcessHandle,
    epfd: u32,
    output: &mut [ReadyEvent],
) -> Result<usize, EpollError> {
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
        let (ready, generation, invalid) = match target_readiness(watch.target) {
            Some((ready, generation)) => (ready, generation, false),
            None => (EPOLLERR | EPOLLHUP, 0, true),
        };
        let interested = ready & ((watch.events & !EPOLLET) | EPOLLERR | EPOLLHUP);
        let edge = watch.events & EPOLLET != 0;
        let should_report = if invalid {
            true
        } else if edge {
            interested != 0 && (!watch.edge_seen || watch.last_generation != generation)
        } else {
            interested != 0
        };
        let emitted = should_report && count < output.len();
        if emitted {
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
        if edge && emitted {
            watch.edge_seen = true;
            watch.last_generation = generation;
        } else if edge && interested == 0 {
            watch.edge_seen = false;
            watch.last_generation = generation;
        }
    }

    let mut table = EPOLLS.lock();
    let slot = &mut table[index];
    if !slot.occupied() || slot.owner != owner {
        return Err(EpollError::BadFileDescriptor);
    }
    for watch in &watches {
        if let Some(current) = slot.watches.iter_mut().find(|current| {
            current.target == watch.target && current.registration == watch.registration
        }) {
            current.last_ready = watch.last_ready;
            current.last_generation = watch.last_generation;
            current.edge_seen = watch.edge_seen;
        }
    }
    Ok(count)
}

/// Return readiness for `poll(2)` when the descriptor is an epoll object.
pub fn readiness(owner: ProcessHandle, epfd: u32) -> Result<u32, EpollError> {
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
                target_readiness(watch.target).unwrap_or((EPOLLERR | EPOLLHUP, 0));
            let edge = watch.events & EPOLLET != 0;
            let edge_pending = !edge || !watch.edge_seen || watch.last_generation != generation;
            if ready & ((watch.events & !EPOLLET) | EPOLLERR | EPOLLHUP) != 0 && edge_pending {
                return Ok(EPOLLIN);
            }
        }
    }
    Ok(0)
}

/// Close one epoll instance owned by `owner`.
pub fn close(
    owner: ProcessHandle,
    epfd: u32,
    watched: &mut [ObjectKey],
) -> Result<usize, EpollError> {
    let index = index_for_fd(epfd).ok_or(EpollError::BadFileDescriptor)?;
    let mut table = EPOLLS.lock();
    let slot = &mut table[index];
    if !slot.occupied() || slot.owner != owner {
        return Err(EpollError::BadFileDescriptor);
    }
    let count = slot.watches.iter().filter(|watch| watch.occupied()).count();
    if count > watched.len() {
        return Err(EpollError::Capacity);
    }
    for (cursor, watch) in slot
        .watches
        .iter()
        .filter(|watch| watch.occupied())
        .enumerate()
    {
        watched[cursor] = watch.target;
    }
    *slot = EpollSlot::EMPTY;
    Ok(count)
}

/// Remove every watch for an open object whose last public descriptor closed.
/// The caller drops the corresponding retained object references after this
/// table lock is released.
pub(crate) fn remove_target(target: ObjectKey) -> usize {
    let mut table = EPOLLS.lock();
    let mut removed = 0;
    for slot in table.iter_mut().filter(|slot| slot.occupied()) {
        for watch in &mut slot.watches {
            if watch.target == target {
                *watch = Watch::EMPTY;
                removed += 1;
            }
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: ProcessHandle = ProcessHandle {
        pid: 0x5301,
        generation: 3,
    };

    #[test]
    fn level_watch_reports_eventfd_readiness_until_consumed() {
        let eventfd = crate::linux_fd::eventfd(OWNER, 1, 0).unwrap();
        let epfd = crate::linux_fd::epoll_create(OWNER, 0).unwrap();
        crate::linux_fd::epoll_ctl(OWNER, epfd, EPOLL_CTL_ADD, eventfd, EPOLLIN, 0x55).unwrap();
        assert_eq!(crate::linux_fd::readiness(OWNER, epfd, 0), Ok(EPOLLIN));
        let mut output = [ReadyEvent { events: 0, data: 0 }; 1];
        assert_eq!(crate::linux_fd::epoll_wait(OWNER, epfd, &mut output), Ok(1));
        assert_eq!(
            output[0],
            ReadyEvent {
                events: EPOLLIN,
                data: 0x55
            }
        );
        assert_eq!(crate::linux_fd::epoll_wait(OWNER, epfd, &mut output), Ok(1));
        let mut value = [0_u8; 8];
        crate::linux_fd::read(OWNER, eventfd, &mut value, 0).unwrap();
        assert_eq!(crate::linux_fd::epoll_wait(OWNER, epfd, &mut output), Ok(0));
        assert_eq!(crate::linux_fd::readiness(OWNER, epfd, 0), Ok(0));
        crate::linux_fd::close_all(OWNER);
    }

    #[test]
    fn edge_watch_reports_only_a_new_ready_transition() {
        let owner = ProcessHandle {
            pid: 0x5302,
            generation: 3,
        };
        let eventfd = crate::linux_fd::eventfd(owner, 0, 0).unwrap();
        let epfd = crate::linux_fd::epoll_create(owner, 0).unwrap();
        crate::linux_fd::epoll_ctl(owner, epfd, EPOLL_CTL_ADD, eventfd, EPOLLIN | EPOLLET, 7)
            .unwrap();
        let mut output = [ReadyEvent { events: 0, data: 0 }; 1];
        assert_eq!(crate::linux_fd::epoll_wait(owner, epfd, &mut output), Ok(0));
        let value = 1_u64.to_ne_bytes();
        crate::linux_fd::write(owner, eventfd, &value, 0).unwrap();
        assert_eq!(crate::linux_fd::epoll_wait(owner, epfd, &mut output), Ok(1));
        assert_eq!(crate::linux_fd::epoll_wait(owner, epfd, &mut output), Ok(0));
        let mut drained = [0_u8; 8];
        crate::linux_fd::read(owner, eventfd, &mut drained, 0).unwrap();
        crate::linux_fd::write(owner, eventfd, &value, 0).unwrap();
        assert_eq!(crate::linux_fd::epoll_wait(owner, epfd, &mut output), Ok(1));
        crate::linux_fd::close_all(owner);
    }

    #[test]
    fn edge_watch_beyond_output_capacity_remains_pending() {
        let owner = ProcessHandle {
            pid: 0x5303,
            generation: 3,
        };
        let first = crate::linux_fd::eventfd(owner, 1, 0).unwrap();
        let second = crate::linux_fd::eventfd(owner, 1, 0).unwrap();
        let epfd = crate::linux_fd::epoll_create(owner, 0).unwrap();
        crate::linux_fd::epoll_ctl(owner, epfd, EPOLL_CTL_ADD, first, EPOLLIN | EPOLLET, 1)
            .unwrap();
        crate::linux_fd::epoll_ctl(owner, epfd, EPOLL_CTL_ADD, second, EPOLLIN | EPOLLET, 2)
            .unwrap();

        let mut output = [ReadyEvent { events: 0, data: 0 }; 1];
        assert_eq!(crate::linux_fd::epoll_wait(owner, epfd, &mut output), Ok(1));
        assert_eq!(output[0].data, 1);
        assert_eq!(crate::linux_fd::epoll_wait(owner, epfd, &mut output), Ok(1));
        assert_eq!(output[0].data, 2);
        assert_eq!(crate::linux_fd::epoll_wait(owner, epfd, &mut output), Ok(0));
        crate::linux_fd::close_all(owner);
    }

    #[test]
    fn pipe_hup_is_reported_without_explicit_interest() {
        let owner = ProcessHandle {
            pid: 0x5304,
            generation: 3,
        };
        let (reader, writer) = crate::linux_fd::pipe(owner, crate::linux_file::O_NONBLOCK).unwrap();
        let epfd = crate::linux_fd::epoll_create(owner, 0).unwrap();
        crate::linux_fd::epoll_ctl(owner, epfd, EPOLL_CTL_ADD, reader, EPOLLIN, 0x77).unwrap();
        crate::linux_fd::close(owner, writer).unwrap();

        let mut output = [ReadyEvent { events: 0, data: 0 }; 1];
        assert_eq!(crate::linux_fd::epoll_wait(owner, epfd, &mut output), Ok(1));
        assert_eq!(output[0].events, EPOLLHUP);
        assert_eq!(output[0].data, 0x77);
        crate::linux_fd::close_all(owner);
    }
}
