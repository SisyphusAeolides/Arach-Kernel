//! Generation-safe Linux private futex wait queues.
//!
//! Waiters are keyed by address-space root and aligned userspace address, not
//! by a bare virtual address. The queue lock remains held across the user-word
//! comparison and lifecycle block transition. A concurrent wake therefore
//! observes either no eligible waiter before the comparison or a completely
//! saved, blocked PID generation afterward; it cannot disappear between an
//! unlocked comparison and queue insertion.

use crate::process::context::{SavedUserContext, USER_ADDRESS_LIMIT, USER_ADDRESS_MINIMUM};
use crate::process::lifecycle::{
    LifecycleError, ProcessHandle, ScheduleDecision, mark_runnable, schedule_block,
};
use crate::sync::SpinLock;

pub const MAXIMUM_FUTEX_WAITERS: usize = crate::process::lifecycle::MAXIMUM_PROCESSES;
const FUTEX_WORD_BYTES: u64 = core::mem::size_of::<u32>() as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FutexKey {
    address_space_root: u64,
    address: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FutexWaiter {
    owner: ProcessHandle,
    key: FutexKey,
    sequence: u64,
}

impl FutexWaiter {
    const EMPTY: Self = Self {
        owner: ProcessHandle {
            pid: 0,
            generation: 0,
        },
        key: FutexKey {
            address_space_root: 0,
            address: 0,
        },
        sequence: 0,
    };

    const fn occupied(self) -> bool {
        self.owner.pid != 0 && self.owner.generation != 0 && self.sequence != 0
    }
}

struct FutexTable {
    waiters: [FutexWaiter; MAXIMUM_FUTEX_WAITERS],
    next_sequence: u64,
}

impl FutexTable {
    const fn new() -> Self {
        Self {
            waiters: [FutexWaiter::EMPTY; MAXIMUM_FUTEX_WAITERS],
            next_sequence: 1,
        }
    }

    fn contains_owner(&self, owner: ProcessHandle) -> bool {
        self.waiters
            .iter()
            .any(|waiter| waiter.occupied() && waiter.owner == owner)
    }

    fn enqueue(&mut self, owner: ProcessHandle, key: FutexKey) -> Result<(), FutexQueueError> {
        if self.contains_owner(owner) {
            return Err(FutexQueueError::AlreadyWaiting);
        }
        let sequence = self.next_sequence;
        let next_sequence = sequence.checked_add(1).ok_or(FutexQueueError::Capacity)?;
        let slot = self
            .waiters
            .iter_mut()
            .find(|waiter| !waiter.occupied())
            .ok_or(FutexQueueError::Capacity)?;
        *slot = FutexWaiter {
            owner,
            key,
            sequence,
        };
        self.next_sequence = next_sequence;
        Ok(())
    }

    fn take_oldest(&mut self, key: FutexKey) -> Option<ProcessHandle> {
        let index = self
            .waiters
            .iter()
            .enumerate()
            .filter(|(_, waiter)| waiter.occupied() && waiter.key == key)
            .min_by_key(|(_, waiter)| waiter.sequence)
            .map(|(index, _)| index)?;
        let owner = self.waiters[index].owner;
        self.waiters[index] = FutexWaiter::EMPTY;
        Some(owner)
    }

    fn cancel(&mut self, owner: ProcessHandle) -> bool {
        let Some(waiter) = self
            .waiters
            .iter_mut()
            .find(|waiter| waiter.occupied() && waiter.owner == owner)
        else {
            return false;
        };
        *waiter = FutexWaiter::EMPTY;
        true
    }
}

static FUTEXES: SpinLock<FutexTable> = SpinLock::new(FutexTable::new());

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FutexQueueError {
    InvalidOwner,
    InvalidAddress,
    AlreadyWaiting,
    Capacity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FutexWaitError<E> {
    Queue(FutexQueueError),
    UserMemory(E),
    ValueChanged,
    Lifecycle(LifecycleError),
}

fn valid_address(address: u64) -> bool {
    address >= USER_ADDRESS_MINIMUM
        && address % FUTEX_WORD_BYTES == 0
        && address
            .checked_add(FUTEX_WORD_BYTES)
            .is_some_and(|end| end <= USER_ADDRESS_LIMIT)
}

fn current_owner_and_key(address: u64) -> Result<(ProcessHandle, FutexKey), FutexQueueError> {
    if !valid_address(address) {
        return Err(FutexQueueError::InvalidAddress);
    }
    let owner = crate::process::lifecycle::current_handle().ok_or(FutexQueueError::InvalidOwner)?;
    let snapshot =
        crate::process::lifecycle::snapshot_exact(owner).ok_or(FutexQueueError::InvalidOwner)?;
    Ok((
        owner,
        FutexKey {
            address_space_root: snapshot.launch.address_space_root,
            address,
        },
    ))
}

/// Compares one userspace futex word, queues the exact calling generation,
/// and blocks it as one wait-queue transaction.
pub fn wait_current<E, F>(
    address: u64,
    expected: u32,
    saved: SavedUserContext,
    read_word: F,
) -> Result<ScheduleDecision, FutexWaitError<E>>
where
    F: FnOnce() -> Result<u32, E>,
{
    let (owner, key) = current_owner_and_key(address).map_err(FutexWaitError::Queue)?;
    let mut table = FUTEXES.lock();
    if table.contains_owner(owner) {
        return Err(FutexWaitError::Queue(FutexQueueError::AlreadyWaiting));
    }
    let observed = read_word().map_err(FutexWaitError::UserMemory)?;
    if observed != expected {
        return Err(FutexWaitError::ValueChanged);
    }
    table.enqueue(owner, key).map_err(FutexWaitError::Queue)?;
    match schedule_block(saved) {
        Ok(decision) => Ok(decision),
        Err(error) => {
            let _ = table.cancel(owner);
            Err(FutexWaitError::Lifecycle(error))
        }
    }
}

/// Wakes at most `maximum` waiters sharing the caller's address-space key.
/// Stale queue entries are discarded but never counted as successful wakes.
pub fn wake_current(address: u64, maximum: usize) -> Result<usize, FutexQueueError> {
    let (_, key) = current_owner_and_key(address)?;
    let mut table = FUTEXES.lock();
    let mut woken = 0;
    while woken < maximum {
        let Some(owner) = table.take_oldest(key) else {
            break;
        };
        if mark_runnable(owner).is_ok() {
            woken += 1;
        }
    }
    Ok(woken)
}

/// Removes any queued wait owned by an exiting or otherwise cancelled exact
/// PID generation. A later recycled PID cannot inherit the entry.
pub fn cancel_wait(owner: ProcessHandle) -> bool {
    FUTEXES.lock().cancel(owner)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(pid: u32, generation: u32) -> ProcessHandle {
        ProcessHandle { pid, generation }
    }

    fn key(root: u64, address: u64) -> FutexKey {
        FutexKey {
            address_space_root: root,
            address,
        }
    }

    #[test]
    fn queue_is_fifo_per_address_space_key_and_generation_safe() {
        let mut table = FutexTable::new();
        let first = owner(7, 1);
        let second = owner(8, 3);
        let same_pid_recycled = owner(7, 2);
        let target = key(0x1000, 0x4000);

        assert_eq!(table.enqueue(first, target), Ok(()));
        assert_eq!(table.enqueue(second, target), Ok(()));
        assert_eq!(
            table.enqueue(first, target),
            Err(FutexQueueError::AlreadyWaiting)
        );
        assert_eq!(table.take_oldest(target), Some(first));
        assert_eq!(table.enqueue(same_pid_recycled, target), Ok(()));
        assert_eq!(table.take_oldest(target), Some(second));
        assert_eq!(table.take_oldest(target), Some(same_pid_recycled));
        assert_eq!(table.take_oldest(target), None);
    }

    #[test]
    fn virtual_addresses_from_different_roots_never_alias() {
        let mut table = FutexTable::new();
        let first_key = key(0x1000, 0x7000);
        let other_root = key(0x2000, 0x7000);
        table.enqueue(owner(2, 1), first_key).unwrap();
        table.enqueue(owner(3, 1), other_root).unwrap();

        assert_eq!(table.take_oldest(first_key), Some(owner(2, 1)));
        assert_eq!(table.take_oldest(first_key), None);
        assert_eq!(table.take_oldest(other_root), Some(owner(3, 1)));
    }

    #[test]
    fn cancellation_requires_the_exact_generation() {
        let mut table = FutexTable::new();
        let original = owner(11, 4);
        table.enqueue(original, key(0x3000, 0x8000)).unwrap();
        assert!(!table.cancel(owner(11, 5)));
        assert!(table.cancel(original));
        assert!(!table.cancel(original));
    }

    #[test]
    fn futex_words_must_be_aligned_and_wholly_userspace() {
        assert!(valid_address(0x4000));
        assert!(!valid_address(0));
        assert!(!valid_address(0x4001));
        assert!(!valid_address(USER_ADDRESS_LIMIT));
        assert!(!valid_address(u64::MAX - 1));
    }
}
