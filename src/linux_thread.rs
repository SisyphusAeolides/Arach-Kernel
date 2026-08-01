//! Bounded Linux thread-exit identity metadata.
//!
//! `set_tid_address(2)` registers one optional userspace `clear_child_tid`
//! pointer for the exact PID generation that made the call. The pointer is
//! validated at registration time, removed atomically at exit, and can never
//! be inherited by a recycled PID. Clearing the word remains best-effort at
//! exit because userspace may unmap it after registration.

use crate::process::context::{USER_ADDRESS_LIMIT, USER_ADDRESS_MINIMUM};
use crate::process::lifecycle::ProcessHandle;
use crate::sync::SpinLock;

const MAXIMUM_THREAD_IDENTITIES: usize = crate::process::lifecycle::MAXIMUM_PROCESSES;
const TID_WORD_BYTES: u64 = core::mem::size_of::<u32>() as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadIdentityError {
    InvalidOwner,
    InvalidAddress,
    Capacity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ThreadIdentitySlot {
    owner: ProcessHandle,
    clear_child_tid: u64,
}

impl ThreadIdentitySlot {
    const EMPTY: Self = Self {
        owner: ProcessHandle {
            pid: 0,
            generation: 0,
        },
        clear_child_tid: 0,
    };

    const fn occupied(self) -> bool {
        self.owner.pid != 0 && self.owner.generation != 0
    }
}

static THREAD_IDENTITIES: SpinLock<[ThreadIdentitySlot; MAXIMUM_THREAD_IDENTITIES]> =
    SpinLock::new([ThreadIdentitySlot::EMPTY; MAXIMUM_THREAD_IDENTITIES]);

fn valid_owner(owner: ProcessHandle) -> bool {
    owner.pid != 0 && owner.generation != 0
}

fn valid_tid_address(address: u64) -> bool {
    if address == 0 {
        return true;
    }
    address >= USER_ADDRESS_MINIMUM
        && address % TID_WORD_BYTES == 0
        && address
            .checked_add(TID_WORD_BYTES)
            .is_some_and(|end| end <= USER_ADDRESS_LIMIT)
}

/// Register or clear the calling thread's `clear_child_tid` pointer and return
/// the Linux thread identifier observed by userspace.
pub fn set_tid_address(owner: ProcessHandle, address: u64) -> Result<u32, ThreadIdentityError> {
    if !valid_owner(owner) {
        return Err(ThreadIdentityError::InvalidOwner);
    }
    if !valid_tid_address(address) {
        return Err(ThreadIdentityError::InvalidAddress);
    }

    let mut table = THREAD_IDENTITIES.lock();
    if let Some(slot) = table
        .iter_mut()
        .find(|slot| slot.occupied() && slot.owner == owner)
    {
        if address == 0 {
            *slot = ThreadIdentitySlot::EMPTY;
        } else {
            slot.clear_child_tid = address;
        }
        return Ok(owner.pid);
    }
    if address == 0 {
        return Ok(owner.pid);
    }
    let slot = table
        .iter_mut()
        .find(|slot| !slot.occupied())
        .ok_or(ThreadIdentityError::Capacity)?;
    *slot = ThreadIdentitySlot {
        owner,
        clear_child_tid: address,
    };
    Ok(owner.pid)
}

/// Remove and return the exact exiting PID generation's registered pointer.
/// A recycled PID cannot observe or clear metadata from an earlier generation.
pub fn take_clear_child_tid(owner: ProcessHandle) -> Option<u64> {
    if !valid_owner(owner) {
        return None;
    }
    let mut table = THREAD_IDENTITIES.lock();
    let slot = table
        .iter_mut()
        .find(|slot| slot.occupied() && slot.owner == owner)?;
    let address = slot.clear_child_tid;
    *slot = ThreadIdentitySlot::EMPTY;
    (address != 0).then_some(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_SERIALIZATION: SpinLock<()> = SpinLock::new(());

    const OWNER: ProcessHandle = ProcessHandle {
        pid: 0x5101,
        generation: 3,
    };

    #[test]
    fn registers_replaces_and_clears_one_exact_owner() {
        let _serial = TEST_SERIALIZATION.lock();
        assert_eq!(set_tid_address(OWNER, 0x4000), Ok(OWNER.pid));
        assert_eq!(set_tid_address(OWNER, 0x5000), Ok(OWNER.pid));
        assert_eq!(take_clear_child_tid(OWNER), Some(0x5000));
        assert_eq!(take_clear_child_tid(OWNER), None);
        assert_eq!(set_tid_address(OWNER, 0), Ok(OWNER.pid));
    }

    #[test]
    fn pid_generation_is_part_of_the_authority() {
        let _serial = TEST_SERIALIZATION.lock();
        let recycled = ProcessHandle {
            pid: OWNER.pid,
            generation: OWNER.generation + 1,
        };
        assert_eq!(set_tid_address(OWNER, 0x6000), Ok(OWNER.pid));
        assert_eq!(take_clear_child_tid(recycled), None);
        assert_eq!(take_clear_child_tid(OWNER), Some(0x6000));
    }

    #[test]
    fn rejects_kernel_unaligned_overflowing_and_ownerless_addresses() {
        let _serial = TEST_SERIALIZATION.lock();
        assert_eq!(
            set_tid_address(
                ProcessHandle {
                    pid: 0,
                    generation: 1
                },
                0x4000
            ),
            Err(ThreadIdentityError::InvalidOwner)
        );
        assert_eq!(
            set_tid_address(OWNER, 0x4001),
            Err(ThreadIdentityError::InvalidAddress)
        );
        assert_eq!(
            set_tid_address(OWNER, USER_ADDRESS_LIMIT),
            Err(ThreadIdentityError::InvalidAddress)
        );
        assert_eq!(
            set_tid_address(OWNER, u64::MAX - 1),
            Err(ThreadIdentityError::InvalidAddress)
        );
    }
}
