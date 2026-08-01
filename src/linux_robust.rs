//! Bounded Linux robust-futex registration and exit recovery.
//!
//! Each registration belongs to one exact PID generation. Exit consumes the
//! registration before walking user memory, so a recycled TID cannot inherit
//! stale cleanup authority. The walker accepts Linux's x86-64
//! `robust_list_head` layout, follows at most `ROBUST_LIST_LIMIT` links, and
//! treats malformed, PI-tagged, or inaccessible entries as a local cleanup
//! fault rather than a kernel-fatal condition.

use crate::process::context::{USER_ADDRESS_LIMIT, USER_ADDRESS_MINIMUM};
use crate::process::lifecycle::ProcessHandle;
use crate::sync::SpinLock;

pub const ROBUST_LIST_HEAD_BYTES: u64 = 24;
pub const ROBUST_LIST_LIMIT: usize = 2048;
pub const FUTEX_WAITERS: u32 = 0x8000_0000;
pub const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
pub const FUTEX_TID_MASK: u32 = 0x3fff_ffff;

const MAXIMUM_ROBUST_LISTS: usize = crate::process::lifecycle::MAXIMUM_PROCESSES;
const POINTER_BYTES: u64 = core::mem::size_of::<u64>() as u64;
const FUTEX_WORD_BYTES: u64 = core::mem::size_of::<u32>() as u64;
const PI_TAG: u64 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RobustListError {
    InvalidOwner,
    InvalidAddress,
    InvalidLength,
    Capacity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RobustListRegistration {
    pub head: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RobustListSlot {
    owner: ProcessHandle,
    head: u64,
}

impl RobustListSlot {
    const EMPTY: Self = Self {
        owner: ProcessHandle {
            pid: 0,
            generation: 0,
        },
        head: 0,
    };

    const fn occupied(self) -> bool {
        self.owner.pid != 0 && self.owner.generation != 0
    }
}

static ROBUST_LISTS: SpinLock<[RobustListSlot; MAXIMUM_ROBUST_LISTS]> =
    SpinLock::new([RobustListSlot::EMPTY; MAXIMUM_ROBUST_LISTS]);

fn valid_owner(owner: ProcessHandle) -> bool {
    owner.pid != 0 && owner.generation != 0 && owner.pid & FUTEX_TID_MASK == owner.pid
}

fn valid_range(address: u64, bytes: u64, alignment: u64) -> bool {
    address >= USER_ADDRESS_MINIMUM
        && address % alignment == 0
        && address
            .checked_add(bytes)
            .is_some_and(|end| end <= USER_ADDRESS_LIMIT)
}

fn valid_head(address: u64) -> bool {
    valid_range(address, ROBUST_LIST_HEAD_BYTES, POINTER_BYTES)
}

fn valid_node(address: u64) -> bool {
    valid_range(address, POINTER_BYTES, POINTER_BYTES)
}

fn valid_futex(address: u64) -> bool {
    valid_range(address, FUTEX_WORD_BYTES, FUTEX_WORD_BYTES)
}

/// Register or clear one thread's robust-list head.
pub fn set_robust_list(
    owner: ProcessHandle,
    head: u64,
    length: u64,
) -> Result<(), RobustListError> {
    if !valid_owner(owner) {
        return Err(RobustListError::InvalidOwner);
    }
    if length != ROBUST_LIST_HEAD_BYTES {
        return Err(RobustListError::InvalidLength);
    }
    if head != 0 && !valid_head(head) {
        return Err(RobustListError::InvalidAddress);
    }

    let mut table = ROBUST_LISTS.lock();
    if let Some(slot) = table
        .iter_mut()
        .find(|slot| slot.occupied() && slot.owner == owner)
    {
        if head == 0 {
            *slot = RobustListSlot::EMPTY;
        } else {
            slot.head = head;
        }
        return Ok(());
    }
    if head == 0 {
        return Ok(());
    }
    let slot = table
        .iter_mut()
        .find(|slot| !slot.occupied())
        .ok_or(RobustListError::Capacity)?;
    *slot = RobustListSlot { owner, head };
    Ok(())
}

/// Return an exact live generation's registration without consuming it.
pub fn robust_list(owner: ProcessHandle) -> Option<RobustListRegistration> {
    if !valid_owner(owner) {
        return None;
    }
    ROBUST_LISTS
        .lock()
        .iter()
        .find(|slot| slot.occupied() && slot.owner == owner)
        .map(|slot| RobustListRegistration { head: slot.head })
}

/// Consume an exact exiting generation's registration.
pub fn take_robust_list(owner: ProcessHandle) -> Option<RobustListRegistration> {
    if !valid_owner(owner) {
        return None;
    }
    let mut table = ROBUST_LISTS.lock();
    let slot = table
        .iter_mut()
        .find(|slot| slot.occupied() && slot.owner == owner)?;
    let registration = RobustListRegistration { head: slot.head };
    *slot = RobustListSlot::EMPTY;
    Some(registration)
}

/// The atomic transformation required when the exiting TID still owns a
/// robust futex. Only the waiter bit survives; ownership is replaced by the
/// Linux owner-died bit.
pub fn owner_died_replacement(word: u32, owner_tid: u32) -> Option<u32> {
    (word & FUTEX_TID_MASK == owner_tid).then_some((word & FUTEX_WAITERS) | FUTEX_OWNER_DIED)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RobustExitReport {
    pub visited: usize,
    pub recovered: usize,
    pub wake_requests: usize,
    pub faulted: bool,
    pub truncated: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OwnerDeathResult {
    pub recovered: bool,
    pub wake_requested: bool,
}

fn decode_pointer(encoded: u64) -> Option<u64> {
    (encoded & PI_TAG == 0).then_some(encoded)
}

fn futex_address(node: u64, offset: i64) -> Option<u64> {
    let address = node.checked_add_signed(offset)?;
    valid_futex(address).then_some(address)
}

/// Walk and recover one consumed robust list using caller-provided user-copy
/// and atomic owner-death operations. Any user-memory failure stops bounded
/// traversal and is reported; exit itself can continue safely.
pub fn recover_robust_list<E, ReadPointer, Recover>(
    registration: RobustListRegistration,
    owner_tid: u32,
    mut read_pointer: ReadPointer,
    mut recover: Recover,
) -> RobustExitReport
where
    ReadPointer: FnMut(u64) -> Result<u64, E>,
    Recover: FnMut(u64, u32) -> Result<OwnerDeathResult, E>,
{
    let mut report = RobustExitReport::default();
    let head = registration.head;
    if !valid_head(head) || owner_tid == 0 || owner_tid & FUTEX_TID_MASK != owner_tid {
        report.faulted = true;
        return report;
    }

    let Some(mut next) = read_pointer(head).ok().and_then(decode_pointer) else {
        report.faulted = true;
        return report;
    };
    let offset = match read_pointer(head + POINTER_BYTES) {
        Ok(encoded) => encoded as i64,
        Err(_) => {
            report.faulted = true;
            return report;
        }
    };
    let pending = match read_pointer(head + 2 * POINTER_BYTES) {
        Ok(encoded) => match decode_pointer(encoded) {
            Some(pointer) => pointer,
            None => {
                report.faulted = true;
                return report;
            }
        },
        Err(_) => {
            report.faulted = true;
            return report;
        }
    };

    while next != head && report.visited < ROBUST_LIST_LIMIT {
        if next == 0 || !valid_node(next) {
            report.faulted = true;
            break;
        }
        let node = next;
        next = match read_pointer(node).ok().and_then(decode_pointer) {
            Some(pointer) => pointer,
            None => {
                report.faulted = true;
                break;
            }
        };
        report.visited += 1;
        if node != pending {
            let Some(address) = futex_address(node, offset) else {
                report.faulted = true;
                break;
            };
            match recover(address, owner_tid) {
                Ok(result) => {
                    report.recovered += usize::from(result.recovered);
                    report.wake_requests += usize::from(result.wake_requested);
                }
                Err(_) => {
                    report.faulted = true;
                    break;
                }
            }
        }
    }
    if next != head && report.visited == ROBUST_LIST_LIMIT {
        report.truncated = true;
    }

    if pending != 0 {
        if let Some(address) = futex_address(pending, offset) {
            match recover(address, owner_tid) {
                Ok(result) => {
                    report.recovered += usize::from(result.recovered);
                    report.wake_requests += usize::from(result.wake_requested);
                }
                Err(_) => report.faulted = true,
            }
        } else {
            report.faulted = true;
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_SERIALIZATION: SpinLock<()> = SpinLock::new(());

    const OWNER: ProcessHandle = ProcessHandle {
        pid: 0x611,
        generation: 7,
    };

    #[test]
    fn registration_is_generation_bound_replaceable_and_consumed_once() {
        let _serial = TEST_SERIALIZATION.lock();
        assert_eq!(
            set_robust_list(OWNER, 0x4000, ROBUST_LIST_HEAD_BYTES),
            Ok(())
        );
        assert_eq!(robust_list(OWNER).unwrap().head, 0x4000);
        assert_eq!(
            set_robust_list(OWNER, 0x5000, ROBUST_LIST_HEAD_BYTES),
            Ok(())
        );
        let recycled = ProcessHandle {
            generation: OWNER.generation + 1,
            ..OWNER
        };
        assert_eq!(take_robust_list(recycled), None);
        assert_eq!(take_robust_list(OWNER).unwrap().head, 0x5000);
        assert_eq!(take_robust_list(OWNER), None);
    }

    #[test]
    fn registration_rejects_bad_owners_lengths_and_ranges() {
        let _serial = TEST_SERIALIZATION.lock();
        assert_eq!(
            set_robust_list(
                ProcessHandle {
                    pid: 0,
                    generation: 1,
                },
                0x4000,
                ROBUST_LIST_HEAD_BYTES,
            ),
            Err(RobustListError::InvalidOwner)
        );
        assert_eq!(
            set_robust_list(OWNER, 0x4000, ROBUST_LIST_HEAD_BYTES - 1),
            Err(RobustListError::InvalidLength)
        );
        assert_eq!(
            set_robust_list(OWNER, 0x4001, ROBUST_LIST_HEAD_BYTES),
            Err(RobustListError::InvalidAddress)
        );
        assert_eq!(
            set_robust_list(OWNER, USER_ADDRESS_LIMIT, ROBUST_LIST_HEAD_BYTES),
            Err(RobustListError::InvalidAddress)
        );
    }

    #[test]
    fn owner_death_preserves_waiters_and_requires_exact_tid() {
        assert_eq!(
            owner_died_replacement(FUTEX_WAITERS | OWNER.pid, OWNER.pid),
            Some(FUTEX_WAITERS | FUTEX_OWNER_DIED)
        );
        assert_eq!(
            owner_died_replacement(OWNER.pid, OWNER.pid),
            Some(FUTEX_OWNER_DIED)
        );
        assert_eq!(owner_died_replacement(OWNER.pid + 1, OWNER.pid), None);
    }

    #[test]
    fn walker_recovers_linked_and_pending_nodes_once() {
        let head = 0x4000;
        let first = 0x5008;
        let pending = 0x6008;
        let offset = -8_i64;
        let mut recovered = [0_u64; 2];
        let mut recovered_count = 0;
        let report = recover_robust_list(
            RobustListRegistration { head },
            OWNER.pid,
            |address| match address {
                0x4000 => Ok(first),
                0x4008 => Ok(offset as u64),
                0x4010 => Ok(pending),
                0x5008 => Ok(pending),
                0x6008 => Ok(head),
                _ => Err(()),
            },
            |address, tid| {
                assert_eq!(tid, OWNER.pid);
                recovered[recovered_count] = address;
                recovered_count += 1;
                Ok(OwnerDeathResult {
                    recovered: true,
                    wake_requested: true,
                })
            },
        );
        assert_eq!(recovered_count, 2);
        assert_eq!(recovered, [first - 8, pending - 8]);
        assert_eq!(report.visited, 2);
        assert_eq!(report.recovered, 2);
        assert_eq!(report.wake_requests, 2);
        assert!(!report.faulted);
        assert!(!report.truncated);
    }

    #[test]
    fn walker_bounds_cycles_and_rejects_pi_tagged_links() {
        let cyclic = recover_robust_list(
            RobustListRegistration { head: 0x4000 },
            OWNER.pid,
            |address| match address {
                0x4000 => Ok(0x5000),
                0x4008 | 0x4010 => Ok(0),
                0x5000 => Ok(0x5000),
                _ => Err(()),
            },
            |_, _| Ok(OwnerDeathResult::default()),
        );
        assert_eq!(cyclic.visited, ROBUST_LIST_LIMIT);
        assert!(cyclic.truncated);

        let tagged = recover_robust_list(
            RobustListRegistration { head: 0x4000 },
            OWNER.pid,
            |address| match address {
                0x4000 => Ok(0x5001),
                _ => Err(()),
            },
            |_, _| Ok(OwnerDeathResult::default()),
        );
        assert!(tagged.faulted);
        assert_eq!(tagged.visited, 0);
    }
}
