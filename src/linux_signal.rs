//! Bounded Linux signal disposition, mask, pending, and frame authority.
//!
//! Dispositions belong to an exact thread-group leader generation while masks,
//! pending bits, and active return frames belong to an exact TID generation.
//! The first runtime slice admits standard signals 1 through 64, one active
//! frame per thread, and a single coalesced pending bit per signal.

use crate::process::context::{USER_ADDRESS_LIMIT, USER_ADDRESS_MINIMUM};
use crate::process::lifecycle::ProcessHandle;
use crate::sync::SpinLock;

pub const MAXIMUM_SIGNAL: u32 = 64;
pub const SIGKILL: u32 = 9;
pub const SIGSTOP: u32 = 19;
pub const SA_SIGINFO: u64 = 0x0000_0004;
pub const SA_RESTORER: u64 = 0x0400_0000;
pub const SA_RESTART: u64 = 0x1000_0000;
pub const SA_NODEFER: u64 = 0x4000_0000;
pub const SA_RESETHAND: u64 = 0x8000_0000;
pub const SUPPORTED_ACTION_FLAGS: u64 =
    SA_SIGINFO | SA_RESTORER | SA_RESTART | SA_NODEFER | SA_RESETHAND;

const MAXIMUM_ENTRIES: usize = crate::process::lifecycle::MAXIMUM_PROCESSES;
const SIGNAL_COUNT: usize = MAXIMUM_SIGNAL as usize;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct SignalAction {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalError {
    InvalidOwner,
    InvalidSignal,
    InvalidAction,
    InvalidMaskOperation,
    InvalidFrame,
    Unsupported,
    Capacity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Delivery {
    None,
    Terminate(u32),
    Handler {
        signal: u32,
        action: SignalAction,
        previous_mask: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GroupSlot {
    owner: ProcessHandle,
    actions: [SignalAction; SIGNAL_COUNT],
}

impl GroupSlot {
    const EMPTY: Self = Self {
        owner: ProcessHandle {
            pid: 0,
            generation: 0,
        },
        actions: [SignalAction {
            handler: 0,
            flags: 0,
            restorer: 0,
            mask: 0,
        }; SIGNAL_COUNT],
    };

    const fn occupied(self) -> bool {
        self.owner.pid != 0 && self.owner.generation != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ThreadSlot {
    owner: ProcessHandle,
    blocked: u64,
    pending: u64,
    active_frame: u64,
}

impl ThreadSlot {
    const EMPTY: Self = Self {
        owner: ProcessHandle {
            pid: 0,
            generation: 0,
        },
        blocked: 0,
        pending: 0,
        active_frame: 0,
    };

    const fn occupied(self) -> bool {
        self.owner.pid != 0 && self.owner.generation != 0
    }
}

struct SignalTable {
    groups: [GroupSlot; MAXIMUM_ENTRIES],
    threads: [ThreadSlot; MAXIMUM_ENTRIES],
}

impl SignalTable {
    const fn new() -> Self {
        Self {
            groups: [GroupSlot::EMPTY; MAXIMUM_ENTRIES],
            threads: [ThreadSlot::EMPTY; MAXIMUM_ENTRIES],
        }
    }

    fn thread_mut(&mut self, owner: ProcessHandle) -> Result<&mut ThreadSlot, SignalError> {
        if let Some(index) = self
            .threads
            .iter()
            .position(|slot| slot.occupied() && slot.owner == owner)
        {
            return Ok(&mut self.threads[index]);
        }
        let slot = self
            .threads
            .iter_mut()
            .find(|slot| !slot.occupied())
            .ok_or(SignalError::Capacity)?;
        *slot = ThreadSlot {
            owner,
            ..ThreadSlot::EMPTY
        };
        Ok(slot)
    }

    fn action(&self, group: ProcessHandle, signal: u32) -> SignalAction {
        self.groups
            .iter()
            .find(|slot| slot.occupied() && slot.owner == group)
            .map_or(SignalAction::default(), |slot| {
                slot.actions[(signal - 1) as usize]
            })
    }
}

static SIGNALS: SpinLock<SignalTable> = SpinLock::new(SignalTable::new());

fn valid_owner(owner: ProcessHandle) -> bool {
    owner.pid != 0 && owner.generation != 0
}

fn signal_bit(signal: u32) -> Result<u64, SignalError> {
    if !(1..=MAXIMUM_SIGNAL).contains(&signal) {
        return Err(SignalError::InvalidSignal);
    }
    Ok(1_u64 << (signal - 1))
}

fn unmaskable_bits() -> u64 {
    (1_u64 << (SIGKILL - 1)) | (1_u64 << (SIGSTOP - 1))
}

fn sanitize_mask(mask: u64) -> u64 {
    mask & !unmaskable_bits()
}

fn valid_user_code(address: u64) -> bool {
    (USER_ADDRESS_MINIMUM..USER_ADDRESS_LIMIT).contains(&address)
}

fn validate_action(signal: u32, action: SignalAction) -> Result<(), SignalError> {
    signal_bit(signal)?;
    if action.flags & !SUPPORTED_ACTION_FLAGS != 0 {
        return Err(SignalError::InvalidAction);
    }
    if action.handler > 1
        && (!valid_user_code(action.handler)
            || action.flags & SA_RESTORER == 0
            || !valid_user_code(action.restorer))
    {
        return Err(SignalError::InvalidAction);
    }
    Ok(())
}

pub fn set_action(
    group: ProcessHandle,
    signal: u32,
    replacement: Option<SignalAction>,
) -> Result<SignalAction, SignalError> {
    if !valid_owner(group) {
        return Err(SignalError::InvalidOwner);
    }
    signal_bit(signal)?;
    if let Some(action) = replacement {
        if matches!(signal, SIGKILL | SIGSTOP) {
            return Err(SignalError::InvalidAction);
        }
        validate_action(signal, action)?;
    }
    let mut table = SIGNALS.lock();
    let index = if let Some(index) = table
        .groups
        .iter()
        .position(|slot| slot.occupied() && slot.owner == group)
    {
        index
    } else if replacement.is_some() {
        let index = table
            .groups
            .iter()
            .position(|slot| !slot.occupied())
            .ok_or(SignalError::Capacity)?;
        table.groups[index] = GroupSlot {
            owner: group,
            ..GroupSlot::EMPTY
        };
        index
    } else {
        return Ok(SignalAction::default());
    };
    let action = &mut table.groups[index].actions[(signal - 1) as usize];
    let previous = *action;
    if let Some(mut replacement) = replacement {
        replacement.mask = sanitize_mask(replacement.mask);
        *action = replacement;
    }
    Ok(previous)
}

pub fn update_mask(
    owner: ProcessHandle,
    operation: u32,
    replacement: Option<u64>,
) -> Result<u64, SignalError> {
    if !valid_owner(owner) {
        return Err(SignalError::InvalidOwner);
    }
    if replacement.is_some() && operation > 2 {
        return Err(SignalError::InvalidMaskOperation);
    }
    let mut table = SIGNALS.lock();
    let thread = table.thread_mut(owner)?;
    let previous = thread.blocked;
    if let Some(mask) = replacement {
        let mask = sanitize_mask(mask);
        thread.blocked = match operation {
            0 => previous | mask,
            1 => previous & !mask,
            2 => mask,
            _ => return Err(SignalError::InvalidMaskOperation),
        };
    }
    Ok(previous)
}

pub fn inherit_mask(parent: ProcessHandle, child: ProcessHandle) -> Result<(), SignalError> {
    if !valid_owner(parent) || !valid_owner(child) {
        return Err(SignalError::InvalidOwner);
    }
    let mut table = SIGNALS.lock();
    let parent_mask = table
        .threads
        .iter()
        .find(|slot| slot.occupied() && slot.owner == parent)
        .map_or(0, |slot| slot.blocked);
    table.thread_mut(child)?.blocked = parent_mask;
    Ok(())
}

pub fn queue(owner: ProcessHandle, signal: u32) -> Result<(), SignalError> {
    if !valid_owner(owner) {
        return Err(SignalError::InvalidOwner);
    }
    let bit = signal_bit(signal)?;
    if signal == SIGSTOP {
        return Err(SignalError::Unsupported);
    }
    SIGNALS.lock().thread_mut(owner)?.pending |= bit;
    Ok(())
}

/// Return the pending standard-signal bits for one exact thread generation.
/// The snapshot is used by signalfd readiness and is intentionally bounded to
/// the first 64 Linux signals represented by this personality.
pub fn pending_mask(owner: ProcessHandle) -> u64 {
    SIGNALS
        .lock()
        .threads
        .iter()
        .find(|slot| slot.occupied() && slot.owner == owner)
        .map_or(0, |thread| thread.pending)
}

pub fn pending_for_signalfd(owner: ProcessHandle, mask: u64) -> bool {
    pending_mask(owner) & mask != 0
}

/// Remove and return the lowest-numbered pending signal selected by a
/// signalfd mask. Signals remain coalesced exactly as they are for ordinary
/// delivery; consuming one here clears only that signal's pending bit.
pub fn dequeue_for_signalfd(owner: ProcessHandle, mask: u64) -> Option<u32> {
    let mut table = SIGNALS.lock();
    let thread = table
        .threads
        .iter_mut()
        .find(|slot| slot.occupied() && slot.owner == owner)?;
    let selected = thread.pending & mask;
    if selected == 0 {
        return None;
    }
    let signal = selected.trailing_zeros() + 1;
    thread.pending &= !(1_u64 << (signal - 1));
    Some(signal)
}

pub fn delivery_pending(owner: ProcessHandle) -> bool {
    SIGNALS
        .lock()
        .threads
        .iter()
        .find(|slot| slot.occupied() && slot.owner == owner)
        .is_some_and(|thread| {
            thread.active_frame == 0 && thread.pending & (!thread.blocked | unmaskable_bits()) != 0
        })
}

fn default_ignored(signal: u32) -> bool {
    matches!(signal, 17 | 18 | 23 | 28)
}

pub fn begin_delivery(
    owner: ProcessHandle,
    group: ProcessHandle,
    frame: u64,
) -> Result<Delivery, SignalError> {
    if !valid_owner(owner) || !valid_owner(group) || !valid_user_code(frame) {
        return Err(SignalError::InvalidOwner);
    }
    let mut table = SIGNALS.lock();
    let thread_index = table
        .threads
        .iter()
        .position(|slot| slot.occupied() && slot.owner == owner)
        .ok_or(SignalError::InvalidOwner)?;
    if table.threads[thread_index].active_frame != 0 {
        return Ok(Delivery::None);
    }
    loop {
        let deliverable = table.threads[thread_index].pending
            & !table.threads[thread_index].blocked
            & !unmaskable_bits();
        let forced = table.threads[thread_index].pending & unmaskable_bits();
        let candidates = deliverable | forced;
        if candidates == 0 {
            return Ok(Delivery::None);
        }
        let signal = candidates.trailing_zeros() + 1;
        let bit = signal_bit(signal)?;
        let action = table.action(group, signal);
        table.threads[thread_index].pending &= !bit;
        if action.handler == 1 || action.handler == 0 && default_ignored(signal) {
            continue;
        }
        if action.handler == 0 || matches!(signal, SIGKILL | SIGSTOP) {
            return Ok(Delivery::Terminate(signal));
        }
        let previous_mask = table.threads[thread_index].blocked;
        let self_mask = if action.flags & SA_NODEFER == 0 {
            bit
        } else {
            0
        };
        table.threads[thread_index].blocked =
            sanitize_mask(previous_mask | action.mask | self_mask);
        table.threads[thread_index].active_frame = frame;
        if action.flags & SA_RESETHAND != 0 {
            if let Some(group_slot) = table
                .groups
                .iter_mut()
                .find(|slot| slot.occupied() && slot.owner == group)
            {
                group_slot.actions[(signal - 1) as usize] = SignalAction::default();
            }
        }
        return Ok(Delivery::Handler {
            signal,
            action,
            previous_mask,
        });
    }
}

pub fn active_frame(owner: ProcessHandle) -> Option<u64> {
    SIGNALS
        .lock()
        .threads
        .iter()
        .find(|slot| slot.occupied() && slot.owner == owner && slot.active_frame != 0)
        .map(|slot| slot.active_frame)
}

pub fn finish_sigreturn(
    owner: ProcessHandle,
    frame: u64,
    restored_mask: u64,
) -> Result<(), SignalError> {
    let mut table = SIGNALS.lock();
    let thread = table
        .threads
        .iter_mut()
        .find(|slot| slot.occupied() && slot.owner == owner)
        .ok_or(SignalError::InvalidOwner)?;
    if frame == 0 || thread.active_frame != frame {
        return Err(SignalError::InvalidFrame);
    }
    thread.blocked = sanitize_mask(restored_mask);
    thread.active_frame = 0;
    Ok(())
}

pub fn clear_thread(owner: ProcessHandle, clear_group: Option<ProcessHandle>) {
    let mut table = SIGNALS.lock();
    if let Some(thread) = table
        .threads
        .iter_mut()
        .find(|slot| slot.occupied() && slot.owner == owner)
    {
        *thread = ThreadSlot::EMPTY;
    }
    if let Some(group) = clear_group {
        if let Some(slot) = table
            .groups
            .iter_mut()
            .find(|slot| slot.occupied() && slot.owner == group)
        {
            *slot = GroupSlot::EMPTY;
        }
    }
}

/// Applies Linux's successful-exec signal transition.
///
/// Caught dispositions return to default, ignored dispositions remain
/// ignored, the calling thread keeps its mask, and pending/frame state from
/// the former address space is discarded.
pub fn reset_for_exec(owner: ProcessHandle) {
    const SIG_IGN: u64 = 1;

    let mut table = SIGNALS.lock();
    if let Some(group) = table
        .groups
        .iter_mut()
        .find(|slot| slot.occupied() && slot.owner == owner)
    {
        for action in &mut group.actions {
            if action.handler != SIG_IGN {
                *action = SignalAction::default();
            }
        }
    }
    if let Some(thread) = table
        .threads
        .iter_mut()
        .find(|slot| slot.occupied() && slot.owner == owner)
    {
        thread.pending = 0;
        thread.active_frame = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_SERIALIZATION: SpinLock<()> = SpinLock::new(());
    const GROUP: ProcessHandle = ProcessHandle {
        pid: 500,
        generation: 2,
    };
    const THREAD: ProcessHandle = ProcessHandle {
        pid: 501,
        generation: 4,
    };

    #[test]
    fn action_mask_pending_and_return_are_generation_bound() {
        let _serial = TEST_SERIALIZATION.lock();
        let action = SignalAction {
            handler: 0x4000,
            flags: SA_RESTORER,
            restorer: 0x5000,
            mask: 1 << 11,
        };
        assert_eq!(
            set_action(GROUP, 10, Some(action)),
            Ok(SignalAction::default())
        );
        assert_eq!(update_mask(THREAD, 0, Some(1 << 9)), Ok(0));
        assert_eq!(queue(THREAD, 10), Ok(()));
        assert_eq!(begin_delivery(THREAD, GROUP, 0x7000), Ok(Delivery::None));
        assert_eq!(update_mask(THREAD, 1, Some(1 << 9)), Ok(1 << 9));
        assert!(matches!(
            begin_delivery(THREAD, GROUP, 0x7000),
            Ok(Delivery::Handler { signal: 10, .. })
        ));
        assert_eq!(active_frame(THREAD), Some(0x7000));
        assert_eq!(
            finish_sigreturn(THREAD, 0x7008, 0),
            Err(SignalError::InvalidFrame)
        );
        assert_eq!(finish_sigreturn(THREAD, 0x7000, 0), Ok(()));
        clear_thread(THREAD, Some(GROUP));
    }

    #[test]
    fn uncatchable_signals_cannot_be_masked_or_handled() {
        let _serial = TEST_SERIALIZATION.lock();
        assert_eq!(
            set_action(
                GROUP,
                SIGKILL,
                Some(SignalAction {
                    handler: 0x4000,
                    flags: SA_RESTORER,
                    restorer: 0x5000,
                    mask: 0,
                })
            ),
            Err(SignalError::InvalidAction)
        );
        assert_eq!(update_mask(THREAD, 2, Some(u64::MAX)), Ok(0));
        assert_eq!(update_mask(THREAD, 0, None), Ok(sanitize_mask(u64::MAX)));
        clear_thread(THREAD, Some(GROUP));
    }

    #[test]
    fn exec_resets_caught_signals_and_retains_ignored_signals_and_mask() {
        let _serial = TEST_SERIALIZATION.lock();
        let caught = SignalAction {
            handler: 0x4000,
            flags: SA_RESTORER,
            restorer: 0x5000,
            mask: 0,
        };
        let ignored = SignalAction {
            handler: 1,
            flags: 0,
            restorer: 0,
            mask: 0,
        };
        set_action(GROUP, 10, Some(caught)).unwrap();
        set_action(GROUP, 12, Some(ignored)).unwrap();
        update_mask(GROUP, 0, Some(1 << 4)).unwrap();
        queue(GROUP, 10).unwrap();
        assert!(matches!(
            begin_delivery(GROUP, GROUP, 0x7000),
            Ok(Delivery::Handler { signal: 10, .. })
        ));

        reset_for_exec(GROUP);

        assert_eq!(set_action(GROUP, 10, None), Ok(SignalAction::default()));
        assert_eq!(set_action(GROUP, 12, None), Ok(ignored));
        assert_eq!(update_mask(GROUP, 0, None), Ok((1 << 4) | (1 << 9)));
        assert_eq!(active_frame(GROUP), None);
        assert_eq!(begin_delivery(GROUP, GROUP, 0x7000), Ok(Delivery::None));
        clear_thread(GROUP, Some(GROUP));
    }
}
