//! Native Crest pointing-device ABI.
//!
//! Boulder normalizes one trusted controller packet at a time.  This client
//! exposes neither raw controller bytes nor an I/O capability to user space.

use crate::SyscallError;
#[cfg(target_os = "none")]
use crate::syscall;
use crate::syscalls::{SYS_INPUT_KEY_NEXT, SYS_INPUT_NEXT};

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PointerMotion {
    pub delta_x: i16,
    pub delta_y: i16,
    /// Horizontal wheel movement in device-notches. Zero means no horizontal
    /// scroll was observed in this packet.
    pub scroll_x: i16,
    /// Vertical wheel movement in device-notches. Positive is a physical
    /// wheel-up motion; applications may apply their persisted scroll policy.
    pub scroll_y: i16,
    pub buttons: u8,
    _reserved: [u8; 3],
}

impl PointerMotion {
    pub const fn new(
        delta_x: i16,
        delta_y: i16,
        scroll_x: i16,
        scroll_y: i16,
        buttons: u8,
    ) -> Self {
        Self {
            delta_x,
            delta_y,
            scroll_x,
            scroll_y,
            buttons,
            _reserved: [0; 3],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyEvent {
    pub code: u32,
    pub pressed: u8,
    _reserved: [u8; 3],
}

impl KeyEvent {
    pub const fn new(code: u32, pressed: bool) -> Self {
        Self {
            code,
            pressed: pressed as u8,
            _reserved: [0; 3],
        }
    }

    pub const fn is_pressed(self) -> bool {
        self.pressed != 0
    }
}

/// Returns at most one authentic normalized pointer packet. `None` is normal
/// when the controller has no packet waiting; it is not a synthetic event.
/// Motion, wheel, and button state originate in the same kernel-owned packet,
/// so Crest cannot accidentally combine data from different controller reads.
#[cfg(target_os = "none")]
pub fn next_pointer_motion() -> Result<Option<PointerMotion>, SyscallError> {
    let mut motion = PointerMotion::new(0, 0, 0, 0, 0);
    let available = unsafe {
        syscall(
            SYS_INPUT_NEXT,
            [
                (&mut motion as *mut PointerMotion) as usize,
                core::mem::size_of::<PointerMotion>(),
                0,
                0,
                0,
                0,
            ],
        )?
    };
    match available {
        0 => Ok(None),
        1 => Ok(Some(motion)),
        _ => Err(SyscallError(-74)),
    }
}

/// Returns at most one authentic normalized keyboard event. None is normal
/// when the controller queue is empty; it is not a synthesized input event.
#[cfg(target_os = "none")]
pub fn next_key_event() -> Result<Option<KeyEvent>, SyscallError> {
    let mut event = KeyEvent::new(0, false);
    let available = unsafe {
        syscall(
            SYS_INPUT_KEY_NEXT,
            [
                (&mut event as *mut KeyEvent) as usize,
                core::mem::size_of::<KeyEvent>(),
                0,
                0,
                0,
                0,
            ],
        )?
    };
    match available {
        0 => Ok(None),
        1 => Ok(Some(event)),
        _ => Err(SyscallError(-74)),
    }
}

#[cfg(not(target_os = "none"))]
pub fn next_key_event() -> Result<Option<KeyEvent>, SyscallError> {
    let _ = SYS_INPUT_KEY_NEXT;
    Err(SyscallError(-38))
}

#[cfg(not(target_os = "none"))]
pub fn next_pointer_motion() -> Result<Option<PointerMotion>, SyscallError> {
    let _ = SYS_INPUT_NEXT;
    Err(SyscallError(-38))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_motion_has_a_stable_wire_size() {
        assert_eq!(core::mem::size_of::<PointerMotion>(), 12);
        let motion = PointerMotion::new(-4, 9, 0, -1, 1);
        assert_eq!(motion.buttons, 1);
        assert_eq!(motion.scroll_y, -1);
    }

    #[test]
    fn key_event_has_a_stable_wire_size() {
        assert_eq!(core::mem::size_of::<KeyEvent>(), 8);
        assert!(KeyEvent::new(28, true).is_pressed());
        assert!(!KeyEvent::new(28, false).is_pressed());
    }
}
