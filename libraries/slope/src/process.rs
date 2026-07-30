use crate::{SyscallError, syscall};

pub mod tachyon;

use aether::grimoire;

/// Cooperatively yields the current process while preserving its execution
/// context.
pub fn yield_now() -> Result<(), SyscallError> {
    yield_with_hint(0)
}

/// Cooperatively yields while attaching a bounded scheduler-policy hint.
///
/// The current Boulder boundary records the scalar hint for future scheduler
/// policy; it does not promise retroactive execution or priority changes.
pub fn yield_with_hint(unfinished_work: u64) -> Result<(), SyscallError> {
    // SAFETY: Yield carries no pointer arguments and follows Slope's native
    // six-register syscall convention.
    unsafe {
        syscall(
            grimoire::SYS_YIELD,
            [unfinished_work as usize, 0, 0, 0, 0, 0],
        )
    }
    .map(|_| ())
}

/// Requests termination of the current process.
///
/// On native Boulder, a successful request is a scheduling boundary and does
/// not return to the caller. A returned result is therefore an error path.
pub fn request_exit(status: i32) -> Result<(), SyscallError> {
    let arguments = [status as isize as usize, 0, 0, 0, 0, 0];
    // SAFETY: Exit carries only a scalar status and follows Slope's native
    // six-register syscall convention.
    unsafe { syscall(grimoire::SYS_EXIT, arguments) }.map(|_| ())
}

/// Requests launch of a boot-measured service image.
///
/// The kernel owns all executable entry points and address spaces. `service_class`
/// selects a registered image; it is not an arbitrary code pointer.
pub fn spawn_service(service_class: u16) -> Result<u32, SyscallError> {
    unsafe { syscall(grimoire::SYS_SPAWN, [service_class as usize, 0, 0, 0, 0, 0]) }
        .map(|v| v as u32)
}

/// Waits for any child process to exit without blocking.
pub fn wait_nohang() -> Result<Option<(u32, i32)>, SyscallError> {
    let mut pid = 0u32;
    let mut status = 0i32;
    match unsafe {
        syscall(
            grimoire::SYS_WAIT,
            [
                &mut pid as *mut _ as usize,
                &mut status as *mut _ as usize,
                0,
                0,
                0,
                0,
            ],
        )
    } {
        Ok(_) => Ok(Some((pid, status))),
        Err(e) if e.0 == -11 => Ok(None),
        Err(e) => Err(e),
    }
}
