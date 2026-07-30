//! Read-only Aegis service observation.
//!
//! Boulder authenticates the caller against the exact live measured image;
//! this client never accepts a PID supplied by user space.

use crate::SyscallError;
#[cfg(target_os = "none")]
use crate::syscall;
use aether::grimoire;

#[cfg(any(target_os = "none", test))]
const STATUS_RUNNING: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrestServiceState {
    Running,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CrestServiceStatus {
    pub state: CrestServiceState,
    pub pid: u32,
}

#[cfg(any(target_os = "none", test))]
impl CrestServiceStatus {
    fn decode(word: u64) -> Option<Self> {
        let state = match word as u8 {
            STATUS_RUNNING => CrestServiceState::Running,
            _ => return None,
        };
        let pid = (word >> 8) as u32;
        (pid != 0).then_some(Self { state, pid })
    }
}

/// Returns live Crest status only to the currently-running measured Crest
/// image. Other images and host builds fail closed.
#[cfg(target_os = "none")]
pub fn crest_status() -> Result<CrestServiceStatus, SyscallError> {
    let word = unsafe { syscall(grimoire::SYS_AEGIS_STATUS, [0; 6])? } as u64;
    CrestServiceStatus::decode(word).ok_or(SyscallError(-74))
}

/// Host builds have no Boulder process registry and must not issue a raw host
/// syscall using Sisyphus's ABI number.
#[cfg(not(target_os = "none"))]
pub fn crest_status() -> Result<CrestServiceStatus, SyscallError> {
    let _ = grimoire::SYS_AEGIS_STATUS;
    Err(SyscallError(-38))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_the_kernel_running_status_encoding() {
        assert_eq!(
            CrestServiceStatus::decode((47_u64 << 8) | u64::from(STATUS_RUNNING)),
            Some(CrestServiceStatus {
                state: CrestServiceState::Running,
                pid: 47,
            })
        );
        assert_eq!(CrestServiceStatus::decode(0), None);
        assert_eq!(CrestServiceStatus::decode(2), None);
    }
}
