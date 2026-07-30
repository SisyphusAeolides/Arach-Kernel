//! Crest's capability-preserving firmware presentation client.
//!
//! This ABI accepts pixels only.  Boulder authenticates the live measured
//! Crest process and owns every display object, MMIO mapping, and page flip.

use crate::SyscallError;
#[cfg(target_os = "none")]
use crate::syscall;
use crate::syscalls::SYS_DISP_PRESENT;

pub const BGRA8888_BYTES_PER_PIXEL: u32 = 4;

pub fn present_bgra8888(
    frame: &[u8],
    width: u32,
    height: u32,
    pitch: u32,
) -> Result<u64, SyscallError> {
    let required = usize::try_from(
        u64::from(pitch)
            .checked_mul(u64::from(height))
            .ok_or(SyscallError(-22))?,
    )
    .map_err(|_| SyscallError(-22))?;
    if width == 0
        || height == 0
        || pitch
            < width
                .checked_mul(BGRA8888_BYTES_PER_PIXEL)
                .ok_or(SyscallError(-22))?
        || frame.len() != required
    {
        return Err(SyscallError(-22));
    }
    #[cfg(target_os = "none")]
    {
        let receipt = unsafe {
            syscall(
                SYS_DISP_PRESENT,
                [
                    frame.as_ptr() as usize,
                    width as usize,
                    height as usize,
                    pitch as usize,
                    0,
                    0,
                ],
            )?
        };
        Ok(receipt as u64)
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = SYS_DISP_PRESENT;
        Err(SyscallError(-38))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_an_incomplete_bgra_frame() {
        assert_eq!(present_bgra8888(&[0; 3], 1, 1, 4), Err(SyscallError(-22)));
    }
}
