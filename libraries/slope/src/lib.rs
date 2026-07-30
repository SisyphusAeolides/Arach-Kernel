#![no_std]

pub mod aegis;
pub mod bridge;
pub mod capability;
pub mod certificate;
pub mod display;
pub mod env;
pub mod executor;
pub mod fabric;
pub mod fs;
pub mod hermes_manifold;
pub mod hypermedia;
pub mod input;
pub mod io;
pub mod ipc;
pub mod kairos;
pub mod memory;
pub mod net;
pub mod nexus;
pub mod process;
pub mod quantum_crest;
pub mod resonance_plane;
pub mod runtime;
pub mod scheduler;
pub mod service_calculus;
pub mod signal;
pub mod storage;
pub mod sync;
pub mod syscalls;
pub mod thermogenesis;
pub mod time;
pub mod tuning;
pub mod wayland;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallError(pub isize);

/// Executes Sisyphus's six-register syscall ABI only in a native Sisyphus
/// image. Host builds must never accidentally interpret these numbers as the
/// host kernel's unrelated syscall table.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn syscall(number: usize, arguments: [usize; 6]) -> Result<usize, SyscallError> {
    let result: isize;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") number as isize => result,
            in("rdi") arguments[0],
            in("rsi") arguments[1],
            in("rdx") arguments[2],
            in("r10") arguments[3],
            in("r8")  arguments[4],
            in("r9")  arguments[5],
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    if result < 0 {
        Err(SyscallError(result))
    } else {
        Ok(result as usize)
    }
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub unsafe fn syscall(_number: usize, _arguments: [usize; 6]) -> Result<usize, SyscallError> {
    Err(SyscallError(-38))
}

#[cfg(all(test, not(target_os = "none")))]
mod tests {
    use super::*;

    #[test]
    fn host_builds_cannot_invoke_the_sisyphus_syscall_abi() {
        // SAFETY: the host implementation is an explicit fail-closed stub.
        assert_eq!(unsafe { syscall(0, [0; 6]) }, Err(SyscallError(-38)));
    }
}
