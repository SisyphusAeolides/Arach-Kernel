#![no_main]
#![no_std]

use core::panic::PanicInfo;

const PASS: &[u8] = b"ARACH_C0_RING3_SYSCALL_PASS\n";
const LINUX_PASS: &[u8] = b"ARACH_C1_LINUX_SYSCALL_PASS\n";
const PANIC: &[u8] = b"ARACH_C0_RING3_PANIC\n";

const SYS_WRITE: usize = 1;
const SYS_MMAP: usize = 9;
const SYS_MUNMAP: usize = 11;
const SYS_BRK: usize = 12;
const SYS_GETPID: usize = 39;
const SYS_GETPPID: usize = 110;
const SYS_GETTID: usize = 186;
const SYS_EXIT_GROUP: usize = 231;

const PROT_READ: usize = 0x1;
const PROT_WRITE: usize = 0x2;
const MAP_PRIVATE: usize = 0x02;
const MAP_ANONYMOUS: usize = 0x20;

#[inline(always)]
unsafe fn linux_syscall1(number: usize, arg0: usize) -> isize {
    let result: isize;
    // SAFETY: The probe is an x86-64 Linux-personality image. The kernel
    // syscall entry preserves the ABI-required clobbers and returns in RAX.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") number as isize => result,
            in("rdi") arg0,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

#[inline(always)]
unsafe fn linux_syscall3(number: usize, arg0: usize, arg1: usize, arg2: usize) -> isize {
    let result: isize;
    // SAFETY: Arguments use the stable x86-64 Linux syscall register order.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") number as isize => result,
            in("rdi") arg0,
            in("rsi") arg1,
            in("rdx") arg2,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

#[inline(always)]
unsafe fn linux_syscall6(
    number: usize,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
) -> isize {
    let result: isize;
    // SAFETY: The six scalar arguments are copied into the Linux x86-64
    // syscall ABI registers; the kernel validates every pointer and range.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") number as isize => result,
            in("rdi") arg0,
            in("rsi") arg1,
            in("rdx") arg2,
            in("r10") arg3,
            in("r8") arg4,
            in("r9") arg5,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

#[inline(always)]
fn passed(value: isize) -> bool {
    value >= 0
}

fn fail() -> ! {
    // SAFETY: exit_group accepts a scalar status and never returns.
    unsafe {
        let _ = linux_syscall1(SYS_EXIT_GROUP, 127);
    }
    loop {
        core::hint::spin_loop();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // Keep the original marker: it proves the image entered Ring 3 and
    // crossed the syscall boundary. The second marker is emitted only after
    // the Linux personality has serviced every operation below.
    // SAFETY: PASS is a read-only, kernel-readable static byte slice.
    let wrote = unsafe { linux_syscall3(SYS_WRITE, 1, PASS.as_ptr() as usize, PASS.len()) };
    if wrote != PASS.len() as isize {
        fail();
    }

    // Identity calls must all resolve to this exact running process. The
    // parent is PID 1 (Push) in the measured C0 launch graph.
    // SAFETY: These calls carry no pointers.
    let pid = unsafe { linux_syscall1(SYS_GETPID, 0) };
    let tid = unsafe { linux_syscall1(SYS_GETTID, 0) };
    let ppid = unsafe { linux_syscall1(SYS_GETPPID, 0) };
    if !passed(pid) || tid != pid || ppid != 1 {
        fail();
    }

    // Exercise the real generation-bound anonymous mapping path. The write
    // proves the returned user page is writable before the exact-range unmap.
    // SAFETY: The Linux ABI arguments are scalar and the returned address is
    // checked before it is dereferenced.
    let mapped = unsafe {
        linux_syscall6(
            SYS_MMAP,
            0,
            4096,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            usize::MAX,
            0,
        )
    };
    if mapped <= 0 || mapped as usize & 0xfff != 0 {
        fail();
    }
    // SAFETY: mmap returned a page-aligned user address and the kernel just
    // installed it writable for this process.
    unsafe {
        core::ptr::write_volatile(mapped as *mut u8, 0xa5);
        if core::ptr::read_volatile(mapped as *const u8) != 0xa5 {
            fail();
        }
    }
    // SAFETY: The address and length exactly describe the mapping above.
    if unsafe { linux_syscall3(SYS_MUNMAP, mapped as usize, 4096, 0) } != 0 {
        fail();
    }

    // A zero brk query must return the process's bounded initial break.
    // SAFETY: brk's first argument is a scalar query.
    if unsafe { linux_syscall1(SYS_BRK, 0) } <= 0 {
        fail();
    }

    // SAFETY: LINUX_PASS is a read-only static byte slice.
    let wrote =
        unsafe { linux_syscall3(SYS_WRITE, 1, LINUX_PASS.as_ptr() as usize, LINUX_PASS.len()) };
    if wrote != LINUX_PASS.len() as isize {
        fail();
    }

    // SAFETY: exit_group accepts a scalar status and is handled before the
    // ordinary Linux syscall dispatcher schedules the next process.
    unsafe {
        let _ = linux_syscall1(SYS_EXIT_GROUP, 0);
    }
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    // SAFETY: PANIC is a read-only, kernel-readable static byte slice.
    let _ = unsafe { linux_syscall3(SYS_WRITE, 2, PANIC.as_ptr() as usize, PANIC.len()) };
    // SAFETY: exit_group accepts a scalar status and never returns.
    let _ = unsafe { linux_syscall1(SYS_EXIT_GROUP, 127) };
    loop {
        core::hint::spin_loop();
    }
}
