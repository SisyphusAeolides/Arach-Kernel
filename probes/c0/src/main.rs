#![no_main]
#![no_std]

use core::panic::PanicInfo;

const PASS: &[u8] = b"ARACH_C0_RING3_SYSCALL_PASS\n";
const LINUX_PASS: &[u8] = b"ARACH_C1_LINUX_SYSCALL_PASS\n";
const PANIC: &[u8] = b"ARACH_C0_RING3_PANIC\n";

const SYS_WRITE: usize = 1;
const SYS_READ: usize = 0;
const SYS_CLOSE: usize = 3;
const SYS_MMAP: usize = 9;
const SYS_MUNMAP: usize = 11;
const SYS_BRK: usize = 12;
const SYS_GETPID: usize = 39;
const SYS_UNAME: usize = 63;
const SYS_GETUID: usize = 102;
const SYS_GETGID: usize = 104;
const SYS_GETPPID: usize = 110;
const SYS_GETTID: usize = 186;
const SYS_CLOCK_GETTIME: usize = 228;
const SYS_EXIT_GROUP: usize = 231;
const SYS_EVENTFD2: usize = 290;
const SYS_POLL: usize = 7;
const SYS_EPOLL_WAIT: usize = 232;
const SYS_EPOLL_CTL: usize = 233;
const SYS_EPOLL_CREATE1: usize = 291;

const EFD_SEMAPHORE: usize = 0x1;
const POLLIN: u16 = 0x001;
const EPOLLIN: u32 = 0x001;
const EPOLL_CTL_ADD: usize = 1;

const PROT_READ: usize = 0x1;
const PROT_WRITE: usize = 0x2;
const MAP_PRIVATE: usize = 0x02;
const MAP_ANONYMOUS: usize = 0x20;

#[repr(C)]
struct LinuxTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[repr(C)]
struct LinuxUtsName {
    fields: [[u8; 65]; 6],
}

#[repr(C)]
struct LinuxPollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

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
unsafe fn linux_syscall4(
    number: usize,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
) -> isize {
    let result: isize;
    // SAFETY: Arguments use the stable x86-64 Linux syscall register order;
    // the fourth argument is carried in R10 rather than RCX.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") number as isize => result,
            in("rdi") arg0,
            in("rsi") arg1,
            in("rdx") arg2,
            in("r10") arg3,
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
    let uid = unsafe { linux_syscall1(SYS_GETUID, 0) };
    let gid = unsafe { linux_syscall1(SYS_GETGID, 0) };
    if !passed(pid) || tid != pid || ppid != 1 || uid != 0 || gid != 0 {
        fail();
    }

    // The kernel's monotonic clock is advanced from the calibrated periodic
    // timer, and uname is a fixed-size Linux wire object rather than a Rust
    // string crossing the boundary.
    let mut clock = LinuxTimespec {
        tv_sec: -1,
        tv_nsec: -1,
    };
    let mut identity = LinuxUtsName {
        fields: [[0; 65]; 6],
    };
    if unsafe { linux_syscall3(SYS_CLOCK_GETTIME, 1, &mut clock as *mut _ as usize, 0) } != 0
        || clock.tv_sec < 0
        || !(0..1_000_000_000).contains(&clock.tv_nsec)
        || unsafe { linux_syscall3(SYS_UNAME, &mut identity as *mut _ as usize, 0, 0) } != 0
        || !identity.fields[0].starts_with(b"Arach")
    {
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

    // Exercise the first real Linux descriptor object.  The normal counter
    // must accumulate and drain atomically; semaphore mode must release one
    // unit per read; an empty read must return EAGAIN rather than sleeping.
    let mut event_value: u64;
    let eventfd = unsafe { linux_syscall3(SYS_EVENTFD2, 5, 0, 0) };
    if eventfd < 3 {
        fail();
    }
    event_value = 7;
    if unsafe {
        linux_syscall3(
            SYS_WRITE,
            eventfd as usize,
            &event_value as *const _ as usize,
            core::mem::size_of::<u64>(),
        )
    } != core::mem::size_of::<u64>() as isize
    {
        fail();
    }
    // poll(2) must observe the readable eventfd without consuming it.
    let mut pollfd = LinuxPollFd {
        fd: eventfd as i32,
        events: POLLIN as i16,
        revents: 0,
    };
    if unsafe { linux_syscall3(SYS_POLL, &mut pollfd as *mut _ as usize, 1, 0) } != 1
        || pollfd.revents & POLLIN as i16 == 0
    {
        fail();
    }

    // epoll_wait uses the native x86-64 Linux epoll_event layout: a u32
    // mask followed by the caller's u64 data value.
    let epfd = unsafe { linux_syscall3(SYS_EPOLL_CREATE1, 0, 0, 0) };
    if epfd < 3 {
        fail();
    }
    let mut epoll_spec = [0_u8; 12];
    epoll_spec[0..4].copy_from_slice(&EPOLLIN.to_ne_bytes());
    epoll_spec[4..12].copy_from_slice(&0x55_u64.to_ne_bytes());
    if unsafe {
        linux_syscall4(
            SYS_EPOLL_CTL,
            epfd as usize,
            EPOLL_CTL_ADD,
            eventfd as usize,
            epoll_spec.as_ptr() as usize,
        )
    } != 0
    {
        fail();
    }
    let mut epoll_out = [0_u8; 12];
    if unsafe {
        linux_syscall4(
            SYS_EPOLL_WAIT,
            epfd as usize,
            epoll_out.as_mut_ptr() as usize,
            1,
            0,
        )
    } != 1
        || u32::from_ne_bytes(epoll_out[0..4].try_into().unwrap()) & EPOLLIN == 0
        || u64::from_ne_bytes(epoll_out[4..12].try_into().unwrap()) != 0x55
    {
        fail();
    }

    event_value = 0;
    if unsafe {
        linux_syscall3(
            SYS_READ,
            eventfd as usize,
            &mut event_value as *mut _ as usize,
            core::mem::size_of::<u64>(),
        )
    } != core::mem::size_of::<u64>() as isize
        || event_value != 12
    {
        fail();
    }
    pollfd.revents = 0;
    if unsafe { linux_syscall3(SYS_POLL, &mut pollfd as *mut _ as usize, 1, 0) } != 0
        || pollfd.revents != 0
    {
        fail();
    }
    if unsafe {
        linux_syscall4(
            SYS_EPOLL_WAIT,
            epfd as usize,
            epoll_out.as_mut_ptr() as usize,
            1,
            0,
        )
    } != 0
    {
        fail();
    }
    if unsafe { linux_syscall1(SYS_CLOSE, epfd as usize) } != 0
        || unsafe {
            linux_syscall3(
                SYS_READ,
                eventfd as usize,
                &mut event_value as *mut _ as usize,
                core::mem::size_of::<u64>(),
            )
        } != -11
        || unsafe { linux_syscall1(SYS_CLOSE, eventfd as usize) } != 0
    {
        fail();
    }

    let semaphore = unsafe { linux_syscall3(SYS_EVENTFD2, 2, EFD_SEMAPHORE, 0) };
    if semaphore < 3 {
        fail();
    }
    for _ in 0..2 {
        event_value = 0;
        if unsafe {
            linux_syscall3(
                SYS_READ,
                semaphore as usize,
                &mut event_value as *mut _ as usize,
                core::mem::size_of::<u64>(),
            )
        } != core::mem::size_of::<u64>() as isize
            || event_value != 1
        {
            fail();
        }
    }
    if unsafe { linux_syscall1(SYS_CLOSE, semaphore as usize) } != 0 {
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
