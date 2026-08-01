#![no_main]
#![no_std]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, Ordering};

const PASS: &[u8] = b"ARACH_C0_RING3_SYSCALL_PASS\n";
const THREAD_PASS: &[u8] = b"ARACH_C1_THREAD_FUTEX_PASS\n";
const ROBUST_PASS: &[u8] = b"ARACH_C1_ROBUST_FUTEX_PASS\n";
const SIGNAL_PASS: &[u8] = b"ARACH_C1_SIGNAL_RETURN_PASS\n";
const LINUX_PASS: &[u8] = b"ARACH_C1_LINUX_SYSCALL_PASS\n";
const PANIC: &[u8] = b"ARACH_C0_RING3_PANIC\n";
const EXEC_PATH: &[u8] = b"/exec-target\0";
const RUNTIME_LINKER_PATH: &[u8] = b"/arach-ld.so\0";
const EXEC_ARG0: &[u8] = b"exec-target\0";
const EXEC_ENV0: &[u8] = b"ARACH_EXEC_TRANSACTION=1\0";
const EXEC_TARGET: &[u8] = include_bytes!(env!("ARACH_EXEC_TARGET_IMAGE_PATH"));
const RUNTIME_LINKER: &[u8] = include_bytes!(env!("ARACH_RUNTIME_LINKER_IMAGE_PATH"));

const SYS_WRITE: usize = 1;
const SYS_READ: usize = 0;
const SYS_CLOSE: usize = 3;
const SYS_MMAP: usize = 9;
const SYS_MUNMAP: usize = 11;
const SYS_BRK: usize = 12;
const SYS_RT_SIGACTION: usize = 13;
const SYS_RT_SIGPROCMASK: usize = 14;
const SYS_RT_SIGRETURN: usize = 15;
const SYS_GETPID: usize = 39;
const SYS_CLONE: usize = 56;
const SYS_EXECVE: usize = 59;
const SYS_EXIT: usize = 60;
const SYS_UNAME: usize = 63;
const SYS_GETUID: usize = 102;
const SYS_GETGID: usize = 104;
const SYS_GETPPID: usize = 110;
const SYS_ARCH_PRCTL: usize = 158;
const SYS_GETTID: usize = 186;
const SYS_FUTEX: usize = 202;
const SYS_SET_ROBUST_LIST: usize = 273;
const SYS_GET_ROBUST_LIST: usize = 274;
const SYS_TGKILL: usize = 234;
const SYS_CLOCK_GETTIME: usize = 228;
const SYS_EXIT_GROUP: usize = 231;
const SYS_EVENTFD2: usize = 290;
const SYS_POLL: usize = 7;
const SYS_EPOLL_WAIT: usize = 232;
const SYS_EPOLL_CTL: usize = 233;
const SYS_EPOLL_CREATE1: usize = 291;
const SYS_OPEN: usize = 2;

const O_RDWR: usize = 0x2;
const O_CREAT: usize = 0x40;
const O_EXCL: usize = 0x80;

const EFD_SEMAPHORE: usize = 0x1;
const POLLIN: u16 = 0x001;
const EPOLLIN: u32 = 0x001;
const EPOLL_CTL_ADD: usize = 1;
const FUTEX_WAIT_PRIVATE: usize = 128;
const FUTEX_WAKE_PRIVATE: usize = 129;
const FUTEX_WAITERS: u32 = 0x8000_0000;
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
const SIGUSR1: u32 = 10;
const SIG_BLOCK: usize = 0;
const SIG_UNBLOCK: usize = 1;
const SA_SIGINFO: usize = 0x0000_0004;
const SA_RESTORER: usize = 0x0400_0000;
const ARCH_SET_FS: usize = 0x1002;
const ARCH_GET_FS: usize = 0x1003;

const PROT_READ: usize = 0x1;
const PROT_WRITE: usize = 0x2;
const MAP_PRIVATE: usize = 0x02;
const MAP_ANONYMOUS: usize = 0x20;

const CLONE_VM: usize = 0x0000_0100;
const CLONE_FS: usize = 0x0000_0200;
const CLONE_FILES: usize = 0x0000_0400;
const CLONE_SIGHAND: usize = 0x0000_0800;
const CLONE_THREAD: usize = 0x0001_0000;
const CLONE_SYSVSEM: usize = 0x0004_0000;
const CLONE_PARENT_SETTID: usize = 0x0010_0000;
const CLONE_CHILD_CLEARTID: usize = 0x0020_0000;
const CLONE_CHILD_SETTID: usize = 0x0100_0000;
const THREAD_CLONE_FLAGS: usize = CLONE_VM
    | CLONE_FS
    | CLONE_FILES
    | CLONE_SIGHAND
    | CLONE_THREAD
    | CLONE_SYSVSEM
    | CLONE_PARENT_SETTID
    | CLONE_CHILD_CLEARTID
    | CLONE_CHILD_SETTID;

const THREAD_STACK_BYTES: usize = 16 * 1024;

#[repr(C, align(16))]
struct ThreadStack([u8; THREAD_STACK_BYTES]);

static mut THREAD_STACK: ThreadStack = ThreadStack([0; THREAD_STACK_BYTES]);
static THREAD_TID: AtomicU32 = AtomicU32::new(0);
static THREAD_OBSERVED_TID: AtomicU32 = AtomicU32::new(0);
static THREAD_OBSERVED_PID: AtomicU32 = AtomicU32::new(0);
static THREAD_EVENT_FD: AtomicU32 = AtomicU32::new(0);
static THREAD_DESCRIPTOR_WRITE: AtomicU32 = AtomicU32::new(0);
static SIGNAL_HITS: AtomicU32 = AtomicU32::new(0);

#[repr(C)]
struct RobustListHead {
    next: usize,
    futex_offset: isize,
    list_op_pending: usize,
}

#[repr(C)]
struct RobustNode {
    next: usize,
    futex: AtomicU32,
}

static mut ROBUST_HEAD: RobustListHead = RobustListHead {
    next: 0,
    futex_offset: 0,
    list_op_pending: 0,
};
static mut ROBUST_NODE: RobustNode = RobustNode {
    next: 0,
    futex: AtomicU32::new(0),
};

core::arch::global_asm!(
    r#"
    .global arach_clone_thread
    .type arach_clone_thread,@function
arach_clone_thread:
    mov r10, rcx
    mov eax, {clone_syscall}
    syscall
    test rax, rax
    jnz 1f
    xor ebp, ebp
    call r9
    mov rdi, rax
    mov eax, {exit_syscall}
    syscall
    ud2
1:
    ret
    .size arach_clone_thread, .-arach_clone_thread
"#,
    clone_syscall = const SYS_CLONE,
    exit_syscall = const SYS_EXIT,
);

core::arch::global_asm!(
    r#"
    .global arach_signal_restorer
    .type arach_signal_restorer,@function
arach_signal_restorer:
    mov eax, {sigreturn_syscall}
    syscall
    ud2
    .size arach_signal_restorer, .-arach_signal_restorer
"#,
    sigreturn_syscall = const SYS_RT_SIGRETURN,
);

unsafe extern "C" {
    fn arach_clone_thread(
        flags: usize,
        child_stack: usize,
        parent_tid: *mut u32,
        child_tid: *mut u32,
        tls: usize,
        child_entry: extern "C" fn() -> isize,
    ) -> isize;
    fn arach_signal_restorer();
}

#[repr(C)]
struct LinuxSignalAction {
    handler: usize,
    flags: usize,
    restorer: usize,
    mask: u64,
}

#[repr(C)]
struct LinuxSignalInfoPrefix {
    signal: i32,
    errno: i32,
    code: i32,
    padding: i32,
}

#[repr(C)]
struct LinuxSignalContextPrefix {
    flags: usize,
}

extern "C" fn signal_handler(
    signal: usize,
    info: *const LinuxSignalInfoPrefix,
    context: *const LinuxSignalContextPrefix,
) {
    if signal != SIGUSR1 as usize || info.is_null() || context.is_null() {
        return;
    }
    // SAFETY: SA_SIGINFO delivery supplies pointers into the live kernel-built
    // rt_sigframe for the complete duration of this handler.
    let valid = unsafe { (*info).signal == SIGUSR1 as i32 && (*info).code == -6 }
        && unsafe { (*context).flags == 0x6 };
    if valid {
        SIGNAL_HITS.fetch_add(1, Ordering::AcqRel);
    }
}

extern "C" fn thread_entry() -> isize {
    // SAFETY: Identity syscalls have scalar-only Linux x86-64 arguments.
    let tid = unsafe { linux_syscall1(SYS_GETTID, 0) };
    let pid = unsafe { linux_syscall1(SYS_GETPID, 0) };
    if tid <= 0 || pid <= 0 || tid == pid {
        return 126;
    }
    THREAD_OBSERVED_TID.store(tid as u32, Ordering::Release);
    THREAD_OBSERVED_PID.store(pid as u32, Ordering::Release);
    let head = core::ptr::addr_of_mut!(ROBUST_HEAD);
    let node = core::ptr::addr_of_mut!(ROBUST_NODE);
    let futex = unsafe { core::ptr::addr_of_mut!((*node).futex) };
    // SAFETY: The child is the only task mutating these list links. The parent
    // only touches the atomic futex word before blocking, and the objects stay
    // mapped until the child exit walk has completed.
    unsafe {
        core::ptr::addr_of_mut!((*head).next).write(node as usize);
        core::ptr::addr_of_mut!((*head).futex_offset)
            .write((futex as usize - node as usize) as isize);
        core::ptr::addr_of_mut!((*head).list_op_pending).write(0);
        core::ptr::addr_of_mut!((*node).next).write(head as usize);
    }
    if unsafe {
        linux_syscall3(
            SYS_SET_ROBUST_LIST,
            head as usize,
            core::mem::size_of::<RobustListHead>(),
            0,
        )
    } != 0
    {
        return 124;
    }
    let mut reported_head = 0_usize;
    let mut reported_length = 0_usize;
    if unsafe {
        linux_syscall3(
            SYS_GET_ROBUST_LIST,
            0,
            &mut reported_head as *mut _ as usize,
            &mut reported_length as *mut _ as usize,
        )
    } != 0
        || reported_head != head as usize
        || reported_length != core::mem::size_of::<RobustListHead>()
    {
        return 123;
    }
    let event_value = 1_u64;
    let eventfd = THREAD_EVENT_FD.load(Ordering::Acquire);
    let wrote = unsafe {
        // SAFETY: The descriptor was created by the group leader before the
        // clone, and event_value is live on the dedicated child stack.
        linux_syscall3(
            SYS_WRITE,
            eventfd as usize,
            &event_value as *const _ as usize,
            core::mem::size_of::<u64>(),
        )
    };
    if wrote != core::mem::size_of::<u64>() as isize {
        return 125;
    }
    THREAD_DESCRIPTOR_WRITE.store(1, Ordering::Release);
    0
}

extern "C" fn clear_tid_thread_entry() -> isize {
    // SAFETY: Identity syscalls have scalar-only Linux x86-64 arguments.
    let tid = unsafe { linux_syscall1(SYS_GETTID, 0) };
    let pid = unsafe { linux_syscall1(SYS_GETPID, 0) };
    if tid <= 0 || pid <= 0 || tid == pid {
        return 126;
    }
    THREAD_OBSERVED_TID.store(tid as u32, Ordering::Release);
    THREAD_OBSERVED_PID.store(pid as u32, Ordering::Release);
    let event_value = 1_u64;
    let eventfd = THREAD_EVENT_FD.load(Ordering::Acquire);
    let wrote = unsafe {
        linux_syscall3(
            SYS_WRITE,
            eventfd as usize,
            &event_value as *const _ as usize,
            core::mem::size_of::<u64>(),
        )
    };
    if wrote != core::mem::size_of::<u64>() as isize {
        return 125;
    }
    THREAD_DESCRIPTOR_WRITE.store(1, Ordering::Release);
    0
}

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

fn write_all(fd: usize, bytes: &[u8]) -> bool {
    let mut written = 0_usize;
    while written < bytes.len() {
        let result = unsafe {
            linux_syscall3(
                SYS_WRITE,
                fd,
                bytes.as_ptr().add(written) as usize,
                bytes.len() - written,
            )
        };
        if result <= 0 {
            return false;
        }
        written += result as usize;
    }
    true
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

    // Prove that the generation-bound return path installs FS-base TLS and
    // that arch_prctl reports the same value back through user memory.
    let tls_word = 0x4152_4143_4854_4c53_u64;
    let tls_base = &tls_word as *const _ as usize;
    let mut reported_fs = usize::MAX;
    if unsafe { linux_syscall3(SYS_ARCH_PRCTL, ARCH_SET_FS, tls_base, 0) } != 0
        || unsafe {
            linux_syscall3(
                SYS_ARCH_PRCTL,
                ARCH_GET_FS,
                &mut reported_fs as *mut _ as usize,
                0,
            )
        } != 0
        || reported_fs != tls_base
    {
        fail();
    }
    let observed_tls: u64;
    // SAFETY: ARCH_SET_FS selected the address of the live `tls_word` and the
    // one-word read remains within that object.
    unsafe {
        core::arch::asm!(
            "mov {}, fs:[0]",
            out(reg) observed_tls,
            options(nostack, readonly, preserves_flags),
        );
    }
    if observed_tls != tls_word || unsafe { linux_syscall3(SYS_ARCH_PRCTL, ARCH_SET_FS, 0, 0) } != 0
    {
        fail();
    }

    // A mismatched WAIT must never enqueue or block, and an empty wake must
    // report that no generation was selected.
    let futex_word = 7_u32;
    if unsafe {
        linux_syscall6(
            SYS_FUTEX,
            &futex_word as *const _ as usize,
            FUTEX_WAIT_PRIVATE,
            8,
            0,
            0,
            0,
        )
    } != -11
        || unsafe {
            linux_syscall6(
                SYS_FUTEX,
                &futex_word as *const _ as usize,
                FUTEX_WAKE_PRIVATE,
                1,
                0,
                0,
                0,
            )
        } != 0
    {
        fail();
    }

    // Create one measured shared-address-space peer. The assembly trampoline
    // ensures the child never returns through a Rust frame created on the
    // parent's stack. Parent and child TID publication happen before either
    // task can return to user mode.
    THREAD_TID.store(0, Ordering::Release);
    THREAD_OBSERVED_TID.store(0, Ordering::Release);
    THREAD_OBSERVED_PID.store(0, Ordering::Release);
    THREAD_DESCRIPTOR_WRITE.store(0, Ordering::Release);
    let robust_futex = unsafe {
        // SAFETY: Taking the raw address creates no reference to the mutable
        // static; atomic accesses synchronize the parent with exit recovery.
        &*core::ptr::addr_of!(ROBUST_NODE.futex)
    };
    robust_futex.store(0, Ordering::Release);
    let thread_eventfd = unsafe { linux_syscall3(SYS_EVENTFD2, 0, 0, 0) };
    if thread_eventfd < 3 {
        fail();
    }
    THREAD_EVENT_FD.store(thread_eventfd as u32, Ordering::Release);
    let stack_top = unsafe {
        // SAFETY: addr_of_mut creates no reference to the mutable static. The
        // one-past-end pointer is 16-byte aligned and the first child push
        // enters the dedicated writable stack object.
        core::ptr::addr_of_mut!(THREAD_STACK.0)
            .cast::<u8>()
            .add(THREAD_STACK_BYTES) as usize
    };
    let tid_word = (&THREAD_TID as *const AtomicU32).cast_mut().cast::<u32>();
    let cloned = unsafe {
        // SAFETY: The trampoline obeys the Linux x86-64 clone register ABI;
        // both TID pointers and the entire child stack are live writable
        // objects in this shared address space.
        arach_clone_thread(
            THREAD_CLONE_FLAGS,
            stack_top,
            tid_word,
            tid_word,
            0,
            thread_entry,
        )
    };
    if cloned <= 0 || cloned == pid || THREAD_TID.load(Ordering::Acquire) != cloned as u32 {
        fail();
    }

    // FUTEX_WAIT blocks the leader and is the only path that can schedule the
    // new peer. The child registers a robust list and exits while owning this
    // exact word. Exit atomically publishes OWNER_DIED, wakes the leader, then
    // clears child_tid before retiring the non-waitable TID slot.
    let owned_robust_word = FUTEX_WAITERS | cloned as u32;
    robust_futex.store(owned_robust_word, Ordering::Release);
    if unsafe {
        linux_syscall6(
            SYS_FUTEX,
            robust_futex as *const _ as usize,
            FUTEX_WAIT_PRIVATE,
            owned_robust_word as usize,
            0,
            0,
            0,
        )
    } != 0
    {
        fail();
    }
    if THREAD_OBSERVED_TID.load(Ordering::Acquire) != cloned as u32
        || THREAD_OBSERVED_PID.load(Ordering::Acquire) != pid as u32
        || THREAD_DESCRIPTOR_WRITE.load(Ordering::Acquire) != 1
        || THREAD_TID.load(Ordering::Acquire) != 0
        || robust_futex.load(Ordering::Acquire) != FUTEX_WAITERS | FUTEX_OWNER_DIED
    {
        fail();
    }
    let mut thread_event_value = 0_u64;
    if unsafe {
        linux_syscall3(
            SYS_READ,
            thread_eventfd as usize,
            &mut thread_event_value as *mut _ as usize,
            core::mem::size_of::<u64>(),
        )
    } != core::mem::size_of::<u64>() as isize
        || thread_event_value != 1
    {
        fail();
    }
    let wrote = unsafe {
        linux_syscall3(
            SYS_WRITE,
            1,
            ROBUST_PASS.as_ptr() as usize,
            ROBUST_PASS.len(),
        )
    };
    if wrote != ROBUST_PASS.len() as isize {
        fail();
    }

    // Reuse the now-retired child stack for an independent clear-child-tid
    // wake. This preserves the original measured contract while ensuring the
    // robust wake above is not mistaken for clear-child-tid behavior.
    THREAD_TID.store(0, Ordering::Release);
    THREAD_OBSERVED_TID.store(0, Ordering::Release);
    THREAD_OBSERVED_PID.store(0, Ordering::Release);
    THREAD_DESCRIPTOR_WRITE.store(0, Ordering::Release);
    let clear_tid_child = unsafe {
        arach_clone_thread(
            THREAD_CLONE_FLAGS,
            stack_top,
            tid_word,
            tid_word,
            0,
            clear_tid_thread_entry,
        )
    };
    if clear_tid_child <= 0
        || clear_tid_child == pid
        || THREAD_TID.load(Ordering::Acquire) != clear_tid_child as u32
    {
        fail();
    }
    loop {
        let observed = THREAD_TID.load(Ordering::Acquire);
        if observed == 0 {
            break;
        }
        let waited = unsafe {
            linux_syscall6(
                SYS_FUTEX,
                tid_word as usize,
                FUTEX_WAIT_PRIVATE,
                observed as usize,
                0,
                0,
                0,
            )
        };
        if waited != 0 && waited != -11 {
            fail();
        }
    }
    if THREAD_OBSERVED_TID.load(Ordering::Acquire) != clear_tid_child as u32
        || THREAD_OBSERVED_PID.load(Ordering::Acquire) != pid as u32
        || THREAD_DESCRIPTOR_WRITE.load(Ordering::Acquire) != 1
    {
        fail();
    }
    thread_event_value = 0;
    if unsafe {
        linux_syscall3(
            SYS_READ,
            thread_eventfd as usize,
            &mut thread_event_value as *mut _ as usize,
            core::mem::size_of::<u64>(),
        )
    } != core::mem::size_of::<u64>() as isize
        || thread_event_value != 1
        || unsafe { linux_syscall1(SYS_CLOSE, thread_eventfd as usize) } != 0
    {
        fail();
    }
    let wrote = unsafe {
        linux_syscall3(
            SYS_WRITE,
            1,
            THREAD_PASS.as_ptr() as usize,
            THREAD_PASS.len(),
        )
    };
    if wrote != THREAD_PASS.len() as isize {
        fail();
    }

    // Install a three-argument SA_SIGINFO handler with an explicit x86-64
    // restorer. SIGUSR1 is first queued while blocked, then delivered as part
    // of the unblock syscall return. Returning from the handler must execute
    // rt_sigreturn and resume this exact instruction stream.
    SIGNAL_HITS.store(0, Ordering::Release);
    let action = LinuxSignalAction {
        handler: signal_handler as *const () as usize,
        flags: SA_SIGINFO | SA_RESTORER,
        restorer: arach_signal_restorer as *const () as usize,
        mask: 0,
    };
    let mut previous_action = LinuxSignalAction {
        handler: usize::MAX,
        flags: usize::MAX,
        restorer: usize::MAX,
        mask: u64::MAX,
    };
    if unsafe {
        linux_syscall4(
            SYS_RT_SIGACTION,
            SIGUSR1 as usize,
            &action as *const _ as usize,
            &mut previous_action as *mut _ as usize,
            core::mem::size_of::<u64>(),
        )
    } != 0
        || previous_action.handler != 0
        || previous_action.flags != 0
        || previous_action.restorer != 0
        || previous_action.mask != 0
    {
        fail();
    }
    let signal_mask = 1_u64 << (SIGUSR1 - 1);
    let mut previous_mask = u64::MAX;
    if unsafe {
        linux_syscall4(
            SYS_RT_SIGPROCMASK,
            SIG_BLOCK,
            &signal_mask as *const _ as usize,
            &mut previous_mask as *mut _ as usize,
            core::mem::size_of::<u64>(),
        )
    } != 0
        || previous_mask != 0
        || unsafe { linux_syscall3(SYS_TGKILL, pid as usize, tid as usize, SIGUSR1 as usize) } != 0
        || SIGNAL_HITS.load(Ordering::Acquire) != 0
    {
        fail();
    }
    previous_mask = 0;
    if unsafe {
        linux_syscall4(
            SYS_RT_SIGPROCMASK,
            SIG_UNBLOCK,
            &signal_mask as *const _ as usize,
            &mut previous_mask as *mut _ as usize,
            core::mem::size_of::<u64>(),
        )
    } != 0
        || previous_mask != signal_mask
        || SIGNAL_HITS.load(Ordering::Acquire) != 1
    {
        fail();
    }
    let wrote = unsafe {
        linux_syscall3(
            SYS_WRITE,
            1,
            SIGNAL_PASS.as_ptr() as usize,
            SIGNAL_PASS.len(),
        )
    };
    if wrote != SIGNAL_PASS.len() as isize {
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

    // Materialize an immutable VFS snapshot, then replace this same PID with
    // the measured target. Successful execve cannot return to this image.
    let runtime_linker = unsafe {
        linux_syscall3(
            SYS_OPEN,
            RUNTIME_LINKER_PATH.as_ptr() as usize,
            O_CREAT | O_EXCL | O_RDWR,
            0,
        )
    };
    if runtime_linker < 3
        || !write_all(runtime_linker as usize, RUNTIME_LINKER)
        || unsafe { linux_syscall1(SYS_CLOSE, runtime_linker as usize) } != 0
    {
        fail();
    }
    let target = unsafe {
        linux_syscall3(
            SYS_OPEN,
            EXEC_PATH.as_ptr() as usize,
            O_CREAT | O_EXCL | O_RDWR,
            0,
        )
    };
    if target < 3
        || !write_all(target as usize, EXEC_TARGET)
        || unsafe { linux_syscall1(SYS_CLOSE, target as usize) } != 0
    {
        fail();
    }
    let argv = [EXEC_ARG0.as_ptr(), core::ptr::null()];
    let envp = [EXEC_ENV0.as_ptr(), core::ptr::null()];
    let result = unsafe {
        linux_syscall3(
            SYS_EXECVE,
            EXEC_PATH.as_ptr() as usize,
            argv.as_ptr() as usize,
            envp.as_ptr() as usize,
        )
    };
    if result != 0 {
        fail();
    }
    fail();
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
