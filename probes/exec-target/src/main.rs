#![no_main]
#![no_std]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, Ordering};

const EXEC_PASS: &[u8] = b"ARACH_C1_EXECVE_PASS\n";
const EXIT_GROUP_ARMED: &[u8] = b"ARACH_C1_EXIT_GROUP_ARMED\n";
const EXPECTED_ARG0: &[u8] = b"exec-target";
const EXPECTED_ENV0: &[u8] = b"ARACH_EXEC_TRANSACTION=1";
const EXPECTED_COPY_VALUE: u64 =
    0x0123_4567_89ab_cdef ^ 0x1357_9bdf_2468_ace0 ^ 0xfedc_ba98_7654_3210;
const SYS_READ: usize = 0;
const SYS_WRITE: usize = 1;
const SYS_CLOSE: usize = 3;
const SYS_CLONE: usize = 56;
const SYS_EXIT: usize = 60;
const SYS_GETPID: usize = 39;
const SYS_FUTEX: usize = 202;
const SYS_EXIT_GROUP: usize = 231;
const FUTEX_WAIT_PRIVATE: usize = 128;
const FUTEX_WAKE_PRIVATE: usize = 129;
const CLONE_FLAGS: usize = 0x0000_0100
    | 0x0000_0200
    | 0x0000_0400
    | 0x0000_0800
    | 0x0001_0000
    | 0x0004_0000
    | 0x0010_0000
    | 0x0020_0000
    | 0x0100_0000;
const STACK_BYTES: usize = 16 * 1024;

#[repr(C, align(16))]
struct Stack([u8; STACK_BYTES]);

static mut CHILD_STACK: Stack = Stack([0; STACK_BYTES]);
static CHILD_TID: AtomicU32 = AtomicU32::new(0);
static CHILD_READY: AtomicU32 = AtomicU32::new(0);
static CHILD_HOLD: AtomicU32 = AtomicU32::new(0);

core::arch::global_asm!(
    r#"
    .global arach_exec_clone
    .type arach_exec_clone,@function
arach_exec_clone:
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
    .size arach_exec_clone, .-arach_exec_clone
"#,
    clone_syscall = const SYS_CLONE,
    exit_syscall = const SYS_EXIT,
);

core::arch::global_asm!(
    r#"
    .global arach_exec_copy_probe
    .type arach_exec_copy_probe,@function
arach_exec_copy_probe:
    mov rax, qword ptr [rip + arach_copy_source]
    xor rax, qword ptr [rip + arach_copy_source + 8]
    xor rax, qword ptr [rip + arach_copy_source + 16]
    ret
    .size arach_exec_copy_probe, .-arach_exec_copy_probe
"#,
);

core::arch::global_asm!(
    r#"
    .global _start
    .type _start,@function
_start:
    mov rsi, rdx
    mov rdi, rsp
    call arach_exec_start
    ud2
    .size _start, .-_start
"#,
);

unsafe extern "C" {
    fn arach_exec_clone(
        flags: usize,
        child_stack: usize,
        parent_tid: *mut u32,
        child_tid: *mut u32,
        tls: usize,
        child_entry: extern "C" fn() -> isize,
    ) -> isize;
    fn arach_exec_copy_probe() -> u64;
}

#[inline(always)]
unsafe fn syscall1(number: usize, argument: usize) -> isize {
    let result: isize;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") number as isize => result,
            in("rdi") argument,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

#[inline(always)]
unsafe fn syscall3(number: usize, first: usize, second: usize, third: usize) -> isize {
    let result: isize;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") number as isize => result,
            in("rdi") first,
            in("rsi") second,
            in("rdx") third,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

#[inline(always)]
unsafe fn futex(address: usize, operation: usize, value: usize) -> isize {
    let result: isize;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") SYS_FUTEX as isize => result,
            in("rdi") address,
            in("rsi") operation,
            in("rdx") value,
            in("r10") 0,
            in("r8") 0,
            in("r9") 0,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

extern "C" fn child() -> isize {
    CHILD_READY.store(1, Ordering::Release);
    if unsafe { futex(&CHILD_READY as *const _ as usize, FUTEX_WAKE_PRIVATE, 1) } != 1 {
        return 126;
    }
    loop {
        let result = unsafe { futex(&CHILD_HOLD as *const _ as usize, FUTEX_WAIT_PRIVATE, 0) };
        if result != 0 && result != -11 {
            return 125;
        }
    }
}

fn fail() -> ! {
    let _ = unsafe { syscall1(SYS_EXIT_GROUP, 127) };
    loop {
        core::hint::spin_loop();
    }
}

unsafe fn stack_string_matches(pointer: usize, expected: &[u8]) -> bool {
    if pointer == 0 {
        return false;
    }
    for (index, expected_byte) in expected.iter().copied().enumerate() {
        if unsafe { (pointer as *const u8).add(index).read() } != expected_byte {
            return false;
        }
    }
    unsafe { (pointer as *const u8).add(expected.len()).read() == 0 }
}

#[unsafe(no_mangle)]
extern "C" fn arach_exec_start(stack: *const usize, finalizer: usize) -> ! {
    if stack.is_null()
        || finalizer == 0
        || unsafe { stack.read() } != 1
        || !unsafe { stack_string_matches(stack.add(1).read(), EXPECTED_ARG0) }
        || unsafe { stack.add(2).read() } != 0
        || !unsafe { stack_string_matches(stack.add(3).read(), EXPECTED_ENV0) }
        || unsafe { stack.add(4).read() } != 0
    {
        fail();
    }
    if unsafe { arach_exec_copy_probe() } != EXPECTED_COPY_VALUE {
        fail();
    }
    let mut inherited_value = 0_u64;
    if unsafe { syscall1(SYS_CLOSE, 126) } != -9
        || unsafe {
            syscall3(
                SYS_READ,
                125,
                &mut inherited_value as *mut _ as usize,
                core::mem::size_of::<u64>(),
            )
        } != core::mem::size_of::<u64>() as isize
        || inherited_value != 1
        || unsafe { syscall1(SYS_CLOSE, 125) } != 0
    {
        fail();
    }
    if unsafe { syscall3(SYS_WRITE, 1, EXEC_PASS.as_ptr() as usize, EXEC_PASS.len()) }
        != EXEC_PASS.len() as isize
    {
        fail();
    }
    let pid = unsafe { syscall1(SYS_GETPID, 0) };
    let stack_top = core::ptr::addr_of_mut!(CHILD_STACK) as usize + STACK_BYTES;
    let tid_word = &CHILD_TID as *const AtomicU32 as *mut u32;
    let peer = unsafe { arach_exec_clone(CLONE_FLAGS, stack_top, tid_word, tid_word, 0, child) };
    if peer <= 0 || peer == pid {
        fail();
    }
    let waited = unsafe { futex(&CHILD_READY as *const _ as usize, FUTEX_WAIT_PRIVATE, 0) };
    if waited != 0
        || CHILD_READY.load(Ordering::Acquire) != 1
        || CHILD_TID.load(Ordering::Acquire) != peer as u32
    {
        fail();
    }
    let finalize: unsafe extern "C" fn() =
        unsafe { core::mem::transmute(finalizer) };
    unsafe { finalize() };
    if unsafe {
        syscall3(
            SYS_WRITE,
            1,
            EXIT_GROUP_ARMED.as_ptr() as usize,
            EXIT_GROUP_ARMED.len(),
        )
    } != EXIT_GROUP_ARMED.len() as isize
    {
        fail();
    }
    let _ = unsafe { syscall1(SYS_EXIT_GROUP, 0) };
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    fail()
}
