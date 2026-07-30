#![no_main]
#![no_std]

use core::panic::PanicInfo;

const PASS: &[u8] = b"ARACH_C0_RING3_SYSCALL_PASS\n";
const PANIC: &[u8] = b"ARACH_C0_RING3_PANIC\n";

#[global_allocator]
static HEAP: slope::memory::GlobalSlabHeap = slope::memory::GlobalSlabHeap::new();

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    HEAP.init();
    let _ = slope::io::write(1, PASS);
    let _ = slope::process::request_exit(0);
    loop {
        let _ = slope::process::yield_now();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    let _ = slope::io::write(2, PANIC);
    let _ = slope::process::request_exit(127);
    loop {
        let _ = slope::process::yield_now();
    }
}
