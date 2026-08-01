#!/usr/bin/env python3
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new)


lib_path = Path("src/lib.rs")
lib = lib_path.read_text(encoding="utf-8")
lib = replace_once(
    lib,
    "pub mod linux_file;\npub mod linux_timerfd;",
    "pub mod linux_file;\npub mod linux_thread;\npub mod linux_timerfd;",
    "Linux thread module export",
)
lib_path.write_text(lib, encoding="utf-8")

syscalls_path = Path("src/syscalls.rs")
syscalls = syscalls_path.read_text(encoding="utf-8")
syscalls = replace_once(
    syscalls,
    '''        Some(crate::process::abi::LinuxSyscall::Gettid) => {
            crate::process::lifecycle::current_pid() as isize
        }
        Some(crate::process::abi::LinuxSyscall::Getppid) => {''',
    '''        Some(crate::process::abi::LinuxSyscall::Gettid) => {
            crate::process::lifecycle::current_pid() as isize
        }
        Some(crate::process::abi::LinuxSyscall::SetTidAddress) => {
            linux_set_tid_address(arguments)
        }
        Some(crate::process::abi::LinuxSyscall::Getppid) => {''',
    "set_tid_address dispatch",
)

handler = '''#[cfg(target_os = "none")]
fn linux_set_tid_address(arguments: [u64; 6]) -> isize {
    let owner = match current_akashic_owner() {
        Ok(owner) => owner,
        Err(error) => return error,
    };
    match crate::linux_thread::set_tid_address(owner, arguments[0]) {
        Ok(tid) => tid as isize,
        Err(crate::linux_thread::ThreadIdentityError::InvalidOwner) => ERROR_PERMISSION_DENIED,
        Err(crate::linux_thread::ThreadIdentityError::InvalidAddress) => ERROR_INVALID_ARGUMENT,
        Err(crate::linux_thread::ThreadIdentityError::Capacity) => ERROR_TRY_AGAIN,
    }
}

'''
marker = '''#[cfg(target_os = "none")]
fn linux_eventfd2(arguments: [u64; 6]) -> isize {'''
syscalls = replace_once(syscalls, marker, handler + marker, "set_tid_address handler")

syscalls = replace_once(
    syscalls,
    '''    let exiting = match crate::process::lifecycle::current_handle() {
        Some(handle) => handle,
        None => crate::arch::x86_64::halt(),
    };
    let _ = crate::linux_file::close_all(exiting);''',
    '''    let exiting = match crate::process::lifecycle::current_handle() {
        Some(handle) => handle,
        None => crate::arch::x86_64::halt(),
    };
    if let Some(clear_child_tid) = crate::linux_thread::take_clear_child_tid(exiting) {
        let _ = copy_value_to_user(clear_child_tid, &0_u32);
    }
    let _ = crate::linux_file::close_all(exiting);''',
    "clear_child_tid exit handling",
)
syscalls_path.write_text(syscalls, encoding="utf-8")
