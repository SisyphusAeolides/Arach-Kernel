#!/usr/bin/env python3
from pathlib import Path

path = Path("src/syscalls.rs")
text = path.read_text(encoding="utf-8")

marker = '''#[cfg(target_os = "none")]
fn linux_poll(arguments: [u64; 6]) -> isize {'''
if text.count(marker) != 1:
    raise SystemExit(f"unexpected linux_poll marker count: {text.count(marker)}")
if "fn linux_descriptor_revents(" in text:
    raise SystemExit("linux_descriptor_revents is already present")

helper = '''#[cfg(target_os = "none")]
fn linux_descriptor_revents(
    owner: crate::process::lifecycle::ProcessHandle,
    fd: i32,
    requested: u16,
) -> u16 {
    if fd < 0 {
        return 0;
    }
    let Ok(fd) = u32::try_from(fd) else {
        return LINUX_POLLNVAL;
    };
    let ready = if let Ok(ready) = crate::linux_file::readiness(owner, fd) {
        ready
    } else if let Ok(ready) = crate::linux_eventfd::readiness(owner.pid, fd) {
        ready
    } else if let Ok(ready) = crate::linux_timerfd::readiness(
        owner.pid,
        fd,
        crate::interrupts::monotonic_nanoseconds(),
    ) {
        ready
    } else if let Ok(ready) = crate::linux_epoll::readiness(owner.pid, fd) {
        ready
    } else {
        return LINUX_POLLNVAL;
    };
    let mut revents = (ready as u16) & requested;
    revents |= (ready as u16) & (LINUX_POLLERR | LINUX_POLLHUP);
    revents
}

'''
text = text.replace(marker, helper + marker)

old_owner = '''    let owner = crate::process::lifecycle::current_pid();
    let mut ready_count: isize = 0;
    for index in 0..nfds {'''
new_owner = '''    let owner = match current_akashic_owner() {
        Ok(owner) => owner,
        Err(error) => return error,
    };
    let mut ready_count: isize = 0;
    for index in 0..nfds {'''
if text.count(old_owner) != 1:
    raise SystemExit(f"unexpected linux_poll owner marker count: {text.count(old_owner)}")
text = text.replace(old_owner, new_owner)

path.write_text(text, encoding="utf-8")
