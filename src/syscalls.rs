#[cfg(target_os = "none")]
use core::sync::atomic::AtomicBool;
#[cfg(target_os = "none")]
use core::sync::atomic::AtomicU32;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
pub mod spectral_router;
#[cfg(target_os = "none")]
use crate::arch::x86_64::{active_page_table_root, cpu_local, current_hardware_thread_id};
#[cfg(target_os = "none")]
use crate::mmio::{EARLY_MAPPED_PHYSICAL_LIMIT, direct_map_address};
use crate::process::context::{AuthorizedUserReturn, ContextError};
use crate::process::lifecycle::ScheduledProcess;
#[cfg(target_os = "none")]
use crate::process::{lifecycle::LifecycleError, preemption};
#[cfg(target_os = "none")]
use crate::serial::SerialPort;
#[cfg(target_os = "none")]
use crate::sync::SpinLock;

use aether::grimoire;

const ERROR_BAD_FILE_DESCRIPTOR: isize = -9;
#[cfg(target_os = "none")]
const ERROR_OPERATION_NOT_PERMITTED: isize = -1;
#[cfg(any(target_os = "none", test))]
const ERROR_NO_ENTRY: isize = -2;
#[cfg(any(target_os = "none", test))]
const ERROR_IO: isize = -5;
#[cfg(any(target_os = "none", test))]
const ERROR_PERMISSION_DENIED: isize = -13;
#[cfg(any(target_os = "none", test))]
const ERROR_BUSY: isize = -16;
#[cfg(any(target_os = "none", test))]
const ERROR_ALREADY_EXISTS: isize = -17;
#[cfg(any(target_os = "none", test))]
const ERROR_NOT_DIRECTORY: isize = -20;
#[cfg(any(target_os = "none", test))]
const ERROR_IS_DIRECTORY: isize = -21;
#[cfg(any(target_os = "none", test))]
const ERROR_FILE_TOO_LARGE: isize = -27;
#[cfg(any(target_os = "none", test))]
const ERROR_NO_SPACE: isize = -28;
#[cfg(any(target_os = "none", test))]
const ERROR_DIRECTORY_NOT_EMPTY: isize = -39;
#[cfg(any(target_os = "none", test))]
const ERROR_NOT_SUPPORTED: isize = -95;
#[cfg(target_os = "none")]
const ERROR_TRY_AGAIN: isize = -11;
#[cfg(target_os = "none")]
const ERROR_BAD_ADDRESS: isize = -14;
const ERROR_INVALID_ARGUMENT: isize = -22;
const ERROR_NOT_IMPLEMENTED: isize = -38;
#[cfg(target_os = "none")]
const ERROR_TOO_MANY_OPEN_FILES: isize = -24;
#[cfg(target_os = "none")]
const ERROR_NAME_TOO_LONG: isize = -36;
#[cfg(target_os = "none")]
const ERROR_OUT_OF_MEMORY: isize = -12;
#[cfg(any(target_os = "none", test))]
const USER_ADDRESS_MINIMUM: u64 = 0x1000;
#[cfg(any(target_os = "none", test))]
const USER_ADDRESS_LIMIT: u64 = 0x0000_8000_0000_0000;
#[cfg(any(target_os = "none", test))]
const PAGE_SIZE: usize = 4096;
#[cfg(any(target_os = "none", test))]
const PAGE_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
#[cfg(any(target_os = "none", test))]
const ENTRY_PRESENT: u64 = 1 << 0;
#[cfg(any(target_os = "none", test))]
const ENTRY_USER: u64 = 1 << 2;
#[cfg(any(target_os = "none", test))]
const ENTRY_WRITABLE: u64 = 1 << 1;
#[cfg(any(target_os = "none", test))]
const ENTRY_HUGE: u64 = 1 << 7;
#[cfg(target_os = "none")]
const MAXIMUM_WRITE_BYTES: usize = 256;
#[cfg(target_os = "none")]
const MAXIMUM_AKASHIC_IO_BYTES: usize = 4096;
#[cfg(target_os = "none")]
const MAXIMUM_LINUX_POLL_FDS: usize = 64;
#[cfg(target_os = "none")]
const LINUX_POLLERR: u16 = 0x008;
#[cfg(target_os = "none")]
const LINUX_POLLHUP: u16 = 0x010;
#[cfg(target_os = "none")]
const LINUX_POLLNVAL: u16 = 0x020;
#[cfg(target_os = "none")]
// Crest's bounded 640×400 BGRA frame fits beneath this fixed one-MiB ceiling.
// The limit remains explicit so an untrusted caller cannot turn present into
// an unbounded kernel copy.
const MAXIMUM_CREST_PRESENT_BYTES: usize = 1024 * 1024;
#[cfg(target_os = "none")]
const LINUX_AT_FDCWD: i64 = -100;
#[cfg(target_os = "none")]
const LINUX_AT_REMOVEDIR: u32 = 0x200;
#[cfg(target_os = "none")]
const COM1: u16 = 0x3f8;

#[cfg(any(target_os = "none", test))]
const UTS_FIELD_BYTES: usize = 65;

#[cfg(any(target_os = "none", test))]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AkashicRawStat {
    size_bytes: u64,
    created_ticks: u64,
    modified_ticks: u64,
    flags: u32,
    kind: u8,
    reserved: [u8; 3],
}

#[cfg(any(target_os = "none", test))]
impl From<crate::akashic_vfs::Stat> for AkashicRawStat {
    fn from(value: crate::akashic_vfs::Stat) -> Self {
        Self {
            size_bytes: value.size_bytes,
            created_ticks: value.created_ticks,
            modified_ticks: value.modified_ticks,
            flags: value.flags,
            kind: value.kind as u8,
            reserved: [0; 3],
        }
    }
}

#[cfg(any(target_os = "none", test))]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AkashicRawDirent {
    name: [u8; crate::akashic_vfs::MAXIMUM_PATH_BYTES],
    name_len: u8,
    kind: u8,
    reserved: [u8; 6],
}

#[cfg(any(target_os = "none", test))]
impl From<crate::akashic_vfs::Dirent> for AkashicRawDirent {
    fn from(value: crate::akashic_vfs::Dirent) -> Self {
        Self {
            name: value.name,
            name_len: value.name_len,
            kind: value.kind as u8,
            reserved: [0; 6],
        }
    }
}

/// Linux's fixed-size `struct timespec` wire layout.  Keeping this separate
/// from any Rust time type makes the copy-to-user boundary explicit.
#[cfg(any(target_os = "none", test))]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LinuxTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

/// Linux `struct itimerspec`: two adjacent `struct timespec` values.
#[cfg(any(target_os = "none", test))]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LinuxItimerspec {
    it_interval: LinuxTimespec,
    it_value: LinuxTimespec,
}

/// Linux's fixed-size `struct utsname` wire layout (six 65-byte fields).
/// Values are intentionally compile-time, bounded identity data until the
/// device tree and kernel-release providers are available to userspace.
#[cfg(any(target_os = "none", test))]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LinuxUtsName {
    sysname: [u8; UTS_FIELD_BYTES],
    nodename: [u8; UTS_FIELD_BYTES],
    release: [u8; UTS_FIELD_BYTES],
    version: [u8; UTS_FIELD_BYTES],
    machine: [u8; UTS_FIELD_BYTES],
    domainname: [u8; UTS_FIELD_BYTES],
}

#[cfg(any(target_os = "none", test))]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LinuxStat {
    st_dev: u64,
    st_ino: u64,
    st_nlink: u64,
    st_mode: u32,
    st_uid: u32,
    st_gid: u32,
    pad0: u32,
    st_rdev: u64,
    st_size: i64,
    st_blksize: i64,
    st_blocks: i64,
    st_atime: i64,
    st_atime_nsec: i64,
    st_mtime: i64,
    st_mtime_nsec: i64,
    st_ctime: i64,
    st_ctime_nsec: i64,
    unused: [i64; 3],
}

static YIELD_HITS: AtomicUsize = AtomicUsize::new(0);
static LAST_YIELD_HINT: AtomicU64 = AtomicU64::new(0);
static WRITE_HITS: AtomicUsize = AtomicUsize::new(0);
static EXIT_REQUESTS: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "none")]
static CREST_POINTER_DELIVERY_REPORTED: AtomicBool = AtomicBool::new(false);
#[cfg(target_os = "none")]
static CREST_PRESENT_STAGING: SpinLock<[u8; MAXIMUM_CREST_PRESENT_BYTES]> =
    SpinLock::new([0; MAXIMUM_CREST_PRESENT_BYTES]);
#[cfg(target_os = "none")]
static AKASHIC_IO_STAGING: SpinLock<[u8; MAXIMUM_AKASHIC_IO_BYTES]> =
    SpinLock::new([0; MAXIMUM_AKASHIC_IO_BYTES]);

/// The syscall entry frame combines the complete user register image with the
/// generation and epoch authority selected by the lifecycle scheduler.
pub type SyscallFrame = AuthorizedUserReturn;

/// Replaces a syscall return frame with a lifecycle-selected process. The
/// caller must activate the returned CR3 and kernel stack before returning to
/// user mode.
pub fn install_scheduled_return(
    frame: &mut SyscallFrame,
    scheduled: ScheduledProcess,
) -> Result<AuthorizedUserReturn, ContextError> {
    let authority = scheduled.authorized_return();
    authority.validate()?;
    *frame = authority;
    Ok(authority)
}

pub fn dispatch(number: usize, arguments: [usize; 6]) -> isize {
    match number {
        grimoire::SYS_YIELD => 0,
        grimoire::SYS_WRITE if arguments[0] != 1 => ERROR_BAD_FILE_DESCRIPTOR,
        grimoire::SYS_WRITE => ERROR_NOT_IMPLEMENTED,
        // Host dispatch cannot own a real process address space or switch
        // privilege levels. Process lifecycle syscalls remain unavailable in
        // this host-only scalar entry point.
        grimoire::SYS_EXIT | grimoire::SYS_SPAWN | grimoire::SYS_WAIT => ERROR_NOT_IMPLEMENTED,
        grimoire::SYS_NEXUS_ENTANGLE | grimoire::SYS_NEXUS_STATS | grimoire::SYS_NEXUS_POLICY => {
            dispatch_scalar_nexus(number, arguments.map(|value| value as u64))
        }
        _ => ERROR_NOT_IMPLEMENTED,
    }
}

pub fn yield_hits() -> usize {
    YIELD_HITS.load(Ordering::Acquire)
}

pub fn last_yield_hint() -> u64 {
    LAST_YIELD_HINT.load(Ordering::Acquire)
}

pub fn write_hits() -> usize {
    WRITE_HITS.load(Ordering::Acquire)
}

pub fn exit_requests() -> usize {
    EXIT_REQUESTS.load(Ordering::Acquire)
}

fn dispatch_scalar_nexus(number: usize, arguments: [u64; 6]) -> isize {
    use aether::nexus_wire::{NexusCommand, NexusOpcode, NexusStatus};

    let (opcode, command_arguments, capability, sequence) = match number {
        grimoire::SYS_NEXUS_ENTANGLE => (
            NexusOpcode::Entangle,
            [arguments[0], arguments[1], arguments[2], arguments[3]],
            arguments[4],
            arguments[5],
        ),
        grimoire::SYS_NEXUS_STATS => (NexusOpcode::QueryStats, [0; 4], arguments[0], arguments[1]),
        grimoire::SYS_NEXUS_POLICY => {
            let opcode = match arguments[0] {
                0 => NexusOpcode::SetCollapseThreshold,
                1 => NexusOpcode::SetPriorityMass,
                2 => NexusOpcode::OfferKairos,
                _ => return ERROR_INVALID_ARGUMENT,
            };
            (opcode, [arguments[1], 0, 0, 0], arguments[2], arguments[3])
        }
        _ => return ERROR_NOT_IMPLEMENTED,
    };

    if capability == 0 || sequence == 0 {
        return ERROR_INVALID_ARGUMENT;
    }

    let command = NexusCommand::new(opcode, sequence, capability, command_arguments);
    let reply = crate::nexus_runtime::control(
        &command,
        <crate::arch::Active as crate::arch::Architecture>::counter_sample(),
    );

    let status = match reply.validate(sequence) {
        Ok(status) => status,
        Err(_) => return -74,
    };

    match status {
        NexusStatus::Ok => isize::try_from(reply.values[0]).unwrap_or(isize::MAX),
        NexusStatus::BadFrame => -74,
        NexusStatus::Denied => -13,
        NexusStatus::Expired => -62,
        NexusStatus::InvalidArgument => -22,
        NexusStatus::Capacity => -28,
        NexusStatus::ThermalThrottle => -11,
        NexusStatus::NotReady => -19,
        NexusStatus::InternalFault => -5,
    }
}

#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
extern "C" fn arach_syscall_dispatch(frame: *mut SyscallFrame) {
    let Some(frame) = (unsafe { frame.as_mut() }) else {
        crate::arch::x86_64::halt();
    };
    if validate_active_machine_entry().is_err() {
        crate::arch::x86_64::halt();
    }
    if frame.dispatch.user.validate().is_err() {
        crate::arch::x86_64::halt();
    }

    let number = frame.dispatch.user.rax as usize;
    let arguments = frame.dispatch.user.syscall_arguments();
    // A Linux process has a distinct syscall-number personality. Until the
    // corresponding Linux implementations are admitted, fail closed with
    // ENOSYS rather than letting a Linux number reach the native Aether table
    // (where, for example, Linux `pread64` would otherwise be interpreted as
    // Arach `yield`).
    let scheduled = if crate::process::lifecycle::current_execution_abi().is_linux() {
        match crate::process::abi::LinuxSyscall::from_number(number) {
            Some(crate::process::abi::LinuxSyscall::Exit) => {
                if crate::process::lifecycle::current_is_thread_group_leader()
                    && crate::process::lifecycle::current_thread_group_member_count() != 1
                {
                    resume_linux_result(frame.dispatch.user, ERROR_NOT_IMPLEMENTED)
                } else {
                    schedule_exit_return(arguments[0] as isize)
                }
            }
            Some(crate::process::abi::LinuxSyscall::ExitGroup) => {
                if crate::process::lifecycle::current_thread_group_member_count() != 1 {
                    resume_linux_result(frame.dispatch.user, ERROR_NOT_IMPLEMENTED)
                } else {
                    schedule_exit_return(arguments[0] as isize)
                }
            }
            Some(crate::process::abi::LinuxSyscall::Clone) => {
                schedule_linux_clone_return(frame.dispatch.user, arguments)
            }
            Some(crate::process::abi::LinuxSyscall::Futex) => {
                schedule_linux_futex_return(frame.dispatch.user, arguments)
            }
            _ => {
                let mut saved = frame.dispatch.user;
                saved.set_syscall_result(dispatch_linux_syscall(number, arguments));
                match crate::process::lifecycle::resume_current(saved) {
                    Ok(scheduled) => scheduled,
                    Err(_) => crate::arch::x86_64::halt(),
                }
            }
        }
    } else {
        match number {
            grimoire::SYS_YIELD => {
                LAST_YIELD_HINT.store(arguments[0], Ordering::Release);
                YIELD_HITS.fetch_add(1, Ordering::AcqRel);
                let scheduled = if let Some(ticket) = preemption::take_at_safe_point() {
                    let mut saved = frame.dispatch.user;
                    saved.set_syscall_result(0);
                    match crate::process::lifecycle::schedule_preempt(saved, ticket.authority) {
                        Ok(scheduled) => {
                            report_timer_preemption_service(ticket);
                            Ok(scheduled)
                        }
                        Err(LifecycleError::StalePreemptionAuthority) => {
                            preemption::record_stale();
                            crate::process::lifecycle::schedule_yield(saved)
                        }
                        Err(error) => Err(error),
                    }
                } else {
                    crate::process::lifecycle::schedule_yield(frame.dispatch.user)
                };
                match scheduled {
                    Ok(scheduled) => scheduled,
                    Err(_) => crate::arch::x86_64::halt(),
                }
            }
            grimoire::SYS_EXIT => schedule_exit_return(arguments[0] as isize),
            _ => {
                let result = match number {
                    grimoire::SYS_WRITE => write_from_user(arguments),
                    grimoire::SYS_AOPEN => akashic_open_from_user(arguments),
                    grimoire::SYS_AREAD => akashic_read_to_user(arguments),
                    grimoire::SYS_AWRITE => akashic_write_from_user(arguments),
                    grimoire::SYS_ACLOSE => akashic_close(arguments),
                    grimoire::SYS_ASEEK => akashic_seek(arguments),
                    grimoire::SYS_AMKDIR => akashic_mkdir_from_user(arguments),
                    grimoire::SYS_AUNLINK => akashic_unlink_from_user(arguments),
                    grimoire::SYS_ARENAME => akashic_rename_from_user(arguments),
                    grimoire::SYS_AREADDIR => akashic_readdir_to_user(arguments),
                    grimoire::SYS_ASTAT => akashic_stat_to_user(arguments),
                    grimoire::SYS_SPAWN => spawn_measured_service(arguments),
                    grimoire::SYS_WAIT => wait_for_child_nohang(arguments),
                    grimoire::SYS_AEGIS_STATUS => aegis_status_for_current_crest(arguments),
                    grimoire::SYS_DISP_QUERY => kairos_query_to_user(arguments),
                    grimoire::SYS_DISP_LEASE => kairos_abi_to_user(arguments),
                    grimoire::SYS_DISP_PRESENT => present_current_crest(arguments),
                    grimoire::SYS_INPUT_NEXT => next_pointer_for_current_crest(arguments),
                    grimoire::SYS_INPUT_KEY_NEXT => next_key_for_current_crest(arguments),
                    grimoire::SYS_NEXUS_TELEMETRY => nexus_telemetry_to_user(arguments),
                    grimoire::SYS_NEXUS_CONTROL => nexus_control_from_user(arguments),
                    grimoire::SYS_NEXUS_ENTANGLE
                    | grimoire::SYS_NEXUS_STATS
                    | grimoire::SYS_NEXUS_POLICY => dispatch_scalar_nexus(number, arguments),
                    _ => ERROR_NOT_IMPLEMENTED,
                };
                let mut saved = frame.dispatch.user;
                saved.set_syscall_result(result);
                let scheduled = if let Some(ticket) = preemption::take_at_safe_point() {
                    match crate::process::lifecycle::schedule_preempt(saved, ticket.authority) {
                        Ok(scheduled) => {
                            report_timer_preemption_service(ticket);
                            Ok(scheduled)
                        }
                        Err(LifecycleError::StalePreemptionAuthority) => {
                            preemption::record_stale();
                            crate::process::lifecycle::resume_current(saved)
                        }
                        Err(error) => Err(error),
                    }
                } else {
                    crate::process::lifecycle::resume_current(saved)
                };
                match scheduled {
                    Ok(scheduled) => scheduled,
                    Err(_) => crate::arch::x86_64::halt(),
                }
            }
        }
    };
    // Timer IRQ work is consumed outside interrupt context. One pass keeps
    // syscall-exit latency bounded while ensuring periodic requests have a
    // production safe-point caller.
    let _ = crate::nexus_deferred::run_deferred(1);
    if install_scheduled_return(frame, scheduled).is_err() {
        crate::arch::x86_64::halt();
    }
}

#[cfg(target_os = "none")]
fn schedule_exit_return(exit_code: isize) -> crate::process::lifecycle::ScheduledProcess {
    EXIT_REQUESTS.fetch_add(1, Ordering::AcqRel);
    preemption::retire_superseded();
    let exiting = match crate::process::lifecycle::current_handle() {
        Some(handle) => handle,
        None => crate::arch::x86_64::halt(),
    };
    let _ = crate::linux_futex::cancel_wait(exiting);
    recover_exiting_robust_list(exiting);
    if let Some(clear_child_tid) = crate::linux_thread::take_clear_child_tid(exiting) {
        if copy_value_to_user(clear_child_tid, &0_u32).is_ok() {
            let _ = crate::linux_futex::wake_current(clear_child_tid, 1);
        }
    }
    if !crate::process::lifecycle::current_is_thread_group_leader() {
        let decision = match crate::process::lifecycle::schedule_thread_exit() {
            Ok(decision) => decision,
            Err(_) => crate::arch::x86_64::halt(),
        };
        return complete_schedule_decision(decision);
    }
    let process_owner = crate::process::lifecycle::current_thread_group_handle().unwrap_or(exiting);
    let _ = crate::linux_file::close_all(process_owner);
    let _ = crate::akashic_vfs::close_all(process_owner);
    // Linux descriptors are process-owned. Reclaim the bounded eventfd set
    // before publishing the zombie transition so an exiting service cannot
    // leak wake objects into a later PID generation.
    let _ = crate::linux_epoll::close_all(process_owner.pid);
    let _ = crate::linux_timerfd::close_all(process_owner.pid);
    let _ = crate::linux_eventfd::close_all(process_owner.pid);
    let decision = match crate::process::lifecycle::schedule_exit(exit_code) {
        Ok(decision) => decision,
        Err(_) => crate::arch::x86_64::halt(),
    };
    match crate::process::service_registry::take_exited_service(exiting) {
        Ok(Some(image)) => {
            if crate::process::runtime::defer_reap(image).is_err() {
                crate::arch::x86_64::halt();
            }
        }
        Ok(None) => {}
        Err(_) => crate::arch::x86_64::halt(),
    }
    complete_schedule_decision(decision)
}

#[cfg(target_os = "none")]
fn schedule_linux_clone_return(
    saved: crate::process::context::SavedUserContext,
    arguments: [u64; 6],
) -> crate::process::lifecycle::ScheduledProcess {
    const CLONE_VM: u64 = 0x0000_0100;
    const CLONE_FS: u64 = 0x0000_0200;
    const CLONE_FILES: u64 = 0x0000_0400;
    const CLONE_SIGHAND: u64 = 0x0000_0800;
    const CLONE_THREAD: u64 = 0x0001_0000;
    const CLONE_SYSVSEM: u64 = 0x0004_0000;
    const CLONE_SETTLS: u64 = 0x0008_0000;
    const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
    const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
    const CLONE_CHILD_SETTID: u64 = 0x0100_0000;
    const EXIT_SIGNAL_MASK: u64 = 0xff;
    const REQUIRED: u64 =
        CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;
    const OPTIONAL: u64 =
        CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID;

    let flags = arguments[0];
    if flags & EXIT_SIGNAL_MASK != 0
        || flags & REQUIRED != REQUIRED
        || flags & !(REQUIRED | OPTIONAL) != 0
    {
        return resume_linux_result(saved, ERROR_INVALID_ARGUMENT);
    }
    let child_stack = arguments[1];
    if !crate::process::context::valid_user_address(child_stack) {
        return resume_linux_result(saved, ERROR_INVALID_ARGUMENT);
    }
    let child_fs_base = if flags & CLONE_SETTLS != 0 {
        arguments[4]
    } else {
        match crate::process::lifecycle::current_fs_base() {
            Ok(value) => value,
            Err(_) => return resume_linux_result(saved, ERROR_PERMISSION_DENIED),
        }
    };
    if !crate::process::context::valid_user_tls_base(child_fs_base) {
        return resume_linux_result(saved, ERROR_INVALID_ARGUMENT);
    }
    if flags & CLONE_PARENT_SETTID != 0
        && validate_user_write_range(arguments[2], core::mem::size_of::<u32>()).is_err()
        || flags & (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID) != 0
            && validate_user_write_range(arguments[3], core::mem::size_of::<u32>()).is_err()
    {
        return resume_linux_result(saved, ERROR_BAD_ADDRESS);
    }

    let (child, parent_return) =
        match crate::process::lifecycle::clone_current_thread(saved, child_stack, child_fs_base) {
            Ok(result) => result,
            Err(crate::process::lifecycle::LifecycleError::Capacity) => {
                return resume_linux_result(saved, ERROR_TRY_AGAIN);
            }
            Err(_) => return resume_linux_result(saved, ERROR_INVALID_ARGUMENT),
        };

    let mut publication_failed = false;
    if flags & CLONE_CHILD_CLEARTID != 0
        && crate::linux_thread::set_tid_address(child, arguments[3]).is_err()
    {
        publication_failed = true;
    }
    if !publication_failed
        && flags & CLONE_PARENT_SETTID != 0
        && copy_value_to_user(arguments[2], &child.pid).is_err()
    {
        publication_failed = true;
    }
    if !publication_failed
        && flags & CLONE_CHILD_SETTID != 0
        && copy_value_to_user(arguments[3], &child.pid).is_err()
    {
        publication_failed = true;
    }
    if publication_failed {
        let _ = crate::linux_thread::take_clear_child_tid(child);
        if crate::process::lifecycle::discard_runnable_thread(child).is_err() {
            crate::arch::x86_64::halt();
        }
        return resume_linux_result(saved, ERROR_BAD_ADDRESS);
    }
    parent_return
}

#[cfg(target_os = "none")]
fn complete_schedule_decision(
    decision: crate::process::lifecycle::ScheduleDecision,
) -> crate::process::lifecycle::ScheduledProcess {
    match decision {
        crate::process::lifecycle::ScheduleDecision::User(scheduled) => scheduled,
        crate::process::lifecycle::ScheduleDecision::Pid0(mut idle) => loop {
            // SAFETY: lifecycle selected PID0 at a serialized syscall
            // boundary. The immutable kernel root remains reachable through
            // every retained user hierarchy, and any exited image can be
            // reclaimed only after this root switch.
            if unsafe { crate::process::runtime::enter_kernel_idle_and_reap() }.is_err() {
                crate::arch::x86_64::halt();
            }
            // SAFETY: SYSCALL entered with interrupts masked and the inherited
            // kernel mapping retains this frame. STI's one-instruction shadow
            // makes HLT atomic with respect to maskable wakeups.
            unsafe {
                core::arch::asm!("sti", "hlt", "cli", options(nostack));
            }
            match crate::process::lifecycle::schedule_from_pid0(idle) {
                Ok(crate::process::lifecycle::ScheduleDecision::User(scheduled)) => {
                    break scheduled;
                }
                Ok(crate::process::lifecycle::ScheduleDecision::Pid0(next)) => idle = next,
                Err(_) => crate::arch::x86_64::halt(),
            }
        },
    }
}

#[cfg(target_os = "none")]
fn resume_linux_result(
    mut saved: crate::process::context::SavedUserContext,
    result: isize,
) -> crate::process::lifecycle::ScheduledProcess {
    saved.set_syscall_result(result);
    match crate::process::lifecycle::resume_current(saved) {
        Ok(scheduled) => scheduled,
        Err(_) => crate::arch::x86_64::halt(),
    }
}

#[cfg(target_os = "none")]
fn schedule_linux_futex_return(
    mut saved: crate::process::context::SavedUserContext,
    arguments: [u64; 6],
) -> crate::process::lifecycle::ScheduledProcess {
    const FUTEX_WAIT: u32 = 0;
    const FUTEX_WAKE: u32 = 1;
    const FUTEX_PRIVATE_FLAG: u32 = 128;
    const FUTEX_COMMAND_MASK: u32 = 127;

    let operation = arguments[1] as u32;
    let command = operation & FUTEX_COMMAND_MASK;
    let flags = operation & !FUTEX_COMMAND_MASK;
    // Shared futex keys require a physical-page or file-backed identity. The
    // current address-space key is exact for private futexes only, so fail
    // closed instead of aliasing unrelated mappings at the same VA.
    if flags != FUTEX_PRIVATE_FLAG {
        return resume_linux_result(saved, ERROR_NOT_IMPLEMENTED);
    }

    match command {
        FUTEX_WAIT => {
            if arguments[3] != 0 {
                // Deadline-driven wakeup is admitted separately once timer
                // expiry can remove the exact queue generation atomically.
                return resume_linux_result(saved, ERROR_NOT_IMPLEMENTED);
            }
            let expected = arguments[2] as u32;
            saved.set_syscall_result(0);
            let waited = crate::linux_futex::wait_current(arguments[0], expected, saved, || {
                let mut encoded = [0_u8; core::mem::size_of::<u32>()];
                copy_from_user(arguments[0], &mut encoded)?;
                Ok::<u32, UserCopyError>(u32::from_ne_bytes(encoded))
            });
            match waited {
                Ok(decision) => complete_schedule_decision(decision),
                Err(crate::linux_futex::FutexWaitError::ValueChanged) => {
                    resume_linux_result(saved, ERROR_TRY_AGAIN)
                }
                Err(crate::linux_futex::FutexWaitError::UserMemory(_)) => {
                    resume_linux_result(saved, ERROR_BAD_ADDRESS)
                }
                Err(crate::linux_futex::FutexWaitError::Queue(
                    crate::linux_futex::FutexQueueError::InvalidAddress,
                )) => resume_linux_result(saved, ERROR_INVALID_ARGUMENT),
                Err(crate::linux_futex::FutexWaitError::Queue(
                    crate::linux_futex::FutexQueueError::InvalidOwner,
                )) => resume_linux_result(saved, -13),
                Err(crate::linux_futex::FutexWaitError::Queue(_))
                | Err(crate::linux_futex::FutexWaitError::Lifecycle(_)) => {
                    resume_linux_result(saved, ERROR_TRY_AGAIN)
                }
            }
        }
        FUTEX_WAKE => {
            let maximum = arguments[2] as i64;
            if maximum < 0 {
                return resume_linux_result(saved, ERROR_INVALID_ARGUMENT);
            }
            let result = match crate::linux_futex::wake_current(arguments[0], maximum as usize) {
                Ok(woken) => isize::try_from(woken).unwrap_or(isize::MAX),
                Err(crate::linux_futex::FutexQueueError::InvalidAddress) => ERROR_INVALID_ARGUMENT,
                Err(crate::linux_futex::FutexQueueError::InvalidOwner) => -13,
                Err(_) => ERROR_TRY_AGAIN,
            };
            resume_linux_result(saved, result)
        }
        _ => resume_linux_result(saved, ERROR_NOT_IMPLEMENTED),
    }
}

#[cfg(target_os = "none")]
fn dispatch_linux_syscall(number: usize, arguments: [u64; 6]) -> isize {
    match crate::process::abi::LinuxSyscall::from_number(number) {
        // The bounded serial write has the same first three scalar arguments
        // on x86-64 Linux and Arach. Eventfd is the first real Linux file
        // descriptor object: it gives libc/COSMIC a wake primitive without
        // claiming that ordinary path/socket descriptors already exist.
        Some(crate::process::abi::LinuxSyscall::Read) => linux_read(arguments),
        Some(crate::process::abi::LinuxSyscall::Write) => linux_write(arguments),
        Some(crate::process::abi::LinuxSyscall::Open) => linux_open(arguments),
        Some(crate::process::abi::LinuxSyscall::Close) => linux_close(arguments),
        Some(crate::process::abi::LinuxSyscall::Stat) => linux_stat(arguments),
        Some(crate::process::abi::LinuxSyscall::Fstat) => linux_fstat(arguments),
        Some(crate::process::abi::LinuxSyscall::Poll) => linux_poll(arguments),
        Some(crate::process::abi::LinuxSyscall::Lseek) => linux_lseek(arguments),
        Some(crate::process::abi::LinuxSyscall::Getpid) => {
            crate::process::lifecycle::current_thread_group() as isize
        }
        Some(crate::process::abi::LinuxSyscall::Gettid) => {
            crate::process::lifecycle::current_pid() as isize
        }
        Some(crate::process::abi::LinuxSyscall::SetTidAddress) => linux_set_tid_address(arguments),
        Some(crate::process::abi::LinuxSyscall::SetRobustList) => linux_set_robust_list(arguments),
        Some(crate::process::abi::LinuxSyscall::GetRobustList) => linux_get_robust_list(arguments),
        Some(crate::process::abi::LinuxSyscall::Getppid) => {
            let Some(handle) = crate::process::lifecycle::current_handle() else {
                return -3;
            };
            crate::process::lifecycle::snapshot_exact(handle)
                .map(|snapshot| snapshot.parent as isize)
                .unwrap_or(-3)
        }
        Some(crate::process::abi::LinuxSyscall::Uname) => linux_uname(arguments),
        Some(crate::process::abi::LinuxSyscall::Getuid)
        | Some(crate::process::abi::LinuxSyscall::Getgid)
        | Some(crate::process::abi::LinuxSyscall::Geteuid)
        | Some(crate::process::abi::LinuxSyscall::Getegid) => {
            // Arach's initial boot image has one authenticated root identity.
            // Returning that identity is useful to libc while account/PAM
            // services are still being brought up; it is not a claim that
            // multi-user credentials are implemented.
            0
        }
        Some(crate::process::abi::LinuxSyscall::ArchPrctl) => linux_arch_prctl(arguments),
        Some(crate::process::abi::LinuxSyscall::ClockGettime) => linux_clock_gettime(arguments),
        Some(crate::process::abi::LinuxSyscall::Mmap) => linux_mmap(arguments),
        Some(crate::process::abi::LinuxSyscall::Munmap) => linux_munmap(arguments),
        Some(crate::process::abi::LinuxSyscall::Brk) => linux_brk(arguments),
        Some(crate::process::abi::LinuxSyscall::Eventfd2) => linux_eventfd2(arguments),
        Some(crate::process::abi::LinuxSyscall::TimerfdCreate) => linux_timerfd_create(arguments),
        Some(crate::process::abi::LinuxSyscall::TimerfdSettime) => linux_timerfd_settime(arguments),
        Some(crate::process::abi::LinuxSyscall::TimerfdGettime) => linux_timerfd_gettime(arguments),
        Some(crate::process::abi::LinuxSyscall::EpollWait) => linux_epoll_wait(arguments),
        Some(crate::process::abi::LinuxSyscall::EpollPwait) => linux_epoll_pwait(arguments),
        Some(crate::process::abi::LinuxSyscall::EpollCreate1) => linux_epoll_create1(arguments),
        Some(crate::process::abi::LinuxSyscall::EpollCtl) => linux_epoll_ctl(arguments),
        Some(crate::process::abi::LinuxSyscall::OpenAt) => linux_openat(arguments),
        Some(crate::process::abi::LinuxSyscall::UnlinkAt) => linux_unlinkat(arguments),
        Some(_) => ERROR_NOT_IMPLEMENTED,
        None => ERROR_NOT_IMPLEMENTED,
    }
}

#[cfg(target_os = "none")]
fn linux_arch_prctl(arguments: [u64; 6]) -> isize {
    const ARCH_SET_FS: u64 = 0x1002;
    const ARCH_GET_FS: u64 = 0x1003;

    match arguments[0] {
        ARCH_SET_FS => {
            if !crate::process::context::valid_user_tls_base(arguments[1]) {
                return ERROR_OPERATION_NOT_PERMITTED;
            }
            crate::process::lifecycle::set_current_fs_base(arguments[1])
                .map(|()| 0)
                .unwrap_or(ERROR_OPERATION_NOT_PERMITTED)
        }
        ARCH_GET_FS => {
            let Ok(fs_base) = crate::process::lifecycle::current_fs_base() else {
                return ERROR_OPERATION_NOT_PERMITTED;
            };
            if copy_value_to_user(arguments[1], &fs_base).is_ok() {
                0
            } else {
                ERROR_BAD_ADDRESS
            }
        }
        _ => ERROR_INVALID_ARGUMENT,
    }
}

#[cfg(target_os = "none")]
fn linux_set_tid_address(arguments: [u64; 6]) -> isize {
    let owner = match crate::process::lifecycle::current_handle() {
        Some(owner) => owner,
        None => return ERROR_PERMISSION_DENIED,
    };
    match crate::linux_thread::set_tid_address(owner, arguments[0]) {
        Ok(tid) => tid as isize,
        Err(crate::linux_thread::ThreadIdentityError::InvalidOwner) => ERROR_PERMISSION_DENIED,
        Err(crate::linux_thread::ThreadIdentityError::InvalidAddress) => ERROR_INVALID_ARGUMENT,
        Err(crate::linux_thread::ThreadIdentityError::Capacity) => ERROR_TRY_AGAIN,
    }
}

#[cfg(target_os = "none")]
fn linux_set_robust_list(arguments: [u64; 6]) -> isize {
    let owner = match crate::process::lifecycle::current_handle() {
        Some(owner) => owner,
        None => return ERROR_PERMISSION_DENIED,
    };
    match crate::linux_robust::set_robust_list(owner, arguments[0], arguments[1]) {
        Ok(()) => 0,
        Err(crate::linux_robust::RobustListError::InvalidOwner) => ERROR_PERMISSION_DENIED,
        Err(crate::linux_robust::RobustListError::InvalidAddress)
        | Err(crate::linux_robust::RobustListError::InvalidLength) => ERROR_INVALID_ARGUMENT,
        Err(crate::linux_robust::RobustListError::Capacity) => ERROR_TRY_AGAIN,
    }
}

#[cfg(target_os = "none")]
fn linux_get_robust_list(arguments: [u64; 6]) -> isize {
    let owner = match crate::process::lifecycle::current_handle() {
        Some(owner) => owner,
        None => return ERROR_PERMISSION_DENIED,
    };
    if arguments[0] != 0 && arguments[0] != owner.pid as u64 {
        return -3;
    }
    if validate_user_write_range(arguments[1], core::mem::size_of::<u64>()).is_err()
        || validate_user_write_range(arguments[2], core::mem::size_of::<u64>()).is_err()
    {
        return ERROR_BAD_ADDRESS;
    }
    let head = crate::linux_robust::robust_list(owner)
        .map(|registration| registration.head)
        .unwrap_or(0);
    let length = crate::linux_robust::ROBUST_LIST_HEAD_BYTES;
    if copy_value_to_user(arguments[1], &head).is_err()
        || copy_value_to_user(arguments[2], &length).is_err()
    {
        ERROR_BAD_ADDRESS
    } else {
        0
    }
}

#[cfg(target_os = "none")]
fn read_user_u64(address: u64) -> Result<u64, UserCopyError> {
    let mut encoded = [0_u8; core::mem::size_of::<u64>()];
    copy_from_user(address, &mut encoded)?;
    Ok(u64::from_ne_bytes(encoded))
}

#[cfg(target_os = "none")]
fn mark_robust_owner_died(
    address: u64,
    owner_tid: u32,
) -> Result<crate::linux_robust::OwnerDeathResult, UserCopyError> {
    if address % core::mem::align_of::<AtomicU32>() as u64 != 0 {
        return Err(UserCopyError::InvalidRange);
    }
    // SAFETY: Exit runs at a serialized syscall boundary while the exiting
    // address space is still active and retained.
    let root = unsafe { active_page_table_root() };
    let physical = translate_user_address_for_write(root, address, read_active_entry)?;
    if physical
        .checked_add(core::mem::size_of::<u32>() as u64)
        .ok_or(UserCopyError::UnmappedPhysicalMemory)?
        > EARLY_MAPPED_PHYSICAL_LIMIT
    {
        return Err(UserCopyError::UnmappedPhysicalMemory);
    }
    let pointer = direct_map_address(physical).ok_or(UserCopyError::UnmappedPhysicalMemory)?
        as *const AtomicU32;
    // SAFETY: The user address and translated physical address are u32
    // aligned, the writable mapping covers the complete word, and its page is
    // retained for this non-preemptible exit operation.
    let word = unsafe { &*pointer };
    let mut observed = word.load(Ordering::Acquire);
    loop {
        let Some(replacement) = crate::linux_robust::owner_died_replacement(observed, owner_tid)
        else {
            return Ok(crate::linux_robust::OwnerDeathResult::default());
        };
        match word.compare_exchange_weak(observed, replacement, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(previous) => {
                let wake_requested = previous & crate::linux_robust::FUTEX_WAITERS != 0;
                if wake_requested {
                    let _ = crate::linux_futex::wake_current(address, 1);
                }
                return Ok(crate::linux_robust::OwnerDeathResult {
                    recovered: true,
                    wake_requested,
                });
            }
            Err(updated) => observed = updated,
        }
    }
}

#[cfg(target_os = "none")]
fn recover_exiting_robust_list(owner: crate::process::lifecycle::ProcessHandle) {
    let Some(registration) = crate::linux_robust::take_robust_list(owner) else {
        return;
    };
    let _ = crate::linux_robust::recover_robust_list(
        registration,
        owner.pid,
        read_user_u64,
        mark_robust_owner_died,
    );
}

#[cfg(target_os = "none")]
fn linux_eventfd2(arguments: [u64; 6]) -> isize {
    let initial = arguments[0];
    let Ok(flags) = u32::try_from(arguments[1]) else {
        return ERROR_INVALID_ARGUMENT;
    };
    let owner = crate::process::lifecycle::current_thread_group();
    if owner == 0 {
        return -13;
    }
    match crate::linux_eventfd::create(owner, initial, flags) {
        Ok(fd) => fd as isize,
        Err(crate::linux_eventfd::EventFdError::InvalidArgument) => ERROR_INVALID_ARGUMENT,
        Err(crate::linux_eventfd::EventFdError::Capacity) => -28,
        Err(_) => -5,
    }
}

#[cfg(any(target_os = "none", test))]
fn timespec_to_nanoseconds(value: LinuxTimespec) -> Option<u64> {
    if value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
        return None;
    }
    let seconds = u64::try_from(value.tv_sec).ok()?;
    let nanoseconds = value.tv_nsec as u64;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
}

#[cfg(any(target_os = "none", test))]
fn nanoseconds_to_timespec(value: u64) -> LinuxTimespec {
    LinuxTimespec {
        tv_sec: (value / 1_000_000_000) as i64,
        tv_nsec: (value % 1_000_000_000) as i64,
    }
}

#[cfg(target_os = "none")]
fn read_itimerspec(source: u64) -> Result<crate::linux_timerfd::TimerSpec, isize> {
    let mut encoded = [0_u8; core::mem::size_of::<LinuxItimerspec>()];
    if copy_from_user(source, &mut encoded).is_err() {
        return Err(ERROR_BAD_ADDRESS);
    }
    // SAFETY: LinuxItimerspec is repr(C), Copy, and the complete byte array
    // was initialized by the bounded user copy above.
    let value = unsafe { core::ptr::read_unaligned(encoded.as_ptr().cast::<LinuxItimerspec>()) };
    let interval_ns = timespec_to_nanoseconds(value.it_interval).ok_or(ERROR_INVALID_ARGUMENT)?;
    let value_ns = timespec_to_nanoseconds(value.it_value).ok_or(ERROR_INVALID_ARGUMENT)?;
    Ok(crate::linux_timerfd::TimerSpec {
        value_ns,
        interval_ns,
    })
}

#[cfg(target_os = "none")]
fn write_itimerspec(destination: u64, value: crate::linux_timerfd::TimerSpec) -> Result<(), isize> {
    let encoded = LinuxItimerspec {
        it_interval: nanoseconds_to_timespec(value.interval_ns),
        it_value: nanoseconds_to_timespec(value.value_ns),
    };
    copy_value_to_user(destination, &encoded).map_err(|_| ERROR_BAD_ADDRESS)
}

#[cfg(target_os = "none")]
fn linux_timerfd_create(arguments: [u64; 6]) -> isize {
    let Ok(clockid) = u32::try_from(arguments[0]) else {
        return ERROR_INVALID_ARGUMENT;
    };
    let Ok(flags) = u32::try_from(arguments[1]) else {
        return ERROR_INVALID_ARGUMENT;
    };
    let owner = crate::process::lifecycle::current_thread_group();
    if owner == 0 {
        return -13;
    }
    match crate::linux_timerfd::create(owner, clockid, flags) {
        Ok(fd) => fd as isize,
        Err(crate::linux_timerfd::TimerFdError::InvalidArgument) => ERROR_INVALID_ARGUMENT,
        Err(crate::linux_timerfd::TimerFdError::Capacity) => -28,
        Err(_) => -5,
    }
}

#[cfg(target_os = "none")]
fn linux_timerfd_settime(arguments: [u64; 6]) -> isize {
    let Ok(fd) = u32::try_from(arguments[0]) else {
        return ERROR_BAD_FILE_DESCRIPTOR;
    };
    let Ok(flags) = u32::try_from(arguments[1]) else {
        return ERROR_INVALID_ARGUMENT;
    };
    let new_value = match read_itimerspec(arguments[2]) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let owner = crate::process::lifecycle::current_thread_group();
    let now = crate::interrupts::monotonic_nanoseconds();
    let old = match crate::linux_timerfd::settime(owner, fd, flags, new_value, now) {
        Ok(value) => value,
        Err(crate::linux_timerfd::TimerFdError::InvalidArgument) => return ERROR_INVALID_ARGUMENT,
        Err(crate::linux_timerfd::TimerFdError::BadFileDescriptor) => {
            return ERROR_BAD_FILE_DESCRIPTOR;
        }
        Err(_) => return -5,
    };
    if arguments[3] != 0 {
        if let Err(error) = write_itimerspec(arguments[3], old) {
            return error;
        }
    }
    0
}

#[cfg(target_os = "none")]
fn linux_timerfd_gettime(arguments: [u64; 6]) -> isize {
    let Ok(fd) = u32::try_from(arguments[0]) else {
        return ERROR_BAD_FILE_DESCRIPTOR;
    };
    let owner = crate::process::lifecycle::current_thread_group();
    let value = match crate::linux_timerfd::gettime(
        owner,
        fd,
        crate::interrupts::monotonic_nanoseconds(),
    ) {
        Ok(value) => value,
        Err(crate::linux_timerfd::TimerFdError::BadFileDescriptor) => {
            return ERROR_BAD_FILE_DESCRIPTOR;
        }
        Err(_) => return -5,
    };
    match write_itimerspec(arguments[1], value) {
        Ok(()) => 0,
        Err(error) => error,
    }
}

#[cfg(target_os = "none")]
fn linux_read(arguments: [u64; 6]) -> isize {
    let Ok(fd) = u32::try_from(arguments[0]) else {
        return ERROR_BAD_FILE_DESCRIPTOR;
    };
    let owner_handle = match current_akashic_owner() {
        Ok(owner) => owner,
        Err(error) => return error,
    };
    let length = core::cmp::min(arguments[2], MAXIMUM_AKASHIC_IO_BYTES as u64) as usize;
    {
        let mut staging = AKASHIC_IO_STAGING.lock();
        match crate::linux_file::read(owner_handle, fd, &mut staging[..length]) {
            Ok(copied) => {
                return if copy_to_user(arguments[1], &staging[..copied]).is_ok() {
                    copied as isize
                } else {
                    ERROR_BAD_ADDRESS
                };
            }
            Err(crate::linux_file::FileError::BadFileDescriptor) => {}
            Err(error) => return map_linux_file_error(error),
        }
    }

    if arguments[2] != core::mem::size_of::<u64>() as u64 {
        return ERROR_INVALID_ARGUMENT;
    }
    let owner = owner_handle.pid;
    match crate::linux_eventfd::read(owner, fd) {
        Ok(value) => {
            if copy_value_to_user(arguments[1], &value).is_err() {
                ERROR_BAD_ADDRESS
            } else {
                core::mem::size_of::<u64>() as isize
            }
        }
        Err(crate::linux_eventfd::EventFdError::WouldBlock) => ERROR_TRY_AGAIN,
        Err(crate::linux_eventfd::EventFdError::BadFileDescriptor) => {
            match crate::linux_timerfd::read(owner, fd, crate::interrupts::monotonic_nanoseconds())
            {
                Ok(value) => {
                    if copy_value_to_user(arguments[1], &value).is_err() {
                        ERROR_BAD_ADDRESS
                    } else {
                        core::mem::size_of::<u64>() as isize
                    }
                }
                Err(crate::linux_timerfd::TimerFdError::WouldBlock) => ERROR_TRY_AGAIN,
                Err(crate::linux_timerfd::TimerFdError::BadFileDescriptor) => {
                    ERROR_BAD_FILE_DESCRIPTOR
                }
                Err(_) => ERROR_IO,
            }
        }
        Err(_) => ERROR_IO,
    }
}

#[cfg(target_os = "none")]
fn linux_write(arguments: [u64; 6]) -> isize {
    if arguments[0] == 1 || arguments[0] == 2 {
        return write_from_user(arguments);
    }
    let Ok(fd) = u32::try_from(arguments[0]) else {
        return ERROR_BAD_FILE_DESCRIPTOR;
    };
    let owner_handle = match current_akashic_owner() {
        Ok(owner) => owner,
        Err(error) => return error,
    };
    if crate::linux_file::is_open(owner_handle, fd) {
        let length = core::cmp::min(arguments[2], MAXIMUM_AKASHIC_IO_BYTES as u64) as usize;
        let mut staging = AKASHIC_IO_STAGING.lock();
        if copy_from_user(arguments[1], &mut staging[..length]).is_err() {
            return ERROR_BAD_ADDRESS;
        }
        return match crate::linux_file::write(
            owner_handle,
            fd,
            &staging[..length],
            crate::interrupts::monotonic_nanoseconds(),
        ) {
            Ok(written) => written as isize,
            Err(error) => map_linux_file_error(error),
        };
    }

    if arguments[2] != core::mem::size_of::<u64>() as u64 {
        return ERROR_INVALID_ARGUMENT;
    }
    let mut bytes = [0_u8; core::mem::size_of::<u64>()];
    if copy_from_user(arguments[1], &mut bytes).is_err() {
        return ERROR_BAD_ADDRESS;
    }
    let value = u64::from_ne_bytes(bytes);
    match crate::linux_eventfd::write(owner_handle.pid, fd, value) {
        Ok(()) => core::mem::size_of::<u64>() as isize,
        Err(crate::linux_eventfd::EventFdError::InvalidArgument) => ERROR_INVALID_ARGUMENT,
        Err(crate::linux_eventfd::EventFdError::Overflow) => ERROR_TRY_AGAIN,
        Err(crate::linux_eventfd::EventFdError::BadFileDescriptor) => ERROR_BAD_FILE_DESCRIPTOR,
        Err(_) => ERROR_IO,
    }
}

#[cfg(target_os = "none")]
fn linux_close(arguments: [u64; 6]) -> isize {
    let Ok(fd) = u32::try_from(arguments[0]) else {
        return ERROR_BAD_FILE_DESCRIPTOR;
    };
    let owner_handle = match current_akashic_owner() {
        Ok(owner) => owner,
        Err(error) => return error,
    };
    match crate::linux_file::close(owner_handle, fd) {
        Ok(()) => return 0,
        Err(crate::linux_file::FileError::BadFileDescriptor) => {}
        Err(error) => return map_linux_file_error(error),
    }

    let owner = owner_handle.pid;
    match crate::linux_eventfd::close(owner, fd) {
        Ok(()) => 0,
        Err(crate::linux_eventfd::EventFdError::BadFileDescriptor) => {
            match crate::linux_timerfd::close(owner, fd) {
                Ok(()) => 0,
                Err(crate::linux_timerfd::TimerFdError::BadFileDescriptor) => {
                    match crate::linux_epoll::close(owner, fd) {
                        Ok(()) => 0,
                        Err(crate::linux_epoll::EpollError::BadFileDescriptor) => {
                            ERROR_BAD_FILE_DESCRIPTOR
                        }
                        Err(_) => ERROR_IO,
                    }
                }
                Err(_) => ERROR_IO,
            }
        }
        Err(_) => ERROR_IO,
    }
}

#[cfg(target_os = "none")]
fn linux_open(arguments: [u64; 6]) -> isize {
    let Ok(flags) = u32::try_from(arguments[1]) else {
        return ERROR_INVALID_ARGUMENT;
    };
    linux_open_path(arguments[0], flags, None)
}

#[cfg(target_os = "none")]
fn linux_openat(arguments: [u64; 6]) -> isize {
    let Ok(flags) = u32::try_from(arguments[2]) else {
        return ERROR_INVALID_ARGUMENT;
    };
    linux_open_path(arguments[1], flags, Some(arguments[0] as i64))
}

#[cfg(target_os = "none")]
fn linux_open_path(pointer: u64, flags: u32, dirfd: Option<i64>) -> isize {
    let (path, length, was_absolute) = match copy_linux_path(pointer) {
        Ok(value) => value,
        Err(error) => return error,
    };
    if !was_absolute && dirfd.is_some_and(|fd| fd != LINUX_AT_FDCWD) {
        return ERROR_BAD_FILE_DESCRIPTOR;
    }
    let owner = match current_akashic_owner() {
        Ok(owner) => owner,
        Err(error) => return error,
    };
    match crate::linux_file::open(
        owner,
        &path[..length],
        flags,
        crate::interrupts::monotonic_nanoseconds(),
    ) {
        Ok(fd) => fd as isize,
        Err(error) => map_linux_file_error(error),
    }
}

#[cfg(target_os = "none")]
fn linux_stat(arguments: [u64; 6]) -> isize {
    let (path, length, _) = match copy_linux_path(arguments[0]) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let stat = match crate::linux_file::stat(&path[..length]) {
        Ok(stat) => stat,
        Err(error) => return map_linux_file_error(error),
    };
    write_linux_stat(arguments[1], stat, stable_linux_inode(&path[..length]))
}

#[cfg(target_os = "none")]
fn linux_fstat(arguments: [u64; 6]) -> isize {
    let Ok(fd) = u32::try_from(arguments[0]) else {
        return ERROR_BAD_FILE_DESCRIPTOR;
    };
    let owner = match current_akashic_owner() {
        Ok(owner) => owner,
        Err(error) => return error,
    };
    let stat = match crate::linux_file::fstat(owner, fd) {
        Ok(stat) => stat,
        Err(error) => return map_linux_file_error(error),
    };
    write_linux_stat(arguments[1], stat, u64::from(fd) + 1)
}

#[cfg(target_os = "none")]
fn linux_lseek(arguments: [u64; 6]) -> isize {
    let Ok(fd) = u32::try_from(arguments[0]) else {
        return ERROR_BAD_FILE_DESCRIPTOR;
    };
    let Ok(whence) = u32::try_from(arguments[2]) else {
        return ERROR_INVALID_ARGUMENT;
    };
    let owner = match current_akashic_owner() {
        Ok(owner) => owner,
        Err(error) => return error,
    };
    match crate::linux_file::seek(owner, fd, arguments[1] as i64, whence) {
        Ok(offset) => isize::try_from(offset).unwrap_or(isize::MAX),
        Err(error) => map_linux_file_error(error),
    }
}

#[cfg(target_os = "none")]
fn linux_unlinkat(arguments: [u64; 6]) -> isize {
    let Ok(flags) = u32::try_from(arguments[2]) else {
        return ERROR_INVALID_ARGUMENT;
    };
    if flags & !LINUX_AT_REMOVEDIR != 0 {
        return ERROR_INVALID_ARGUMENT;
    }
    let (path, length, was_absolute) = match copy_linux_path(arguments[1]) {
        Ok(value) => value,
        Err(error) => return error,
    };
    if !was_absolute && arguments[0] as i64 != LINUX_AT_FDCWD {
        return ERROR_BAD_FILE_DESCRIPTOR;
    }
    match crate::linux_file::unlink(&path[..length]) {
        Ok(()) => 0,
        Err(error) => map_linux_file_error(error),
    }
}

#[cfg(target_os = "none")]
fn copy_linux_path(
    pointer: u64,
) -> Result<([u8; crate::akashic_vfs::MAXIMUM_PATH_BYTES], usize, bool), isize> {
    if pointer == 0 {
        return Err(ERROR_BAD_ADDRESS);
    }
    let mut path = [0_u8; crate::akashic_vfs::MAXIMUM_PATH_BYTES];
    let mut length = 0_usize;
    loop {
        if length == path.len() {
            return Err(ERROR_NAME_TOO_LONG);
        }
        let address = pointer
            .checked_add(length as u64)
            .ok_or(ERROR_BAD_ADDRESS)?;
        let mut byte = [0_u8; 1];
        copy_from_user(address, &mut byte).map_err(|_| ERROR_BAD_ADDRESS)?;
        if byte[0] == 0 {
            break;
        }
        path[length] = byte[0];
        length += 1;
    }
    if length == 0 {
        return Err(ERROR_NO_ENTRY);
    }
    let was_absolute = path[0] == b'/';
    if !was_absolute {
        if length == path.len() {
            return Err(ERROR_NAME_TOO_LONG);
        }
        path.copy_within(0..length, 1);
        path[0] = b'/';
        length += 1;
    }
    Ok((path, length, was_absolute))
}

#[cfg(target_os = "none")]
fn write_linux_stat(destination: u64, stat: crate::akashic_vfs::Stat, inode: u64) -> isize {
    let (mode, links) = match stat.kind {
        crate::akashic_vfs::NodeKind::File => (0o100_644, 1),
        crate::akashic_vfs::NodeKind::Directory => (0o040_755, 2),
    };
    let seconds = core::cmp::min(stat.modified_ticks / 1_000_000_000, i64::MAX as u64) as i64;
    let nanoseconds = (stat.modified_ticks % 1_000_000_000) as i64;
    let size = core::cmp::min(stat.size_bytes, i64::MAX as u64) as i64;
    let encoded = LinuxStat {
        st_dev: 1,
        st_ino: inode.max(1),
        st_nlink: links,
        st_mode: mode,
        st_uid: 0,
        st_gid: 0,
        pad0: 0,
        st_rdev: 0,
        st_size: size,
        st_blksize: PAGE_SIZE as i64,
        st_blocks: size.saturating_add(511) / 512,
        st_atime: seconds,
        st_atime_nsec: nanoseconds,
        st_mtime: seconds,
        st_mtime_nsec: nanoseconds,
        st_ctime: seconds,
        st_ctime_nsec: nanoseconds,
        unused: [0; 3],
    };
    if copy_value_to_user(destination, &encoded).is_ok() {
        0
    } else {
        ERROR_BAD_ADDRESS
    }
}

#[cfg(target_os = "none")]
fn stable_linux_inode(path: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in path {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash.max(1)
}

#[cfg(target_os = "none")]
fn map_linux_file_error(error: crate::linux_file::FileError) -> isize {
    match error {
        crate::linux_file::FileError::InvalidArgument => ERROR_INVALID_ARGUMENT,
        crate::linux_file::FileError::BadFileDescriptor => ERROR_BAD_FILE_DESCRIPTOR,
        crate::linux_file::FileError::Capacity => ERROR_TOO_MANY_OPEN_FILES,
        crate::linux_file::FileError::Vfs(error) => map_akashic_error(error),
    }
}

#[cfg(target_os = "none")]
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
    } else if let Ok(ready) =
        crate::linux_timerfd::readiness(owner.pid, fd, crate::interrupts::monotonic_nanoseconds())
    {
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

#[cfg(target_os = "none")]
fn linux_poll(arguments: [u64; 6]) -> isize {
    let Ok(nfds) = usize::try_from(arguments[1]) else {
        return ERROR_INVALID_ARGUMENT;
    };
    if nfds > MAXIMUM_LINUX_POLL_FDS {
        return ERROR_INVALID_ARGUMENT;
    }
    if nfds == 0 {
        // A positive timeout would normally sleep.  The early Arach
        // personality is explicitly non-sleeping; return the empty result so
        // an event loop can continue to make progress without a deadlock.
        return 0;
    }
    let Some(length) = nfds.checked_mul(8) else {
        return ERROR_INVALID_ARGUMENT;
    };
    let mut records = [0_u8; MAXIMUM_LINUX_POLL_FDS * 8];
    if copy_from_user(arguments[0], &mut records[..length]).is_err() {
        return ERROR_BAD_ADDRESS;
    }
    let owner = match current_akashic_owner() {
        Ok(owner) => owner,
        Err(error) => return error,
    };
    let mut ready_count: isize = 0;
    for index in 0..nfds {
        let offset = index * 8;
        let fd = i32::from_ne_bytes(records[offset..offset + 4].try_into().unwrap());
        let requested = u16::from_ne_bytes(records[offset + 4..offset + 6].try_into().unwrap());
        let revents = linux_descriptor_revents(owner, fd, requested);
        records[offset + 6..offset + 8].copy_from_slice(&revents.to_ne_bytes());
        if revents != 0 {
            ready_count += 1;
        }
    }
    if copy_to_user(arguments[0], &records[..length]).is_err() {
        ERROR_BAD_ADDRESS
    } else {
        ready_count
    }
}

#[cfg(target_os = "none")]
fn linux_epoll_create1(arguments: [u64; 6]) -> isize {
    let Ok(flags) = u32::try_from(arguments[0]) else {
        return ERROR_INVALID_ARGUMENT;
    };
    let owner = crate::process::lifecycle::current_thread_group();
    if owner == 0 {
        return -13;
    }
    match crate::linux_epoll::create(owner, flags) {
        Ok(fd) => fd as isize,
        Err(crate::linux_epoll::EpollError::InvalidArgument) => ERROR_INVALID_ARGUMENT,
        Err(crate::linux_epoll::EpollError::Capacity) => -28,
        Err(_) => -5,
    }
}

#[cfg(target_os = "none")]
fn linux_epoll_ctl(arguments: [u64; 6]) -> isize {
    let Ok(epfd) = u32::try_from(arguments[0]) else {
        return ERROR_BAD_FILE_DESCRIPTOR;
    };
    let Ok(operation) = u32::try_from(arguments[1]) else {
        return ERROR_INVALID_ARGUMENT;
    };
    let Ok(fd) = u32::try_from(arguments[2]) else {
        return ERROR_BAD_FILE_DESCRIPTOR;
    };
    let mut events = 0_u32;
    let mut data = 0_u64;
    if operation != crate::linux_epoll::EPOLL_CTL_DEL {
        let mut encoded = [0_u8; 12];
        if copy_from_user(arguments[3], &mut encoded).is_err() {
            return ERROR_BAD_ADDRESS;
        }
        events = u32::from_ne_bytes(encoded[0..4].try_into().unwrap());
        data = u64::from_ne_bytes(encoded[4..12].try_into().unwrap());
    }
    let owner = crate::process::lifecycle::current_thread_group();
    match crate::linux_epoll::ctl(owner, epfd, operation, fd, events, data) {
        Ok(()) => 0,
        Err(crate::linux_epoll::EpollError::BadFileDescriptor) => ERROR_BAD_FILE_DESCRIPTOR,
        Err(crate::linux_epoll::EpollError::InvalidArgument) => ERROR_INVALID_ARGUMENT,
        Err(crate::linux_epoll::EpollError::AlreadyExists) => -17,
        Err(crate::linux_epoll::EpollError::NotFound) => -2,
        Err(crate::linux_epoll::EpollError::Capacity) => -28,
    }
}

#[cfg(target_os = "none")]
fn linux_epoll_wait(arguments: [u64; 6]) -> isize {
    let Ok(epfd) = u32::try_from(arguments[0]) else {
        return ERROR_BAD_FILE_DESCRIPTOR;
    };
    let Ok(maxevents) = usize::try_from(arguments[2]) else {
        return ERROR_INVALID_ARGUMENT;
    };
    if maxevents == 0 || maxevents > crate::linux_epoll::MAXIMUM_READY_EVENTS {
        return ERROR_INVALID_ARGUMENT;
    }
    let owner = crate::process::lifecycle::current_thread_group();
    let mut ready = [crate::linux_epoll::ReadyEvent { events: 0, data: 0 };
        crate::linux_epoll::MAXIMUM_READY_EVENTS];
    let count = match crate::linux_epoll::wait(owner, epfd, &mut ready[..maxevents]) {
        Ok(count) => count,
        Err(crate::linux_epoll::EpollError::BadFileDescriptor) => {
            return ERROR_BAD_FILE_DESCRIPTOR;
        }
        Err(crate::linux_epoll::EpollError::InvalidArgument) => {
            return ERROR_INVALID_ARGUMENT;
        }
        Err(_) => return -5,
    };
    let mut encoded = [0_u8; crate::linux_epoll::MAXIMUM_READY_EVENTS * 12];
    for (index, event) in ready[..count].iter().enumerate() {
        let offset = index * 12;
        encoded[offset..offset + 4].copy_from_slice(&event.events.to_ne_bytes());
        encoded[offset + 4..offset + 12].copy_from_slice(&event.data.to_ne_bytes());
    }
    if count != 0 && copy_to_user(arguments[1], &encoded[..count * 12]).is_err() {
        ERROR_BAD_ADDRESS
    } else {
        count as isize
    }
}

#[cfg(target_os = "none")]
fn linux_epoll_pwait(arguments: [u64; 6]) -> isize {
    // Signal-mask installation is not yet part of the Linux personality. Do
    // not silently ignore a caller that depends on it.
    if arguments[4] != 0 || arguments[5] != 0 {
        return ERROR_NOT_IMPLEMENTED;
    }
    linux_epoll_wait(arguments)
}

#[cfg(target_os = "none")]
fn linux_mmap(arguments: [u64; 6]) -> isize {
    const PROT_READ: u64 = 0x1;
    const PROT_WRITE: u64 = 0x2;
    const PROT_EXEC: u64 = 0x4;
    const MAP_PRIVATE: u64 = 0x02;
    const MAP_ANONYMOUS: u64 = 0x20;
    const MAP_STACK: u64 = 0x20_000;
    const MAP_NORESERVE: u64 = 0x4000;
    let [hint, length, prot, flags, fd, offset] = arguments;
    if length == 0
        || prot & !(PROT_READ | PROT_WRITE | PROT_EXEC) != 0
        || prot & PROT_READ == 0
        || prot & PROT_WRITE != 0 && prot & PROT_EXEC != 0
        || flags & (MAP_PRIVATE | MAP_ANONYMOUS) != (MAP_PRIVATE | MAP_ANONYMOUS)
        || flags & !(MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK | MAP_NORESERVE) != 0
        || fd != u64::MAX
        || offset != 0
    {
        return ERROR_INVALID_ARGUMENT;
    }
    let permissions = crate::process::install::MappingPermissions {
        readable: true,
        writable: prot & PROT_WRITE != 0,
        executable: prot & PROT_EXEC != 0,
    };
    match crate::process::runtime::linux_mmap_current(
        hint,
        usize::try_from(length).unwrap_or(usize::MAX),
        permissions,
    ) {
        Ok(address) => isize::try_from(address).unwrap_or(-75),
        Err(crate::process::runtime::ProcessRuntimeError::Backend(
            crate::process::x86_64::FrameBackedError::CapacityExceeded,
        ))
        | Err(crate::process::runtime::ProcessRuntimeError::Backend(
            crate::process::x86_64::FrameBackedError::Memory(_),
        )) => ERROR_OUT_OF_MEMORY,
        Err(_) => ERROR_INVALID_ARGUMENT,
    }
}

#[cfg(target_os = "none")]
fn linux_munmap(arguments: [u64; 6]) -> isize {
    // Linux consumes only the first two registers for `munmap`; the remaining
    // syscall registers are caller-clobbered and must not be treated as
    // hidden validation fields.
    let [address, length, _, _, _, _] = arguments;
    match crate::process::runtime::linux_munmap_current(
        address,
        usize::try_from(length).unwrap_or(usize::MAX),
    ) {
        Ok(()) => 0,
        Err(_) => ERROR_INVALID_ARGUMENT,
    }
}

#[cfg(target_os = "none")]
fn linux_brk(arguments: [u64; 6]) -> isize {
    // Linux returns the new break on success and the previous break on
    // failure.  A zero argument is the read-current-break form.
    let requested = arguments[0];
    match crate::process::runtime::linux_brk_current(requested) {
        Ok(address) => isize::try_from(address).unwrap_or(-75),
        Err(_) => crate::process::runtime::linux_brk_current(0)
            .ok()
            .and_then(|address| isize::try_from(address).ok())
            .unwrap_or(ERROR_INVALID_ARGUMENT),
    }
}

#[cfg(target_os = "none")]
fn linux_clock_gettime(arguments: [u64; 6]) -> isize {
    const CLOCK_MONOTONIC: u64 = 1;
    if arguments[0] != CLOCK_MONOTONIC {
        return ERROR_INVALID_ARGUMENT;
    }
    let (seconds, nanoseconds) =
        split_monotonic_nanoseconds(crate::interrupts::monotonic_nanoseconds());
    let value = LinuxTimespec {
        tv_sec: seconds,
        tv_nsec: nanoseconds,
    };
    if copy_value_to_user(arguments[1], &value).is_err() {
        ERROR_BAD_ADDRESS
    } else {
        0
    }
}

#[cfg(target_os = "none")]
fn linux_uname(arguments: [u64; 6]) -> isize {
    if arguments[1..].iter().any(|argument| *argument != 0) {
        return ERROR_INVALID_ARGUMENT;
    }
    let mut value = LinuxUtsName {
        sysname: [0; UTS_FIELD_BYTES],
        nodename: [0; UTS_FIELD_BYTES],
        release: [0; UTS_FIELD_BYTES],
        version: [0; UTS_FIELD_BYTES],
        machine: [0; UTS_FIELD_BYTES],
        domainname: [0; UTS_FIELD_BYTES],
    };
    write_uts_field(&mut value.sysname, b"Arach");
    write_uts_field(&mut value.nodename, b"arach");
    write_uts_field(&mut value.release, b"0.1.0-arach");
    write_uts_field(&mut value.version, b"Arach Kernel");
    write_uts_field(&mut value.machine, b"x86_64");
    write_uts_field(&mut value.domainname, b"(none)");
    if copy_value_to_user(arguments[0], &value).is_err() {
        ERROR_BAD_ADDRESS
    } else {
        0
    }
}

#[cfg(target_os = "none")]
fn write_uts_field(field: &mut [u8; UTS_FIELD_BYTES], value: &[u8]) {
    let length = core::cmp::min(value.len(), field.len().saturating_sub(1));
    field[..length].copy_from_slice(&value[..length]);
}

#[cfg(any(target_os = "none", test))]
const fn split_monotonic_nanoseconds(value: u64) -> (i64, i64) {
    (
        (value / 1_000_000_000) as i64,
        (value % 1_000_000_000) as i64,
    )
}

#[cfg(target_os = "none")]
fn aegis_status_for_current_crest(arguments: [u64; 6]) -> isize {
    if arguments != [0; 6] {
        return ERROR_INVALID_ARGUMENT;
    }
    let Some(caller) = crate::process::lifecycle::current_handle() else {
        return -13;
    };
    match crate::process::service_registry::authenticated_crest_status(caller) {
        Ok(status) => isize::try_from(status).unwrap_or(-75),
        Err(crate::process::service_registry::ServiceRegistryError::UnauthorizedCaller) => -13,
        Err(crate::process::service_registry::ServiceRegistryError::NotRunning) => -19,
        Err(_) => -5,
    }
}

/// The sole path from Crest pixels to the firmware display.  The caller's
/// exact PID generation is authenticated before any user memory is copied;
/// neither a display object nor a physical address crosses this ABI.
#[cfg(target_os = "none")]
fn present_current_crest(arguments: [u64; 6]) -> isize {
    let [source, width, height, pitch, reserved0, reserved1] = arguments;
    if reserved0 != 0 || reserved1 != 0 || width == 0 || height == 0 || pitch == 0 {
        return ERROR_INVALID_ARGUMENT;
    }
    let required_pitch = match width.checked_mul(4) {
        Some(value) if pitch >= value => value,
        _ => return ERROR_INVALID_ARGUMENT,
    };
    let _ = required_pitch;
    let length = match pitch
        .checked_mul(height)
        .and_then(|value| usize::try_from(value).ok())
    {
        Some(value) if value != 0 && value <= MAXIMUM_CREST_PRESENT_BYTES => value,
        _ => return ERROR_INVALID_ARGUMENT,
    };
    let Some(caller) = crate::process::lifecycle::current_handle() else {
        return -13;
    };
    match crate::process::service_registry::authenticated_crest_status(caller) {
        Ok(_) => {}
        Err(crate::process::service_registry::ServiceRegistryError::UnauthorizedCaller) => {
            return -13;
        }
        Err(crate::process::service_registry::ServiceRegistryError::NotRunning) => return -19,
        Err(_) => return -5,
    }

    let mut staging = CREST_PRESENT_STAGING.lock();
    if copy_from_user(source, &mut staging[..length]).is_err() {
        return ERROR_BAD_ADDRESS;
    }
    match crate::drivers::firmware_display::present_crest_bgra8888(
        &staging[..length],
        width as u32,
        height as u32,
        pitch as u32,
    ) {
        Ok(root) => isize::try_from(root & 0x7fff_ffff_ffff_ffff).unwrap_or(-75),
        Err(crate::drivers::firmware_display::FirmwareDisplayError::NotFound) => -19,
        Err(crate::drivers::firmware_display::FirmwareDisplayError::InvalidEvidence) => {
            ERROR_INVALID_ARGUMENT
        }
        Err(_) => -5,
    }
}

/// Delivers one bounded, normalized pointing-device packet only to the exact
/// measured Crest image.  The kernel retains controller ownership; user space
/// sees neither legacy I/O ports nor raw packet bytes.
#[cfg(target_os = "none")]
fn next_pointer_for_current_crest(arguments: [u64; 6]) -> isize {
    let [
        destination,
        length,
        reserved0,
        reserved1,
        reserved2,
        reserved3,
    ] = arguments;
    if reserved0 != 0
        || reserved1 != 0
        || reserved2 != 0
        || reserved3 != 0
        || length != core::mem::size_of::<crate::drivers::ps2_pointer::PointerMotion>() as u64
    {
        return ERROR_INVALID_ARGUMENT;
    }
    let Some(caller) = crate::process::lifecycle::current_handle() else {
        return -13;
    };
    match crate::process::service_registry::authenticated_crest_status(caller) {
        Ok(_) => {}
        Err(crate::process::service_registry::ServiceRegistryError::UnauthorizedCaller) => {
            return -13;
        }
        Err(crate::process::service_registry::ServiceRegistryError::NotRunning) => return -19,
        Err(_) => return -5,
    }
    match crate::drivers::ps2_pointer::poll() {
        None => 0,
        Some(motion) if copy_value_to_user(destination, &motion).is_ok() => {
            if !CREST_POINTER_DELIVERY_REPORTED.swap(true, Ordering::AcqRel) {
                let mut serial = unsafe { SerialPort::initialize(COM1) };
                let _ = core::fmt::Write::write_str(
                    &mut serial,
                    "Arach: PS/2 pointer packet delivered to Crest\n",
                );
            }
            1
        }
        Some(_) => ERROR_BAD_ADDRESS,
    }
}

/// Delivers one bounded, normalized keyboard event only to the exact measured
/// Crest image. Arach retains controller ownership and translates the
/// controller stream before copying it to user space.
#[cfg(target_os = "none")]
fn next_key_for_current_crest(arguments: [u64; 6]) -> isize {
    let [
        destination,
        length,
        reserved0,
        reserved1,
        reserved2,
        reserved3,
    ] = arguments;
    if reserved0 != 0
        || reserved1 != 0
        || reserved2 != 0
        || reserved3 != 0
        || length != core::mem::size_of::<crate::drivers::ps2_pointer::KeyEvent>() as u64
    {
        return ERROR_INVALID_ARGUMENT;
    }
    let Some(caller) = crate::process::lifecycle::current_handle() else {
        return -13;
    };
    match crate::process::service_registry::authenticated_crest_status(caller) {
        Ok(_) => {}
        Err(crate::process::service_registry::ServiceRegistryError::UnauthorizedCaller) => {
            return -13;
        }
        Err(crate::process::service_registry::ServiceRegistryError::NotRunning) => return -19,
        Err(_) => return -5,
    }
    match crate::drivers::ps2_pointer::poll_key() {
        None => 0,
        Some(event) if copy_value_to_user(destination, &event).is_ok() => 1,
        Some(_) => ERROR_BAD_ADDRESS,
    }
}

#[cfg(target_os = "none")]
fn report_timer_preemption_service(ticket: preemption::PreemptionTicket) {
    if preemption::record_serviced() {
        let statistics = preemption::statistics();
        let mut serial = unsafe { SerialPort::initialize(COM1) };
        let _ = core::fmt::Write::write_fmt(
            &mut serial,
            format_args!(
                "Arach: timer preemption safe-point serviced pid={}:{} epoch={} tick={} irq={} published={} coalesced={}\n",
                ticket.authority.handle.pid,
                ticket.authority.handle.generation,
                ticket.authority.scheduler_epoch,
                ticket.requested_tick,
                statistics.irq_requests,
                statistics.published,
                statistics.coalesced,
            ),
        );
    }
}

#[cfg(any(target_os = "none", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TaskStateDescriptor {
    base: u64,
    limit: u64,
}

#[cfg(any(target_os = "none", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TaskStateDescriptorError {
    NotSystemSegment,
    NotTaskStateSegment,
    NotPresent,
    Truncated,
    InvalidBase,
}

#[cfg(target_os = "none")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MachineDispatchError {
    TaskState(TaskStateDescriptorError),
    CpuLocal(cpu_local::CpuLocalError),
    TaskStateWriteFailed,
    FsBaseWriteFailed,
}

/// Decodes an x86-64 16-byte available/active TSS descriptor. Keeping this
/// transformation pure makes the architecture boundary independently
/// testable without executing privileged instructions.
#[cfg(any(target_os = "none", test))]
fn decode_task_state_descriptor(
    low: u64,
    high: u64,
) -> Result<TaskStateDescriptor, TaskStateDescriptorError> {
    if low & (1 << 44) != 0 {
        return Err(TaskStateDescriptorError::NotSystemSegment);
    }
    if !matches!((low >> 40) & 0xf, 0x9 | 0xb) {
        return Err(TaskStateDescriptorError::NotTaskStateSegment);
    }
    if low & (1 << 47) == 0 {
        return Err(TaskStateDescriptorError::NotPresent);
    }

    let base = ((low >> 16) & 0xffff)
        | ((low >> 32) & 0xff) << 16
        | ((low >> 56) & 0xff) << 24
        | (high & 0xffff_ffff) << 32;
    let mut limit = (low & 0xffff) | ((low >> 48) & 0xf) << 16;
    if low & (1 << 55) != 0 {
        limit = (limit << 12) | 0xfff;
    }
    // A 64-bit TSS architecturally occupies 104 bytes. RSP0 lies near the
    // beginning, but accepting a shorter segment would bless malformed CPU
    // privilege state.
    if limit < 103 {
        return Err(TaskStateDescriptorError::Truncated);
    }
    if base < crate::process::context::KERNEL_ADDRESS_MINIMUM {
        return Err(TaskStateDescriptorError::InvalidBase);
    }
    Ok(TaskStateDescriptor { base, limit })
}

#[cfg(target_os = "none")]
#[repr(C, packed)]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

#[cfg(target_os = "none")]
fn active_task_state_descriptor() -> Result<TaskStateDescriptor, TaskStateDescriptorError> {
    let mut table = DescriptorTablePointer { limit: 0, base: 0 };
    let selector: u16;
    // SAFETY: SGDT and STR only snapshot descriptor state already owned by
    // this CPU. The packed destination has the architectural ten-byte shape.
    unsafe {
        core::arch::asm!(
            "sgdt [{}]",
            in(reg) core::ptr::addr_of_mut!(table),
            options(nostack, preserves_flags),
        );
        core::arch::asm!(
            "str {selector:x}",
            selector = out(reg) selector,
            options(nomem, nostack, preserves_flags),
        );
    }
    if selector & 0x4 != 0 {
        return Err(TaskStateDescriptorError::NotTaskStateSegment);
    }
    let offset = usize::from(selector & !0x7);
    if offset
        .checked_add(15)
        .is_none_or(|last| last > usize::from(table.limit))
    {
        return Err(TaskStateDescriptorError::Truncated);
    }
    if table.base < crate::process::context::KERNEL_ADDRESS_MINIMUM {
        return Err(TaskStateDescriptorError::InvalidBase);
    }

    let descriptor = table.base as *const u8;
    // SAFETY: The loaded GDTR bounds check above proves both descriptor words
    // are inside the active GDT. The GDT is 8-byte aligned and immutable after
    // bootstrap publication.
    let low = unsafe { descriptor.add(offset).cast::<u64>().read_volatile() };
    let high = unsafe { descriptor.add(offset + 8).cast::<u64>().read_volatile() };
    decode_task_state_descriptor(low, high)
}

#[cfg(target_os = "none")]
fn task_state_rsp0(tss: TaskStateDescriptor) -> u64 {
    // SAFETY: Descriptor validation proves the complete architectural TSS is
    // present. Per-byte volatile reads preserve packed-field semantics without
    // imposing alignment Rust cannot derive from an arbitrary TSS descriptor.
    let mut bytes = [0_u8; 8];
    for (index, byte) in bytes.iter_mut().enumerate() {
        // SAFETY: RSP0 occupies bytes 4..12 of every validated 64-bit TSS.
        *byte = unsafe { (tss.base as *const u8).add(4 + index).read_volatile() };
    }
    u64::from_le_bytes(bytes)
}

#[cfg(target_os = "none")]
fn write_task_state_rsp0(tss: TaskStateDescriptor, rsp0: u64) {
    for (index, byte) in rsp0.to_le_bytes().into_iter().enumerate() {
        // SAFETY: RSP0 occupies bytes 4..12 of every validated 64-bit TSS.
        // Syscall entry has IF masked, so hardware cannot consume a partial
        // value before publication and readback complete.
        unsafe {
            (tss.base as *mut u8).add(4 + index).write_volatile(byte);
        }
    }
}

#[cfg(target_os = "none")]
fn validate_active_machine_entry() -> Result<(), MachineDispatchError> {
    let tss = active_task_state_descriptor().map_err(MachineDispatchError::TaskState)?;
    cpu_local::validate_machine_entry(current_hardware_thread_id(), tss.base, task_state_rsp0(tss))
        .map(|_| ())
        .map_err(MachineDispatchError::CpuLocal)
}

#[cfg(target_os = "none")]
fn activate_machine_dispatch(authority: AuthorizedUserReturn) -> Result<(), MachineDispatchError> {
    let tss = active_task_state_descriptor().map_err(MachineDispatchError::TaskState)?;
    let current_rsp0 = task_state_rsp0(tss);
    let stack = authority.dispatch.kernel_stack_pointer;
    let return_lease =
        cpu_local::prepare_return(current_hardware_thread_id(), tss.base, current_rsp0, stack)
            .map_err(MachineDispatchError::CpuLocal)?;
    // SAFETY: The lifecycle authority was revalidated immediately before this
    // call. CPU-local preparation proved this exact TSS and old RSP0 match the
    // entry generation. Interrupts remain masked across publication.
    write_task_state_rsp0(tss, stack);
    if task_state_rsp0(tss) != stack {
        return Err(MachineDispatchError::TaskStateWriteFailed);
    }
    cpu_local::commit_return(return_lease, tss.base, stack)
        .map_err(MachineDispatchError::CpuLocal)?;
    // SAFETY: Dispatch validation admits only canonical lower-half bases.
    // IA32_FS_BASE is architectural in x86-64 long mode and readback closes
    // the return gate if the per-thread TLS state was not published.
    unsafe {
        crate::arch::x86_64::write_msr(0xc000_0100, authority.dispatch.fs_base);
        if crate::arch::x86_64::read_msr(0xc000_0100) != authority.dispatch.fs_base {
            return Err(MachineDispatchError::FsBaseWriteFailed);
        }
    }
    // SAFETY: The lifecycle and CPU-local generations are committed, the new
    // TSS RSP0 was read back, and the target hierarchy retains this entry
    // frame through its inherited higher-half kernel mapping.
    unsafe {
        core::arch::asm!(
            "mov cr3, {root}",
            root = in(reg) authority.dispatch.address_space_root,
            options(nostack, preserves_flags),
        );
    }
    Ok(())
}

/// Final generation-safe architecture activation called from the assembly
/// return gate. Any stale, malformed, or superseded authority halts rather
/// than returning through attacker-selected registers or address-space state.
#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
extern "C" fn arach_syscall_activate(frame: *const SyscallFrame) {
    let Some(authority) = (unsafe { frame.as_ref() }).copied() else {
        crate::arch::x86_64::halt();
    };
    let Ok(scheduled) = crate::process::lifecycle::authorize_user_return(authority) else {
        crate::arch::x86_64::halt();
    };
    if scheduled.authorized_return() != authority || activate_machine_dispatch(authority).is_err() {
        crate::arch::x86_64::halt();
    }
    if crate::process::runtime::reap_after_root_switch().is_err() {
        crate::arch::x86_64::halt();
    }
}

#[cfg(any(target_os = "none", test))]
const fn valid_user_control_address(address: u64) -> bool {
    address >= USER_ADDRESS_MINIMUM && address < USER_ADDRESS_LIMIT
}

#[cfg(target_os = "none")]
fn write_from_user(arguments: [u64; 6]) -> isize {
    if arguments[0] != 1 && arguments[0] != 2 {
        return ERROR_BAD_FILE_DESCRIPTOR;
    }
    let Ok(length) = usize::try_from(arguments[2]) else {
        return ERROR_INVALID_ARGUMENT;
    };
    if length > MAXIMUM_WRITE_BYTES {
        return ERROR_INVALID_ARGUMENT;
    }

    let mut bytes = [0_u8; MAXIMUM_WRITE_BYTES];
    if copy_from_user(arguments[1], &mut bytes[..length]).is_err() {
        return ERROR_BAD_ADDRESS;
    }
    // SAFETY: The syscall gate serializes this bootstrap CPU and COM1 is the
    // kernel's established debug sink. User bytes are copied before I/O.
    let mut serial = unsafe { SerialPort::initialize(COM1) };
    serial.write_bytes(&bytes[..length]);
    WRITE_HITS.fetch_add(1, Ordering::AcqRel);
    length as isize
}

#[cfg(target_os = "none")]
fn spawn_measured_service(arguments: [u64; 6]) -> isize {
    if arguments[1..].iter().any(|argument| *argument != 0) {
        return ERROR_INVALID_ARGUMENT;
    }
    let Ok(service_class) = u16::try_from(arguments[0]) else {
        return ERROR_INVALID_ARGUMENT;
    };
    let parent = crate::process::lifecycle::current_pid();
    match crate::process::service_registry::launch(parent, service_class) {
        Ok(handle) => handle.pid as isize,
        Err(
            crate::process::service_registry::ServiceRegistryError::UnsupportedService
            | crate::process::service_registry::ServiceRegistryError::NotInit,
        ) => ERROR_INVALID_ARGUMENT,
        Err(crate::process::service_registry::ServiceRegistryError::AlreadyLaunched) => {
            crate::process::lifecycle::ERROR_AGAIN
        }
        Err(crate::process::service_registry::ServiceRegistryError::Lifecycle(
            LifecycleError::Capacity,
        )) => crate::process::lifecycle::ERROR_CAPACITY,
        Err(_) => -5,
    }
}

#[cfg(target_os = "none")]
fn wait_for_child_nohang(arguments: [u64; 6]) -> isize {
    if arguments[3..].iter().any(|argument| *argument != 0) {
        return ERROR_INVALID_ARGUMENT;
    }
    let requested_pid = match arguments[2] {
        0 => None,
        pid if pid <= u64::from(u32::MAX) => Some(pid as u32),
        _ => return ERROR_INVALID_ARGUMENT,
    };
    let parent = crate::process::lifecycle::current_pid();
    let child = match crate::process::lifecycle::wait_child(parent, requested_pid) {
        Ok(child) => child,
        Err(LifecycleError::StillRunning) => return crate::process::lifecycle::ERROR_AGAIN,
        Err(LifecycleError::NoChild) => return crate::process::lifecycle::ERROR_NO_CHILD,
        Err(_) => return -5,
    };
    let status = child.exit_code as i32;
    if copy_value_to_user(arguments[0], &child.handle.pid).is_err()
        || copy_value_to_user(arguments[1], &status).is_err()
    {
        return ERROR_BAD_ADDRESS;
    }
    match crate::process::lifecycle::reap_child(parent, child.handle) {
        Ok(_) => child.handle.pid as isize,
        Err(_) => -5,
    }
}

#[cfg(any(target_os = "none", test))]
fn map_akashic_error(error: crate::akashic_vfs::VfsError) -> isize {
    match error {
        crate::akashic_vfs::VfsError::NotFound => ERROR_NO_ENTRY,
        crate::akashic_vfs::VfsError::AlreadyExists => ERROR_ALREADY_EXISTS,
        crate::akashic_vfs::VfsError::PermissionDenied => ERROR_PERMISSION_DENIED,
        crate::akashic_vfs::VfsError::NotDirectory => ERROR_NOT_DIRECTORY,
        crate::akashic_vfs::VfsError::NotFile => ERROR_IS_DIRECTORY,
        crate::akashic_vfs::VfsError::DirectoryNotEmpty => ERROR_DIRECTORY_NOT_EMPTY,
        crate::akashic_vfs::VfsError::InvalidPath | crate::akashic_vfs::VfsError::InvalidSeek => {
            ERROR_INVALID_ARGUMENT
        }
        crate::akashic_vfs::VfsError::InvalidHandle => ERROR_BAD_FILE_DESCRIPTOR,
        crate::akashic_vfs::VfsError::Capacity => ERROR_NO_SPACE,
        crate::akashic_vfs::VfsError::FileTooLarge => ERROR_FILE_TOO_LARGE,
        crate::akashic_vfs::VfsError::Busy => ERROR_BUSY,
        crate::akashic_vfs::VfsError::Unsupported => ERROR_NOT_SUPPORTED,
    }
}

#[cfg(target_os = "none")]
fn current_akashic_owner() -> Result<crate::process::lifecycle::ProcessHandle, isize> {
    crate::process::lifecycle::current_thread_group_handle().ok_or(ERROR_PERMISSION_DENIED)
}

#[cfg(target_os = "none")]
fn copy_akashic_path<'a>(
    pointer: u64,
    length: u64,
    staging: &'a mut [u8; crate::akashic_vfs::MAXIMUM_PATH_BYTES],
) -> Result<&'a [u8], isize> {
    let length = usize::try_from(length).map_err(|_| ERROR_INVALID_ARGUMENT)?;
    if length == 0 || length > staging.len() {
        return Err(ERROR_INVALID_ARGUMENT);
    }
    copy_from_user(pointer, &mut staging[..length]).map_err(|_| ERROR_BAD_ADDRESS)?;
    Ok(&staging[..length])
}

#[cfg(target_os = "none")]
fn akashic_open_from_user(arguments: [u64; 6]) -> isize {
    let owner = match current_akashic_owner() {
        Ok(owner) => owner,
        Err(error) => return error,
    };
    let Ok(open_flags) = u32::try_from(arguments[2]) else {
        return ERROR_INVALID_ARGUMENT;
    };
    let mut path = [0_u8; crate::akashic_vfs::MAXIMUM_PATH_BYTES];
    let path = match copy_akashic_path(arguments[0], arguments[1], &mut path) {
        Ok(path) => path,
        Err(error) => return error,
    };
    match crate::akashic_vfs::open(
        owner,
        path,
        open_flags,
        crate::interrupts::monotonic_nanoseconds(),
    ) {
        Ok(handle) => isize::try_from(handle).unwrap_or(ERROR_IO),
        Err(error) => map_akashic_error(error),
    }
}

#[cfg(target_os = "none")]
fn akashic_close(arguments: [u64; 6]) -> isize {
    let owner = match current_akashic_owner() {
        Ok(owner) => owner,
        Err(error) => return error,
    };
    match crate::akashic_vfs::close(owner, arguments[0]) {
        Ok(()) => 0,
        Err(error) => map_akashic_error(error),
    }
}

#[cfg(target_os = "none")]
fn akashic_read_to_user(arguments: [u64; 6]) -> isize {
    let owner = match current_akashic_owner() {
        Ok(owner) => owner,
        Err(error) => return error,
    };
    let requested = match usize::try_from(arguments[2]) {
        Ok(requested) => requested,
        Err(_) => return ERROR_INVALID_ARGUMENT,
    };
    let length = core::cmp::min(requested, MAXIMUM_AKASHIC_IO_BYTES);
    if length == 0 {
        return 0;
    }
    if validate_user_write_range(arguments[1], length).is_err() {
        return ERROR_BAD_ADDRESS;
    }
    let mut staging = AKASHIC_IO_STAGING.lock();
    match crate::akashic_vfs::read(owner, arguments[0], &mut staging[..length]) {
        Ok(copied) => {
            if copy_to_user(arguments[1], &staging[..copied]).is_err() {
                ERROR_BAD_ADDRESS
            } else {
                copied as isize
            }
        }
        Err(error) => map_akashic_error(error),
    }
}

#[cfg(target_os = "none")]
fn akashic_write_from_user(arguments: [u64; 6]) -> isize {
    let owner = match current_akashic_owner() {
        Ok(owner) => owner,
        Err(error) => return error,
    };
    let requested = match usize::try_from(arguments[2]) {
        Ok(requested) => requested,
        Err(_) => return ERROR_INVALID_ARGUMENT,
    };
    let length = core::cmp::min(requested, MAXIMUM_AKASHIC_IO_BYTES);
    if length == 0 {
        return 0;
    }
    let mut staging = AKASHIC_IO_STAGING.lock();
    if copy_from_user(arguments[1], &mut staging[..length]).is_err() {
        return ERROR_BAD_ADDRESS;
    }
    match crate::akashic_vfs::write(
        owner,
        arguments[0],
        &staging[..length],
        crate::interrupts::monotonic_nanoseconds(),
    ) {
        Ok(written) => written as isize,
        Err(error) => map_akashic_error(error),
    }
}

#[cfg(target_os = "none")]
fn akashic_seek(arguments: [u64; 6]) -> isize {
    let owner = match current_akashic_owner() {
        Ok(owner) => owner,
        Err(error) => return error,
    };
    let Ok(whence) = u32::try_from(arguments[2]) else {
        return ERROR_INVALID_ARGUMENT;
    };
    match crate::akashic_vfs::seek(owner, arguments[0], arguments[1] as i64, whence) {
        Ok(position) => isize::try_from(position).unwrap_or(ERROR_INVALID_ARGUMENT),
        Err(error) => map_akashic_error(error),
    }
}

#[cfg(target_os = "none")]
fn akashic_stat_to_user(arguments: [u64; 6]) -> isize {
    if validate_user_write_range(arguments[2], core::mem::size_of::<AkashicRawStat>()).is_err() {
        return ERROR_BAD_ADDRESS;
    }
    let mut path = [0_u8; crate::akashic_vfs::MAXIMUM_PATH_BYTES];
    let path = match copy_akashic_path(arguments[0], arguments[1], &mut path) {
        Ok(path) => path,
        Err(error) => return error,
    };
    let stat = match crate::akashic_vfs::stat(path) {
        Ok(stat) => AkashicRawStat::from(stat),
        Err(error) => return map_akashic_error(error),
    };
    match copy_value_to_user(arguments[2], &stat) {
        Ok(()) => 0,
        Err(_) => ERROR_BAD_ADDRESS,
    }
}

#[cfg(target_os = "none")]
fn akashic_mkdir_from_user(arguments: [u64; 6]) -> isize {
    let mut path = [0_u8; crate::akashic_vfs::MAXIMUM_PATH_BYTES];
    let path = match copy_akashic_path(arguments[0], arguments[1], &mut path) {
        Ok(path) => path,
        Err(error) => return error,
    };
    match crate::akashic_vfs::mkdir(path, crate::interrupts::monotonic_nanoseconds()) {
        Ok(()) => 0,
        Err(error) => map_akashic_error(error),
    }
}

#[cfg(target_os = "none")]
fn akashic_unlink_from_user(arguments: [u64; 6]) -> isize {
    let mut path = [0_u8; crate::akashic_vfs::MAXIMUM_PATH_BYTES];
    let path = match copy_akashic_path(arguments[0], arguments[1], &mut path) {
        Ok(path) => path,
        Err(error) => return error,
    };
    match crate::akashic_vfs::unlink(path) {
        Ok(()) => 0,
        Err(error) => map_akashic_error(error),
    }
}

#[cfg(target_os = "none")]
fn akashic_rename_from_user(arguments: [u64; 6]) -> isize {
    let mut from = [0_u8; crate::akashic_vfs::MAXIMUM_PATH_BYTES];
    let mut to = [0_u8; crate::akashic_vfs::MAXIMUM_PATH_BYTES];
    let from = match copy_akashic_path(arguments[0], arguments[1], &mut from) {
        Ok(path) => path,
        Err(error) => return error,
    };
    let to = match copy_akashic_path(arguments[2], arguments[3], &mut to) {
        Ok(path) => path,
        Err(error) => return error,
    };
    match crate::akashic_vfs::rename(from, to, crate::interrupts::monotonic_nanoseconds()) {
        Ok(()) => 0,
        Err(error) => map_akashic_error(error),
    }
}

#[cfg(target_os = "none")]
fn akashic_readdir_to_user(arguments: [u64; 6]) -> isize {
    let owner = match current_akashic_owner() {
        Ok(owner) => owner,
        Err(error) => return error,
    };
    if validate_user_write_range(arguments[1], core::mem::size_of::<AkashicRawDirent>()).is_err() {
        return ERROR_BAD_ADDRESS;
    }
    let entry = match crate::akashic_vfs::readdir(owner, arguments[0]) {
        Ok(Some(entry)) => AkashicRawDirent::from(entry),
        Ok(None) => return 0,
        Err(error) => return map_akashic_error(error),
    };
    match copy_value_to_user(arguments[1], &entry) {
        Ok(()) => 1,
        Err(_) => ERROR_BAD_ADDRESS,
    }
}

#[cfg(target_os = "none")]
fn validate_user_write_range(target: u64, length: usize) -> Result<(), UserCopyError> {
    if length == 0 {
        return Ok(());
    }
    let end = target
        .checked_add(length as u64)
        .ok_or(UserCopyError::InvalidRange)?;
    if target < USER_ADDRESS_MINIMUM || end > USER_ADDRESS_LIMIT {
        return Err(UserCopyError::InvalidRange);
    }
    // SAFETY: SYSCALL entered from the process whose retained hierarchy owns
    // the active root for the complete non-preemptible validation pass.
    let root = unsafe { active_page_table_root() };
    let mut checked = 0;
    while checked < length {
        let user_address = target + checked as u64;
        let physical = translate_user_address_for_write(root, user_address, read_active_entry)?;
        let page_remaining = PAGE_SIZE - (user_address as usize & (PAGE_SIZE - 1));
        let span = core::cmp::min(page_remaining, length - checked);
        if physical
            .checked_add(span as u64)
            .ok_or(UserCopyError::UnmappedPhysicalMemory)?
            > EARLY_MAPPED_PHYSICAL_LIMIT
        {
            return Err(UserCopyError::UnmappedPhysicalMemory);
        }
        checked += span;
    }
    Ok(())
}

#[cfg(target_os = "none")]
fn copy_from_user(source: u64, target: &mut [u8]) -> Result<(), UserCopyError> {
    if target.is_empty() {
        return Ok(());
    }
    let end = source
        .checked_add(target.len() as u64)
        .ok_or(UserCopyError::InvalidRange)?;
    if source < USER_ADDRESS_MINIMUM || end > USER_ADDRESS_LIMIT {
        return Err(UserCopyError::InvalidRange);
    }

    // SAFETY: SYSCALL entered from the process whose hierarchy remains active
    // throughout this non-preemptible copy.
    let root = unsafe { active_page_table_root() };
    let mut copied = 0;
    while copied < target.len() {
        let user_address = source + copied as u64;
        let physical = translate_user_address(root, user_address, read_active_entry)?;
        let page_remaining = PAGE_SIZE - (user_address as usize & (PAGE_SIZE - 1));
        let length = core::cmp::min(page_remaining, target.len() - copied);
        let physical_end = physical
            .checked_add(length as u64)
            .ok_or(UserCopyError::UnmappedPhysicalMemory)?;
        if physical_end > EARLY_MAPPED_PHYSICAL_LIMIT {
            return Err(UserCopyError::UnmappedPhysicalMemory);
        }
        let source_pointer =
            direct_map_address(physical).ok_or(UserCopyError::UnmappedPhysicalMemory)? as *const u8;
        // SAFETY: The page walk verified a user-readable mapping, the direct
        // map covers this bounded physical span, and the local array cannot
        // overlap process memory.
        unsafe {
            core::ptr::copy_nonoverlapping(source_pointer, target.as_mut_ptr().add(copied), length);
        }
        copied += length;
    }
    Ok(())
}

#[cfg(target_os = "none")]
fn copy_to_user(target: u64, source: &[u8]) -> Result<(), UserCopyError> {
    if source.is_empty() {
        return Ok(());
    }
    let end = target
        .checked_add(source.len() as u64)
        .ok_or(UserCopyError::InvalidRange)?;
    if target < USER_ADDRESS_MINIMUM || end > USER_ADDRESS_LIMIT {
        return Err(UserCopyError::InvalidRange);
    }

    // SAFETY: The syscall gate retains the calling process hierarchy for the
    // duration of this bounded copy.
    let root = unsafe { active_page_table_root() };
    let mut copied = 0;
    while copied < source.len() {
        let user_address = target + copied as u64;
        let physical = translate_user_address_for_write(root, user_address, read_active_entry)?;
        let page_remaining = PAGE_SIZE - (user_address as usize & (PAGE_SIZE - 1));
        let length = core::cmp::min(page_remaining, source.len() - copied);
        let physical_end = physical
            .checked_add(length as u64)
            .ok_or(UserCopyError::UnmappedPhysicalMemory)?;
        if physical_end > EARLY_MAPPED_PHYSICAL_LIMIT {
            return Err(UserCopyError::UnmappedPhysicalMemory);
        }
        let target_pointer =
            direct_map_address(physical).ok_or(UserCopyError::UnmappedPhysicalMemory)? as *mut u8;
        // SAFETY: The page walk verified a user-writable mapping, the direct
        // map covers this span, and `source` is kernel-owned memory.
        unsafe {
            core::ptr::copy_nonoverlapping(source.as_ptr().add(copied), target_pointer, length);
        }
        copied += length;
    }
    Ok(())
}

#[cfg(target_os = "none")]
fn copy_value_to_user<T>(target: u64, value: &T) -> Result<(), UserCopyError> {
    // SAFETY: All callers use C wire structures whose padding is explicit and
    // initialized, so their complete object representation may be copied.
    let bytes = unsafe {
        core::slice::from_raw_parts((value as *const T).cast::<u8>(), core::mem::size_of::<T>())
    };
    copy_to_user(target, bytes)
}

#[cfg(target_os = "none")]
fn kairos_query_to_user(arguments: [u64; 6]) -> isize {
    use ::kairos::wire::{RawCpuEntry, RawDomainEntry, RawTopologyHeader, RawTopologyReply};

    if arguments[1] != core::mem::size_of::<RawTopologyReply>() as u64 {
        return ERROR_INVALID_ARGUMENT;
    }
    let destination = arguments[0];
    let Ok(header) = crate::kairos::topology_header() else {
        return ERROR_NOT_IMPLEMENTED;
    };
    if copy_value_to_user(destination, &header).is_err() {
        return ERROR_BAD_ADDRESS;
    }

    let cpu_base = destination + core::mem::size_of::<RawTopologyHeader>() as u64;
    for index in 0..header.cpu_count as usize {
        let Ok(entry) = crate::kairos::cpu_entry(index) else {
            return ERROR_NOT_IMPLEMENTED;
        };
        let target = cpu_base + (index * core::mem::size_of::<RawCpuEntry>()) as u64;
        if copy_value_to_user(target, &entry).is_err() {
            return ERROR_BAD_ADDRESS;
        }
    }

    let domain_base = destination + core::mem::offset_of!(RawTopologyReply, domains) as u64;
    for index in 0..header.domain_count as usize {
        let Ok(entry) = crate::kairos::domain_entry(index) else {
            return ERROR_NOT_IMPLEMENTED;
        };
        let target = domain_base + (index * core::mem::size_of::<RawDomainEntry>()) as u64;
        if copy_value_to_user(target, &entry).is_err() {
            return ERROR_BAD_ADDRESS;
        }
    }
    0
}

#[cfg(target_os = "none")]
fn kairos_abi_to_user(arguments: [u64; 6]) -> isize {
    use ::kairos::wire::{AbiReply, AbiRequest};

    if arguments[1] != core::mem::size_of::<AbiRequest>() as u64
        || arguments[3] != core::mem::size_of::<AbiReply>() as u64
    {
        return ERROR_INVALID_ARGUMENT;
    }
    let mut bytes = [0_u8; core::mem::size_of::<AbiRequest>()];
    if copy_from_user(arguments[0], &mut bytes).is_err() {
        return ERROR_BAD_ADDRESS;
    }
    // SAFETY: The byte array contains exactly one fully initialized request;
    // every field accepts all integer bit patterns. Unaligned access is used
    // because the byte array itself has alignment one.
    let request = unsafe { bytes.as_ptr().cast::<AbiRequest>().read_unaligned() };
    let reply = crate::kairos::negotiate_request(request);
    if copy_value_to_user(arguments[2], &reply).is_err() {
        return ERROR_BAD_ADDRESS;
    }
    0
}

#[cfg(target_os = "none")]
fn read_active_entry(table: u64, index: usize) -> Option<u64> {
    if table & (PAGE_SIZE as u64 - 1) != 0 || index >= 512 {
        return None;
    }
    let offset = (index * core::mem::size_of::<u64>()) as u64;
    let physical = table.checked_add(offset)?;
    if physical.checked_add(8)? > EARLY_MAPPED_PHYSICAL_LIMIT {
        return None;
    }
    let pointer = direct_map_address(physical)? as *const u64;
    // SAFETY: The active root and all process page-table frames are retained,
    // page-aligned allocator-owned memory covered by the immutable direct map.
    Some(unsafe { pointer.read_volatile() })
}

#[cfg(any(target_os = "none", test))]
fn translate_user_address(
    root: u64,
    address: u64,
    read_entry: impl FnMut(u64, usize) -> Option<u64>,
) -> Result<u64, UserCopyError> {
    translate_user_address_with_access(root, address, false, read_entry)
}

#[cfg(any(target_os = "none", test))]
fn translate_user_address_for_write(
    root: u64,
    address: u64,
    read_entry: impl FnMut(u64, usize) -> Option<u64>,
) -> Result<u64, UserCopyError> {
    translate_user_address_with_access(root, address, true, read_entry)
}

#[cfg(any(target_os = "none", test))]
fn translate_user_address_with_access(
    root: u64,
    address: u64,
    write: bool,
    mut read_entry: impl FnMut(u64, usize) -> Option<u64>,
) -> Result<u64, UserCopyError> {
    if root == 0 || root & (PAGE_SIZE as u64 - 1) != 0 || !valid_user_control_address(address) {
        return Err(UserCopyError::InvalidRange);
    }
    let indices = [
        ((address >> 39) & 0x1ff) as usize,
        ((address >> 30) & 0x1ff) as usize,
        ((address >> 21) & 0x1ff) as usize,
        ((address >> 12) & 0x1ff) as usize,
    ];
    if indices[0] >= 256 {
        return Err(UserCopyError::InvalidRange);
    }

    let mut table = root;
    for index in &indices[..3] {
        let entry = read_entry(table, *index).ok_or(UserCopyError::MissingMapping)?;
        if entry & (ENTRY_PRESENT | ENTRY_USER) != ENTRY_PRESENT | ENTRY_USER {
            return Err(UserCopyError::PermissionDenied);
        }
        if write && entry & ENTRY_WRITABLE == 0 {
            return Err(UserCopyError::PermissionDenied);
        }
        if entry & ENTRY_HUGE != 0 {
            return Err(UserCopyError::HugePageUnsupported);
        }
        table = entry & PAGE_ADDRESS_MASK;
    }
    let leaf = read_entry(table, indices[3]).ok_or(UserCopyError::MissingMapping)?;
    if leaf & (ENTRY_PRESENT | ENTRY_USER) != ENTRY_PRESENT | ENTRY_USER {
        return Err(UserCopyError::PermissionDenied);
    }
    if write && leaf & ENTRY_WRITABLE == 0 {
        return Err(UserCopyError::PermissionDenied);
    }
    Ok((leaf & PAGE_ADDRESS_MASK) | (address & (PAGE_SIZE as u64 - 1)))
}

#[cfg(any(target_os = "none", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UserCopyError {
    InvalidRange,
    MissingMapping,
    PermissionDenied,
    HugePageUnsupported,
    #[cfg(target_os = "none")]
    UnmappedPhysicalMemory,
}

#[cfg(target_os = "none")]
fn nexus_control_from_user(arguments: [u64; 6]) -> isize {
    use crate::arch::{Active, Architecture};
    use aether::nexus_wire::{NexusCommand, NexusReply};

    if arguments[2] != core::mem::size_of::<NexusCommand>() as u64
        || arguments[3] != core::mem::size_of::<NexusReply>() as u64
    {
        return ERROR_INVALID_ARGUMENT;
    }

    let mut command = NexusCommand::ZERO;

    // SAFETY: NexusCommand contains only integer fields and initialized arrays.
    // The byte slice covers the complete 64-byte wire object.
    let command_bytes = unsafe {
        core::slice::from_raw_parts_mut(
            (&mut command as *mut NexusCommand).cast::<u8>(),
            core::mem::size_of::<NexusCommand>(),
        )
    };

    if copy_from_user(arguments[0], command_bytes).is_err() {
        return ERROR_BAD_ADDRESS;
    }

    let wall_tick = Active::counter_sample();
    let reply = crate::nexus_runtime::control(&command, wall_tick);

    if copy_value_to_user(arguments[1], &reply).is_err() {
        return ERROR_BAD_ADDRESS;
    }

    0
}

#[cfg(target_os = "none")]
fn nexus_telemetry_to_user(arguments: [u64; 6]) -> isize {
    use crate::arch::{Active, Architecture};
    use aether::nexus_wire::NexusTelemetry;

    if arguments[1] != core::mem::size_of::<NexusTelemetry>() as u64 {
        return ERROR_INVALID_ARGUMENT;
    }

    let sequence = arguments[2];
    let telemetry = crate::nexus_runtime::telemetry(sequence, Active::counter_sample());

    if copy_value_to_user(arguments[0], &telemetry).is_err() {
        return ERROR_BAD_ADDRESS;
    }

    core::mem::size_of::<NexusTelemetry>() as isize
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::context::{DispatchContext, SavedUserContext};
    use crate::process::lifecycle::ProcessHandle;

    #[test]
    fn akashic_wire_layout_matches_slope() {
        assert_eq!(core::mem::size_of::<AkashicRawStat>(), 32);
        assert_eq!(
            core::mem::size_of::<AkashicRawDirent>(),
            crate::akashic_vfs::MAXIMUM_PATH_BYTES + 8
        );
    }

    #[test]
    fn akashic_errors_have_stable_errno_mapping() {
        use crate::akashic_vfs::VfsError;

        assert_eq!(map_akashic_error(VfsError::NotFound), -2);
        assert_eq!(map_akashic_error(VfsError::InvalidHandle), -9);
        assert_eq!(map_akashic_error(VfsError::PermissionDenied), -13);
        assert_eq!(map_akashic_error(VfsError::AlreadyExists), -17);
        assert_eq!(map_akashic_error(VfsError::NotDirectory), -20);
        assert_eq!(map_akashic_error(VfsError::NotFile), -21);
        assert_eq!(map_akashic_error(VfsError::FileTooLarge), -27);
        assert_eq!(map_akashic_error(VfsError::Capacity), -28);
        assert_eq!(map_akashic_error(VfsError::DirectoryNotEmpty), -39);
        assert_eq!(map_akashic_error(VfsError::Unsupported), -95);
    }

    #[test]
    fn scheduled_context_overwrites_the_complete_syscall_return_frame() {
        let mut frame = AuthorizedUserReturn::EMPTY;
        frame.dispatch.user = SavedUserContext::initial(0x2000, 0x8000);
        frame.dispatch.user.r15 = 1;
        frame.dispatch.user.rbx = 2;
        frame.dispatch.user.rax = grimoire::SYS_YIELD as u64;

        let mut next_user = SavedUserContext::initial(0x3000, 0x9000);
        next_user.r15 = 0x15;
        next_user.rbx = 0xb;
        let next = ScheduledProcess {
            handle: ProcessHandle {
                pid: 7,
                generation: 11,
            },
            context: DispatchContext {
                user: next_user,
                address_space_root: 0x4000,
                kernel_stack_pointer: 0xffff_8000_0000_8000,
                fs_base: 0x7000,
            },
            scheduler_epoch: 19,
        };

        assert_eq!(
            install_scheduled_return(&mut frame, next),
            Ok(next.authorized_return())
        );
        assert_eq!(frame, next.authorized_return());
    }

    #[test]
    fn monotonic_clock_split_preserves_seconds_and_subseconds() {
        assert_eq!(split_monotonic_nanoseconds(2_345_678_901), (2, 345_678_901));
    }

    #[test]
    fn utsname_wire_layout_matches_linux() {
        assert_eq!(core::mem::size_of::<LinuxUtsName>(), 390);
        assert_eq!(core::mem::size_of::<LinuxTimespec>(), 16);
        assert_eq!(core::mem::size_of::<LinuxStat>(), 144);
    }

    #[test]
    fn timerfd_wire_layout_and_timespec_validation_are_bounded() {
        assert_eq!(core::mem::size_of::<LinuxItimerspec>(), 32);
        let encoded = nanoseconds_to_timespec(2_345_678_901);
        assert_eq!(
            encoded,
            LinuxTimespec {
                tv_sec: 2,
                tv_nsec: 345_678_901
            }
        );
        assert_eq!(timespec_to_nanoseconds(encoded), Some(2_345_678_901));
        assert_eq!(
            timespec_to_nanoseconds(LinuxTimespec {
                tv_sec: -1,
                tv_nsec: 0,
            }),
            None
        );
        assert_eq!(
            timespec_to_nanoseconds(LinuxTimespec {
                tv_sec: 0,
                tv_nsec: 1_000_000_000,
            }),
            None
        );
    }

    fn encoded_tss_descriptor(base: u64, limit: u32, present: bool, kind: u64) -> (u64, u64) {
        let mut low = u64::from(limit & 0xffff)
            | (base & 0xffff) << 16
            | ((base >> 16) & 0xff) << 32
            | (kind & 0xf) << 40
            | (u64::from(limit >> 16) & 0xf) << 48
            | ((base >> 24) & 0xff) << 56;
        if present {
            low |= 1 << 47;
        }
        (low, base >> 32)
    }

    #[test]
    fn task_state_descriptor_decode_rejects_non_tss_privilege_state() {
        let base = 0xffff_8000_1234_5000;
        let (low, high) = encoded_tss_descriptor(base, 103, true, 0xb);
        assert_eq!(
            decode_task_state_descriptor(low, high),
            Ok(TaskStateDescriptor { base, limit: 103 })
        );

        let (not_present, high) = encoded_tss_descriptor(base, 103, false, 0xb);
        assert_eq!(
            decode_task_state_descriptor(not_present, high),
            Err(TaskStateDescriptorError::NotPresent)
        );
        let (wrong_kind, high) = encoded_tss_descriptor(base, 103, true, 0x2);
        assert_eq!(
            decode_task_state_descriptor(wrong_kind, high),
            Err(TaskStateDescriptorError::NotTaskStateSegment)
        );
        let (truncated, high) = encoded_tss_descriptor(base, 11, true, 0x9);
        assert_eq!(
            decode_task_state_descriptor(truncated, high),
            Err(TaskStateDescriptorError::Truncated)
        );
    }

    fn mapped_entry(physical: u64) -> u64 {
        physical | ENTRY_PRESENT | ENTRY_USER
    }

    fn writable_entry(physical: u64) -> u64 {
        mapped_entry(physical) | ENTRY_WRITABLE
    }

    #[test]
    fn dispatch_exposes_only_implemented_non_pointer_work() {
        assert_eq!(dispatch(grimoire::SYS_YIELD, [0; 6]), 0);
        assert_eq!(dispatch(grimoire::SYS_EXIT, [0; 6]), ERROR_NOT_IMPLEMENTED);
        assert_eq!(dispatch(99, [0; 6]), ERROR_NOT_IMPLEMENTED);
        assert_eq!(
            dispatch(grimoire::SYS_WRITE, [2, 0, 0, 0, 0, 0]),
            ERROR_BAD_FILE_DESCRIPTOR
        );
    }

    #[test]
    fn yield_hint_storage_is_scalar_and_bounded_to_the_call() {
        LAST_YIELD_HINT.store(0x55aa, Ordering::Release);
        assert_eq!(last_yield_hint(), 0x55aa);
    }

    #[test]
    fn translates_a_user_page_through_all_four_levels() {
        let result = translate_user_address(0x1000, 0x1234, |table, index| match (table, index) {
            (0x1000, 0) => Some(mapped_entry(0x2000)),
            (0x2000, 0) => Some(mapped_entry(0x3000)),
            (0x3000, 0) => Some(mapped_entry(0x4000)),
            (0x4000, 1) => Some(mapped_entry(0x9000)),
            _ => None,
        });
        assert_eq!(result, Ok(0x9234));
    }

    #[test]
    fn rejects_supervisor_and_huge_page_paths() {
        let supervisor =
            translate_user_address(0x1000, 0x1000, |table, index| match (table, index) {
                (0x1000, 0) => Some(0x2000 | ENTRY_PRESENT),
                _ => None,
            });
        assert_eq!(supervisor, Err(UserCopyError::PermissionDenied));

        let huge = translate_user_address(0x1000, 0x1000, |table, index| match (table, index) {
            (0x1000, 0) => Some(mapped_entry(0x2000) | ENTRY_HUGE),
            _ => None,
        });
        assert_eq!(huge, Err(UserCopyError::HugePageUnsupported));
    }

    #[test]
    fn write_translation_requires_writable_hierarchy() {
        let read_only =
            translate_user_address_for_write(0x1000, 0x1000, |table, index| match (table, index) {
                (0x1000, 0) => Some(mapped_entry(0x2000)),
                (0x2000, 0) => Some(writable_entry(0x3000)),
                (0x3000, 0) => Some(writable_entry(0x4000)),
                (0x4000, 1) => Some(writable_entry(0x9000)),
                _ => None,
            });
        assert_eq!(read_only, Err(UserCopyError::PermissionDenied));

        let writable =
            translate_user_address_for_write(0x1000, 0x1234, |table, index| match (table, index) {
                (0x1000, 0) => Some(writable_entry(0x2000)),
                (0x2000, 0) => Some(writable_entry(0x3000)),
                (0x3000, 0) => Some(writable_entry(0x4000)),
                (0x4000, 1) => Some(writable_entry(0x9000)),
                _ => None,
            });
        assert_eq!(writable, Ok(0x9234));
    }
}
