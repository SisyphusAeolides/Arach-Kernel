//! Persistent ownership for installed user address spaces.
//!
//! Bootstrap constructs the first user images, then transfers the backend to
//! this runtime before Ring 3 is entered. A retiring image is released only
//! after the return path has switched CR3 away from that image's root.

use crate::process::install::{ProcessImageHandle, UserAddressSpaceBackend};
use crate::process::x86_64::{
    DirectMapFrameMemory, DirectMapMemoryError, FrameBackedAddressSpace, FrameBackedError,
};
use crate::sync::SpinLock;

pub type KernelProcessBackend = FrameBackedAddressSpace<DirectMapFrameMemory<'static, 'static>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessRuntimeError {
    AlreadyInstalled,
    Unavailable,
    ReapAlreadyPending,
    Backend(FrameBackedError<DirectMapMemoryError>),
}

struct ProcessRuntime {
    backend: KernelProcessBackend,
    pending_reap: Option<ProcessImageHandle>,
}

static RUNTIME: SpinLock<Option<ProcessRuntime>> = SpinLock::new(None);

/// Transfers the boot-installed address-space backend into persistent kernel
/// ownership. This is a one-way handoff made before the first Ring 3 entry.
pub fn install(backend: KernelProcessBackend) -> Result<(), ProcessRuntimeError> {
    let mut runtime = RUNTIME.lock();
    if runtime.is_some() {
        return Err(ProcessRuntimeError::AlreadyInstalled);
    }
    *runtime = Some(ProcessRuntime {
        backend,
        pending_reap: None,
    });
    Ok(())
}

/// Records a fully stopped image for deferred reclamation.
///
/// The caller must arrange a CR3 transition before invoking
/// [`reap_after_root_switch`]. Keeping one pending record is intentional:
/// the scheduler serializes an exiting process, and a second retirement
/// before the first is reclaimed is an invariant failure rather than an
/// opportunity to lose image ownership.
pub fn defer_reap(image: ProcessImageHandle) -> Result<(), ProcessRuntimeError> {
    let mut runtime = RUNTIME.lock();
    let runtime = runtime.as_mut().ok_or(ProcessRuntimeError::Unavailable)?;
    if runtime.pending_reap.is_some() {
        return Err(ProcessRuntimeError::ReapAlreadyPending);
    }
    runtime.pending_reap = Some(image);
    Ok(())
}

/// Releases a deferred image after execution has moved to another valid CR3.
///
/// `FrameBackedAddressSpace` rejects release of the active root. On failure
/// the exact handle remains pending, so a later safe path cannot mistake a
/// partial failure for reclaimed ownership.
pub fn reap_after_root_switch() -> Result<bool, ProcessRuntimeError> {
    let mut runtime = RUNTIME.lock();
    let runtime = runtime.as_mut().ok_or(ProcessRuntimeError::Unavailable)?;
    let Some(image) = runtime.pending_reap.take() else {
        return Ok(false);
    };
    match runtime.backend.release_process(&image) {
        Ok(()) => Ok(true),
        Err(error) => {
            runtime.pending_reap = Some(image);
            Err(ProcessRuntimeError::Backend(error))
        }
    }
}

/// Services the Linux anonymous-memory subset against the exact lifecycle
/// root currently running.  The root lookup is repeated under the runtime
/// lock, so a recycled PID or a stale syscall frame cannot mutate another
/// process's page tables.
#[cfg(target_os = "none")]
pub fn linux_mmap_current(
    hint: u64,
    length: usize,
    permissions: crate::process::install::MappingPermissions,
) -> Result<u64, ProcessRuntimeError> {
    let snapshot = crate::process::lifecycle::current_handle()
        .and_then(crate::process::lifecycle::snapshot_exact)
        .ok_or(ProcessRuntimeError::Unavailable)?;
    let mut runtime = RUNTIME.lock();
    let runtime = runtime.as_mut().ok_or(ProcessRuntimeError::Unavailable)?;
    runtime
        .backend
        .linux_mmap_for_root(
            snapshot.launch.address_space_root,
            hint,
            length,
            permissions,
        )
        .map_err(ProcessRuntimeError::Backend)
}

#[cfg(target_os = "none")]
pub fn linux_munmap_current(
    virtual_address: u64,
    length: usize,
) -> Result<(), ProcessRuntimeError> {
    let snapshot = crate::process::lifecycle::current_handle()
        .and_then(crate::process::lifecycle::snapshot_exact)
        .ok_or(ProcessRuntimeError::Unavailable)?;
    let mut runtime = RUNTIME.lock();
    let runtime = runtime.as_mut().ok_or(ProcessRuntimeError::Unavailable)?;
    runtime
        .backend
        .linux_munmap_for_root(snapshot.launch.address_space_root, virtual_address, length)
        .map_err(ProcessRuntimeError::Backend)
}

/// Switches the idle scheduler path back to the immutable kernel root, then
/// drains any image retired by the syscall that selected PID0.
///
/// # Safety
///
/// The caller must be at a serialized kernel scheduling boundary with
/// interrupts masked. The retained kernel root maps the active kernel stack
/// and direct map used by the reaper.
#[cfg(target_os = "none")]
pub unsafe fn enter_kernel_idle_and_reap() -> Result<bool, ProcessRuntimeError> {
    use crate::arch::x86_64::load_page_table_root;

    let mut runtime = RUNTIME.lock();
    let runtime = runtime.as_mut().ok_or(ProcessRuntimeError::Unavailable)?;
    // SAFETY: The caller established the serialized kernel-root transition.
    unsafe { load_page_table_root(runtime.backend.kernel_root()) };
    let Some(image) = runtime.pending_reap.take() else {
        return Ok(false);
    };
    match runtime.backend.release_process(&image) {
        Ok(()) => Ok(true),
        Err(error) => {
            runtime.pending_reap = Some(image);
            Err(ProcessRuntimeError::Backend(error))
        }
    }
}
