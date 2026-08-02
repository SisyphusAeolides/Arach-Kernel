//! Persistent ownership for installed user address spaces.
//!
//! Bootstrap constructs the first user images, then transfers the backend to
//! this runtime before Ring 3 is entered. A retiring image is released only
//! after the return path has switched CR3 away from that image's root.

use blacklab::oureboros::{ArtifactMeasurement, sha256};

use crate::capability::RuntimeImageControl;
use crate::process::image::UserImageError;
#[cfg(target_os = "none")]
use crate::process::image::{
    prepare_runtime_dynamic_image, prepare_runtime_linker_image, prepare_runtime_user_image,
};
use crate::process::install::{InstallError, ProcessImageHandle, UserAddressSpaceBackend};
#[cfg(target_os = "none")]
use crate::process::install::{install_runtime_linked_user_image, install_runtime_user_image};
#[cfg(target_os = "none")]
use crate::process::x86_64::LinuxAuxiliaryVector;
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
    Image(UserImageError),
    Install(InstallError<FrameBackedError<DirectMapMemoryError>>),
    Backend(FrameBackedError<DirectMapMemoryError>),
}

pub struct RuntimeReplacement {
    pub process: ProcessImageHandle,
    pub entry_point: u64,
    pub user_stack_pointer: u64,
    pub address_space_root: u64,
    pub image_measurement_root: u64,
    pub measurement: ArtifactMeasurement,
    pub runtime_linker_measurement: Option<ArtifactMeasurement>,
}

struct ProcessRuntime {
    backend: KernelProcessBackend,
    #[cfg(target_os = "none")]
    image_control: RuntimeImageControl,
    pending_reap: Option<ProcessImageHandle>,
}

static RUNTIME: SpinLock<Option<ProcessRuntime>> = SpinLock::new(None);

/// Transfers the boot-installed address-space backend into persistent kernel
/// ownership. This is a one-way handoff made before the first Ring 3 entry.
pub fn install(
    backend: KernelProcessBackend,
    _image_control: RuntimeImageControl,
) -> Result<(), ProcessRuntimeError> {
    let mut runtime = RUNTIME.lock();
    if runtime.is_some() {
        return Err(ProcessRuntimeError::AlreadyInstalled);
    }
    *runtime = Some(ProcessRuntime {
        backend,
        #[cfg(target_os = "none")]
        image_control: _image_control,
        pending_reap: None,
    });
    Ok(())
}

/// Installs and activation-validates a measured static ELF replacement while
/// the former image remains active and untouched.
///
/// The returned handle is not yet published to lifecycle ownership. Callers
/// must either atomically exchange it into the service registry or return it
/// through [`discard_exec_image`].
#[cfg(target_os = "none")]
pub fn install_exec_image(
    inode_id: u32,
    bytes: &[u8],
    argv: &[&[u8]],
    envp: &[&[u8]],
) -> Result<RuntimeReplacement, ProcessRuntimeError> {
    let mut runtime = RUNTIME.lock();
    let runtime = runtime.as_mut().ok_or(ProcessRuntimeError::Unavailable)?;
    if runtime.pending_reap.is_some() {
        return Err(ProcessRuntimeError::ReapAlreadyPending);
    }
    let image = prepare_runtime_user_image(inode_id, bytes, &runtime.image_control)
        .map_err(ProcessRuntimeError::Image)?;
    let installed = install_runtime_user_image(image, &mut runtime.backend, &runtime.image_control)
        .map_err(ProcessRuntimeError::Install)?;
    let process = installed.process;
    if let Err(error) = runtime
        .backend
        .install_runtime_stack(&process, &runtime.image_control)
    {
        discard_failed_install(runtime, process);
        return Err(ProcessRuntimeError::Backend(error));
    }
    let user_stack_pointer = match runtime.backend.prepare_initial_stack(&process, argv, envp) {
        Ok(pointer) => pointer,
        Err(error) => {
            discard_failed_install(runtime, process);
            return Err(ProcessRuntimeError::Backend(error));
        }
    };
    // SAFETY: The syscall gate is serialized with interrupts masked. The new
    // image is not lifecycle-visible, and validation restores the old active
    // root before returning.
    if let Err(error) = unsafe {
        runtime
            .backend
            .validate_runtime_activation(&process, &runtime.image_control)
    } {
        discard_failed_install(runtime, process);
        return Err(ProcessRuntimeError::Backend(error));
    }
    let Some(info) = runtime.backend.process_info(&process) else {
        discard_failed_install(runtime, process);
        return Err(ProcessRuntimeError::Unavailable);
    };
    let Some(address_space_root) = info.address_space_root else {
        discard_failed_install(runtime, process);
        return Err(ProcessRuntimeError::Unavailable);
    };
    Ok(RuntimeReplacement {
        process,
        entry_point: installed.entry_point,
        user_stack_pointer,
        address_space_root,
        image_measurement_root: fold_measurement_root(installed.measurement.sha256),
        measurement: installed.measurement,
        runtime_linker_measurement: None,
    })
}

/// Installs and activation-validates a measured main ELF plus its separately
/// measured ET_DYN runtime linker. Both images share one unpublished
/// hierarchy and one Linux auxiliary-vector stack.
#[cfg(target_os = "none")]
#[allow(clippy::too_many_arguments)]
pub fn install_dynamic_exec_image(
    executable_inode_id: u32,
    executable_bytes: &[u8],
    runtime_linker_inode_id: u32,
    runtime_linker_bytes: &[u8],
    executable_path: &[u8],
    argv: &[&[u8]],
    envp: &[&[u8]],
) -> Result<RuntimeReplacement, ProcessRuntimeError> {
    let mut runtime = RUNTIME.lock();
    let runtime = runtime.as_mut().ok_or(ProcessRuntimeError::Unavailable)?;
    if runtime.pending_reap.is_some() {
        return Err(ProcessRuntimeError::ReapAlreadyPending);
    }
    let executable = prepare_runtime_dynamic_image(
        executable_inode_id,
        executable_bytes,
        &runtime.image_control,
    )
    .map_err(ProcessRuntimeError::Image)?;
    let runtime_linker = prepare_runtime_linker_image(
        runtime_linker_inode_id,
        runtime_linker_bytes,
        &runtime.image_control,
    )
    .map_err(ProcessRuntimeError::Image)?;
    let installed = install_runtime_linked_user_image(
        executable,
        runtime_linker,
        &mut runtime.backend,
        &runtime.image_control,
    )
    .map_err(ProcessRuntimeError::Install)?;
    let process = installed.process;
    if let Err(error) = runtime
        .backend
        .install_runtime_stack(&process, &runtime.image_control)
    {
        discard_failed_install(runtime, process);
        return Err(ProcessRuntimeError::Backend(error));
    }
    let random = derive_auxiliary_random(
        installed.executable_measurement.sha256,
        installed.runtime_linker_measurement.sha256,
        process.generation(),
    );
    let user_stack_pointer = match runtime.backend.prepare_linux_dynamic_stack(
        &process,
        argv,
        envp,
        LinuxAuxiliaryVector {
            program_header_address: installed.executable_program_header,
            program_header_count: installed.executable_program_header_count,
            runtime_linker_base: installed.runtime_linker_base,
            executable_entry_point: installed.executable_entry_point,
            executable_path,
            random,
        },
    ) {
        Ok(pointer) => pointer,
        Err(error) => {
            discard_failed_install(runtime, process);
            return Err(ProcessRuntimeError::Backend(error));
        }
    };
    // SAFETY: The syscall gate is serialized with interrupts masked. The
    // composite image is not lifecycle-visible, and validation restores the
    // former active root before returning.
    if let Err(error) = unsafe {
        runtime
            .backend
            .validate_runtime_activation(&process, &runtime.image_control)
    } {
        discard_failed_install(runtime, process);
        return Err(ProcessRuntimeError::Backend(error));
    }
    let Some(info) = runtime.backend.process_info(&process) else {
        discard_failed_install(runtime, process);
        return Err(ProcessRuntimeError::Unavailable);
    };
    let Some(address_space_root) = info.address_space_root else {
        discard_failed_install(runtime, process);
        return Err(ProcessRuntimeError::Unavailable);
    };
    Ok(RuntimeReplacement {
        process,
        entry_point: installed.entry_point,
        user_stack_pointer,
        address_space_root,
        image_measurement_root: fold_linked_measurement_root(
            installed.executable_measurement.sha256,
            installed.runtime_linker_measurement.sha256,
        ),
        measurement: installed.executable_measurement,
        runtime_linker_measurement: Some(installed.runtime_linker_measurement),
    })
}

#[cfg(target_os = "none")]
fn derive_auxiliary_random(
    executable_digest: [u8; 32],
    runtime_linker_digest: [u8; 32],
    process_generation: u32,
) -> [u8; 16] {
    use crate::arch::Architecture;

    let mut material = [0_u8; 84];
    material[..32].copy_from_slice(&executable_digest);
    material[32..64].copy_from_slice(&runtime_linker_digest);
    material[64..72].copy_from_slice(&crate::interrupts::monotonic_nanoseconds().to_le_bytes());
    material[72..80].copy_from_slice(&crate::arch::Active::counter_sample().to_le_bytes());
    material[80..84].copy_from_slice(&process_generation.to_le_bytes());
    let digest = sha256(&material);
    let mut random = [0_u8; 16];
    random.copy_from_slice(&digest[..16]);
    random
}

#[cfg(target_os = "none")]
fn discard_failed_install(runtime: &mut ProcessRuntime, process: ProcessImageHandle) {
    if runtime.backend.release_process(&process).is_err() {
        runtime.pending_reap = Some(process);
    }
}

#[cfg(target_os = "none")]
pub fn discard_exec_image(process: ProcessImageHandle) -> Result<(), ProcessRuntimeError> {
    let mut runtime = RUNTIME.lock();
    let runtime = runtime.as_mut().ok_or(ProcessRuntimeError::Unavailable)?;
    match runtime.backend.release_process(&process) {
        Ok(()) => Ok(()),
        Err(error) => {
            if runtime.pending_reap.is_none() {
                runtime.pending_reap = Some(process);
            }
            Err(ProcessRuntimeError::Backend(error))
        }
    }
}

pub const fn fold_measurement_root(digest: [u8; 32]) -> u64 {
    let mut root = 0_u64;
    let mut index = 0;
    while index < 4 {
        let offset = index * 8;
        let word = u64::from_le_bytes([
            digest[offset],
            digest[offset + 1],
            digest[offset + 2],
            digest[offset + 3],
            digest[offset + 4],
            digest[offset + 5],
            digest[offset + 6],
            digest[offset + 7],
        ]);
        root ^= word.rotate_left((index as u32) * 13);
        index += 1;
    }
    if root == 0 { 1 } else { root }
}

pub fn fold_linked_measurement_root(
    executable_digest: [u8; 32],
    runtime_linker_digest: [u8; 32],
) -> u64 {
    let mut transcript = [0_u8; 64];
    transcript[..32].copy_from_slice(&executable_digest);
    transcript[32..].copy_from_slice(&runtime_linker_digest);
    fold_measurement_root(sha256(&transcript))
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

/// Services one eager private file mapping against the exact lifecycle root.
/// `initialized` is already a descriptor-authorized immutable snapshot; the
/// backend copies it into newly owned frames before publishing the VMA.
#[cfg(target_os = "none")]
pub fn linux_mmap_file_current(
    hint: u64,
    length: usize,
    permissions: crate::process::install::MappingPermissions,
    initialized: &[u8],
) -> Result<u64, ProcessRuntimeError> {
    let snapshot = crate::process::lifecycle::current_handle()
        .and_then(crate::process::lifecycle::snapshot_exact)
        .ok_or(ProcessRuntimeError::Unavailable)?;
    let mut runtime = RUNTIME.lock();
    let runtime = runtime.as_mut().ok_or(ProcessRuntimeError::Unavailable)?;
    runtime
        .backend
        .linux_mmap_file_for_root(
            snapshot.launch.address_space_root,
            hint,
            length,
            permissions,
            initialized,
        )
        .map_err(ProcessRuntimeError::Backend)
}

#[cfg(target_os = "none")]
pub fn linux_shared_memory_create(identity: u32) -> Result<(), ProcessRuntimeError> {
    let mut runtime = RUNTIME.lock();
    let runtime = runtime.as_mut().ok_or(ProcessRuntimeError::Unavailable)?;
    runtime
        .backend
        .linux_shared_memory_create(identity)
        .map_err(ProcessRuntimeError::Backend)
}

#[cfg(target_os = "none")]
pub fn linux_shared_memory_resize(
    identity: u32,
    expected_size: usize,
    size_bytes: usize,
) -> Result<(), ProcessRuntimeError> {
    let mut runtime = RUNTIME.lock();
    let runtime = runtime.as_mut().ok_or(ProcessRuntimeError::Unavailable)?;
    runtime
        .backend
        .linux_shared_memory_resize(identity, expected_size, size_bytes)
        .map_err(ProcessRuntimeError::Backend)
}

#[cfg(target_os = "none")]
pub fn linux_shared_memory_close(identity: u32) -> Result<(), ProcessRuntimeError> {
    let mut runtime = RUNTIME.lock();
    let runtime = runtime.as_mut().ok_or(ProcessRuntimeError::Unavailable)?;
    runtime
        .backend
        .linux_shared_memory_close(identity)
        .map_err(ProcessRuntimeError::Backend)
}

#[cfg(target_os = "none")]
pub fn linux_mmap_shared_current(
    identity: u32,
    hint: u64,
    length: usize,
    offset: usize,
    permissions: crate::process::install::MappingPermissions,
) -> Result<u64, ProcessRuntimeError> {
    let snapshot = crate::process::lifecycle::current_handle()
        .and_then(crate::process::lifecycle::snapshot_exact)
        .ok_or(ProcessRuntimeError::Unavailable)?;
    let mut runtime = RUNTIME.lock();
    let runtime = runtime.as_mut().ok_or(ProcessRuntimeError::Unavailable)?;
    runtime
        .backend
        .linux_mmap_shared_for_root(
            snapshot.launch.address_space_root,
            identity,
            hint,
            length,
            offset,
            permissions,
        )
        .map_err(ProcessRuntimeError::Backend)
}

/// Changes one complete private VMA for the exact lifecycle-published root.
/// The architecture return gate reloads that root before Ring 3 resumes,
/// flushing stale non-global translations after the page-table transaction.
#[cfg(target_os = "none")]
pub fn linux_mprotect_current(
    virtual_address: u64,
    length: usize,
    permissions: crate::process::install::MappingPermissions,
) -> Result<(), ProcessRuntimeError> {
    let snapshot = crate::process::lifecycle::current_handle()
        .and_then(crate::process::lifecycle::snapshot_exact)
        .ok_or(ProcessRuntimeError::Unavailable)?;
    let mut runtime = RUNTIME.lock();
    let runtime = runtime.as_mut().ok_or(ProcessRuntimeError::Unavailable)?;
    runtime
        .backend
        .linux_mprotect_for_root(
            snapshot.launch.address_space_root,
            virtual_address,
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

/// Services Linux `brk` against the exact generation-bound address space of
/// the currently running process.  The backend returns the new exact break
/// on success; the syscall layer can query with `requested == 0` to implement
/// Linux's "return the old break on failure" rule.
#[cfg(target_os = "none")]
pub fn linux_brk_current(requested: u64) -> Result<u64, ProcessRuntimeError> {
    let snapshot = crate::process::lifecycle::current_handle()
        .and_then(crate::process::lifecycle::snapshot_exact)
        .ok_or(ProcessRuntimeError::Unavailable)?;
    let mut runtime = RUNTIME.lock();
    let runtime = runtime.as_mut().ok_or(ProcessRuntimeError::Unavailable)?;
    runtime
        .backend
        .linux_brk_for_root(snapshot.launch.address_space_root, requested)
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
