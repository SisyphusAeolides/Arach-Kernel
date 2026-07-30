//! Measured service images admitted by the bootstrap loader.
//!
//! A `SYS_SPAWN` caller never supplies an instruction pointer or address-space
//! root. Those are immutable properties of an image that was measured,
//! installed, and activation-validated during serialized boot. The initial
//! registry deliberately retains one Crest image beside PID 1. On Crest's
//! exact terminal exit, the registry transfers that image to the runtime
//! reaper; it is released only after execution has left its page-table root.
//! This remains single-use until Arach can construct a fresh measured image.

use crate::sync::SpinLock;

use super::install::ProcessImageHandle;
use super::lifecycle::{self, INIT_PID, ProcessHandle, ProcessLaunch, ProcessPhase};

pub const CREST_SERVICE_CLASS: u16 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceRegistryError {
    InvalidLaunch,
    UnsupportedService,
    NotInit,
    AlreadyInstalled,
    AlreadyLaunched,
    UnauthorizedCaller,
    NotRunning,
    Lifecycle(lifecycle::LifecycleError),
}

struct ServiceImageRegistry {
    crest: Option<ProcessLaunch>,
    crest_image: Option<ProcessImageHandle>,
    crest_launched: bool,
    crest_handle: Option<ProcessHandle>,
}

impl ServiceImageRegistry {
    const EMPTY: Self = Self {
        crest: None,
        crest_image: None,
        crest_launched: false,
        crest_handle: None,
    };

    fn install_crest(
        &mut self,
        launch: ProcessLaunch,
        image: ProcessImageHandle,
    ) -> Result<(), ServiceRegistryError> {
        if !launch.validate() || launch.service_class != CREST_SERVICE_CLASS {
            return Err(ServiceRegistryError::InvalidLaunch);
        }
        if self.crest.is_some() {
            return Err(ServiceRegistryError::AlreadyInstalled);
        }
        self.crest = Some(launch);
        self.crest_image = Some(image);
        Ok(())
    }

    fn launch(
        &mut self,
        parent: u32,
        service_class: u16,
    ) -> Result<ProcessHandle, ServiceRegistryError> {
        if parent != INIT_PID {
            return Err(ServiceRegistryError::NotInit);
        }
        if service_class != CREST_SERVICE_CLASS {
            return Err(ServiceRegistryError::UnsupportedService);
        }
        if self.crest_launched {
            return Err(ServiceRegistryError::AlreadyLaunched);
        }
        let launch = self.crest.ok_or(ServiceRegistryError::UnsupportedService)?;
        let handle =
            lifecycle::commit_child(parent, launch).map_err(ServiceRegistryError::Lifecycle)?;
        self.crest_launched = true;
        self.crest_handle = Some(handle);
        Ok(handle)
    }

    fn authenticate_crest_caller(
        &self,
        caller: ProcessHandle,
    ) -> Result<ProcessHandle, ServiceRegistryError> {
        match self.crest_handle {
            Some(handle) if caller == handle => Ok(handle),
            _ => Err(ServiceRegistryError::UnauthorizedCaller),
        }
    }

    fn take_exited_crest(
        &mut self,
        caller: ProcessHandle,
    ) -> Result<Option<ProcessImageHandle>, ServiceRegistryError> {
        if self.crest_handle != Some(caller) {
            return Ok(None);
        }
        let snapshot = lifecycle::snapshot_exact(caller).ok_or(ServiceRegistryError::NotRunning)?;
        if snapshot.phase != ProcessPhase::Zombie {
            return Err(ServiceRegistryError::NotRunning);
        }
        let image = self
            .crest_image
            .take()
            .ok_or(ServiceRegistryError::NotRunning)?;
        self.crest_handle = None;
        Ok(Some(image))
    }
}

static REGISTRY: SpinLock<ServiceImageRegistry> = SpinLock::new(ServiceImageRegistry::EMPTY);

/// Publishes the already measured and activation-validated Crest image.
///
/// Bootstrap calls this exactly once before ring 3 is entered. Keeping the
/// registration separate from artifact installation ensures no syscall can
/// observe a partially prepared address space.
pub fn install_crest(
    launch: ProcessLaunch,
    image: ProcessImageHandle,
) -> Result<(), ServiceRegistryError> {
    REGISTRY.lock().install_crest(launch, image)
}

/// Creates a child from a boot-measured service image.
///
/// The registry lock covers lifecycle admission, so a failed PID allocation
/// does not consume the image slot.
pub fn launch(parent: u32, service_class: u16) -> Result<ProcessHandle, ServiceRegistryError> {
    REGISTRY.lock().launch(parent, service_class)
}

/// Returns the live Crest status word to that exact measured Crest process.
///
/// The low byte is the state (1 = running); bits 8..39 hold the PID. The
/// unexported process generation is checked before encoding rather than being
/// exposed to user space.
pub fn authenticated_crest_status(caller: ProcessHandle) -> Result<u64, ServiceRegistryError> {
    let handle = REGISTRY.lock().authenticate_crest_caller(caller)?;
    let snapshot = lifecycle::snapshot_exact(handle).ok_or(ServiceRegistryError::NotRunning)?;
    if snapshot.phase != lifecycle::ProcessPhase::Running
        || snapshot.launch.service_class != CREST_SERVICE_CLASS
    {
        return Err(ServiceRegistryError::NotRunning);
    }
    Ok((u64::from(handle.pid) << 8) | 1)
}

/// Transfers ownership of Crest's exact installed image after its lifecycle
/// entry is terminal. Non-Crest exits deliberately leave the registry alone.
pub fn take_exited_crest(
    caller: ProcessHandle,
) -> Result<Option<ProcessImageHandle>, ServiceRegistryError> {
    REGISTRY.lock().take_exited_crest(caller)
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn launch(service_class: u16) -> ProcessLaunch {
        ProcessLaunch {
            address_space_root: 0x3000,
            entry_point: 0x1000,
            user_stack_pointer: 0x4000,
            kernel_stack_pointer: 0xffff_8000_0000_4000,
            image_measurement_root: 1,
            capability_root: 2,
            service_class,
            priority: 1,
        }
    }

    #[test]
    fn only_accepts_a_complete_crest_launch() {
        let mut registry = ServiceImageRegistry::EMPTY;
        assert_eq!(
            registry.install_crest(launch(7), ProcessImageHandle::new(0, 1)),
            Err(ServiceRegistryError::InvalidLaunch)
        );
        let image = ProcessImageHandle::new(0, 1);
        assert_eq!(
            registry.install_crest(launch(CREST_SERVICE_CLASS), image),
            Ok(())
        );
        assert_eq!(
            registry.install_crest(launch(CREST_SERVICE_CLASS), ProcessImageHandle::new(0, 2)),
            Err(ServiceRegistryError::AlreadyInstalled)
        );
    }

    #[test]
    fn binds_aegis_observation_to_the_exact_crest_handle() {
        let mut registry = ServiceImageRegistry::EMPTY;
        registry.crest_handle = Some(ProcessHandle {
            pid: 2,
            generation: 3,
        });
        assert_eq!(
            registry.authenticate_crest_caller(ProcessHandle {
                pid: 2,
                generation: 3,
            }),
            Ok(ProcessHandle {
                pid: 2,
                generation: 3,
            })
        );
        assert_eq!(
            registry.authenticate_crest_caller(ProcessHandle {
                pid: 2,
                generation: 4,
            }),
            Err(ServiceRegistryError::UnauthorizedCaller)
        );
    }
}
