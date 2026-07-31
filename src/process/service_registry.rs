//! Measured service images admitted by the bootstrap loader.
//!
//! A `SYS_SPAWN` caller never supplies an instruction pointer or address-space
//! root. Those are immutable properties of an image that was measured,
//! installed, and activation-validated during serialized boot. The registry
//! is deliberately fixed-capacity: every service class must be installed by
//! the bootstrap path before Ring 3 can request it.
//!
//! The original implementation had one hard-coded Crest slot. That made the
//! COSMIC supervisor's service graph look complete while the kernel could
//! only ever launch one compatibility probe. The table below admits all
//! measured classes (including the COSMIC dbus/compositor/greetd/session/
//! portal chain) without allowing user space to invent a launch image.

use crate::sync::SpinLock;

use super::install::ProcessImageHandle;
use super::lifecycle::{self, INIT_PID, ProcessHandle, ProcessLaunch, ProcessPhase};

/// Service class zero is reserved. Classes 1..15 are the bounded measured
/// service namespace shared with Push's `ServiceId` values.
pub const MAXIMUM_SERVICE_CLASSES: usize = 16;
pub const PID1_SERVICE_CLASS: u16 = 1;
pub const CREST_SERVICE_CLASS: u16 = 2;
pub const ARGUS_SERVICE_CLASS: u16 = 3;
pub const DBUS_BROKER_SERVICE_CLASS: u16 = 4;
pub const COSMIC_COMPOSITOR_SERVICE_CLASS: u16 = 5;
pub const COSMIC_GREETER_SERVICE_CLASS: u16 = 6;
pub const COSMIC_SESSION_SERVICE_CLASS: u16 = 7;
pub const XDG_PORTAL_SERVICE_CLASS: u16 = 8;
pub const SEATD_SERVICE_CLASS: u16 = 9;
pub const PIPEWIRE_SERVICE_CLASS: u16 = 10;
pub const WIREPLUMBER_SERVICE_CLASS: u16 = 11;

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

/// `ProcessImageHandle` is intentionally non-Copy because it represents
/// ownership of installed page-table frames. The registry stores only its
/// opaque slot/generation identity and reconstructs the handle exactly once
/// when the lifecycle reaches a terminal state.
#[derive(Clone, Copy)]
struct ImageSlot {
    occupied: bool,
    slot: u16,
    generation: u32,
}

impl ImageSlot {
    const EMPTY: Self = Self {
        occupied: false,
        slot: 0,
        generation: 0,
    };

    fn from_handle(handle: &ProcessImageHandle) -> Self {
        Self {
            occupied: true,
            slot: handle.slot(),
            generation: handle.generation(),
        }
    }

    fn take(&mut self) -> Option<ProcessImageHandle> {
        if !self.occupied {
            return None;
        }
        let handle = ProcessImageHandle::new(self.slot, self.generation);
        self.occupied = false;
        self.slot = 0;
        self.generation = 0;
        Some(handle)
    }
}

struct ServiceImageRegistry {
    launches: [Option<ProcessLaunch>; MAXIMUM_SERVICE_CLASSES],
    images: [ImageSlot; MAXIMUM_SERVICE_CLASSES],
    launched: [bool; MAXIMUM_SERVICE_CLASSES],
    handles: [Option<ProcessHandle>; MAXIMUM_SERVICE_CLASSES],
}

impl ServiceImageRegistry {
    const EMPTY: Self = Self {
        launches: [None; MAXIMUM_SERVICE_CLASSES],
        images: [ImageSlot::EMPTY; MAXIMUM_SERVICE_CLASSES],
        launched: [false; MAXIMUM_SERVICE_CLASSES],
        handles: [None; MAXIMUM_SERVICE_CLASSES],
    };

    fn index(service_class: u16) -> Option<usize> {
        let index = service_class as usize;
        (service_class != 0 && index < MAXIMUM_SERVICE_CLASSES).then_some(index)
    }

    fn install(
        &mut self,
        launch: ProcessLaunch,
        image: ProcessImageHandle,
    ) -> Result<(), ServiceRegistryError> {
        let Some(index) = Self::index(launch.service_class) else {
            return Err(ServiceRegistryError::UnsupportedService);
        };
        if !launch.validate() {
            return Err(ServiceRegistryError::InvalidLaunch);
        }
        if self.launches[index].is_some() || self.images[index].occupied {
            return Err(ServiceRegistryError::AlreadyInstalled);
        }
        self.launches[index] = Some(launch);
        self.images[index] = ImageSlot::from_handle(&image);
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
        let Some(index) = Self::index(service_class) else {
            return Err(ServiceRegistryError::UnsupportedService);
        };
        if self.launched[index] {
            return Err(ServiceRegistryError::AlreadyLaunched);
        }
        let launch = self.launches[index].ok_or(ServiceRegistryError::UnsupportedService)?;
        if !self.images[index].occupied {
            return Err(ServiceRegistryError::UnsupportedService);
        }
        let handle =
            lifecycle::commit_child(parent, launch).map_err(ServiceRegistryError::Lifecycle)?;
        self.launched[index] = true;
        self.handles[index] = Some(handle);
        Ok(handle)
    }

    fn authenticate_caller(
        &self,
        caller: ProcessHandle,
        service_class: u16,
    ) -> Result<ProcessHandle, ServiceRegistryError> {
        let Some(index) = Self::index(service_class) else {
            return Err(ServiceRegistryError::UnsupportedService);
        };
        match self.handles[index] {
            Some(handle) if caller == handle => Ok(handle),
            _ => Err(ServiceRegistryError::UnauthorizedCaller),
        }
    }

    fn take_exited(
        &mut self,
        caller: ProcessHandle,
    ) -> Result<Option<ProcessImageHandle>, ServiceRegistryError> {
        let snapshot = lifecycle::snapshot_exact(caller).ok_or(ServiceRegistryError::NotRunning)?;
        if snapshot.phase != ProcessPhase::Zombie {
            return Err(ServiceRegistryError::NotRunning);
        }
        let Some(index) = Self::index(snapshot.launch.service_class) else {
            return Ok(None);
        };
        if self.handles[index] != Some(caller) {
            return Ok(None);
        }
        let image = self.images[index]
            .take()
            .ok_or(ServiceRegistryError::NotRunning)?;
        self.handles[index] = None;
        Ok(Some(image))
    }
}

static REGISTRY: SpinLock<ServiceImageRegistry> = SpinLock::new(ServiceImageRegistry::EMPTY);

/// Publishes one already measured and activation-validated service image.
/// Bootstrap calls this once per service before Ring 3 is entered.
pub fn install_service(
    launch: ProcessLaunch,
    image: ProcessImageHandle,
) -> Result<(), ServiceRegistryError> {
    REGISTRY.lock().install(launch, image)
}

/// Creates a child from a boot-measured service image.
pub fn launch(parent: u32, service_class: u16) -> Result<ProcessHandle, ServiceRegistryError> {
    REGISTRY.lock().launch(parent, service_class)
}

/// Returns the live status word to that exact measured service process.
pub fn authenticated_service_status(
    caller: ProcessHandle,
    service_class: u16,
) -> Result<u64, ServiceRegistryError> {
    let handle = REGISTRY.lock().authenticate_caller(caller, service_class)?;
    let snapshot = lifecycle::snapshot_exact(handle).ok_or(ServiceRegistryError::NotRunning)?;
    if snapshot.phase != ProcessPhase::Running || snapshot.launch.service_class != service_class {
        return Err(ServiceRegistryError::NotRunning);
    }
    Ok((u64::from(handle.pid) << 8) | 1)
}

/// Transfers ownership of a service's exact installed image after its
/// lifecycle entry is terminal. Non-service exits deliberately leave the
/// registry alone.
pub fn take_exited_service(
    caller: ProcessHandle,
) -> Result<Option<ProcessImageHandle>, ServiceRegistryError> {
    REGISTRY.lock().take_exited(caller)
}

// Compatibility wrappers retained for the C0 probe while callers migrate to
// the service-class API. They do not create a second registry or a second
// ownership path.
pub fn install_crest(
    launch: ProcessLaunch,
    image: ProcessImageHandle,
) -> Result<(), ServiceRegistryError> {
    if launch.service_class != CREST_SERVICE_CLASS {
        return Err(ServiceRegistryError::InvalidLaunch);
    }
    install_service(launch, image)
}

pub fn authenticated_crest_status(caller: ProcessHandle) -> Result<u64, ServiceRegistryError> {
    authenticated_service_status(caller, CREST_SERVICE_CLASS)
}

pub fn take_exited_crest(
    caller: ProcessHandle,
) -> Result<Option<ProcessImageHandle>, ServiceRegistryError> {
    take_exited_service(caller)
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
            abi: crate::process::abi::ExecutionAbi::ArachNative,
        }
    }

    #[test]
    fn admits_each_bounded_cosmic_service_class_once() {
        let mut registry = ServiceImageRegistry::EMPTY;
        for class in [
            SEATD_SERVICE_CLASS,
            DBUS_BROKER_SERVICE_CLASS,
            PIPEWIRE_SERVICE_CLASS,
            WIREPLUMBER_SERVICE_CLASS,
            COSMIC_COMPOSITOR_SERVICE_CLASS,
            COSMIC_GREETER_SERVICE_CLASS,
            COSMIC_SESSION_SERVICE_CLASS,
            XDG_PORTAL_SERVICE_CLASS,
        ] {
            assert_eq!(
                registry.install(launch(class), ProcessImageHandle::new(class, 1)),
                Ok(())
            );
            assert_eq!(
                registry.install(launch(class), ProcessImageHandle::new(class, 2)),
                Err(ServiceRegistryError::AlreadyInstalled)
            );
        }
    }

    #[test]
    fn rejects_unknown_and_reserved_service_classes() {
        let mut registry = ServiceImageRegistry::EMPTY;
        assert_eq!(
            registry.install(launch(0), ProcessImageHandle::new(0, 1)),
            Err(ServiceRegistryError::UnsupportedService)
        );
        assert_eq!(
            registry.install(
                launch(MAXIMUM_SERVICE_CLASSES as u16),
                ProcessImageHandle::new(0, 1)
            ),
            Err(ServiceRegistryError::UnsupportedService)
        );
    }

    #[test]
    fn binds_status_to_the_exact_service_handle_generation() {
        let mut registry = ServiceImageRegistry::EMPTY;
        registry.handles[COSMIC_GREETER_SERVICE_CLASS as usize] = Some(ProcessHandle {
            pid: 2,
            generation: 3,
        });
        assert_eq!(
            registry.authenticate_caller(
                ProcessHandle {
                    pid: 2,
                    generation: 3,
                },
                COSMIC_GREETER_SERVICE_CLASS,
            ),
            Ok(ProcessHandle {
                pid: 2,
                generation: 3,
            })
        );
        assert_eq!(
            registry.authenticate_caller(
                ProcessHandle {
                    pid: 2,
                    generation: 4,
                },
                COSMIC_GREETER_SERVICE_CLASS,
            ),
            Err(ServiceRegistryError::UnauthorizedCaller)
        );
    }
}
