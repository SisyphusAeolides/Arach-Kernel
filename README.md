<p align="center">
  <img src="assets/arach-logo.png" alt="Arach Operating System emblem" width="360">
</p>

# Arach Kernel

[![Arach validation](https://github.com/SisyphusAeolides/Arach-Kernel/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/SisyphusAeolides/Arach-Kernel/actions/workflows/ci.yml)
[![NVIDIA Linux contract](https://github.com/SisyphusAeolides/Arach-Kernel/actions/workflows/nvidia-build.yml/badge.svg?branch=main)](https://github.com/SisyphusAeolides/Arach-Kernel/actions/workflows/nvidia-build.yml)

Arach Kernel is the Rust-first monolithic kernel at the foundation of
[Arach OS](https://github.com/SisyphusAeolides/Arach-OS). It targets x86-64
systems with a measured Linux-compatible userspace contract and an unmodified,
reproducibly pinned COSMIC Epoch desktop as its first complete graphical
environment.

Monolithic describes the kernel architecture: scheduling, memory, interrupts,
devices, filesystems, and networking may execute in the kernel address space.
It does **not** move PID 1, the COSMIC compositor, D-Bus, PipeWire, or ordinary
applications into ring 0.

## Design goals

- Boot a complete Arach OS system through the independently versioned Granite
  bootloader and Push PID 1.
- Run the complete COSMIC Epoch experience, including the greeter, compositor,
  portals, applications, audio, networking, suspend, and session lifecycle.
- Provide a measured Linux compatibility contract without silently claiming
  support that has not passed a gate.
- Support real hardware through native drivers and qualified Linux-compatible
  modules, including NVIDIA's open kernel modules.
- Use Rust for the kernel runtime, with deliberately bounded roles for C,
  Fortran, Idris 2, and Agda.

## Current status

Arach Kernel is under active development. The pinned Granite/Arach/Push C0
bundle now executes under QEMU/OVMF in CI, enters a measured ring-3 Linux
personality, and emits serial evidence from the real syscall, lifecycle, and
page-table paths. The currently packaged kernel source is
`1b60dace685c058ab5dbf10f582b897203c17cc2`.

The Linux personality currently covers:

- identity and lifecycle calls used by the measured probe, including `getpid`,
  `gettid`, `getppid`, `exit`, and `exit_group`;
- `write`, anonymous `mmap`/`munmap`, and `brk`;
- bounded process-owned `eventfd`, `timerfd`, `poll`, and `epoll` paths;
- bounded Akashic VFS-backed `open`, `openat`, `read`, `write`, `close`,
  `stat`, `fstat`, `lseek`, and `unlinkat` paths;
- generation-bound `set_tid_address`, with best-effort zeroing of the exact
  exiting PID generation's registered `clear_child_tid` word before zombie
  publication and descriptor cleanup;
- generation- and address-space-bound private futex `WAIT`/`WAKE` queues with
  an atomic compare-to-block scheduler transition and clear-child-tid wake.
- generation- and epoch-bound x86-64 FS-base TLS with Linux `arch_prctl`
  `ARCH_SET_FS`/`ARCH_GET_FS` and hardware readback before every user return.

The file bridge is intentionally bounded and ephemeral. It is not a persistent
block-backed filesystem, and the current Linux descriptor families are not yet
one unified descriptor namespace. The process model also does not yet provide
full Linux `clone` thread groups. Cross-thread futex wake qualification,
robust-list recovery, and signal delivery and return remain future
compatibility slices.

| Subsystem | Working today | Next acceptance gate |
|---|---|---|
| Kernel core | Memory, interrupt, process, capability, driver, filesystem, networking, and native/Linux execution-ABI metadata pass host tests; the QEMU/OVMF C0 probe exercises real generation-bound lifecycle and page-table paths | Keep the C0 gate green while extending the measured Linux surface without weakening fail-closed behavior |
| Linux userspace compatibility | Identity, memory, lifecycle, bounded event/timer/poll/epoll, bounded VFS file calls, generation-bound `set_tid_address`, private futex compare/block/wake, and FS-base TLS are implemented and tested | Qualify futex wake with shared-address-space threads, then add robust-list exit recovery, signal delivery, thread groups, a unified descriptor namespace, and persistent storage |
| System bootstrap | The pinned Granite/Arach/Push C0 bundle executes under QEMU/OVMF and emits measured ring-3 syscall evidence | Promote the measured bootstrap into a native Push service graph and qualified COSMIC login/session path |
| Linux module compatibility | RHEL 10/Linux 6.12 and Ubuntu 24.04/Linux 6.8 modules pass ELF validation, ABI admission, relocation, measured `struct module` validation, native W^X mapping, and host-mode transaction tests | Complete production special-section, all-CPU TLB, and lifecycle execution backends, then initialize and remove a module in an Arach boot |
| NVIDIA open modules | All four NVIDIA `610.43.03` open modules build and pass the static Linux-module gates | Resolve the live KPI surface and complete initialization, device operation, suspend/resume, and removal on Arach |
| Formal specifications | Idris 2 total specifications and Agda safe proof models compile in CI | Keep each proof artifact bound to a generated table, manifest, or runtime boundary |
| COSMIC Epoch | The complete desktop and session compatibility contract is documented and its required service images are measured during bundle construction | Boot the pinned greeter and complete login, desktop, suspend/resume, logout, and shutdown qualification |

The current critical path is:

1. Keep the measured C0 QEMU/OVMF path green.
2. Qualify futex wake across a measured shared-address-space thread group and
   complete robust-list exit recovery.
3. Add signal delivery/return, then expand measured thread groups without
   weakening generation isolation or per-thread TLS ownership.
4. Unify Linux descriptor ownership and add persistent block-backed storage.
5. Connect qualified modules and the native Push service graph to a complete
   COSMIC session.

Every status statement is evidence-based. A source build or host unit test is
useful progress, but it is not counted as runtime, desktop, persistence, or
hardware qualification.

## Language boundary

| Language | Production role |
|---|---|
| Rust | Kernel runtime, drivers, memory safety boundaries, and ABI implementation |
| C | Firmware and Linux ABI shims, external-driver compatibility, and reference drivers |
| Fortran | Bounded, allocation-free numerical kernels exported through a narrow C ABI |
| Idris 2 | Total protocol and state-machine specifications used to validate generated tables and manifests |
| Agda | Safe proofs of transition, authority, and compatibility laws |

Idris and Agda proofs are build evidence; they do not become privileged runtime
interpreters. Fortran routines may enter the kernel only when they are
freestanding, have no runtime-library dependency, use fixed bounds, and have a
Rust-owned safe wrapper.

## Repository layout

```text
src/                    Arach kernel and Linux compatibility surfaces
src/akashic_vfs.rs      bounded in-memory VFS authority
src/linux_file.rs       Linux file-descriptor bridge
src/linux_thread.rs     generation-bound thread-exit identity
core/                   bounded kernel primitives
libraries/driver-abi/   stable foreign-driver boundary
libraries/slope/        typed kernel/userspace ABI definitions
drivers/reference/      reference C driver used by ABI tests
formal/idris2/          total executable specifications
formal/agda/            safe proof models
```

The `core/` and `libraries/` trees are integration snapshots. Granite, Push,
Slope, Corinth, and the other Arach OS components remain independently
versioned repositories. The Arach OS repository pins qualified component
releases and is the integration authority; this repository remains focused on
the kernel.

## Validation

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets

scripts/materialize-linux-contract-sdk.sh /usr/src/kernels/$(uname -r)
scripts/test-linux-kbuild-sdk.sh

ARACH_PUSH_ROOT=/path/to/Push \
ARACH_GRANITE_ROOT=/path/to/Granite \
    scripts/build-c0-bundle.sh

ARACH_PUSH_ROOT=/path/to/Push \
ARACH_GRANITE_ROOT=/path/to/Granite \
ARACH_COSMIC_SERVICES_DIR=/path/to/cosmic-services \
    scripts/build-desktop-bundle.sh
```

The custom target is `x86_64-arach.json`. The `cargo kernel` alias selects the
`arach` package and binary, but a release kernel build also requires pinned
formal attestation and measured external PID 1/session artifacts. Those inputs
remain controlled by their own repositories and the Arach OS component lock.

## COSMIC target

COSMIC compatibility is an observable contract, not a source-language claim.
The required ABI and qualification stages are specified in
[COSMIC compatibility](docs/COSMIC_COMPATIBILITY.md). The target includes the
COSMIC greeter, authentication and session launch, compositor, panel/applets,
settings, portals, applications, store, media, lock/suspend path, and clean
logout—not just a compositor process.

`scripts/build-desktop-bundle.sh` is fail-closed: it requires `seatd`,
`pipewire`, `wireplumber`, `dbus-broker`, `cosmic-comp`, `cosmic-greeter`,
`cosmic-session`, and `xdg-desktop-portal-cosmic` as target-compatible ELF
images. It enables Push's `cosmic-boot` service graph, measures all eight
native boot services in Arach and Granite, and never downloads or silently
substitutes host COSMIC binaries.

The kernel and module boundaries are governed by the
[Linux kernel compatibility contract](docs/LINUX_KERNEL_CONTRACT.md). External
module builds, Linux `.ko` loading, in-kernel KPI, userspace UAPI, and hardware
lifecycle are separate evidence profiles; passing one never certifies the
others.

The first separately versioned system integrations are
[libinput-rs, elan-guardian, tuned-rs, and ccze-rs](docs/SYSTEM_COMPONENTS.md).

## NVIDIA driver target

Arach targets NVIDIA's open `610.43.03` kernel modules through a measured
external-Kbuild and Linux-KPI compatibility layer. The pinned source audit and
build entry point are documented in the
[NVIDIA DKMS compatibility contract](docs/NVIDIA_DKMS.md). All four required
modules pass the external build and static load-admission gates, including
load-region planning and allocated-section relocation binding. Arach does not
advertise NVIDIA runtime readiness because live KPI resolution, native W^X
publication, Linux special-section processing, module initialization, device
exercise, and clean removal still require native execution evidence.

## License

MIT
