<p align="center">
  <img src="assets/arach-logo.png" alt="Arach Operating System emblem" width="360">
</p>

# Arach Kernel

[![Arach validation](https://github.com/SisyphusAeolides/Arach-Kernel/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/SisyphusAeolides/Arach-Kernel/actions/workflows/ci.yml)
[![NVIDIA Linux contract](https://github.com/SisyphusAeolides/Arach-Kernel/actions/workflows/nvidia-build.yml/badge.svg?branch=main)](https://github.com/SisyphusAeolides/Arach-Kernel/actions/workflows/nvidia-build.yml)

Arach Kernel is the Rust-first monolithic kernel at the foundation of
[Arach OS](https://github.com/SisyphusAeolides/Arach-OS). It is being built for
x86-64 systems with a Linux-compatible userspace contract and an unmodified,
reproducibly pinned COSMIC Epoch desktop as its first complete graphical
environment.

Monolithic describes the kernel architecture: core scheduling, memory,
interrupt, device, filesystem, and networking services may execute in the
kernel address space. It does **not** move PID 1, the COSMIC compositor, D-Bus,
PipeWire, or ordinary applications into ring 0.

## Design goals

- Boot a complete Arach OS system through the independently versioned Granite
  bootloader and Push PID 1.
- Run the full COSMIC Epoch experience, including the greeter, compositor,
  portals, applications, audio, networking, suspend, and session lifecycle.
- Provide a measured Linux compatibility contract for userspace and external
  kernel modules without silently claiming support that has not passed a gate.
- Support real hardware through native drivers and qualified Linux-compatible
  modules, including NVIDIA's open kernel modules.
- Use Rust for the kernel runtime, with deliberately bounded roles for C,
  Fortran, Idris 2, and Agda.

## Current status

Arach Kernel is under active development. The workspace and its compatibility
contracts are extensively host-tested, but Arach OS does not yet boot to a
COSMIC session. The next major milestone is a measured Granite-to-Arach boot
under QEMU.

| Subsystem | Working today | Next acceptance gate |
|---|---|---|
| Kernel core | Memory, interrupt, process, capability, driver, filesystem, networking, and native/Linux execution-ABI metadata build and pass host tests; Linux identity/process-exit calls plus bounded anonymous `mmap`/`munmap`/`brk` use real generation-bound lifecycle/page-table paths while other Linux calls fail closed | Boot the native kernel through Granite, execute the ring-3 probe, then admit Linux syscall implementations one measured surface at a time |
| System bootstrap | The pinned Granite/Arach/Push C0 bundle executes under QEMU/OVMF in CI and emits measured ring-3 syscall evidence; release `6ca3ca7` is the first green execution qualification | Keep the exact-revision gate green, then promote this C0 path toward a native COSMIC login/session qualification |
| Linux module compatibility | RHEL 10/Linux 6.12 and Ubuntu 24.04/Linux 6.8 modules pass ELF validation, ABI admission, relocation, measured `struct module` validation, native W^X mapping, and host-mode transaction tests | Complete production special-section, all-CPU TLB, and lifecycle execution backends; then initialize, exercise, and remove a module in an Arach boot |
| NVIDIA open modules | All four NVIDIA `610.43.03` open modules build and pass the static Linux-module gates | Resolve the live KPI surface and complete init, device operation, suspend/resume, and removal on Arach |
| Formal specifications | Idris 2 total specifications and Agda safe proof models compile in CI | Connect each proof artifact to a measured generated table, manifest, or runtime boundary |
| COSMIC Epoch | The complete desktop and session compatibility contract is documented | Boot the pinned COSMIC greeter and complete a login, desktop session, suspend/resume, logout, and shutdown cycle |

The critical path is:

1. Boot the measured C0 bundle under QEMU.
2. Bring up the Linux-compatible userspace surface required by Push and COSMIC.
3. Connect transactional Linux-module loading to native memory and execution.
4. Exercise qualified modules through initialization, hardware use, and clean
   removal.
5. Run and qualify the complete pinned COSMIC Epoch session.

Every status statement is evidence-based. A successful source build or host
unit test is useful progress, but it is not counted as boot, runtime, desktop,
or hardware qualification.

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
src/                    Arach kernel
core/                   bounded kernel primitives
libraries/driver-abi/   stable foreign-driver boundary
libraries/slope/        typed kernel/userspace ABI definitions
drivers/reference/      reference C driver used by ABI tests
formal/idris2/          total executable specifications
formal/agda/            safe proof models
```

The `core/` and `libraries/` trees are integration snapshots. Granite, Push,
Slope, Corinth, and the other Arach OS components remain independently
versioned repositories until their interfaces and release gates are stable.
The Arach OS repository pins qualified component releases and is the eventual
integration point; this repository remains focused on the kernel.

## Host validation

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets

scripts/materialize-linux-contract-sdk.sh /usr/src/kernels/$(uname -r)
scripts/test-linux-kbuild-sdk.sh

ARACH_PUSH_ROOT=/path/to/Push \
ARACH_GRANITE_ROOT=/path/to/Granite \
    scripts/build-c0-bundle.sh
```

The custom target is `x86_64-arach.json`. The `cargo kernel` alias now selects
the `arach` package and binary, but a release kernel build also requires pinned
formal attestation and measured external PID 1/session artifacts. Those inputs
will be supplied by their own repositories rather than silently copied from a
local workspace.

## COSMIC target

COSMIC compatibility is an observable contract, not a source-language claim.
The required ABI and qualification stages are specified in
[COSMIC compatibility](docs/COSMIC_COMPATIBILITY.md). The target includes the
COSMIC greeter, authentication and session launch, compositor, panel/applets,
settings, portals, applications, store, media, lock/suspend path, and clean
logout—not just a compositor process. The first acceptance target will be a
pinned COSMIC Epoch release running under QEMU with virtio graphics, input,
storage, audio, and networking before qualification expands to real hardware.

The kernel and module boundaries are governed by the
[Linux kernel compatibility contract](docs/LINUX_KERNEL_CONTRACT.md). External
module builds, Linux `.ko` loading, in-kernel KPI, userspace UAPI, and hardware
lifecycle are separate evidence profiles; passing one never silently certifies
the others.

The first separately versioned system integrations are
[libinput-rs, elan-guardian, tuned-rs, and ccze-rs](docs/SYSTEM_COMPONENTS.md).

## NVIDIA driver target

Arach targets NVIDIA's open `610.43.03` kernel modules through a measured
external-Kbuild and Linux-KPI compatibility layer. The pinned source audit and
build entry point are documented in the
[NVIDIA DKMS compatibility contract](docs/NVIDIA_DKMS.md). All four required
modules currently pass the external build and static load-admission gates,
including load-region planning and allocated-section relocation binding. Arach
does not yet advertise NVIDIA runtime readiness because live KPI resolution,
native W^X publication, Linux special-section processing, module
initialization, device exercise and clean removal still require native
execution evidence.

## License

MIT
