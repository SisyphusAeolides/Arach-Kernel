<p align="center">
  <img src="assets/arach-logo.png" alt="Arach Operating System emblem" width="360">
</p>

# Arach Kernel

[![Arach validation](https://github.com/SisyphusAeolides/Arach-Kernel/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/SisyphusAeolides/Arach-Kernel/actions/workflows/ci.yml)
[![NVIDIA Linux contract](https://github.com/SisyphusAeolides/Arach-Kernel/actions/workflows/nvidia-build.yml/badge.svg?branch=main)](https://github.com/SisyphusAeolides/Arach-Kernel/actions/workflows/nvidia-build.yml)

Arach is the experimental, Rust-first monolithic kernel for Arach OS. Its
userspace compatibility target is an unmodified, reproducibly pinned release
of COSMIC Epoch on x86-64 systems.

Monolithic describes the kernel architecture: core scheduling, memory,
interrupt, device, filesystem, and networking services may execute in the
kernel address space. It does **not** move PID 1, the COSMIC compositor, D-Bus,
PipeWire, or ordinary applications into ring 0.

## Current status

Arach is an active kernel implementation, not yet a bootable COSMIC operating
system release. Status claims are tied to executable gates:

| Area | Evidence available now | Qualification |
|---|---|---|
| Kernel workspace | Rust workspace formatting, all-target compilation and tests; C and Fortran ABI checks | Host CI qualified |
| Formal contracts | Idris 2 total specifications and Agda safe proof models compile in CI | Build-evidence qualified |
| C0 system bundle | Pinned Granite, Arach Kernel and Push artifacts plus a bounded ring-3 syscall probe build into one measured bundle | Build qualified; QEMU execution pending |
| Linux external modules | Real Kbuild modules from RHEL 10/Linux 6.12 and Ubuntu 24.04/Linux 6.8 pass bounded ELF inspection, exact ABI admission, six-region W^X load planning and allocated-section relocation binding | Build and static load-admission qualified; native execution pending |
| NVIDIA open modules | Pinned NVIDIA `610.43.03` sources produce all four required modules; each passes ABI admission, lifecycle placement and complete allocated-section relocation binding | Build and static load-admission qualified; Arach init/device/remove pending |
| Native Arach boot | Boot structures, memory, interrupt, process, driver and ABI subsystems are implemented and host-tested | Granite-to-Arach QEMU boot gate pending |
| COSMIC Epoch | The complete greeter, session, compositor, portal, application and hardware contract is specified | Runtime qualification pending |

The immediate critical path is: boot the measured C0 bundle under QEMU, bring
up the Linux-compatible userspace surface, connect the W^X module transaction
to Arach's native memory/execution backend and exercise qualified modules, then
run an unmodified pinned COSMIC session.
Passing a source build or host unit test never counts as boot, runtime, or
hardware evidence.

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
Slope, Corinth and the other independently versioned Arach OS components
remain separate repositories until their interfaces and release gates are
stable. Component provenance and extraction are tracked in
[the migration plan](docs/MIGRATION.md), not treated as the kernel's identity.

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
