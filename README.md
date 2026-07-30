<p align="center">
  <img src="assets/arach-logo.png" alt="Arach Operating System emblem" width="360">
</p>

# Arach Kernel

Arach is an experimental Rust-first monolithic kernel whose long-term userspace
target is an unmodified, pinned release of COSMIC Epoch.

Monolithic describes the kernel architecture: core scheduling, memory,
interrupt, device, filesystem, and networking services may execute in the
kernel address space. It does **not** move PID 1, the COSMIC compositor, D-Bus,
PipeWire, or ordinary applications into ring 0.

## Current status

The Boulder kernel sources and several shared libraries from Sisyphus-OS have
been imported. The host workspace builds and its unit tests pass, but the
bare-metal image has not yet been requalified under the Arach name. Arach does
not yet satisfy the Linux userspace ABI or device interfaces required to start
COSMIC Epoch.

Sisyphus-OS remains migration input until every retained component, build
script, asset, and relevant history has a verified destination. Do not delete
or archive it based only on the current source import.

## Language boundary

| Language | Production role |
|---|---|
| Rust | Kernel runtime, drivers, memory safety boundaries, and ABI implementation |
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
core/                   imported bounded kernel primitives
libraries/driver-abi/   stable foreign-driver boundary
libraries/slope/        imported kernel/userspace ABI definitions
drivers/reference/      reference C driver used by ABI tests
formal/idris2/          total executable specifications
formal/agda/            safe proof models
```

The current `core/` and `libraries/` copies are an integration snapshot, not a
decision to collapse the component repositories early. See
[the migration plan](docs/MIGRATION.md).

## Host validation

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
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

The first separately versioned system integrations are
[libinput-rs, elan-guardian, tuned-rs, and ccze-rs](docs/SYSTEM_COMPONENTS.md).

## License

MIT
