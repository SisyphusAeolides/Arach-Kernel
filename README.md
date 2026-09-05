<p align="center">
  <img src="assets/arach-logo.png" alt="Arach Operating System emblem" width="360">
</p>

# Arach Kernel

[![Arach validation](https://github.com/SisyphusAeolides/Arach-Kernel/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/SisyphusAeolides/Arach-Kernel/actions/workflows/ci.yml)
[![NVIDIA Linux contract](https://github.com/SisyphusAeolides/Arach-Kernel/actions/workflows/nvidia-build.yml/badge.svg?branch=main)](https://github.com/SisyphusAeolides/Arach-Kernel/actions/workflows/nvidia-build.yml)

Arach Kernel is the Rust-first monolithic kernel at the foundation of
[ArachOS](https://github.com/SisyphusAeolides/ArachOS). It targets x86-64
systems with a measured Linux-compatible userspace contract. Its production
target is ArachOS: an Arch Linux package base composed with ArchISO, GRUB,
RustD as PID 1, and RustD-resolved as the native resolver. Desktop environments
remain Calamares installation choices rather than kernel-bound components.

Monolithic describes the kernel architecture: scheduling, memory, interrupts,
devices, filesystems, and networking may execute in the kernel address space.
It does **not** move PID 1, desktop compositors, D-Bus, PipeWire, or ordinary
applications into ring 0.

## Design goals

- Boot ArachOS directly through GRUB's Multiboot2 path.
- Run the ArachOS pacman userspace with RustD as PID 1 and RustD-resolved as the
  resolver, without a kernel-selected desktop environment.
- Provide a measured Linux compatibility contract without silently claiming
  support that has not passed a gate.
- Support real hardware through native drivers and qualified Linux-compatible
  modules, including NVIDIA's open kernel modules.
- Use Rust for the kernel runtime, with deliberately bounded roles for C,
  Fortran, Idris 2, and Agda.

## Current status

Arach Kernel is under active development. Its host test suite passes and the
custom Multiboot2 kernel contract builds with measured RustD, bootstrap, and
RustD-resolved inputs. The ArachOS integration has a direct GRUB Multiboot2
bundle contract and accepts a measured `rustd` module as Linux-ABI PID 1.
ArachOS pins the exact qualified source revision.

The ArachOS/GRUB path is not yet release-qualified. Persistent block-backed root
storage, the complete RustD Linux ABI, cgroup v2, `/proc`, `/sys`, udev, D-Bus,
RustD-resolved, networking, and graphical Calamares must all pass in BIOS and
UEFI QEMU before Arach Kernel can be the only installed boot path. Retired
legacy boot repositories are not part of the ArachOS architecture.

The Linux personality currently covers:

- identity and lifecycle calls used by the measured probe, including distinct
  `getpid`/`gettid`, bounded pthread-style `clone`, `getppid`, `exit`, and
  bounded multi-member `exit_group`;
- `write`, anonymous and eager Akashic-file-backed private `mmap`, bounded
  memfd-backed `MAP_SHARED`, whole-range W^X `mprotect`/`munmap`, and `brk`;
- one dense, generation-bound descriptor namespace for standard streams,
  regular files, eventfds, timerfds, epoll objects, anonymous pipes, and Unix
  stream and datagram sockets, with
  open-object `dup`/`dup2`/`dup3`, bounded `fcntl`, descriptor-local
  close-on-exec, and poll/epoll readiness;
- bounded `AF_UNIX` `SOCK_STREAM` and `socketpair` endpoints with pathname and
  abstract namespaces, connect/accept queues, full-duplex transfer,
  `sendmsg`/`recvmsg` vectors, bounded `SCM_RIGHTS`, peer identity, half-close,
  and generation-safe cross-process open-description lifetime;
- bounded `AF_UNIX` `SOCK_DGRAM` endpoints with pathname binding, non-blocking
  queues, `sendto`/`recvfrom`, `sendmsg`/`recvmsg`, `SO_PASSCRED`, and
  generation-safe descriptor lifetime;
- generation-bound `memfd_create`/`ftruncate` objects with shared physical
  frame aliases and VMA lifetime independent of the final descriptor;
- bounded Akashic VFS-backed `open`, `openat`, `read`, `write`, `close`,
  `stat`, `fstat`, `lseek`, `mkdir`, `mkdirat`, `unlinkat`, `access`,
  `readlink`, and mode-change paths;
- generation-bound `signalfd`/`signalfd4` descriptors that consume selected
  pending standard signals as fixed-size Linux records;
- generation-bound `set_tid_address`, with best-effort zeroing of the exact
  exiting PID generation's registered `clear_child_tid` word before zombie
  publication and descriptor cleanup;
- generation- and address-space-bound private futex `WAIT`/`WAKE` queues with
  an atomic compare-to-block scheduler transition and measured cross-thread
  clear-child-tid wake;
- generation-bound `set_robust_list`/current-thread `get_robust_list`, a
  2,048-link exit bound, atomic `OWNER_DIED` publication, and measured wake of
  a private robust-futex waiter;
- generation-bound thread-group signal dispositions and per-thread masks,
  coalesced pending state, self-targeted `kill`/`tgkill`, and measured x86-64
  `SA_SIGINFO` frame delivery and exact-frame `rt_sigreturn` restoration;
- bounded exact-generation thread-group snapshots, per-thread exit cleanup,
  atomic non-leader retirement, one waitable leader zombie, and measured PID 1
  reaping after `exit_group` with a live blocked peer;
- generation- and epoch-bound x86-64 FS-base TLS with Linux `arch_prctl`
  `ARCH_SET_FS`/`ARCH_GET_FS`, clone inheritance or `CLONE_SETTLS`, and hardware
  readback before every user return;
- same-PID transactional `execve` for bounded static ELF and the first
  x86-64 `PT_INTERP` profile: atomic executable/interpreter snapshots,
  separate measurements, one inactive composite W^X hierarchy, a System V
  auxiliary vector, runtime-linker entry and main-entry transfer, atomic
  lifecycle/image exchange, rollback before publication, and old-root
  reclamation only after CR3 changes; and
- one fail-closed, eight-object `DT_NEEDED` engine whose freestanding C linker
  performs breadth-first discovery, coalesces duplicate SONAME edges, rejects
  cycles, computes provider-first relocation order, and resolves eager
  `R_X86_64_JUMP_SLOT` bindings through deterministic SysV symbol scope,
  including first-definition weak function lookup and unversioned unresolved
  weak references written as zero. The
  measured four-object diamond applies nine relative writes: seven explicit
  `R_X86_64_RELATIVE` entries plus two root initializer/finalizer pointers
  decoded from one canonical `DT_RELR` address/bitmap pair. Packed decoding is
  two-pass and bounds entry count, expanded writes, ordering, overlap,
  alignment, final-writable targets, mapped implicit addends, and arithmetic.
  The linker also validates the main PIE as a bounded immutable object and
  commits its exact-version `R_X86_64_COPY` only after every source, extent,
  target, and non-aliasing condition has passed. The executable copy enters
  process-global data scope before ordinary shared objects, while a requesting
  object's `DT_SYMBOLIC` definition retains local priority.
  The graph installs one `R_X86_64_TPOFF64` and one
  `R_X86_64_DTPMOD64`/`R_X86_64_DTPOFF64` pair into a bounded Variant-II
  startup TLS arena, publishes a finite dynamic-thread vector at `FS:8`, and
  admits only the exact compiler-generated `__tls_get_addr` resolver edge.
  Exact canonical `DT_RUNPATH=/runpath` entries resolve the three nested
  providers after the probe creates that ephemeral directory with the bounded
  Linux directory syscall profile. It binds seven exact-version object PLT
  edges plus the resolver and two unversioned weak edges, four eager data
  slots—one targeting the interposed executable copy—seals every object
  R/RW/RX, and executes four
  dependency-first initializers, calls through both branches and their shared
  provider, and executes eight finalizers in reverse dependency and array
  order through the x86-64 process-entry callback in QEMU.

The file bridge is intentionally bounded and ephemeral. It is not a persistent
block-backed filesystem. Anonymous pipes use a 4 KiB allocation-free ring,
provide atomic bounded writes, EOF/HUP/EPIPE endpoint lifetime, and
generation-stable epoll watch lifetime and last-close removal. Unix stream
sockets use fixed 4 KiB queues and bounded endpoint, connection, and listen
tables; datagram sockets use bounded message queues and explicit credential
messages. Ancillary queues retain at most eight messages of eight transferable
descriptors per direction. Operations that would block still return `EAGAIN`;
scheduler-backed descriptor waits, `SIGPIPE`, cyclic socket/epoll transfer,
filesystem socket inodes, seqpacket sockets, and persistent storage remain open
gates.
The bounded clone admission
accepts the shared VM/FS/files/sighand/thread/sysvsem profile plus TLS and TID
publication flags; fork-like clone modes and individual leader `exit` with
live peers fail closed. PI and process-shared robust futexes, cross-process and
asynchronous signal delivery, real-time signal queues, alternate signal stacks,
FPU/xstate restoration, stop/continue semantics, and interrupted-syscall
restart remain future compatibility slices.

| Subsystem | Working today | Next acceptance gate |
|---|---|---|
| Kernel core | Memory, interrupt, process, capability, driver, filesystem, networking, and native/Linux execution-ABI metadata pass host tests; the custom Multiboot2 image contract is warning-free with measured runtime inputs | Boot the complete ArachOS graph in BIOS and UEFI while extending the measured Linux surface without weakening its gates |
| Linux userspace compatibility | Identity, anonymous and eager private file mappings, bounded memfd-backed shared mappings, whole-range W^X protection transitions, lifecycle, a unified generation-bound descriptor/open-object table, bounded pipes/event/timer/poll/epoll, Unix stream and datagram sockets with `SCM_RIGHTS`/`SO_PASSCRED`, signalfd, bounded VFS file, directory, metadata, and mode-change calls, transactional static and measured `PT_INTERP` execution, an eight-object dependency engine measured with a deduplicated four-object diamond and canonical finite `DT_RUNPATH`, explicit and packed relative relocation, exact-size main-executable copy relocation and interposition, provider-first static/general-dynamic startup-TLS relocation, exact GNU symbol versions, deterministic eager external PLT binding with bounded weak-function semantics, dependency-first initialization, and reverse finalization, a shared-address-space clone profile, measured private robust-futex recovery, clear-child-tid wake, synchronous self-signal delivery/return, multi-member `exit_group`, and per-thread FS-base TLS are implemented and tested | Add scheduler-backed descriptor waits and filesystem socket nodes; add late-loaded TLS, TLSDESC, general loader search policy, weak data/TLS, GNU-unique/IFUNC binding, and broader relocations; add general VMA split/merge, demand paging, broader signals, complete leader-exit semantics, and persistent storage |
| System bootstrap | GRUB Multiboot2 entry exists and the source accepts measured RustD as Linux-ABI PID 1 | Boot the packaged ArachOS root under RustD and pass the complete service graph in BIOS and UEFI |
| Linux module compatibility | RHEL 10/Linux 6.12 and Ubuntu 24.04/Linux 6.8 modules pass ELF validation, ABI admission, relocation, measured `struct module` validation, native W^X mapping, and host-mode transaction tests | Complete production special-section, all-CPU TLB, and lifecycle execution backends, then initialize and remove a module in an Arach boot |
| NVIDIA open modules | All four NVIDIA `610.43.03` open modules build and pass the static Linux-module gates | Resolve the live KPI surface and complete initialization, device operation, suspend/resume, and removal on Arach |
| Formal specifications | Idris 2 total specifications and Agda safe proof models compile in CI | Keep each proof artifact bound to a generated table, manifest, or runtime boundary |
| ArachOS graphical stack | The pacman userspace and desktop selection belong to Calamares | Qualify graphical Calamares, the selected display manager, Wayland, login, suspend/resume, logout, and shutdown |

The current critical path is:

1. Boot the direct ArachOS GRUB bundle in BIOS and UEFI and retain serial evidence.
2. Extend the measured bounded graph linker with late-loaded TLS and TLSDESC,
   general loader search policy, weak data/TLS, GNU-unique/IFUNC binding, and
   broader relocations.
3. Add scheduler-backed descriptor waits, filesystem socket nodes, and
   persistent block-backed storage on the unified open-object boundary.
4. Boot the ArachOS package graph under RustD/RustD-resolved and qualify graphical
   Calamares plus user-selected desktop environments.

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
src/linux_fd.rs         unified Linux descriptor and open-object table
src/linux_file.rs       regular-file backend for unified descriptors
src/linux_memfd.rs      bounded memory-file metadata and shared-backing identity
src/linux_pipe.rs       bounded anonymous-pipe backend
src/linux_socket.rs     bounded Unix-domain stream-socket backend
src/linux_unix_dgram.rs bounded Unix-domain datagram backend
src/linux_signalfd.rs   generation-bound signalfd backend
src/linux_thread.rs     generation-bound thread-exit identity
src/storage.rs          checked sector I/O, GPT discovery, and partition views
core/                   bounded kernel primitives
libraries/driver-abi/   stable foreign-driver boundary
src/arach_*.rs          typed Arach kernel service contracts
drivers/reference/      reference C driver used by ABI tests
formal/idris2/          total executable specifications
formal/agda/            safe proof models
```

The `core/` and `libraries/` trees are integration snapshots. The ArachOS
repository pins qualified component releases and is the integration authority;
this repository remains focused on the kernel.

## Validation

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets

scripts/materialize-linux-contract-sdk.sh /usr/src/kernels/$(uname -r)
scripts/test-linux-kbuild-sdk.sh

ARACH_KERNEL_IMAGE=/path/to/arach \
ARACH_RUSTD_IMAGE=/path/to/rustd \
ARACH_BOOTSTRAP_IMAGE=/path/to/bootstrap \
ARACH_RESOLVED_IMAGE=/path/to/rustd-resolved \
    scripts/build-arachos-grub-bundle.sh
```

The custom target is `x86_64-arach.json`. The `cargo kernel` alias selects the
`arach` package and binary, but a release kernel build also requires pinned
formal attestation and measured external PID 1 artifacts. Those inputs remain
controlled by their own repositories and the ArachOS component lock. The
ArachOS bundle validates the Multiboot2 kernel and measured RustD/RustD-resolved
artifacts before constructing GRUB media.

## ArachOS userspace target

ArachOS owns the release, package repository, and installer composition. The
Arch Linux packages provide the bootstrap package ecosystem, while RustD owns
PID 1 and service management, RustD-resolved owns DNS, NSS, Varlink, and
the resolver compatibility boundary, and GRUB owns the BIOS and UEFI boot path.

No desktop environment is compiled into or selected by Arach Kernel. ArachOS
uses graphical Calamares package selection, and each selected display-manager,
Wayland, audio, portal, login, and suspend path must pass installed-system
qualification on the same kernel and package set.

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
