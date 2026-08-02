# COSMIC Epoch compatibility contract

## Definition of compatible

Arach may claim compatibility with a COSMIC Epoch release only when the exact
upstream release is pinned in CI and the complete desktop passes on Arach
without source patches that hide missing kernel behavior.

The upstream COSMIC repository currently identifies Linux-facing dependencies
including Wayland, Mesa/EGL, libseat, libinput, udev, D-Bus, xkbcommon,
display-info, GStreamer, and optional PipeWire. That makes Linux ABI and device
compatibility the critical path:

- <https://github.com/pop-os/cosmic-epoch>
- <https://github.com/pop-os/cosmic-comp>
- <https://github.com/pop-os/cosmic-session>

## Qualification ladder

| Gate | Kernel or system contract | Acceptance evidence |
|---|---|---|
| C0 | Reproducible Arach boot, allocator, interrupts, scheduler, Ring 3, syscall entry | QEMU serial transcript and deterministic image digest |
| C1 | Static ELF processes, virtual memory, files, directories, clocks, signals, threads, TLS, futex, and an explicit Linux x86-64 syscall personality | libc ABI probes and Linux Test Project subset; an unimplemented Linux call must return `ENOSYS` and must never enter Aether dispatch |
| C2 | Dynamic ELF, shared objects, `mmap`, `poll`, `epoll`, `eventfd`, `timerfd`, `inotify`, Unix sockets | unmodified dynamic Rust and C test programs |
| C3 | `/dev`, `/proc`, `/sys`, device numbers, uevents, permissions, seats | udev/libseat discovery tests |
| C4 | evdev plus the libinput ioctl surface | libinput-rs running upstream libinput behavioral tests with uinput fixtures |
| C5 | DRM/KMS atomic modesetting, render nodes, GEM, dma-buf, sync objects and fences | Mesa/GBM/EGL probes and kmscube |
| C6 | ALSA, PipeWire prerequisites, networking, DNS, credentials and D-Bus transport | audio, portal, and session-service probes |
| C7 | Push PID 1 plus tuned-rs supply the observable service/session and power contracts needed by COSMIC | login, seat activation, profile changes, service restart and clean shutdown tests |
| C8 | COSMIC greeter plus authentication and session launch | boot-to-greeter, PAM authentication, failed-login isolation, user-session start and logout-to-greeter |
| C9 | Pinned COSMIC compositor and complete desktop session | nested compositor first, then direct DRM session |
| C10 | Complete desktop smoke and endurance suite | applications, suspend/resume, hotplug, multi-monitor, input and 24-hour run |

No gate becomes true from a hand-written boolean. Each gate is derived from
versioned test results attached to the exact kernel commit.

## Complete desktop surface

The release matrix must exercise every component shipped by the pinned COSMIC
Epoch manifest, including:

| Surface | Required qualification |
|---|---|
| `cosmic-greeter` | PAM authentication, account enumeration, seat ownership, session start, failure handling and return after logout |
| `cosmic-session` | service graph, environment activation, crash handling, restart policy and clean logout |
| `cosmic-comp` | direct DRM/KMS, render nodes, input, clipboard, workspaces, window management, lock and recovery |
| panel, applets, launcher and application library | launch, pinning, menus, status surfaces and multiple outputs |
| settings and settings daemon | display, input, sound, power, appearance, locale and persisted configuration |
| notifications, OSD, background, wallpapers and icons | D-Bus activation, rendering and configuration changes |
| idle and lock path | inhibition, timeout, lock authentication, suspend and resume |
| randr, screenshot and workspaces | output configuration, capture portal and workspace transitions |
| files, edit, term and player | storage, MIME launch, terminal PTY, audio/video and removable media |
| store | package metadata, installation authority, progress, cancellation and rollback |
| initial setup and theme editor | first-login lifecycle and durable settings |
| `xdg-desktop-portal-cosmic` | screenshot, screencast, file chooser, settings and application sandbox requests |
| pop launcher and search providers | provider lifecycle, cancellation and bounded result delivery |

The system qualification layer must also cover the services those components
observe: PAM, account and credential lookup, D-Bus activation, seat/session
management, policy authorization, PipeWire, GStreamer, networking, Bluetooth,
power and battery reporting, package/Flatpak integration, font discovery,
localization, accessibility, secure storage, and XWayland for legacy
applications when the selected COSMIC distribution profile enables it.

elan-guardian is included in the C4 and endurance gates for ELAN hardware and
synthetic fault injection. ccze-rs is included in diagnostic-path tests so boot,
session and recovery logs remain usable under sustained output and malformed
records.

## Kernel ABI strategy

The shortest defensible path is a Linux-compatible x86-64 syscall and device
ABI implemented by Arach. Recompiling COSMIC against a bespoke Slope-only ABI
would also require porting libc, Mesa, libinput, libseat, udev, D-Bus,
PipeWire, GStreamer, and many transitive dependencies; that would no longer be
an unmodified COSMIC compatibility target.

Slope remains useful as Arach's typed internal ABI and as the source for
generated Linux-compatibility adapters. A process launch now carries an
immutable execution personality, so Linux syscall numbers cannot be confused
with Aether numbers. Linux compatibility must preserve
observable errno values, structure layouts, ioctl encodings, readiness rules,
object lifetime, and concurrency semantics.

The first Linux personality slice is now exercised by the measured C0 probe:
`write`, `getpid`, `getppid`, `gettid`, `clock_gettime(CLOCK_MONOTONIC)`,
`uname`, `exit`, and `exit_group` are routed through the existing bounded
user-copy and generation-safe lifecycle paths. The monotonic clock is advanced
by the calibrated periodic timer rather than exposing an unscaled TSC, and the
initial single-root credential calls return the authenticated boot identity.
Anonymous and eager Akashic-file-backed private `mmap`, whole-VMA
`mprotect`/`munmap`, and the bounded `brk` heap allocate and reclaim real user
pages with W^X checks. File snapshots are generation-bound and
position-independent; the probe closes the source descriptor before executing a
mapped RX instruction sequence. A bounded, process-owned
`eventfd2` table now implements the eight-byte counter ABI, semaphore mode,
ownership checks, close, and non-sleeping `EAGAIN` behavior. The Linux
personality also implements non-sleeping `poll(2)` plus level/edge `epoll(7)`
control and wait over eventfds and timerfds. A bounded, process-owned
monotonic timerfd implementation now covers create, settime, gettime,
expiration reads, ownership, close, periodic expiry accounting, and readiness
generation for edge-triggered epoll. These are real wake primitives for early
COSMIC services, not a claim that every descriptor family is unified yet.
General VMA split/merge, shared mappings, demand paging, and general
multi-library linking remain gated. Every other decoded
Linux syscall returns `ENOSYS` until its complete memory, signal, file, or IPC
semantics are implemented and tested.

The C0 probe now writes a PIE main executable, a separately built C runtime
linker, and one ET_DYN shared object into Akashic VFS before replacing its own
image through `execve`. The syscall copies bounded argv and environment vectors
from the old hierarchy,
validates `PT_INTERP`, atomically snapshots both files, measures them
independently, and activation-validates one inactive composite W^X hierarchy.
It constructs a bounded System V auxiliary vector and enters the runtime
linker, whose measured marker precedes its `AT_ENTRY` transfer to the Rust main
image. Registry and lifecycle ownership exchange retains the PID generation;
caught signal handlers and close-on-exec objects reset only after publication,
and the former hierarchy is reclaimed only after CR3 points at the replacement.
The interpreter now derives the main load bias from `AT_PHDR`, discovers one
allowlisted `DT_NEEDED` entry, opens that generation-owned Akashic object,
privately maps its page-aligned segments RW, applies and verifies its real
`R_X86_64_RELATIVE` relocation, seals final R/RW/RX permissions, resolves an
exported symbol through the SysV hash table, and calls code that dereferences
the relocated pointer. The admitted slice remains single-threaded at exec and
each Akashic file is bounded to 64 KiB. This is one bounded shared-object
profile, not completion of C2: recursive dependencies, external symbol/PLT/TLS
relocations, constructors, symbol versions, general file mapping semantics,
ASLR, and production entropy remain fail-closed.

The measured probe now also creates a bounded pthread-style clone sharing VM,
filesystem context, descriptor ownership, signal-handler identity, and SysV
semaphore adjustment state. The child has a distinct TID and saved context,
inherits or explicitly installs FS-base TLS, writes through a descriptor
created by the leader, and is scheduled only after the leader atomically
blocks on a private futex. Independent measured children prove both exit paths:
one clears its generation-bound child-TID word and wakes the leader; the other
registers a Linux x86-64 robust list, exits while owning a private futex, and
causes the kernel to atomically publish `OWNER_DIED` and wake the leader. The
walker is generation-bound and limited to 2,048 links. Fork-like clone modes,
PI and process-shared robust futexes, and individual leader `exit` with live
peers remain fail-closed gates.

The first bounded signal slice keeps dispositions generation-bound to the
thread group and masks, pending bits, and active return-frame authority bound
to the exact TID generation. The measured probe blocks `SIGUSR1`, queues it to
itself with `tgkill`, unmasks it, validates the delivered x86-64 `SA_SIGINFO`
frame, and resumes through `rt_sigreturn`. Delivery is currently synchronous at
syscall return, pending standard signals are bit-coalesced, and only self
`kill`/`tgkill` targets are admitted. Cross-process and asynchronous delivery,
real-time queues, alternate stacks, FPU/xstate restoration, stop/continue
semantics, and interrupted-syscall restart remain fail-closed gates.

After replacement, the exec target creates the peer used by the group-exit
gate. Whole-process termination now snapshots at most 64 exact thread generations,
consumes every member's futex, robust-list, child-TID, and signal exit state,
retires every non-leader generation atomically, and publishes only the leader
as a waitable zombie. The measured probe leaves a cloned peer blocked before
calling `exit_group`; Push's subsequent status-0 reap is the external witness
that no group peer remained runnable.

## Push PID 1 boundary

Push stays in userspace. It can replace systemd as PID 1 only if it provides or
hosts the contracts COSMIC actually observes: service supervision, user-session
activation, environment import, D-Bus activation, seat/session ownership,
PipeWire/WirePlumber audio policy, power transitions, logging, and deterministic
shutdown. The measured desktop chain now admits `seatd`, `dbus-broker`,
`pipewire`, `wireplumber`, `cosmic-comp`, `cosmic-greeter`, `cosmic-session`,
and `xdg-desktop-portal-cosmic` in dependency order. Compatibility tests, not
command-name similarity, decide when that work is complete.

## Multi-language rules

- Rust owns memory, concurrency, hardware access, and all unsafe FFI wrappers.
- Fortran receives fixed-size numeric slices only; no allocation, I/O,
  recursion, exceptions, or hidden runtime calls are permitted.
- Idris 2 models protocol selection and rejects incomplete compatibility
  manifests through total functions.
- Agda proves state-transition and authority properties under `--safe`; no
  postulates or proof holes are accepted in release gates.
