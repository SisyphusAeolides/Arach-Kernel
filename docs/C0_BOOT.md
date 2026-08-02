# C0 measured boot qualification

C0 is not a boolean in a manifest. It requires one exact Arach revision to
produce four boot artifacts and then execute them under UEFI/QEMU:

1. Granite UEFI loader;
2. Arach kernel;
3. Push PID 1;
4. the bounded ring-3 syscall probe in `probes/c0`.

The syscall probe embeds four additional independently hashed execution
inputs: the PIE exec target, the freestanding C runtime-linker probe, an ET_DYN
consumer, and its ET_DYN provider. They are materialized as separate Akashic
files at runtime and are never treated as one prelinked blob.

`scripts/build-c0-bundle.sh` builds those artifacts from separate immutable
component checkouts. `ARACH_PUSH_IMAGE` and `ARACH_BOOTSTRAP_IMAGE` remove the
legacy assumption that user images exist under Arach's own target directory.
The bootstrap variable currently feeds a legacy internal slot named `crest`;
the supplied artifact is the C0 probe, not the discarded Crest desktop.

The script accepts `ARACH_PUSH_FEATURES`. Its default `os-bin` builds the
minimal probe supervisor. A desktop bundle build must set
`ARACH_PUSH_FEATURES=os-bin,cosmic-boot` only after measured COSMIC service
artifacts have been assembled; the feature selects the complete ordered
session chain and is not a substitute for those artifact measurements.

The build gate records SHA-256 for every artifact. Qualification additionally
requires a deterministic FAT/UEFI image, a bounded QEMU run, and a serial log
containing all of the following evidence from the same bundle:

- Granite admitted the measured bundle;
- Arach initialized interrupts, scheduling, ring 3, and syscall entry;
- Push reached PID 1;
- `ARACH_C0_RING3_SYSCALL_PASS` was emitted by the measured probe;
- `ARACH_C1_THREAD_FUTEX_PASS` was emitted after shared descriptor access and
  cross-thread clear-child-tid futex wake completed;
- `ARACH_C1_ROBUST_FUTEX_PASS` was emitted after exact robust-list registration,
  private-futex block, atomic `OWNER_DIED` publication, and exit-driven wake;
- `ARACH_C1_SIGNAL_RETURN_PASS` was emitted after a blocked self-signal became
  pending, unmasking delivered an x86-64 `SA_SIGINFO` frame, and the handler
  returned through the kernel's exact-frame `rt_sigreturn` path;
- `ARACH_C2_FILE_MMAP_PASS` was emitted after a generation-bound descriptor
  snapshot populated a private page, retained zero fill, and survived source
  descriptor close;
- `ARACH_C2_MPROTECT_PASS` was emitted after W+X rejection, an exact R-to-RX
  transition, syscall-return TLB flush, and execution from the mapped page;
- `ARACH_C1_PIPE_DESCRIPTOR_PASS` was emitted after dense descriptor
  allocation, open-object duplication, descriptor-local close-on-exec,
  pipe poll/epoll readiness, EOF/HUP/EPIPE, and replacement-image inheritance
  all completed;
- `ARACH_C1_UNIX_SOCKET_PASS` was emitted after generation-bound Unix stream
  socketpair and abstract-namespace paths completed connect, plain and flagged
  accept, full-duplex and vector transfer, peer identity, poll/epoll readiness,
  duplicate lifetime, half-close HUP, namespace reuse, and exact
  `SCM_RIGHTS` control transfer with sender-close lifetime;
- `ARACH_C1_SHARED_MEMORY_PASS` was emitted after a generation-bound memfd was
  resized, transferred as an open description, mapped through two
  `MAP_SHARED` aliases, retained after descriptor close, observed through both
  aliases, and released through exact-range unmaps;
- `ARACH_C1_EXIT_GROUP_ARMED` was emitted only after an independently
  scheduled cloned peer woke the leader and blocked; Push then emitted
  `[PID 1] child 2 exited with status 0` only after `exit_group` retired that
  peer and published the leader as the sole waitable process zombie;
- `ARACH_C1_LINUX_SYSCALL_PASS` was emitted after the Linux personality
  exercised identity, anonymous and private file memory, `mprotect`, `brk`,
  shared-address-space clone, unified descriptor/open-object, pipe, and bounded
  Unix stream-socket, ancillary descriptor, and shared-memory access,
  independent private robust-futex and
  clear-child-tid block/wake paths, kernel owner-death publication, measured
  signal delivery/return, bounded whole-group exit, and clean supervisor reap;
- `ARACH_C2_RUNTIME_LINKER_ENTER` was emitted by the separately measured C
  interpreter after the kernel entered its ET_DYN entry point and it validated
  `AT_PHDR`, `AT_PHENT`, `AT_PHNUM`, `AT_PAGESZ`, `AT_BASE`, `AT_ENTRY`,
  `AT_RANDOM`, and `AT_EXECFN`;
- `ARACH_C2_DT_NEEDED_PASS` was emitted only after the interpreter derived the
  PIE load bias, bounded its dynamic table, and discovered the exact shared
  object name;
- `ARACH_C2_DEPENDENCY_GRAPH_PASS` was emitted only after bounded breadth-first
  discovery reached a complete acyclic closure and every immutable object
  passed ELF, SONAME, dynamic-table, and dependency validation;
- `ARACH_C2_MULTI_OBJECT_GRAPH_PASS` was emitted only after the measured
  four-object diamond coalesced both middle-object references to one core
  snapshot and produced provider-first relocation order;
- `ARACH_C2_RUNPATH_PASS` was emitted only after the probe created `/runpath`,
  three dependencies were opened from their exact nested paths through
  canonical direct-object `DT_RUNPATH` entries, and the root remained at `/`;
- `ARACH_C2_SHARED_RELOCATION_PASS` was emitted only after nine real relative
  relocations, three real TLS relocations, and all ten eager external
  relocations were written to final-writable targets and read back;
- `ARACH_C2_GLOBAL_SYMBOL_SCOPE_PASS` was emitted only after each undefined
  function was resolved through deterministic breadth-first SysV symbol scope;
- `ARACH_C2_WEAK_BINDING_PASS` was emitted only after the first in-scope weak
  function definition won over a later strong definition and a second,
  unversioned unresolved weak function slot was written and read back as zero;
- `ARACH_C2_SYMBOL_VERSION_PASS` was emitted only after every GNU version
  table passed its finite structural bounds and all ten versioned
  relocations matched an exact version, including the importing dependency's
  SONAME;
- `ARACH_C2_STATIC_TLS_PASS` was emitted only after the bounded initial TLS
  template was copied, its checked TPOFF relocation installed, FS base
  published, and the core consumed its initialized TLS word;
- `ARACH_C2_DYNAMIC_TLS_PASS` was emitted only after the bounded DTV was
  published at `FS:8` and the exact `__tls_get_addr` resolver rejected invalid
  module/offset state before serving the measured general-dynamic access;
- `ARACH_C2_INITIALIZER_ORDER_PASS` was emitted only after core, provider,
  observer, and root initializers ran in provider-first order and each
  dependent observed its providers' initialized state;
- `ARACH_C2_EXTERNAL_SYMBOL_PASS` was emitted only after all four objects were
  sealed R/RW/RX and the root call consumed both branches, the measured weak
  provider, and the core's relocated state;
- `ARACH_C2_RUNTIME_LINKER_PASS` was emitted after that complete transaction,
  and the later `ARACH_C1_EXECVE_PASS` proves control transferred to the Rust
  main image;
- `ARACH_C2_FINALIZATION_PASS` was emitted only after that image invoked the
  one-shot x86-64 process-entry callback and four `DT_FINI_ARRAY` functions
  followed by four `DT_FINI` functions completed in reverse dependency order.

The execution gate is implemented in the Arach validation workflow: CI installs
QEMU/OVMF, runs this helper against the freshly assembled image, and uploads
the serial transcript. Revision `b396d3a7fc6538eacc60058d7067bebe9de43537`
is the last qualified release before the Linux-personality probe was added.
The next release must pass the complete workflow, including every measured
marker. Future releases must keep this workflow green for their exact revision;
a host build or a missing local QEMU installation never counts as qualification.

The image and execution helpers are now available:

```sh
scripts/build-c0-fat-image.sh \
  target/c0/granite/x86_64-unknown-uefi/release/granite.efi \
  target/c0/kernel/x86_64-arach/release/arach \
  target/c0/push/x86_64-arach/release/push \
  target/c0/probe/x86_64-arach/release/arach-c0-probe \
  "$PWD/target/c0/arach-c0.img"

scripts/run-c0-qemu.sh "$PWD/target/c0/arach-c0.img"
```

The runner fails with status 69 when QEMU or OVMF is unavailable and never
turns a missing execution environment into a green qualification result.
