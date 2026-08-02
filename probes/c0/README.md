# Arach C0 ring-3 probe

This bounded `no_std` ELF is qualification input, not a desktop or production
service. It is launched with Arach's Linux x86-64 execution personality and
proves the first live userspace slice: `write`, `read`, `close`, `eventfd2`,
`poll`, `epoll_create1`, `epoll_ctl`, `epoll_wait`, `getpid`, `gettid`,
`getppid`, anonymous and eager private file `mmap`, exact-range `mprotect` and
`munmap`, `brk`, private `futex`, transactional static/`PT_INTERP` `execve`, and
`exit_group`.
The probe checks both normal and semaphore eventfd semantics, including
non-sleeping `EAGAIN` on an empty counter, and verifies that poll/epoll
readiness clears after the eventfd is drained. Its single-process futex gate
proves mismatch rejection and an empty wake without claiming a cross-thread
wake. It writes
`ARACH_C0_RING3_SYSCALL_PASS` after entering ring 3 and
`ARACH_C1_LINUX_SYSCALL_PASS` only after every Linux operation succeeds. Both
markers must come from the exact measured bundle.

Before that aggregate marker, the probe writes a six-byte x86-64 function to an
Akashic regular file, maps it read-only, verifies the snapshot and zero-filled
tail, closes the descriptor, rejects W+X, changes the complete VMA to RX, and
executes it. `ARACH_C2_FILE_MMAP_PASS` and `ARACH_C2_MPROTECT_PASS` distinguish
those two live gates.

The probe writes a PIE main ELF, a separately built freestanding C runtime
linker, and an ET_DYN consumer/provider pair into Akashic VFS, then calls `execve` with
bounded argv and environment vectors. The interpreter emits
`ARACH_C2_RUNTIME_LINKER_ENTER`, validates the Linux auxiliary vector,
discovers the main image's and consumer's exact `DT_NEEDED` edges, snapshots
both objects, relocates the provider, eagerly binds the consumer's external
PLT symbol, emits `ARACH_C2_DT_NEEDED_PASS`,
`ARACH_C2_DEPENDENCY_GRAPH_PASS`, `ARACH_C2_SHARED_RELOCATION_PASS`, and
`ARACH_C2_EXTERNAL_SYMBOL_PASS`, emits `ARACH_C2_RUNTIME_LINKER_PASS`, and
transfers to the main image's `AT_ENTRY`. That replacement emits
`ARACH_C1_EXECVE_PASS`,
creates a live thread-group peer, and then emits the existing exit-group
marker. This proves that the old image cannot resume, same-PID ownership
reaches the two-image replacement, and deferred reclamation does not destroy
the new hierarchy. It does not claim arbitrary recursive dependency loading,
general symbol scopes, TLS relocation, constructors, or versioned lookup.

The kernel currently carries a legacy internal `crest` name for its second
boot-process slot. `ARACH_BOOTSTRAP_IMAGE` deliberately replaces that artifact
with this probe during C0 qualification; it does not promote Crest into the
COSMIC architecture.
