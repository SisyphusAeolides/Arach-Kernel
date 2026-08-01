# Arach C0 ring-3 probe

This bounded `no_std` ELF is qualification input, not a desktop or production
service. It is launched with Arach's Linux x86-64 execution personality and
proves the first live userspace slice: `write`, `read`, `close`, `eventfd2`,
`poll`, `epoll_create1`, `epoll_ctl`, `epoll_wait`, `getpid`, `gettid`,
`getppid`, anonymous `mmap`, exact-range `munmap`, `brk`, private `futex`, and
transactional static/`PT_INTERP` `execve`, and `exit_group`.
The probe checks both normal and semaphore eventfd semantics, including
non-sleeping `EAGAIN` on an empty counter, and verifies that poll/epoll
readiness clears after the eventfd is drained. Its single-process futex gate
proves mismatch rejection and an empty wake without claiming a cross-thread
wake. It writes
`ARACH_C0_RING3_SYSCALL_PASS` after entering ring 3 and
`ARACH_C1_LINUX_SYSCALL_PASS` only after every Linux operation succeeds. Both
markers must come from the exact measured bundle.

The probe writes a PIE main ELF and a separately built freestanding C runtime
linker into Akashic VFS, then calls `execve` with bounded argv and environment
vectors. The interpreter emits `ARACH_C2_RUNTIME_LINKER_ENTER`, validates the
Linux auxiliary vector, emits `ARACH_C2_RUNTIME_LINKER_PASS`, and transfers to
the main image's `AT_ENTRY`. That replacement emits `ARACH_C1_EXECVE_PASS`,
creates a live thread-group peer, and then emits the existing exit-group
marker. This proves that the old image cannot resume, same-PID ownership
reaches the two-image replacement, and deferred reclamation does not destroy
the new hierarchy. It does not claim general shared-library relocation.

The kernel currently carries a legacy internal `crest` name for its second
boot-process slot. `ARACH_BOOTSTRAP_IMAGE` deliberately replaces that artifact
with this probe during C0 qualification; it does not promote Crest into the
COSMIC architecture.
