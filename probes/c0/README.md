# Arach C0 ring-3 probe

This bounded `no_std` ELF is qualification input, not a desktop or production
service. It is launched with Arach's Linux x86-64 execution personality and
proves the first live userspace slice: `write`, `read`, `close`, `eventfd2`,
`getpid`, `gettid`, `getppid`, anonymous `mmap`, exact-range `munmap`, `brk`,
and `exit_group`. The probe checks both normal and semaphore eventfd
semantics, including non-sleeping `EAGAIN` on an empty counter. It writes
`ARACH_C0_RING3_SYSCALL_PASS` after entering ring 3 and
`ARACH_C1_LINUX_SYSCALL_PASS` only after every Linux operation succeeds. Both
markers must come from the exact measured bundle.

The kernel currently carries a legacy internal `crest` name for its second
boot-process slot. `ARACH_BOOTSTRAP_IMAGE` deliberately replaces that artifact
with this probe during C0 qualification; it does not promote Crest into the
COSMIC architecture.
