# Arach C0 ring-3 probe

This bounded `no_std` ELF is qualification input, not a desktop or production
service. It is launched with Arach's Linux x86-64 execution personality and
proves the first live userspace slice: `write`, `read`, `close`, `eventfd2`,
`pipe2`, `dup`, `dup3`, `fcntl`, `poll`, `epoll_create1`, `epoll_ctl`,
`epoll_wait`, `socket`, `socketpair`, `bind`, `listen`, `connect`, `accept`,
`accept4`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `shutdown`,
`getsockname`, `getpeername`, `setsockopt`, `getsockopt`, `getpid`, `gettid`,
`getppid`, `memfd_create`, `ftruncate`, anonymous, eager private file, and
memfd-backed shared `mmap`, exact-range `mprotect` and `munmap`, `brk`, private
`futex`, transactional static/`PT_INTERP` `execve`, and `exit_group`.
The probe checks both normal and semaphore eventfd semantics, including
non-sleeping `EAGAIN` on an empty counter, and verifies that poll/epoll
readiness clears after the eventfd is drained. Its single-process futex gate
proves mismatch rejection and an empty wake without claiming a cross-thread
wake. It writes
`ARACH_C0_RING3_SYSCALL_PASS` after entering ring 3 and
`ARACH_C1_LINUX_SYSCALL_PASS` only after every Linux operation succeeds. Both
markers must come from the exact measured bundle.

`ARACH_C1_PIPE_DESCRIPTOR_PASS` is emitted only after the probe observes a
dense collision-free namespace, descriptor-local `FD_CLOEXEC`, a duplicated
writer surviving original-fd close, pipe readiness through both poll and
epoll, automatic watch removal before descriptor reuse, bounded transfer,
EOF/HUP, and EPIPE. It leaves aliases at fixed fds
125 and 126 before `execve`; the replacement image proves that 125 retained
the shared eventfd while close-on-exec independently removed 126.

`ARACH_C1_UNIX_SOCKET_PASS` is emitted only after an `AF_UNIX` stream
socketpair and an abstract named listener complete. The probe verifies socket
creation flags, unnamed and named addresses, connect plus both accept forms,
full-duplex byte and vector transfer, `MSG_PEEK`, fixed buffer options,
`SO_PEERCRED`, poll/epoll readiness, duplicate lifetime, half-close HUP, and
namespace reuse. It also transfers an eventfd and memfd in one bounded
`SCM_RIGHTS` message, closes both sender descriptors before receipt, and proves
receiver-local close-on-exec behavior. The admitted gate is bounded:
operations that would sleep return `EAGAIN`; explicit credential messages,
filesystem socket inodes, datagram and sequenced-packet transports are not
claimed.

`ARACH_C1_SHARED_MEMORY_PASS` follows only after the received memfd is mapped
through two writable `MAP_SHARED` aliases. The probe closes the last descriptor,
writes through one alias, observes the same physical bytes through the other,
unmaps the first, observes the retained second alias, and finally unmaps it.

Before that aggregate marker, the probe writes a six-byte x86-64 function to an
Akashic regular file, maps it read-only, verifies the snapshot and zero-filled
tail, closes the descriptor, rejects W+X, changes the complete VMA to RX, and
executes it. `ARACH_C2_FILE_MMAP_PASS` and `ARACH_C2_MPROTECT_PASS` distinguish
those two live gates.

The probe writes a PIE main ELF, a separately built freestanding C runtime
linker, and a four-object ET_DYN diamond into Akashic VFS, then calls `execve`
with bounded argv and environment vectors. The interpreter emits
`ARACH_C2_RUNTIME_LINKER_ENTER`, validates the Linux auxiliary vector,
discovers the closure breadth-first, coalesces both middle dependencies onto
one core snapshot, rejects cycles, applies provider-first relocation, and
packs and installs one static TLS template, eagerly binds four external PLT
symbols through deterministic global scope, seals all objects, and executes
four dependency-first initializers. It
emits `ARACH_C2_DT_NEEDED_PASS`, `ARACH_C2_DEPENDENCY_GRAPH_PASS`,
`ARACH_C2_MULTI_OBJECT_GRAPH_PASS`, `ARACH_C2_SHARED_RELOCATION_PASS`,
`ARACH_C2_GLOBAL_SYMBOL_SCOPE_PASS`, `ARACH_C2_STATIC_TLS_PASS`,
`ARACH_C2_INITIALIZER_ORDER_PASS`, and `ARACH_C2_EXTERNAL_SYMBOL_PASS`, then
emits `ARACH_C2_RUNTIME_LINKER_PASS` and transfers to the main image's
`AT_ENTRY`. That replacement emits
`ARACH_C1_EXECVE_PASS`,
creates a live thread-group peer, and then emits the existing exit-group
marker. This proves that the old image cannot resume, same-PID ownership
reaches the two-image replacement, and deferred reclamation does not destroy
the new hierarchy. The admitted graph remains bounded to eight objects and
does not claim dynamic TLS allocation, finalizers, versioned lookup, runpaths,
or lazy binding.

The kernel currently carries a legacy internal `crest` name for its second
boot-process slot. `ARACH_BOOTSTRAP_IMAGE` deliberately replaces that artifact
with this probe during C0 qualification; it does not promote Crest into the
COSMIC architecture.
