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
`futex`, bounded `mkdir`/`mkdirat`, transactional static/`PT_INTERP` `execve`,
and `exit_group`.
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

The probe creates `/runpath` through `mkdirat(AT_FDCWD, ..., 0755)`, verifies
that a duplicate `mkdir` returns `EEXIST`, and writes three providers below
that directory. It writes the root ET_DYN object, PIE main ELF, and separately
built freestanding C runtime linker at the Akashic root, then calls `execve`
with bounded argv and environment vectors. The interpreter emits
`ARACH_C2_RUNTIME_LINKER_ENTER`, validates the Linux auxiliary vector,
discovers the closure breadth-first, coalesces both middle dependencies onto
one core snapshot, rejects cycles, applies provider-first relocation, and
decodes the root's canonical `DT_RELR` address/bitmap pair into two disjoint
initializer/finalizer writes only after a bounded validation pass. It packs
and installs one startup TLS template. It publishes a bounded
dynamic-thread vector at `FS:8`, applies one real `R_X86_64_TPOFF64` plus one
real `R_X86_64_DTPMOD64`/`R_X86_64_DTPOFF64` pair, and resolves seven
exact-version external PLT symbols through deterministic global scope. One
additional PLT edge may resolve only the exact unversioned,
undefined, global `STT_NOTYPE` symbol `__tls_get_addr`; the interpreter then
checks every module and offset before returning an address. Two further root
PLT edges are weak: deterministic first-definition scope selects the
provider's weak function ahead of the observer's later strong definition, and
the unversioned optional hook has no provider and is written as zero. The eager
data-binding proof adds three root `R_X86_64_GLOB_DAT` entries: one
exact-version provider object, one weak object that selects the provider's
earlier weak definition ahead of the observer's later strong definition, and
one unversioned optional data reference written as zero. A fourth observer
entry resolves to the main executable's 24-byte `arach_copy_source`. The
interpreter validates the bounded main ET_DYN image and all immutable SysV,
GNU-version, and relocation metadata, resolves an exact-size versioned
`R_X86_64_COPY`, proves disjoint targets and source, and prevalidates the whole
copy batch before writing it. The root's `DT_SYMBOLIC` initializer later
mutates only its original object, while the observer consumes the independent
main copy. The absolute-symbol
proof adds four root `R_X86_64_64` entries: one versioned
function pointer, one versioned provider-vector pointer at a checked
eight-byte addend, one earlier weak object pointer, and one unresolved weak
pointer written as zero. The exact singleton `DT_RUNPATH=/runpath` entries on
the root and both middle objects
drive each direct dependency lookup; the core intentionally carries no
runpath. The
interpreter records each opened path and rejects relative, duplicate, empty,
dot-segment, over-capacity, legacy `DT_RPATH`, and unknown dynamic-table input.
It seals all objects and executes four dependency-first initializers. It
emits `ARACH_C2_DT_NEEDED_PASS`, `ARACH_C2_DEPENDENCY_GRAPH_PASS`,
`ARACH_C2_MULTI_OBJECT_GRAPH_PASS`, `ARACH_C2_RUNPATH_PASS`,
`ARACH_C2_SHARED_RELOCATION_PASS`,
`ARACH_C2_PACKED_RELATIVE_PASS`,
`ARACH_C2_COPY_RELOCATION_PASS`,
`ARACH_C2_GLOBAL_SYMBOL_SCOPE_PASS`, `ARACH_C2_WEAK_BINDING_PASS`,
`ARACH_C2_GLOBAL_DATA_PASS`,
`ARACH_C2_ABSOLUTE_SYMBOL_PASS`,
`ARACH_C2_SYMBOL_VERSION_PASS`,
`ARACH_C2_STATIC_TLS_PASS`, `ARACH_C2_DYNAMIC_TLS_PASS`,
`ARACH_C2_INITIALIZER_ORDER_PASS`, and `ARACH_C2_EXTERNAL_SYMBOL_PASS`, then
emits `ARACH_C2_RUNTIME_LINKER_PASS` and transfers to the main image's
`AT_ENTRY`. That replacement emits
`ARACH_C1_EXECVE_PASS`, creates a live thread-group peer, invokes the one-shot
x86-64 finalizer callback, emits `ARACH_C2_FINALIZATION_PASS`, and then emits
the existing exit-group marker. This proves that the old image cannot resume,
same-PID ownership
reaches the two-image replacement, and deferred reclamation does not destroy
the new hierarchy. The admitted graph remains bounded to eight startup objects
and does not claim late `dlopen` TLS allocation, TLSDESC, `DT_RPATH`,
`$ORIGIN`, environment/cache/hwcaps search, weak TLS binding, broader data
relocation forms, GNU-unique or IFUNC binding, or lazy binding.
Directory admission is limited to the ephemeral Akashic namespace and an exact
0755 request; general Unix mode persistence, ownership, ACLs, and umask
semantics remain outside this gate.

The kernel currently carries a legacy internal `crest` name for its second
boot-process slot. `ARACH_BOOTSTRAP_IMAGE` deliberately replaces that artifact
with this probe during C0 qualification; it does not promote Crest into the
COSMIC architecture.
