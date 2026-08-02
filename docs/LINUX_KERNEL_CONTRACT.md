# Linux kernel compatibility contract

Arach implements Linux compatibility as a set of measured contracts. It does
not equate a similar internal facility with Linux compatibility, and it does
not allow one successful build to stand in for runtime behavior.

## Contract profiles

The Rust contract in `src/linux_contract.rs` defines three initial profiles:

- **External module build** covers Kbuild, generated configuration,
  `Module.symvers`, MODPOST, linker scripts, kernel headers, and Linux `.ko`
  semantics.
- **NVIDIA open runtime** extends the build profile with memory allocation,
  PCI, DMA/IOMMU, MSI/IRQ, synchronization, asynchronous execution, the Linux
  device model, DRM/KMS, firmware loading, and module lifecycle behavior.
- **COSMIC userspace** covers the kernel-facing UAPI and runtime services that
  the pinned COSMIC system exercises. It is independent of module-build
  qualification.

Profiles overlap where they consume the same measured behavior, but none
implies another unless its complete gate set is present.

## Evidence rule

A passed measurement names one gate and carries:

1. a non-empty test-suite identity,
2. at least one passing case, and
3. a non-zero digest for the tested artifact.

The qualification result is derived from admitted measurements. A release
manifest must preserve the suite identity, case count, artifact digest, source
revision, toolchain revision, and target architecture so the result can be
reproduced. Handwritten booleans and native code-path similarity are not
evidence.

## Compatibility boundaries

The Linux kernel has several distinct interfaces:

- userspace syscall, ioctl, device-file, procfs, sysfs, and netlink UAPI;
- the external-module build interface;
- loadable-module ELF metadata, relocations, symbol versions, init and exit;
- in-kernel KPI used by a particular module source revision; and
- observable hardware lifecycle behavior.

Arach versions and tests each boundary separately. Linux does not promise a
stable in-kernel module ABI, so Arach pins the consumer source revision and
derives the required KPI from that source's conftests and behavioral tests.

## Current state

### Unified descriptors, anonymous pipes, and Unix stream sockets

Each exact thread-group leader generation owns one dense table of 128 public
Linux descriptors. Descriptors reference separately generation-tagged open
objects, so regular files, eventfds, timerfds, epoll instances, pipes, Unix
sockets, and the three standard streams cannot collide. `dup`, `dup2`, `dup3`,
`F_DUPFD`, and
`F_DUPFD_CLOEXEC` add references to the same open object; descriptor flags
remain local while status flags, file position, and inode identity remain
shared. A close racing an active operation marks the object closing and defers
backend reclamation until the active lease ends.

Epoll stores the open-object key and retains its own reference instead of
storing a recyclable public fd. Closing one duplicated descriptor leaves the
watch attached while another alias remains; closing the last descriptor
removes every watch for that object before the number can be reused. Closing
the epoll instance releases every retained key. Nested epoll graphs remain
fail-closed, and adding a regular file returns Linux `EPERM`. Error and hangup
events are delivered independently of the requested interest mask.

Anonymous `pipe`/`pipe2` endpoints share an allocation-free 4 KiB ring. Writes
within `PIPE_BUF` commit completely or return `EAGAIN`; reads preserve byte
order, the final writer close produces EOF and `POLLHUP`, and a write after the
last reader closes returns `EPIPE`. Poll and epoll observe the same readiness
generation. The measured probe also proves that one alias survives `execve`
while a second alias to the same eventfd is independently removed by
close-on-exec. `ARACH_C1_PIPE_DESCRIPTOR_PASS` records this complete live
path. Host tests additionally prove duplicate-aware watch lifetime, automatic
last-close removal, and non-retargeting after descriptor reuse.

The bounded `AF_UNIX` profile adds `SOCK_STREAM` and `socketpair` endpoints to
that same open-object table. A fixed registry holds 64 generation-encoded
endpoints, 32 full-duplex connections, eight pending accepts per listener, and
two 4 KiB byte queues per connection. Pathname and length-preserving abstract
addresses support bind, listen, connect, plain accept, and `accept4`.
`getsockname`, `getpeername`, `SO_TYPE`, `SO_DOMAIN`, `SO_ACCEPTCONN`, fixed
send/receive buffer options, and root-profile `SO_PEERCRED` expose the admitted
identity surface. Ordinary reads/writes, `sendto`/`recvfrom`, and
`sendmsg`/`recvmsg` with at most 16 vectors share one transfer path. One
x86-64 `SOL_SOCKET`/`SCM_RIGHTS` control message may carry at most eight
descriptors. In-transit reservations retain the exact global open descriptions,
so a receiver in another process generation observes the same status flags,
file cursor, and backend even after the sender closes every local descriptor.
Eight ancillary boundaries per stream direction are retained without dynamic
allocation. `MSG_CMSG_CLOEXEC` is descriptor-local, undersized control buffers
set `MSG_CTRUNC` and close every uninstalled right, and ordinary `read` safely
discards reached rights. `MSG_PEEK`, half-close, EOF, HUP/error readiness,
duplicate lifetime, final-close epoll detachment, and listener namespace reuse
are measured. Host tests additionally connect distinct exact process
generations and reject stale endpoint handles, namespace collisions, backlog
overflow, unsupported flags, and writes beyond the fixed queue.

`ARACH_C1_UNIX_SOCKET_PASS` records socketpair and named-listener execution in
the measured QEMU image. Idris 2 and Agda place the socket certificate
structurally after the descriptor/pipe certificate, so every downstream group
exit, image replacement, dynamic-linker, and shared-object certificate retains
the local IPC evidence.

This is not yet the complete blocking contract. A pipe operation that would
sleep returns `EAGAIN` even when `O_NONBLOCK` is clear, and `EPIPE` does not yet
queue `SIGPIPE`. Socket operations that would sleep also return `EAGAIN`.
Scheduler-backed waits, asynchronous interruption, `splice`, named FIFOs,
filesystem-backed socket inodes and unlink lifetime, datagram and sequenced-
packet sockets, explicit credential control messages, and process-shared
descriptor tables across fork remain later gates. Passing Unix sockets or
epoll instances is rejected until cyclic descriptor graphs have bounded garbage
collection. `MSG_PEEK` observes bytes without creating duplicate received
descriptors; a subsequent consuming receive obtains the retained rights.

### Generation-bound memory files and shared mappings

`memfd_create`, `ftruncate`, and non-anonymous `MAP_SHARED` provide the first
bounded process-shared memory profile. A generation-encoded registry admits 32
memory files, names of at most 249 bytes, `MFD_CLOEXEC` and
`MFD_ALLOW_SEALING`, and a maximum size of 1 MiB per object. The unified
descriptor table owns the open description, while the process runtime owns the
physical backing independently. Shared mappings from distinct committed page
tables install the same physical frames at independently selected virtual
addresses and may use page-aligned offsets. Shrink is rejected while any VMA
exists. Closing the final descriptor marks the backing private to its VMAs;
the final unmap or process retirement releases the frames.

The live probe transfers a truncated memory file with `SCM_RIGHTS`, closes the
sender descriptor before receipt, applies close-on-exec to the received
descriptor, creates two writable shared aliases, closes that descriptor, and
observes one alias through the other before and after the first unmap.
`ARACH_C1_SHARED_MEMORY_PASS` records the complete path. Host tests separately
prove cross-process physical-frame identity, sender-close transfer lifetime,
shared regular-file offsets, control truncation cleanup, stale-generation
rejection, resize bounds, and final-frame reclamation.

This profile does not yet implement memory-file payload `read`/`write`, seals,
hugetlb flags, private copy-on-write memfd mappings, partial VMA split/merge,
file growth through writes, or Linux `SIGBUS` delivery beyond EOF. Those paths
fail closed.

### Generation-bound private file mappings

The admitted file-backed `mmap` profile is an eager `MAP_PRIVATE` snapshot of a
regular Akashic file. The Linux descriptor must belong to the exact thread-group
generation and carry read authority. One VFS lock hold validates that capability,
captures inode identity and file length, and copies the page-aligned source range
without changing the descriptor cursor. The syscall then allocates private
zeroed frames, copies the snapshot, zero-fills the final partial page, and only
publishes the VMA after every frame and PTE succeeds. Closing the descriptor does
not affect the resulting mapping.

`mprotect` currently accepts only one complete releasable VMA and the R, RW, and
RX profiles. It preflights every generation-owned leaf, preserves hardware
accessed/dirty state, rejects W+X, and restores already changed leaves if a later
PTE write fails. The syscall return gate reloads the selected CR3 before Ring 3
resumes, flushing stale local non-global translations. Partial VMA changes,
`PROT_NONE`, `MAP_FIXED`, shared mappings of non-memfd files, non-Akashic
files, demand paging, and pages wholly beyond EOF remain fail-closed.

The measured Rust probe writes `mov eax, 42; ret` to a regular file, maps it
read-only, validates copied bytes and zero fill, closes the descriptor, proves a
W+X request is rejected, transitions the whole page to RX, and calls the mapped
entry. QEMU must observe `ARACH_C2_FILE_MMAP_PASS` followed by
`ARACH_C2_MPROTECT_PASS`. Host fault injection separately proves a failed
multi-page permission update rolls back to the original leaf permissions. Idris
2 and Agda retain descriptor snapshot, private ownership, W^X transition, and
mapped-entry evidence in a downstream file-mapping certificate.

### Transactional static and interpreter process replacement

The first `execve` profile admits one running Linux thread-group leader with no
peer threads and either one static x86-64 ELF or one ET_DYN main image naming a
bounded ET_DYN runtime linker. Path bytes, argv pointers, environment pointers,
and all referenced strings are copied from the old address space before any
replacement is installed. Static execution uses one locked VFS snapshot. For
`PT_INTERP`, the kernel first validates the embedded absolute path and then
re-snapshots the executable and interpreter under one namespace lock; it
rejects any executable-path drift before using the pair. Runtime-only image
authority measures each immutable file independently.

Installation creates a separate inactive hierarchy and seals every admitted
segment W^X. Dynamic execution places the main image and runtime linker at
distinct deterministic biases and commits them as one transaction. Its fresh
System V x86-64 stack carries argv, envp, `AT_PHDR`, `AT_PHENT`, `AT_PHNUM`,
`AT_PAGESZ`, `AT_BASE`, `AT_ENTRY`, identity values, `AT_RANDOM`, `AT_EXECFN`,
and `AT_NULL`; initial RIP names the interpreter, not the main executable. A
temporary activation validation restores the old root before publication.
Publication then exchanges the service registry's owned image and atomically
updates lifecycle launch/context state while preserving PID generation,
parent, service class, capability root, ABI, and kernel entry stack. Any
failure before lifecycle publication returns ownership to the old image and
releases the rejected hierarchy. Successful publication resets caught signal
dispositions, pending/frame state, robust and child-TID registrations, FS
base, and close-on-exec descriptors. The architecture return gate changes CR3
before it reclaims the deferred old hierarchy.

The measured QEMU chain requires the file-mapping markers above, followed by
`ARACH_C1_PIPE_DESCRIPTOR_PASS`, `ARACH_C1_UNIX_SOCKET_PASS`,
`ARACH_C1_SHARED_MEMORY_PASS`,
`ARACH_C1_LINUX_SYSCALL_PASS`,
`ARACH_C2_RUNTIME_LINKER_ENTER`,
`ARACH_C2_DT_NEEDED_PASS`, `ARACH_C2_DEPENDENCY_GRAPH_PASS`,
`ARACH_C2_MULTI_OBJECT_GRAPH_PASS`, `ARACH_C2_RUNPATH_PASS`,
`ARACH_C2_SHARED_RELOCATION_PASS`,
`ARACH_C2_PACKED_RELATIVE_PASS`, `ARACH_C2_COPY_RELOCATION_PASS`,
`ARACH_C2_GLOBAL_SYMBOL_SCOPE_PASS`, `ARACH_C2_WEAK_BINDING_PASS`,
`ARACH_C2_GLOBAL_DATA_PASS`,
`ARACH_C2_ABSOLUTE_SYMBOL_PASS`,
`ARACH_C2_SYMBOL_VERSION_PASS`,
`ARACH_C2_STATIC_TLS_PASS`, `ARACH_C2_DYNAMIC_TLS_PASS`,
`ARACH_C2_INITIALIZER_ORDER_PASS`, `ARACH_C2_EXTERNAL_SYMBOL_PASS`,
`ARACH_C2_RUNTIME_LINKER_PASS`, `ARACH_C1_EXECVE_PASS`, and
`ARACH_C2_FINALIZATION_PASS`. The
freestanding C runtime-linker probe validates the kernel-generated auxiliary
vector, completes the bounded shared-object transaction below, and jumps to
`AT_ENTRY`; the Rust main image invokes the ABI finalizer callback and then
supplies the existing live-peer `exit_group` evidence. Host tests separately
cover bounded vector capture,
atomic pair snapshots, independent measurements, composite installation,
auxiliary-vector bytes, lifecycle epoch invalidation, registry exchange,
close-on-exec families, signal reset, rollback ownership, and process-pool
recycling. Idris 2 and Agda make those gates fields of a downstream dynamic exec
certificate.

### Bounded dependency and shared-object relocation

The measured main PIE has exactly one `DT_NEEDED` root and one versioned
`R_X86_64_COPY`; the closure engine is bounded for up to eight roots and up to
eight dependencies in each of eight shared objects. The runtime linker derives
the main load bias from `AT_PHDR`, reconstructs the x86-64 ET_DYN header, and
admits only `PT_LOAD`, `PT_PHDR`, the exact `PT_INTERP=/arach-ld.so`, and one
R-only `PT_DYNAMIC`. At most eight disjoint page-aligned W^X load regions may
occupy the first 64 KiB, and `AT_ENTRY` must lie in an executable region. The
ELF header, program headers, and interpreter bytes must remain inside
nonwritable main-image loads. The dynamic table, SysV hash, symbol/string
tables, copy relocations, and optional GNU version requirement tables must
remain inside nonwritable, non-executable loads. `DT_FLAGS_1` must be exactly
`DF_1_PIE`;
SONAME, runpath, symbolic, packed/PLT/relative relocation, initializer,
finalizer, and version-definition state is rejected for the main image.

Every main dependency is a canonical root-only SONAME component. The linker
discovers the closure breadth-first, uses one object slot and immutable
snapshot per SONAME, records every edge, and rejects duplicate edges within
one object, capacity overflow, missing providers, SONAME mismatches,
self-edges, and all other cycles. A bounded topological pass computes
provider-first relocation order before any object is made executable.

The admitted Linux directory slice accepts `mkdir` and `mkdirat` only for an
exact 0755 request. Relative `mkdirat` is limited to `AT_FDCWD`; absolute paths
ignore its directory descriptor as Linux requires. The measured probe creates
the ephemeral `/runpath` directory and proves duplicate creation returns
`EEXIST`. This is not a claim of persistent Unix ownership, ACL, or umask
semantics.

Each dependency must be a regular generation-owned Akashic file no larger than
64 KiB. A shared object may carry one `DT_RUNPATH` containing one to four
unique absolute directories, with a 255-byte total and 63-byte per-directory
bound. Empty components, trailing or repeated slashes, `.` and `..`
components, relative directories, and unsupported bytes fail closed. Lookup
applies that runpath only to the object's direct dependencies, continues only
after exact `ENOENT`, and then tries the qualified Akashic root. The selected
path is retained as evidence. The linker opens each object read-only, derives
its exact size with `lseek`, and
uses a temporary private file mapping to validate one x86-64 ET_DYN image with
at most 16 program headers and eight page-aligned load segments. Object slots
begin at `0x30000000` and are separated by 16 MiB, while each object is bounded
to 64 KiB. Every load is a disjoint eager private RW snapshot; bytes beyond
`p_filesz` are zeroed and every page remains non-executable while relocation
is possible.

Every object requires an exact SONAME, a SysV hash table, and bounded dynamic
symbol and string tables. Each relocation table is bounded to 64 entries.
Symbol-zero `R_X86_64_RELATIVE` entries are checked against final-writable
targets and mapped addends. Eager `R_X86_64_JUMP_SLOT` entries must reference
undefined default-visible global or weak functions and final-writable GOT
slots. GNU's unversioned weak function-reference `STT_NOTYPE` form is admitted
at version index zero. With `DT_SYMBOLIC`, the requesting object is searched
first; remaining definitions are searched in deterministic breadth-first
object order. The first matching bounded executable global or weak function
wins, matching normal Linux runtime scope semantics. An unversioned weak
function with no definition is written as zero; an unresolved global or
explicitly versioned weak reference fails the transaction. Every written slot
is read back.

An object may additionally carry one complete `DT_RELR`/`DT_RELRSZ`/
`DT_RELRENT` triplet. The table must reside entirely in one immutable R-only
load, is naturally aligned, contains at most 128 eight-byte entries, and may
expand to at most 8,192 writes. Decoding requires
an aligned address entry before any bitmap, rejects empty bitmaps, and admits
only monotonically increasing canonical address/bitmap streams. A validation
pass proves every expanded target is aligned and final-writable, every
implicit addend produces a mapped in-object address under checked base
addition, and no packed target overlaps another packed write, `.rela.dyn`, or
`.rela.plt`. Only then does a second pass write and read back each value. A
partial triplet, malformed size, overflow, descending stream, duplicate,
unmapped addend, nonwritable target, or cross-table overlap fails closed before
the first packed write.

The main executable's `.rela.dyn` may contain only `R_X86_64_COPY`. Dynamic
symbol zero must be canonical; every other symbol must be one defined,
default-visible global `STT_OBJECT` matched one-to-one with exactly one copy
relocation at its own writable address. Individual extents are nonempty, all
targets are pairwise disjoint, and their aggregate is bounded to 64 KiB.
Unversioned symbols use ordinary process scope; an explicit GNU requirement
must match both the provider SONAME and version definition. Resolution searches
only the admitted shared-object graph and requires one readable provider object
of exactly the same size. Source and destination ranges may not overlap. The
linker resolves and bounds the complete batch before writing any byte, then
copies and reads back each exact extent. Malformed metadata, a missing or
wrong-sized provider, arithmetic overflow, overlapping targets, or source/
destination aliasing therefore rejects the image before any copy byte is
written.

After the copy is installed, admitted main-executable copy objects precede
ordinary shared objects in process-global data and absolute-object lookup. A
requesting DSO carrying `DT_SYMBOLIC` still searches its own definitions first.
The measured root uses that local preference to mutate its original provider
object while the observer's new `GLOB_DAT` resolves to the independent main
copy, making both the copy and its interposition visible at runtime.

Eager `R_X86_64_GLOB_DAT` entries in `.rela.dyn` admit undefined
default-visible global `STT_OBJECT` references and weak `STT_OBJECT` or GNU
`STT_NOTYPE` references with zero addends. Definitions must be bounded,
nonempty, readable `STT_OBJECT` ranges. Data lookup uses the same exact
version/provider constraints, `DT_SYMBOLIC` requester preference, and
deterministic first-definition object order as function lookup. An import's
nonzero declared size may not exceed its selected definition. An unversioned
weak data reference with no definition is written as zero; unresolved globals
and explicitly versioned weak data references fail closed. Slots are aligned,
final-writable, and read back after every write.

Bounded `R_X86_64_64` entries in `.rela.dyn` admit defined or undefined
default-visible global and weak `STT_FUNC` or `STT_OBJECT` symbols. An
undefined weak `STT_NOTYPE` reference is also admitted at a zero addend.
Resolution uses the same exact version/provider constraints, `DT_SYMBOLIC`
requester preference, and breadth-first first-definition scope as the PLT and
global-data paths. Functions require a zero addend and a nonempty executable
definition. Objects require a nonempty readable definition, a nonnegative
addend strictly inside that definition, and any nonzero imported size must fit
the selected provider. The linker computes `S + A` with checked arithmetic,
writes only aligned final-writable words, and reads every word back. An
unversioned unresolved weak reference with a zero addend becomes zero;
unresolved globals, explicitly versioned weak references, TLS symbols,
negative or out-of-object addends, and function-interior addresses fail
closed.

Versioned objects may provide one `DT_VERSYM` table, at most 16 linked
`DT_VERDEF` records, at most 16 linked `DT_VERNEED` records, and at most 32
requirement auxiliaries. The version-symbol table has exactly one entry per
SysV dynamic symbol. Version-definition index 1 is the base definition and
must name the object's exact SONAME; later definition indices are contiguous,
have validated ELF hashes, and do not inherit other versions. Every version
requirement names one direct `DT_NEEDED` provider, uses a unique bounded index,
and carries an exact validated version hash and name. Explicit imports match
both version and provider SONAME. An unversioned lookup accepts only an
unversioned or default definition, while a hidden definition remains available
only to an explicit version request.

At most one bounded `PT_TLS` template is admitted per object. The linker
packs all admitted templates into one zeroed Variant-II initial-exec arena of
at most 16 KiB, preserves each template alignment up to 4 KiB, assigns stable
load-order module identifiers, places a self-referencing two-word thread
control block after the payload, and installs its address with `ARCH_SET_FS`.
Defined default-visible global TLS symbols must remain inside their exact
template. Bounded `R_X86_64_DTPMOD64`, `R_X86_64_DTPOFF64`, and
`R_X86_64_TPOFF64` writes use the same deterministic symbol scope, target only
final-writable aligned words, use checked signed thread-pointer arithmetic,
and are read back after each write. A finite DTV at `FS:8` records one exact
module address and size per object. Only the compiler-generated undefined,
default-visible global `STT_NOTYPE` symbol `__tls_get_addr` may bind to the
linker's resolver, which checks the DTV, module, offset, arena, and resulting
address before every startup general-dynamic access.

All object relocations run in provider-first order before external PLT binding.
After every object reaches final W^X permissions, each optional `DT_INIT`
function and at most 16 `DT_INIT_ARRAY` entries per object execute in the same
dependency-first order. Every initializer target must remain inside that
object's declared executable loads. After initialization, the linker freezes a
one-shot finalization plan containing each optional `DT_FINI`, at most 16
`DT_FINI_ARRAY` entries per object, and no unvalidated target. It passes the
plan's callback in x86-64 process-entry register `RDX`. The main image invokes
that callback once; objects run in reverse dependency order, each finalization
array runs in reverse index order, and `DT_FINI` follows its array.
Preinitializers, lazy binding, `DT_REL`, text relocations,
`DT_RPATH`, `$ORIGIN`, environment/cache/hwcaps search, weak TLS symbols,
unresolved versioned weak symbols, GNU-unique and IFUNC binding, version
inheritance, and unknown dynamic tags remain rejected.

The measured fixture is the four-object diamond `libarach-probe.so` to
`libarach-provider.so` and `libarach-observer.so`, with both middle objects
depending on `libarach-core.so`. Breadth-first order is probe, provider,
observer, core; the core is snapshotted once and relocation order is core,
provider, observer, probe. The core contributes three explicit relative
relocations and one `R_X86_64_TPOFF64`; each middle object contributes one
initializer and one finalizer-array relocation. The root packs its initializer
and finalizer-array pointers into one `DT_RELR` address/bitmap pair. The middle
objects contribute two versioned object PLT edges each and the root contributes
three versioned plus two unversioned
weak edges; the provider adds the one unversioned resolver edge. The first weak
edge selects the provider's earlier weak definition even though the observer
exports a later strong definition. The second has no definition and is written
as zero without being called. The root also contributes three `GLOB_DAT`
edges: one exact-version provider object, one unversioned weak object that
selects the provider's earlier weak definition over the observer's later
strong definition, and one unresolved unversioned weak data slot written as
zero. The observer adds one `GLOB_DAT` reference to the root's 24-byte
`arach_copy_source`; it resolves to the main executable's exact-version copy,
while the `DT_SYMBOLIC` root retains its original definition. Four root
`R_X86_64_64` entries then bind one exact-version function
pointer, one exact-version provider-vector pointer with an eight-byte interior
addend, one weak object pointer through the earlier provider, and one
unresolved weak `STT_NOTYPE` pointer as zero. Exact evidence therefore requires
nine relative, two packed-relative, one exact-size copy, three TLS, eighteen
external, four global-data, four absolute-symbol, one bounded nonzero-addend,
one resolved and one unresolved weak function, one resolved and one unresolved
weak data, one resolved and one unresolved weak absolute edge, and fourteen
versioned writes.

After relocation, the linker changes every complete VMA to its declared R,
RW, or RX permission and executes core, provider, observer, and root
initializers in that order. It then closes all four descriptors, removes all
four temporary mappings, resolves `arach_shared_probe` through the root's SysV
table, and calls it. Execution measures the provider's first-scope weak result,
crosses the callable root and middle-object PLT edges, consumes the provider's
first-scope weak data, exact-version global data, relocated function pointer,
checked provider-vector interior pointer, and the three-word executable copy.
The root initializer mutates its `DT_SYMBOLIC` source only after the copy has
been installed; the observer still reads the unchanged executable storage,
which makes source/destination independence and main-object interposition
observable. Execution also sees all three optional weak slots at zero before
the core dereferences its relative-relocated pointer and FS-relative TLS word.
Each dependent initializer
records success only after observing its providers' state. After transfer to
the main image, the callback executes root, observer, provider, and core
finalizers; each array precedes that object's `DT_FINI`, and an eight-state TLS
transition makes any reordering observable. The measured success markers
therefore cannot be emitted by merely parsing the graph or relocation tables.

Idris 2 and Agda retain dependency discovery, bounded snapshot ownership,
relative relocation, final W^X sealing, and observed symbol execution in the
existing `SharedObjectCertificate`. A downstream `DependencyGraphCertificate`
adds graph closure, external-symbol relocation, eager PLT binding, and an
observed cross-object call. `MultiObjectGraphCertificate` then requires bounded
closure, breadth-first discovery, duplicate-dependency coalescing, acyclic
provider-first order, and deterministic global symbol scope.
`RuntimeInitializationCertificate` adds measured directory creation,
canonical bounded runpaths, direct-dependency search, first-definition weak
function binding, unresolved weak-function-to-zero behavior, bounded global
data relocation, first-definition weak-data binding, unresolved weak-data-zero
behavior, bounded absolute-symbol relocation, interior-object addend bounds,
first-definition weak absolute binding, unresolved weak-absolute-zero
behavior, bounded packed-relative relocation, canonical finite decoding,
disjoint packed targets, immutable packed metadata, a bounded main-executable
snapshot, exact copy relocation extents, disjoint copy targets and sources, a
prevalidated copy batch, main-executable interposition, the finite startup TLS
layout and DTV, checked TLS
relocation and resolution, and initializer order while retaining the complete
graph certificate. `RuntimeFinalizationCertificate` then requires bounded GNU
version tables, exact version-and-provider resolution, the process-entry
finalizer handoff, and reverse finalizer execution. This is not yet a general
system linker: late dynamic TLS allocation, general search policy, weak TLS
binding, GNU-unique and IFUNC binding, lazy binding, ASLR, general VMA
splitting, demand paging, and cryptographically qualified process entropy
remain separate acceptance gates.

The current tree passes external-Kbuild and static load-admission gates against
real RHEL 10/Linux 6.12 and Ubuntu 24.04/Linux 6.8 module artifacts. Its Linux
`.ko` path now plans six page-separated core/init RX, R and RW regions, freezes
one live-export snapshot before mutation, validates and freezes the supported
x86-64 relocations, and models transactional seal, init, init-discard, cleanup,
rollback and release through a kernel-backend contract. Unit tests exercise
those ownership transitions, including failed init and retryable cleanup.

The x86-64 tree now also contains a capability-gated native module-memory
owner and a transactional native backend adapter. The memory owner reserves
the unused final 1 GiB kernel PML3 slot, keeps module images within signed
PC-relative reach of linked kernel text, stages content in non-present zeroed
frames, publishes exact RX/R/RW leaf permissions, revokes init pages, and
quarantines virtual extents whenever page-table detachment or physical
reclamation is incomplete. The adapter adds a fixed-capacity live-name
registry, explicit sealed-to-committed ownership, lifecycle state, executable
address validation, duplicate-name rejection, and cleanup retry semantics.

The generic installer now requires `prepare_for_seal` after every byte and
relocation has been verified but before any page becomes present. Native
backends must supply an unsafe pre-seal processor that handles every required
Linux and architecture special section or rejects the module. The load plan
now derives a typed inventory from the allocated sections measured in the RHEL
smoke and NVIDIA open-module artifacts. It distinguishes module identity,
alternatives, jump labels, static calls, dynamic tracing, SMP-lock and call-site
patching, ORC unwind data, bug tables, parameters, tracepoints, exports,
per-CPU data, allocation tags and printk indexes. That inventory is an explicit
argument to the unsafe processor, so these sections cannot remain hidden behind
a generic byte image. The processor reads relocated values through a bounded
frame-backed staging API while the module virtual range remains non-present,
then returns an exact category-coverage receipt. Missing or extraneous coverage
aborts the reservation before W^X publication. Lifecycle dispatch is a separate
unsafe executor contract whose error path guarantees module control was never
entered. There are intentionally no permissive no-op or host-call
implementations of either contract.

The first production category processor handles the packed 14-byte x86-64
`.altinstructions` format measured in the RHEL 10 SDK and NVIDIA open modules.
It selects features against an all-eligible-CPU policy, validates every relative
target, retargets admitted rel32 branches and direct calls, pads the original
instruction span, and verifies the staged patch. The currently measured NVIDIA
POPCNT and movabs replacements are admitted. Unknown flags, instruction forms,
or alternative targets outside executable module regions reject the module;
they are never copied speculatively.

The pre-seal processor also validates x86-64 `__jump_table` records. It reads
module-local static-key state from staging, requires an explicit provider for
external keys, checks the original two- or five-byte NOP/JMP form and the
executable target, and applies all initial transitions only after the table has
been preflighted. Dynamic static-key registration and later SMP text updates
remain a separate runtime contract; a successfully admitted table is not
claimed as full jump-label parity by itself.

The same processor now preflights x86-64 `.static_call_sites` and optional
`.static_call_tramp_key` records. It admits only non-tail five-byte call sites,
validates trampoline metadata, resolves module-local function pointers from the
staged image (or requires an explicit external-key provider), and transitions
only recognized NOP/return-zero/call forms to a checked direct call. Tail-call
transforms and dynamic static-call registration remain runtime work.

It also validates x86-64 `.smp_locks` rel32 lock-prefix tables. Every entry
must resolve to an executable module byte and must contain the emitted lock
prefix or its already-patched one-byte NOP. A kernel feature provider supplies
the immutable SMP/UP decision for the transaction; UP admission removes the
prefix only after the complete table has been preflighted. CPU hotplug-aware
repatching remains part of the runtime architecture contract.

Host fault-injection tests cover stale handles, conflicting hierarchy
ownership, allocation failure, partial page-table publication, failed seal
rollback, partial init discard, TLB flush ordering, retryable reclamation,
pre-seal rejection, duplicate live names, failed initialization, and cleanup
dispatch retry.

That is still not runtime qualification. Arach has no qualified synchronous
all-CPU TLB implementation or concrete native lifecycle executor for this
path. Dynamic jump-label/static-call registration and updates, tail-call static
call transforms, tracing, unwind data, parameters, exports, per-CPU data, and
the other inventoried Linux categories still need production runtime
processors, and no admitted module has executed in an Arach boot.
`current_arach_evidence()` therefore grants no NVIDIA-runtime credit until a
native integration suite supplies those observations.

### Native x86-64 module window

The linked Arach kernel occupies PML3 slot 510 in the final PML4 entry. Native
Linux modules are assigned PML3 slot 511, the canonical range
`0xffffffffc0000000..0xffffffffffffffff`. The module-memory owner divides that
range into exclusive 2 MiB extents and allocates private PML1 tables for each
reservation. A reservation is inaccessible while bytes and relocations are
written; the final seal is the first operation that installs present leaf
entries.

The upper hierarchy must remain supervisor-only, writable, executable, and
free of huge-page aliases. Reusing an extent is permitted only after every
leaf has been revoked, its PML2 links have been detached, and a synchronous
kernel-range TLB invalidation has completed on every CPU that shares the
hierarchy. The `LinuxModuleTlb` implementation is therefore an explicit unsafe
architecture contract. A local `invlpg` loop alone is insufficient for SMP
qualification.

## External-Kbuild smoke test

First materialize a prepared Linux header/output tree as an Arach contract SDK:

```sh
scripts/materialize-linux-contract-sdk.sh /usr/src/kernels/$(uname -r)
```

The materializer records the exact kernel release and SHA-256 digests of its
configuration, generated autoconfiguration, and `Module.symvers`. The SDK is a
compile-time contract fixture; Arach still has to implement and test the
corresponding runtime semantics.

`scripts/test-linux-kbuild-sdk.sh` builds a real C out-of-tree module, requires
the generated configuration and symbol-version artifacts, and inspects the
result for module metadata and lifecycle symbols. By default it uses the
prepared kernel-devel tree for the running host. A future Arach SDK is supplied
through `ARACH_KBUILD_SOURCE` and `ARACH_KBUILD_OUTPUT`:

```sh
ARACH_KBUILD_SOURCE=/path/to/arach-contract/source \
ARACH_KBUILD_OUTPUT=/path/to/arach-contract/output \
    scripts/test-linux-kbuild-sdk.sh
```

The generated measurement is written below `target/linux-contract/`. This
smoke test can qualify the external-build profile for that exact SDK artifact;
it provides no runtime credit until Arach loads and exercises the module.
The same artifact is also parsed by Arach's bounded `arach-ko-inspect` preflight.
Inspection validates its allocatable sections and produces the page-separated
core/init load blueprint, keeping the build fixture and loader vocabulary
synchronized.

The smoke source additionally asks the exact configured Kbuild compiler to
emit `.arach.module_abi`. Its fixed-width record measures `struct module`,
`struct module_memory`, name/state/list/lifecycle offsets, every module-memory
slot, alignment, and optional unload/ROX fields after configuration and
randstruct have taken effect. `arach-ko-inspect` bounds-checks every field and
requires the measured structure size to equal
`.gnu.linkonce.this_module` before writing `module-abi.json`. This is necessary
even within one distribution release: the installed RHEL 10.0 and 10.2 SDKs
already differ in the module-memory ROX field and unload offsets. Arach carries
the SDK-derived contract forward instead of borrowing offsets from the running
host kernel.

The first consumer of that contract is the native x86-64 module-identity
processor. While the mapping is still non-present, it validates the compiled
name and relocated init/exit pointers, clears the untrusted compiler-provided
module object, and reconstructs only the measured state, self-linked list,
canonical name, lifecycle pointers, optional reference count, and all seven
Linux 6.12 memory descriptors from the admitted W^X regions. Every write is
read back through owned staging frames. Identity mismatch and unknown memory
models fail before mutation. This processor supplies only the module-identity
coverage bit; it does not grant runtime qualification while the remaining
special-section categories are unimplemented.

The smoke gate preserves the complete Kbuild-generated vermagic byte string
and feeds the module through `arach-ko-admit`. Admission parses fixed-layout
Linux 6.12 `__versions` records and the chained, padded records measured from
Ubuntu Linux 6.8, requires every undefined global to be versioned, resolves
every CRC against the SDK `Module.symvers`, and enforces GPL-only and
symbol-namespace policy. Both record streams are bounded and completely
validated; unknown encodings fail closed. The admission command also binds a
deterministic image address, resolves lifecycle symbols, and freezes every
allocated-section relocation after range and overlap checks. Catalog addresses
are deliberately non-executable placeholders, so this remains static load
admission. Runtime credit requires an Arach export catalog backed by live KPI
addresses, a native W^X memory backend, Linux special-section processing, and
observed initialization, operation, removal and rollback.
