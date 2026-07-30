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
Linux and architecture special section or rejects the module. Lifecycle
dispatch is a separate unsafe executor contract whose error path guarantees
module control was never entered. There are intentionally no permissive no-op
or host-call implementations of either contract.

Host fault-injection tests cover stale handles, conflicting hierarchy
ownership, allocation failure, partial page-table publication, failed seal
rollback, partial init discard, TLB flush ordering, retryable reclamation,
pre-seal rejection, duplicate live names, failed initialization, and cleanup
dispatch retry.

That is still not runtime qualification. Arach has no qualified synchronous
all-CPU TLB implementation or concrete native lifecycle executor for this
path, Linux special sections still need their production runtime processors,
and no admitted module has executed in an Arach boot.
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
