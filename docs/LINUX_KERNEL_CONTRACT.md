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

The current Arach tree has a native driver ABI, a bounded ET_REL loader, a
partial Linux memory/string KPI, and native GPU infrastructure. These are
useful implementation inputs but do not yet pass the external-module or
NVIDIA-runtime profiles. `current_arach_evidence()` therefore returns no Linux
contract credit until the corresponding integration suites exist and pass.

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
The same artifact is also parsed by Arach's bounded `arach-ko-inspect` preflight
to keep the build fixture and loader vocabulary synchronized.
