# NVIDIA DKMS compatibility contract

Arach targets the open NVIDIA Linux GPU kernel modules from release
`610.43.03`, source revision
`452cec62d827034798072827d3866d1881662b77`.

This is a compatibility target, not a current compatibility claim. NVIDIA's
build calls the Linux external-Kbuild interface and depends on generated
configuration, `Module.symvers`, MODPOST, module linker scripts, Linux kernel
headers, and Linux `.ko` metadata. Arach's native C driver ABI, bounded ET_REL
loader, and Hermes GSP path do not substitute for those interfaces.

## Gates

Build qualification requires measured evidence for:

1. external Kbuild (`make -C <kernel> M=<module>`),
2. generated configuration and UTS release headers,
3. exported symbols and symbol versions in `Module.symvers`,
4. MODPOST and module linker scripts,
5. the Linux headers consumed by NVIDIA conftests, and
6. Linux module ELF metadata and relocations.

Runtime qualification additionally requires tested Linux-KPI services for PCI,
DMA/IOMMU, MSI/IRQ, synchronization, workqueues, timers, DRM/KMS, firmware/GSP,
and load, unload, suspend, resume, and failure rollback.

The reusable [Linux kernel compatibility contract](LINUX_KERNEL_CONTRACT.md)
owns these gates. `src/nvidia_dkms.rs` pins the NVIDIA revision and qualifies it
against the external-module and NVIDIA-runtime profiles. Build and static
load-admission evidence exists; NVIDIA-runtime evidence remains intentionally
empty until native Arach execution and hardware integration tests pass.

## Source audit

Clone the pinned official source under `target/nvidia-open`, then run:

```sh
scripts/audit-nvidia-source.sh target/nvidia-open
```

CI performs this audit against NVIDIA's official repository. It detects an
upstream contract change; it does not claim that Arach can load the modules.

## Build entry point

Once Arach exports a compatible source and output tree, build with:

```sh
ARACH_KBUILD_SOURCE=/path/to/arach-kbuild/source \
ARACH_KBUILD_OUTPUT=/path/to/arach-kbuild/output \
NVIDIA_SOURCE_ROOT=/path/to/open-gpu-kernel-modules \
    scripts/build-nvidia-dkms.sh
```

The command refuses to invoke NVIDIA's build when required Arach Kbuild
artifacts are absent, and it requires non-empty `nvidia.ko`,
`nvidia-modeset.ko`, `nvidia-drm.ko`, and `nvidia-uvm.ko` outputs. Passing that
build gate is still insufficient for release: the produced modules must pass
the Arach runtime lifecycle suite on supported NVIDIA hardware.

The default build uses four workers and may be overridden with
`NVIDIA_BUILD_JOBS`. Every required module is checked for `.modinfo` and exact
contract-SDK vermagic, then its SHA-256 digest is recorded in
`target/nvidia-dkms/build-measurement.json`. The report explicitly keeps
runtime qualification false until the Arach loader and GPU lifecycle suites
pass.

Each artifact also passes Arach's bounded structural parser and static
load-admission engine. The engine checks every `__versions` CRC against both
the SDK export catalog and the NVIDIA modules' generated `Module.symvers`,
including GPL-only and namespace rules. It then plans page-separated core/init
RX, R and RW regions, locates init/cleanup in their required regions, and
freezes every allocated-section relocation after bounds, range and overlap
checks. These catalogs use placeholder addresses, so this proves ELF/linker and
ABI consistency without claiming that Arach implements or can execute the
resolved KPI surface.
