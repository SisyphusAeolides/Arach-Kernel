# RLC and GRUB integration

The RLC profile boots Arach Kernel directly through GRUB's Multiboot2 loader.
It does not use Granite, Push, or a COSMIC service bundle. RLC 10.2 is the
userspace and package source; RustD is PID 1 and RustD-resolved is the resolver.

The kernel build must set `ARACH_RUSTD_IMAGE` so the measured PID 1 identity is
bound into the kernel. The GRUB bundle must receive the same binary. Until the
RLC filesystem and complete Linux ABI gates pass, this profile is experimental
and must remain alongside a known-good Linux recovery kernel.

```sh
ARACH_KERNEL_IMAGE=/path/to/arach \
ARACH_RUSTD_IMAGE=/path/to/rustd \
ARACH_BOOTSTRAP_IMAGE=/path/to/bootstrap \
ARACH_RESOLVED_IMAGE=/path/to/rustd-resolved \
    scripts/build-rlc-grub-bundle.sh
```

Acceptance requires all of the following:

1. GRUB validates and enters the Multiboot2 kernel in BIOS and UEFI QEMU.
2. The measured `rustd` module enters ring 3 as Linux ABI PID 1.
3. Persistent RLC root storage, `/proc`, `/sys`, cgroup v2, udev, D-Bus, and
   package-installed RustD units work without compatibility substitutions.
4. RustD-resolved serves NSS, D-Bus, Varlink, and NetworkManager clients.
5. The RLC graphical Anaconda environment starts and completes an installation.
