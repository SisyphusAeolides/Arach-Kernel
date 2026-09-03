# Arach boot qualification

The boot qualification covers one exact Arach-Kernel revision and the
measured modules that GRUB passes to it:

1. the Arach Kernel Multiboot2 image;
2. RustD as PID 1;
3. RustD-resolved as the native resolver;
4. the bounded ring-3 Linux compatibility probe in `probes/c0`.

The ArachOS repository assembles these artifacts into its branded installer
and installed-system media. The kernel build requires explicit paths for all
three measured runtime artifacts; it never searches for a legacy component or
silently substitutes a host kernel.

The kernel-side contract verifies that every module is a bounded ELF image,
that the measured digest and entry offset match the build metadata, and that
the GRUB configuration names the modules `rustd`, `rustd-resolved`, and
`arachos-bootstrap`. A missing or mismatched artifact stops the build.

The ring-3 probe remains a compatibility test, not an init system. It checks
the Linux ABI surface exercised by RustD and records its markers in a serial
transcript when run under QEMU. Host compilation and unit tests are useful
evidence but do not replace a boot qualification run.

For a local kernel contract build:

```sh
CARGO_TARGET_DIR=/tmp/arach-kernel-contract \
ARACH_RUSTD_IMAGE=/path/to/rustd \
ARACH_RESOLVED_IMAGE=/path/to/rustd-resolved \
ARACH_BOOTSTRAP_IMAGE=/path/to/boot-probe \
ARACH_BOOTSTRAP_ABI=linux \
  cargo build --locked --release -p arach --bin arach \
    --no-default-features \
    --features kernel-bin,reference-driver,fortran-control \
    --target x86_64-arach.json -Z json-target-spec \
    -Z build-std=core,alloc,compiler_builtins \
    -Z build-std-features=compiler-builtins-mem
```

The resulting image must pass `grub-file --is-x86-multiboot2`. ArachOS then
performs the BIOS and UEFI installer and installed-system checks before any
release media is written.
